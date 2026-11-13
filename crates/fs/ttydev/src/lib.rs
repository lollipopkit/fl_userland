//! How a terminal reaches processes, and how a descriptor reaches a terminal.
//!
//! The terminal itself — its lock, its line discipline, its job control, the
//! pseudoterminal pair, every ioctl — is `crates/fs/tty`. This is the two edges
//! it has to the rest of the kernel, which is what `fs/tty.c` was left holding:
//!
//! - **the task side**, because what a terminal's rules are actually *about* is
//!   processes. Whose terminal this is, which group is in its foreground, who
//!   gets stopped for reading from the background. `crates/fs/tty` asks through
//!   [`TASK_OPS`] and never sees a `struct task`;
//! - **the device side**: `/dev/tty*`, `/dev/console`, `/dev/ptmx` and the
//!   `fd_ops` a terminal descriptor carries.
//!
//! # Claiming a terminal is two locks, never held together
//!
//! [`set_controlling`] tests and stores through `crates/kernel/ctty` first, and
//! only then tells the terminal. That order is the whole point: claiming takes
//! the terminal's own lock, and asking the process layer about a terminal takes
//! `ctty`'s. Holding both at once, either way round, is the cycle in
//! `docs/changelog/2026-08-31-a-terminal-asked-the-process-layer-while-holding-its-own-lock.md`.
//!
//! # A session is named by number, not followed by pointer
//!
//! [`steal_controlling`] and [`hangup_session`] ask the pid registry for the
//! groups in a session rather than dereferencing a leader they were handed. A
//! session leader can be reaped, and that exact dereference crashed the emulator
//! in `task_leave_session`, forty lines of call graph away, at
//! `offsetof(struct pid, session)`.
//!
//! # The console is enabled by a call
//!
//! `iul_enable_console` (Rust: [`enable_console`]). It was an embedder
//! assigning into a `static mut` driver table until 2026-10-17.

#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::{c_int, c_uint};
use std::sync::Arc;

use fs_tty::tty::{Open, Tty, User};
use std::sync::atomic::{AtomicI32, Ordering};

// The shared Rust types and constants are re-exported by kernel-taskview.
pub use taskview::ffi;

use guest_errno::c_int_::{EINVAL, EIO, ENXIO};

/// The calling task's thread group, lent for `f`. There is one on every path
/// here: each runs inside a syscall. A raw pointer every caller dereferenced
/// until 2026-09-30, so "never null" was a comment rather than a check.
fn group<R>(f: impl FnOnce(&ffi::tgroup) -> R) -> R {
    taskview::with_current_group(f).expect("a terminal operation runs on a task with a group")
}

mod task;

// --------------------------------------------------------- the console driver

/// Whether the host terminal is the guest's console.
///
/// A 256-entry `static mut` driver table until 2026-10-17, `tty_drivers`, that
/// an embedder enabled the console by assigning one entry of -- and of which
/// nothing but "is the console's entry non-null" was ever read. It is that one
/// bit now, set by [`enable_console`].
static CONSOLE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Make the host terminal the guest's console, before the first open of it.
pub fn enable_console() {
    CONSOLE.store(true, std::sync::atomic::Ordering::Release);
}

/// The C spelling of [`enable_console`].
#[unsafe(no_mangle)]
pub extern "C" fn iul_enable_console() {
    enable_console();
}

fn console_enabled(major: c_int) -> bool {
    major == ffi::TTY_CONSOLE_MAJOR as c_int && CONSOLE.load(std::sync::atomic::Ordering::Acquire)
}

/// The host terminal, as a terminal sees it. `crates/fs/ttyreal` is what is
/// behind every method.
struct ConsoleOps;

impl fs_tty::ops::ConsoleOps for ConsoleOps {
    fn init(&self, tty: &Arc<fs_tty::tty::Tty>, num: c_int) -> c_int {
        ttyreal::real_tty_init(tty, num)
    }
    fn write(&self, num: c_int, buf: &[u8]) -> isize {
        ttyreal::real_tty_write(num, buf)
    }
    fn cleanup(&self, num: c_int) {
        ttyreal::real_tty_cleanup(num);
    }
    fn enabled(&self, major: c_int) -> bool {
        console_enabled(major)
    }
}

static CONSOLE_OPS: ConsoleOps = ConsoleOps;

pub fn tty_init_ops() {
    fs_tty::ops::tty_bind_ops(&task::TASK_OPS, &CONSOLE_OPS);
}

// ----------------------------------------------------- an embedder's terminal

/// Only `write` is used. The rest of `struct tty_driver_ops` is accepted so that
/// an embedder built against the older shape still compiles; there is nothing
/// left for the other five to do, because the object they reached into is no
/// longer a struct this side can see.
/// The pointer is published with release ordering before the callback can run.
static EXTERNAL_OPS: std::sync::atomic::AtomicPtr<ffi::tty_driver_ops> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

/// The terminal is `crates/fs/tty`'s `Tty`; the embedder's callback takes the
/// opaque `struct tty *` its header declares, which is the one cast here.
fn external_write(tty: &fs_tty::tty::Tty, buf: &[u8], blocking: bool) -> c_int {
    let ops = EXTERNAL_OPS.load(Ordering::Acquire);
    // SAFETY: published by `pty_open_fake`, whose caller undertook that the
    // driver and its `write` outlive the terminal.
    match unsafe { ops.as_ref() }.and_then(|ops| ops.write) {
        None => buf.len() as c_int,
        // SAFETY: the embedder's callback, given a live terminal and buffer.
        Some(write) => unsafe {
            write(std::ptr::from_ref(tty).cast_mut().cast(), buf.as_ptr().cast(), buf.len(), blocking)
        },
    }
}

/// **Answers an `ERR_PTR`**, which `iul.h` declares and `IS_ERR` is how a
/// caller tells it from a terminal. Never null.
///
/// The encoding is `ffi::err_ptr`, and it was written out by hand as
/// `EINVAL as isize as *mut ffi::tty` at three returns until 2026-09-16. That
/// is the same expression `err_ptr` is, so nothing was wrong at runtime -- what
/// it cost is that `rg err_ptr` found two of the three sites, and both of the
/// two say in a comment that they are "one of the **two** places the `ERR_PTR`
/// encoding is left". They were wrong about the count for as long as this
/// spelled it differently.
///
/// # Safety
/// `driver` is null or live, with an `ops` whose `write` stays callable for as
/// long as the terminal does.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pty_open_fake(driver: *mut ffi::tty_driver) -> *mut ffi::tty {
    if driver.is_null() {
        return ffi::err_ptr(EINVAL);
    }
    let ops = unsafe { (*driver).ops };
    if ops.is_null() || unsafe { (*ops).write }.is_none() {
        return ffi::err_ptr(EINVAL);
    }
    // One embedder, one session driver: ServerBox has exactly one, and so does
    // tests/integration/sbm_api_test.c. A second would need the callback to
    // carry a context, which the C signature has no room for.
    EXTERNAL_OPS.store(ops.cast_mut(), Ordering::Release);
    // `external_write` reads `EXTERNAL_OPS`, just published, and the
    // embedder's `write` behind it is the caller's undertaking above.
    match fs_tty::abi::tty_open_external(external_write) {
        Ok(tty) => tty.cast_mut(),
        Err(e) => ffi::err_ptr(e),
    }
}

/// Bytes typed into the terminal `pty_open_fake` made: what its session reads
/// on fd 0. The count taken, `_EAGAIN` when the input queue is full and
/// `blocking` is false, or another negative errno.
///
/// # Safety
/// `tty` came from [`pty_open_fake`] and has not been released; `buf` is
/// readable for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tty_input(
    tty: *const ffi::tty,
    buf: *const std::ffi::c_void,
    len: usize,
    blocking: bool,
) -> isize {
    if len == 0 {
        return 0;
    }
    if buf.is_null() {
        return EINVAL as isize;
    }
    // SAFETY: the caller's contract.
    let bytes = unsafe { std::slice::from_raw_parts(buf.cast::<u8>(), len) };
    unsafe { fs_tty::abi::tty_input(tty, bytes, blocking) }
}

/// Give back the reference [`pty_open_fake`] handed over. The session's own
/// descriptors hold references of their own, so this is safe while it runs.
///
/// # Safety
/// `tty` came from [`pty_open_fake`], and is not used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tty_release(tty: *mut ffi::tty) {
    unsafe { fs_tty::abi::tty_release(tty) };
}

// ------------------------------------------------------------------ vhangup

/// `vhangup(2)`: hang up the caller's controlling terminal, if it has one.
///
/// Linux's `tty_vhangup_self`, behind `CAP_SYS_TTY_CONFIG`, which here is the
/// superuser. Measured by `rarecalls_probe` and `ttyhup_probe`: the
/// descriptions open on the terminal answer end of file, `EIO` and
/// `POLLHUP`, the session loses it (`/dev/tty` is `ENXIO` after), its leader
/// gets `SIGHUP` and `SIGCONT`, and the terminal opens again and works.
pub fn sys_vhangup() -> Result<(), guest_errno::Errno> {
    if !taskview::capable(taskview::caps::CAP_SYS_TTY_CONFIG) {
        return Err(guest_errno::Errno::EPERM);
    }
    // Held across the hangup, so the references it takes away from the
    // session under `pids_lock` are never the last.
    if let Some(held) = group(|g| g.ctty.retain()) {
        fs_tty::tty::hangup(held.tty());
    }
    Ok(())
}

// ------------------------------------------------------ descriptor operations

/// The terminal this description has open: its driver state, since
/// 2026-09-29, holding one user and one strong count. It was a raw pointer in
/// a union arm that `fd_close` handed to `tty_close` and nulled, and an
/// `Arc<Tty>` whose user was implied until 2026-09-30; a `tty::User` said so,
/// and since 2026-11-12 a `tty::Open` does, which also knows whether this
/// description has been hung up.
fn terminal(fd: &ffi::fd) -> Option<&Open> {
    fd.driver_state::<Open>()
}

fn fd_read(fd: &ffi::fd, buf: &mut [u8]) -> isize {
    let nonblock = fd.flags() & ffi::O_NONBLOCK_ != 0;
    terminal(fd).map_or(EINVAL as isize, |t| fs_tty::tty::read(t, buf, nonblock))
}

fn fd_write(fd: &ffi::fd, buf: &[u8]) -> isize {
    let nonblock = fd.flags() & ffi::O_NONBLOCK_ != 0;
    terminal(fd).map_or(EINVAL as isize, |t| fs_tty::tty::write(t, buf, nonblock))
}

fn fd_poll(fd: &ffi::fd) -> c_int {
    terminal(fd).map_or(0, fs_tty::tty::poll)
}

fn fd_ioctl_size(cmd: c_int) -> isize {
    fs_tty::abi::tty_ioctl_size(cmd)
}

fn fd_ioctl(fd: &ffi::fd, cmd: c_int, arg: ffi::IoctlArg<'_>) -> c_int {
    terminal(fd).map_or(EINVAL, |t| fs_tty::abi::tty_ioctl(t, cmd, arg))
}

fn fd_close(fd: &mut ffi::fd) -> c_int {
    // The terminal's own close, which takes the description's user and gives
    // it back. It went through `abi::tty_close` -- `Arc::into_raw` in,
    // `Arc::from_raw` back out -- until 2026-09-30.
    if let Some(open) = fd.take_driver_state::<Open>() {
        fs_tty::tty::close(*open, &fd.poll_watchers);
    }
    0
}

/// By default `/dev/console` is `/dev/tty1`.
///
/// Atomics rather than `static mut`, and **no `#[no_mangle]`**: no header
/// declares them and no C names them, so the symbol was a second interface with
/// nobody on the other side -- and an optimisation barrier, which `CLAUDE.md`
/// records. `crates/kernel/boot` declared them `extern` and writes them through
/// [`set_console_device`] now, which is a dependency edge cargo can see.
static CONSOLE_MAJOR: AtomicI32 = AtomicI32::new(ffi::TTY_CONSOLE_MAJOR as c_int);
static CONSOLE_MINOR: AtomicI32 = AtomicI32::new(1);

/// Point `/dev/console` somewhere else. An embedder may.
pub fn set_console_device(major: c_int, minor: c_int) {
    CONSOLE_MAJOR.store(major, Ordering::Relaxed);
    CONSOLE_MINOR.store(minor, Ordering::Relaxed);
}

/// Where `/dev/console` points.
pub(crate) fn console_device() -> (c_int, c_int) {
    (
        CONSOLE_MAJOR.load(Ordering::Relaxed),
        CONSOLE_MINOR.load(Ordering::Relaxed),
    )
}

/// The character-device table for a terminal, for `crates/fs/devices`.
///
/// The one reader is `crates/fs/devices`, as a Rust call. `fs/tty.h` declared
/// `tty_dev` and the `#[no_mangle]` was for that; the header has been gone
/// since 2026-09-09 and so is the attribute, which was also what let that
/// crate's test binary carry a **second definition** of the symbol.
pub fn tty_dev_ops() -> &'static ffi::dev_ops {
    &TTY_DEV
}

/// The terminal a device number names, with the user the descriptor will
/// hold taken.
fn open_user(major: c_int, minor: c_int) -> Result<User, c_int> {
    if major == ffi::TTY_ALTERNATE_MAJOR as c_int {
        return match minor as u32 {
            // The caller's controlling terminal, whatever it is, with a
            // reference taken while the group still holds it -- otherwise the
            // group can give it up between the read and the retain.
            ffi::DEV_TTY_MINOR => group(|g| g.ctty.retain()).ok_or(ENXIO),
            ffi::DEV_CONSOLE_MINOR => {
                let (maj, min) = console_device();
                open_user(maj, min)
            }
            ffi::DEV_PTMX_MINOR => fs_tty::pty::open_master(),
            _ => Err(ENXIO),
        };
    }
    // A pty master is never opened by name: /dev/ptmx is the only way to one,
    // and a device node naming its major answers EIO as Linux does.
    if major == ffi::TTY_PSEUDO_MASTER_MAJOR as c_int {
        return Err(EIO);
    }
    let kind = fs_tty::tty::Kind::of(major).ok_or(ENXIO)?;
    let user = User::get(kind, minor)?;
    if kind == fs_tty::tty::Kind::PtySlave {
        let err = fs_tty::pty::open_slave(user.tty());
        if err < 0 {
            return Err(err);
        }
    }
    Ok(user)
}

fn device_open(major: c_int, minor: c_int, fd: &mut ffi::fd) -> c_int {
    let user = match open_user(major, minor) {
        Ok(user) => user,
        Err(err) => return err,
    };
    // On failure the user is dropped, which is the release.
    match Open::new(user, &fd.poll_watchers, fd.flags() as c_int) {
        Ok(open) => {
            fd.set_driver_state(Box::new(open));
            0
        }
        Err(err) => err,
    }
}

fn ptmx_open(_major: c_int, _minor: c_int, fd: &mut ffi::fd) -> c_int {
    device_open(
        ffi::TTY_ALTERNATE_MAJOR as c_int,
        ffi::DEV_PTMX_MINOR as c_int,
        fd,
    )
}

/// The six descriptor operations a terminal carries, shared by both device
/// tables. `ioctl_size` is beside `ioctl` because a missing one makes the other
/// **unreachable**: `fd_ioctl` answers `ENOTTY` for a negative size before it
/// calls the handler at all. See `tools/ops-table-pairs.py` — the pairing is
/// two methods of one trait now, so the two can no longer be set from
/// different places.
///
/// It was a `const fn` returning an `fd_ops` with all fifteen fields written
/// out and six then assigned, because a partly-initialised `#[repr(C)]` table
/// had to say `None` fifteen times before it could say `Some` six.
pub(crate) struct TtyFd;

pub(crate) static TTY_FDOPS: TtyFd = TtyFd;

impl ffi::FdOps for TtyFd {
    fn caps(&self) -> ffi::Caps {
        ffi::Caps::STREAM
    }
    fn read(&self, fd: &ffi::fd, buf: &mut [u8]) -> isize {
        fd_read(fd, buf)
    }
    fn write(&self, fd: &ffi::fd, buf: &[u8]) -> isize {
        fd_write(fd, buf)
    }
    fn poll(&self, fd: &ffi::fd) -> Option<c_int> {
        Some(fd_poll(fd))
    }
    fn ioctl_size(&self, cmd: c_int) -> isize {
        fd_ioctl_size(cmd)
    }
    fn ioctl(&self, fd: &ffi::fd, cmd: c_int, arg: ffi::IoctlArg<'_>) -> c_int {
        fd_ioctl(fd, cmd, arg)
    }
    fn close(&self, fd: &mut ffi::fd) -> c_int {
        fd_close(fd)
    }
}

/// `/dev/tty*`, `/dev/console` and the pseudoterminal pair.
///
/// A plain `static`, not a `static mut`: nothing has ever written either of
/// these and a `&raw const` of a `static mut` is the shape `static_mut_refs`
/// exists to warn about. They could not be plain statics while `dev_ops`
/// embedded an `fd_ops` by value, because that made them a table somebody
/// might fill in.
pub static TTY_DEV: ffi::dev_ops = ffi::dev_ops {
    open: Some(device_open),
    fd: Some(&TTY_FDOPS),
};

/// `/dev/ptmx` as a device of its own.
///
/// **Nothing reads this**, in this workspace or outside it: `/dev/ptmx` is
/// reached through [`TTY_DEV`]'s `device_open` with `DEV_PTMX_MINOR`. It was
/// `#[no_mangle] static mut` and the attribute came off with `dev_ops`'s
/// `#[repr(C)]` — an export that claims a C-visible layout the type no longer
/// has is worse than no export. Left in place rather than deleted because
/// whether an out-of-tree embedder registers it is not a fact this repository
/// holds; `tools/dead-exports.py` is where that question belongs.
pub static PTMX_DEV: ffi::dev_ops = ffi::dev_ops {
    open: Some(ptmx_open),
    fd: Some(&TTY_FDOPS),
};

/// The C this crate calls, for a test build that links none of the kernel.
///
/// Every one of them is reachable from the two operation tables, so without
/// these the tests cannot link at all — which is the reason several crates in
/// this tree had none. They answer nothing; what the tests check is the shape of
/// the tables, not what the calls do.
///
/// The two dev-dependencies this crate's tests need for their *symbols* rather
/// than their API: `crates/kernel/sighand` and `crates/kernel/sigqueue` are what
/// the real `wait_for` reaches, and naming them is what keeps cargo from
/// dropping the edge.
///
/// It held two `#[no_mangle]` doubles as well until 2026-09-09 —
/// `stage_trace_on` and `native_offload_forward_signal` — and neither is an
/// exported symbol any more. See `tools/dead-stubs.py`.
#[cfg(test)]
mod test_c_stubs {
    use kernel_sighand as _;
    use kernel_sigqueue as _;
}

// `mod stubs` went on 2026-09-30. Its last two entries were `tty_open`, a
// double of `crates/fs/tty`'s export that nothing in this crate calls since the
// descriptor open became a Rust call, and `crates/kernel/taskview-teststub`,
// whose `task_self` doubled `taskview`'s own. Neither was ever linked into the
// test binary -- `ld` loads an archive member only for a symbol something
// references, and nothing did -- which is also why `tools/dup-stubs.py`
// could not see them.

#[cfg(test)]
mod tests;
