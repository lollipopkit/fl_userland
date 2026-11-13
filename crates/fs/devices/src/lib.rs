//! Which device is at which number, and the five that are only a rule.
//!
//! Three files of C: the major table (`fs/dev.c`), the minor table under
//! `MEM_MAJOR` (`fs/mem.c`), and the one an embedder registers into
//! (`fs/dyndev.c`). What they have in common is that a **guest chooses the
//! index**: `mknod` names a major and a minor, and the guest is root inside a
//! fakefs, so both numbers are attacker-controlled.
//!
//! Both tables had an unchecked one. A `dev_t` carries a 12-bit major and these
//! tables have 256 entries, so `mknod /dev/x c 300 0` read a function pointer
//! from whatever followed the array and called it; and the minor was handed
//! straight through to the dynamic table, where twenty bits of it meant
//! `mknod /dev/x c 240 1048575` read about eight megabytes past the array. Both
//! took the emulator down with an indirect call to whatever they landed on.
//! Here the tables are slices and the lookup is `get`, so an out-of-range index
//! is `None`.
//!
//! # `RNDGETENTCNT` never ran
//!
//! `/dev/random` had an `ioctl` and no `ioctl_size`, and `fd_ioctl` answers
//! `ENOTTY` for a `size < 0` before it calls anything. So the handler was dead
//! code and the command answered `ENOTTY` where a real kernel answers a count —
//! measured against an arm64 container, which says `count=256`. Programs read
//! it to decide whether entropy is available.


use std::ffi::c_int;
use std::sync::Mutex;

/// `struct fd` and `struct dev_ops`, both of which are
/// `crates/kernel/taskview`'s own Rust, and the `FdOps` trait the four devices
/// below implement. This crate ran bindgen for them and then blocklisted them,
/// so the generated file was the import line below -- plus
/// `enum iul_poll_bits`, which nothing named.
use taskview::ffi;

mod errno {
    pub use guest_errno::c_int_::{EINVAL, ENOSPC, ENOTTY, ENXIO};
    #[cfg(test)]
    pub(crate) use guest_errno::c_int_::EEXIST;
}

/// Loosely `devices.txt` from Linux.
/// How a major and a minor pack into a `dev_t_`, from `fs/dev.h`.
///
/// **Not `major << 16 | minor`.** It is Linux's encoding, which splits the
/// minor: the low eight bits stay at the bottom, the major goes at bit 8, and
/// the rest of the minor goes at bit 20. `dev_make(4, 1)` is `0x401`, not
/// `0x40001`.
///
/// One definition because there were four, each a hand-copy of a `static
/// inline` bindgen cannot emit, and **one of them was the wrong encoding**:
/// `/proc/<pid>/stat` reported a terminal number `ps` attributes to nothing.
pub fn dev_make(major: u32, minor: u32) -> u32 {
    ((minor & 0xfff00) << 12) | ((major & 0xfff) << 8) | (minor & 0xff)
}

/// The major out of a packed `dev_t_`.
pub fn dev_major(dev: u32) -> u32 {
    (dev & 0xfff00) >> 8
}

/// The minor out of a packed `dev_t_`, both halves.
pub fn dev_minor(dev: u32) -> u32 {
    ((dev & 0xfff0_0000) >> 12) | (dev & 0xff)
}

pub mod major {
    pub const MEM: usize = 1;
    pub const TTY_CONSOLE: usize = 4;
    pub const TTY_ALTERNATE: usize = 5;
    pub const TTY_PSEUDO_MASTER: usize = 128;
    pub const TTY_PSEUDO_SLAVE: usize = 136;
    pub const DYN_DEV: usize = 240;
}

pub mod mem_minor {
    pub const NULL: usize = 3;
    pub const ZERO: usize = 5;
    pub const FULL: usize = 7;
    pub const RANDOM: usize = 8;
    pub const URANDOM: usize = 9;
}

/// `DEV_BLOCK` and `DEV_CHAR`.
const DEV_BLOCK: c_int = 0;
/// The bound a guest-supplied major is checked against, and the size of the
/// table it indexes. One definition, so the two cannot drift apart.
const MAJOR_MAX: usize = 256;
/// The same for a minor in the dynamic table.
const MINOR_MAX: usize = 256;

/// A device that does nothing, for the registration tests.
///
/// `struct Ops(ffi::dev_ops)` was here as well, to make a `dev_ops` `Sync` --
/// it holds function pointers and is written once. `dev_ops` holds a
/// `&'static dyn FdOps` now and `FdOps: Send + Sync`, so it is `Sync` on its
/// own and the four device tables are plain statics.
#[cfg(test)]
fn empty_ops() -> ffi::dev_ops {
    ffi::dev_ops::default()
}

// ---------------------------------------------------------------------------
// The five inline devices
// ---------------------------------------------------------------------------

fn ready_poll(_fd: &ffi::fd) -> c_int {
    (fs_poll::bits::READ | fs_poll::bits::WRITE) as c_int
}

/// Whether this descriptor's readiness is a **constant**.
///
/// `poll()` on `/dev/null` reports readable and writable and always will; there
/// is no transition to wait for. Linux says the same thing by a different
/// route: `memory_fops` has no `->poll` at all, so `poll()` falls back to
/// `DEFAULT_POLLMASK` — which is that same always-ready answer — and *epoll*,
/// which needs a method to attach a wait queue to, refuses the file with
/// `EPERM`. That is the same `EPERM` a regular file gets, and for the same
/// reason: registering one is a busy loop the caller did not ask for.
///
/// `epoll_ctl` asks this. It was `fn_addr_eq(ops->poll, ready_poll)` until
/// 2026-09-11 — the operation rather than the table, because that is what a
/// driver chooses — and it is [`ffi::FdOps::readiness_is_constant`] now, which
/// is the driver saying so. What an address comparison could answer is "does
/// this behave like `ready_poll`"; the question is whether this driver's
/// readiness can change, and only the driver knows that.
pub fn readiness_is_constant(fd: &ffi::fd) -> bool {
    fd.ops.is_some_and(|ops| ops.readiness_is_constant())
}

fn null_open(_major: c_int, _minor: c_int, _fd: &mut ffi::fd) -> c_int {
    0
}

fn null_read(_fd: &ffi::fd, _buf: &mut [u8]) -> isize {
    0
}

/// A write to `/dev/null` succeeds and keeps nothing.
fn null_write(_fd: &ffi::fd, buf: &[u8]) -> isize {
    buf.len() as isize
}

/// Every seek on one of these is to zero: they have no position.
fn null_lseek(_fd: &ffi::fd, _off: i64, _whence: c_int) -> i64 {
    0
}

fn zero_read(_fd: &ffi::fd, buf: &mut [u8]) -> isize {
    buf.fill(0);
    buf.len() as isize
}

/// `/dev/full` reads as zeroes and refuses every write, which is what it is
/// for: testing that a program handles a full disk.
fn full_write(_fd: &ffi::fd, _buf: &[u8]) -> isize {
    errno::ENOSPC as isize
}

fn random_read(_fd: &ffi::fd, buf: &mut [u8]) -> isize {
    kernel_random::fill(buf);
    buf.len() as isize
}

/// `RNDGETENTCNT`: how many bits of entropy the pool holds.
const RNDGETENTCNT: c_int = 0x80045200_u32 as c_int;

/// Four bytes for `RNDGETENTCNT`, and nothing else.
///
/// **Without this the handler below never ran.** `fd_ioctl` asks the driver how
/// big the argument is and answers `ENOTTY` for a negative — which is what a
/// missing `ioctl_size` produces — before it calls `ioctl` at all.
fn random_ioctl_size(cmd: c_int) -> isize {
    if cmd == RNDGETENTCNT { 4 } else { -1 }
}

fn random_ioctl(_fd: &ffi::fd, cmd: c_int, mut arg: ffi::IoctlArg<'_>) -> c_int {
    if cmd != RNDGETENTCNT {
        return errno::ENOTTY;
    }
    // A full pool. The host's generator does not block and has no count to
    // report, and a program reads this to decide whether to wait — so the
    // honest answer is the one that says it need not.
    if arg.write(4096i32) { 0 } else { errno::EINVAL }
}

/// The four inline memory devices, as drivers.
///
/// Each was five or seven assignments into a copy of an all-`None` `dev_ops`
/// inside a `LazyLock`, so what `/dev/null` could do was spread over as many
/// statements and a `Default`. They differ only in a read and a write, which is
/// what the four implementations below say and the assignments did not.
///
/// [`ffi::FdOps::readiness_is_constant`] is `true` for all four, and that is the
/// whole of what `epoll_ctl` used to establish by comparing `ready_poll`'s
/// address.
/// What all four share: seekable-to-zero, and ready in both directions for
/// ever. Written once here rather than four times, and a device that wanted a
/// different answer would override it.
const MEM_CAPS: ffi::Caps = ffi::Caps {
    read: true,
    write: true,
    seek: true,
    read_at: false,
    write_at: false,
};

/// `/dev/null`: reads as end-of-file, swallows every write.
struct NullFd;
impl ffi::FdOps for NullFd {
    fn caps(&self) -> ffi::Caps {
        MEM_CAPS
    }
    fn read(&self, fd: &ffi::fd, buf: &mut [u8]) -> isize {
        null_read(fd, buf)
    }
    fn write(&self, fd: &ffi::fd, buf: &[u8]) -> isize {
        null_write(fd, buf)
    }
    fn lseek(&self, fd: &ffi::fd, off: i64, whence: c_int) -> i64 {
        null_lseek(fd, off, whence)
    }
    fn poll(&self, fd: &ffi::fd) -> Option<c_int> {
        Some(ready_poll(fd))
    }
    fn readiness_is_constant(&self) -> bool {
        true
    }
}

/// `/dev/zero`: reads as zeroes, swallows every write.
struct ZeroFd;
impl ffi::FdOps for ZeroFd {
    fn caps(&self) -> ffi::Caps {
        MEM_CAPS
    }
    fn read(&self, fd: &ffi::fd, buf: &mut [u8]) -> isize {
        zero_read(fd, buf)
    }
    fn write(&self, fd: &ffi::fd, buf: &[u8]) -> isize {
        null_write(fd, buf)
    }
    fn lseek(&self, fd: &ffi::fd, off: i64, whence: c_int) -> i64 {
        null_lseek(fd, off, whence)
    }
    fn poll(&self, fd: &ffi::fd) -> Option<c_int> {
        Some(ready_poll(fd))
    }
    fn readiness_is_constant(&self) -> bool {
        true
    }
}

/// `/dev/full`: reads as zeroes, refuses every write with `ENOSPC`.
struct FullFd;
impl ffi::FdOps for FullFd {
    fn caps(&self) -> ffi::Caps {
        MEM_CAPS
    }
    fn read(&self, fd: &ffi::fd, buf: &mut [u8]) -> isize {
        zero_read(fd, buf)
    }
    fn write(&self, fd: &ffi::fd, buf: &[u8]) -> isize {
        full_write(fd, buf)
    }
    fn lseek(&self, fd: &ffi::fd, off: i64, whence: c_int) -> i64 {
        null_lseek(fd, off, whence)
    }
    fn poll(&self, fd: &ffi::fd) -> Option<c_int> {
        Some(ready_poll(fd))
    }
    fn readiness_is_constant(&self) -> bool {
        true
    }
}

/// `/dev/random` and `/dev/urandom`, which are the same device here.
///
/// The only one of the four with an ioctl, and both halves of it are below:
/// `ioctl_size` refusing every command but `RNDGETENTCNT` is what makes the
/// handler reachable at all.
struct RandomFd;
impl ffi::FdOps for RandomFd {
    fn caps(&self) -> ffi::Caps {
        MEM_CAPS
    }
    fn read(&self, fd: &ffi::fd, buf: &mut [u8]) -> isize {
        random_read(fd, buf)
    }
    fn write(&self, fd: &ffi::fd, buf: &[u8]) -> isize {
        null_write(fd, buf)
    }
    fn lseek(&self, fd: &ffi::fd, off: i64, whence: c_int) -> i64 {
        null_lseek(fd, off, whence)
    }
    fn poll(&self, fd: &ffi::fd) -> Option<c_int> {
        Some(ready_poll(fd))
    }
    fn readiness_is_constant(&self) -> bool {
        true
    }
    fn ioctl_size(&self, cmd: c_int) -> isize {
        random_ioctl_size(cmd)
    }
    fn ioctl(&self, fd: &ffi::fd, cmd: c_int, arg: ffi::IoctlArg<'_>) -> c_int {
        random_ioctl(fd, cmd, arg)
    }
}

static NULL_DEV: ffi::dev_ops = ffi::dev_ops {
    open: Some(null_open),
    fd: Some(&NullFd),
};

static ZERO_DEV: ffi::dev_ops = ffi::dev_ops {
    open: Some(null_open),
    fd: Some(&ZeroFd),
};

static FULL_DEV: ffi::dev_ops = ffi::dev_ops {
    open: Some(null_open),
    fd: Some(&FullFd),
};

static RANDOM_DEV: ffi::dev_ops = ffi::dev_ops {
    open: Some(null_open),
    fd: Some(&RandomFd),
};

// ---------------------------------------------------------------------------
// MEM_MAJOR's minors
// ---------------------------------------------------------------------------

/// The device at `minor` under `MEM_MAJOR`.
fn mem_dev_at(minor: c_int) -> Option<&'static ffi::dev_ops> {
    let table: &[(usize, &'static ffi::dev_ops)] = &[
        (mem_minor::NULL, &NULL_DEV),
        (mem_minor::ZERO, &ZERO_DEV),
        (mem_minor::FULL, &FULL_DEV),
        (mem_minor::RANDOM, &RANDOM_DEV),
        // /dev/urandom is the same device. Linux distinguishes them by whether
        // they block before the pool is seeded, and the host's never does.
        (mem_minor::URANDOM, &RANDOM_DEV),
    ];
    if minor < 0 {
        return None;
    }
    table
        .iter()
        .find(|(n, _)| *n == minor as usize)
        .map(|(_, ops)| *ops)
}

/// Attach `dev`'s driver to `fd` and run its open.
///
/// Safe: the descriptor is being built and this is the only reference to it.
fn open_with(
    dev: &'static ffi::dev_ops,
    major: c_int,
    minor: c_int,
    fd: &mut ffi::fd,
) -> c_int {
    fd.ops = dev.fd;
    match dev.open {
        Some(open) => open(major, minor, fd),
        None => 0,
    }
}

fn mem_open(major: c_int, minor: c_int, fd: &mut ffi::fd) -> c_int {
    let Some(dev) = mem_dev_at(minor) else {
        return errno::ENXIO;
    };
    open_with(dev, major, minor, fd)
}

static MEM_DEV: ffi::dev_ops = ffi::dev_ops {
    open: Some(mem_open),
    fd: None,
};

// ---------------------------------------------------------------------------
// The dynamic table
// ---------------------------------------------------------------------------

/// What an embedder registered, by minor number.
///
/// Under a lock on **every** access. The C read it without one, on the strength
/// of a comment saying "it's safe to access devs without locking (read-only)" —
/// and it is not, because `dyn_dev_register` writes it and an embedder may
/// register a device after the guest has started.
static DYN_DEVS: Mutex<DynDevs> = Mutex::new(DynDevs([0; MINOR_MAX]));

/// The table an embedder registers into. Addresses are supplied by the
/// embedder and valid for the life of the process; they are reconstructed only
/// after lookup under the registry lock.
struct DynDevs([usize; MINOR_MAX]);

fn dyn_open_char(major: c_int, minor: c_int, fd: &mut ffi::fd) -> c_int {
    // The minor is the guest's, and this table has MINOR_MAX entries. It used
    // to be handed straight through, and a dev_t carries twenty bits of it.
    if minor < 0 || minor as usize >= MINOR_MAX {
        return errno::ENXIO;
    }
    let ops = {
        let devs = DYN_DEVS.lock().unwrap_or_else(|e| e.into_inner());
        devs.0[minor as usize]
    };
    if ops == 0 {
        return errno::ENXIO;
    }
    // SAFETY: `dev_register` promises an address that outlives the process.
    // SAFETY: `ops` came from the device registry, which holds `&'static`
    // tables.
    open_with(unsafe { &*(ops as *const ffi::dev_ops) }, major, minor, fd)
}

static DYN_DEV_CHAR: ffi::dev_ops = ffi::dev_ops {
    open: Some(dyn_open_char),
    fd: None,
};

// ---------------------------------------------------------------------------
// The major table
// ---------------------------------------------------------------------------

/// The character device at `major`.
///
/// A `match` rather than an array because five of the six entries are constants
/// and the sixth is this crate's own — an array would need runtime
/// initialisation and a lock, for a table that never changes.
fn char_dev_at(major: c_int) -> Option<&'static ffi::dev_ops> {
    if major < 0 || major as usize >= MAJOR_MAX {
        return None;
    }
    match major as usize {
        major::MEM => Some(&MEM_DEV),
        major::TTY_CONSOLE
        | major::TTY_ALTERNATE
        | major::TTY_PSEUDO_MASTER
        | major::TTY_PSEUDO_SLAVE => Some(fs_ttydev::tty_dev_ops()),
        major::DYN_DEV => Some(&DYN_DEV_CHAR),
        _ => None,
    }
}

/// Open the device node at `(major, minor)`.
///
/// **The major is bounded first.** It comes from a `dev_t` a guest wrote with
/// `mknod`, which carries twelve bits of it, and the tables have 256 entries —
/// so an unchecked index read a function pointer from whatever followed the
/// array and called it. `mknod /dev/x c 300 0` in a fakefs, where the guest is
/// root, was an arbitrary indirect call from an unprivileged syscall; it took
/// the emulator down with `SIGBUS` on a pc of `0xb9000fe0d10043ff`.
///
/// Takes the description by `&mut`, which is what it writes through -- `ops`
/// and the driver's state -- and so is called on one nobody else can see yet:
/// `generic_openat` and boot's stdio run it before publishing.
pub fn open_device(major: c_int, minor: c_int, dev_type: c_int, fd: &mut ffi::fd) -> c_int {
    // No block devices yet, so the block table is empty rather than absent:
    // asking for one is ENXIO, which is what an empty table would answer.
    let dev = if dev_type == DEV_BLOCK {
        None
    } else {
        char_dev_at(major)
    };
    let Some(dev) = dev else {
        return errno::ENXIO;
    };
    open_with(dev, major, minor, fd)
}

/// [`open_device`], for `iul.h`.
///
/// # Safety
/// `fd` is a live descriptor being opened, which nothing else is using.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dev_open(major: c_int, minor: c_int, dev_type: c_int, fd: *mut ffi::fd) -> c_int {
    // SAFETY: the caller's contract.
    open_device(major, minor, dev_type, unsafe { &mut *fd })
}

/* `mod c_stubs` was here: a `#[no_mangle] static tty_dev: [u64; 64]`, with a
 * comment saying "`tty_dev` is `fs/tty.c`'s, and a standalone test binary links
 * no C at all". Both halves stopped being true — `tty_dev` is
 * `crates/fs/ttydev`'s Rust static, and this crate names that crate at line 356
 * for `tty_dev_ops()`, so the real symbol is in every one of these test
 * binaries. It was a **second definition** `ld` picked between, which
 * `tools/dup-stubs.py` reported. Removed 2026-09-09. */

#[cfg(test)]
mod dev_number_tests {
    use super::*;

    #[test]
    fn the_packing_is_fs_dev_hs_and_not_the_obvious_one() {
        // `((minor & 0xfff00) << 12) | (major << 8) | (minor & 0xff)`. The
        // obvious `major << 16 | minor` gives 0x40001 for the first of these,
        // which is what one of the four hand-copies did.
        assert_eq!(dev_make(4, 1), 0x401);
        assert_eq!(dev_make(136, 0), 136 << 8);
        assert_eq!(dev_make(136, 5), (136 << 8) | 5);
        assert_eq!(dev_make(5, 2), (5 << 8) | 2);
    }

    #[test]
    fn a_minor_above_255_goes_in_the_top_half() {
        // Which is the whole reason the encoding is not two 16-bit halves: a
        // pty number can exceed 255 and the low byte is all it would fit in.
        let d = dev_make(136, 300);
        assert_eq!(dev_minor(d), 300);
        assert_eq!(dev_major(d), 136);
        assert_ne!(d & 0xff, 300 & 0xfff);
    }

    #[test]
    fn every_pair_survives_the_round_trip() {
        for major in [0u32, 1, 4, 5, 136, 4095] {
            for minor in [0u32, 1, 255, 256, 1000, 0xfffff] {
                let d = dev_make(major, minor);
                assert_eq!(dev_major(d), major, "{major}:{minor}");
                assert_eq!(dev_minor(d), minor, "{major}:{minor}");
            }
        }
    }
}

#[cfg(test)]
const DEV_CHAR: c_int = 1;

#[cfg(test)]
/// Register a character device at `DYN_DEV_MAJOR`.
///
/// `/dev/clipboard` and `/dev/gps` were `DEV_CLIPBOARD_MINOR` and
/// `DEV_LOCATION_MINOR` in `fs/devices.h`. Both were registered through this by
/// the iOS app, which is not in this repository, so nothing claimed either minor
/// and nothing named either constant; they went on 2026-09-05. The **major**
/// stays, because this registers at it and `/proc/devices` lists it.
///
/// `ops` must be valid for the life of the process. `EEXIST` if the minor is
/// taken, `EINVAL` for anything else that is wrong.
///
/// # Safety
/// `ops` is null or points at a `struct dev_ops` that outlives the process.
pub(crate) unsafe fn dyn_dev_register(
    ops: *mut ffi::dev_ops,
    dev_type: c_int,
    major: c_int,
    minor: c_int,
) -> c_int {
    if minor < 0 || minor as usize >= MINOR_MAX {
        return errno::EINVAL;
    }
    if major as usize != major::DYN_DEV || ops.is_null() || dev_type != DEV_CHAR {
        return errno::EINVAL;
    }
    let mut devs = DYN_DEVS.lock().unwrap_or_else(|e| e.into_inner());
    if devs.0[minor as usize] != 0 {
        return errno::EEXIST;
    }
    devs.0[minor as usize] = ops as usize;
    0
}

#[cfg(test)]
mod tests;
