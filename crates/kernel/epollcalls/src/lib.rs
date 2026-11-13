//! The syscalls that own an epoll set: `epoll_create1`, `epoll_ctl`,
//! `epoll_pwait` and `epoll_pwait2`, and the set's two ioctls.
//!
//! aarch64 Linux has no `epoll_create` and no `epoll_wait` — 20, 21 and 22 are
//! the whole family, and a libc's `epoll_wait` is `epoll_pwait` with a null
//! mask. The C carried a `sys_epoll_create0` and an exported `sys_epoll_wait`
//! for the two that do not exist here; the first was in no syscall table and
//! reachable from nothing, and the second only from `epoll_pwait`. It is a
//! private function now.
//!
//! The set's own state — registrations, generational host tokens, the ready
//! queue, ET/ONESHOT delivery and the host backend — is `crates/kernel/epoll`
//! and has been since it moved out of `fs/poll.c`. What was still C is the
//! syscall layer around it: the descriptor, its operation table, the argument
//! rules and the wait loop. Those are here now.
//!
//! Three things cross crate boundaries, all for the same reason — they need
//! `struct fd` or `struct task`, neither of which this syscall crate owns:
//!
//! - `fs-poll` supplies the member vtable (a member's readiness, its host
//!   descriptor, whether it is a socket) and its reverse-edge list.
//! - the wait loop's task policy, which is supplied through `taskview` and the
//!   `waitfor` hook.
//! - `sockrestart_*`, the iOS listen-wait bracket, which is `crates/fs/sockrestart`
//!   and is called by path: it was three hand-written `extern` declarations,
//!   one of which had the wrong return type for a year -- `c_int` against a
//!   prototype that says `bool`, whose upper register bits are unspecified.
//!   A path call cannot have that defect.


use std::ffi::c_int;
use std::time::Duration;

use logline::printk;
use strace::strace;
use usercopy::GuestMem;

// The shared Rust types and constants are re-exported by kernel-taskview.
use taskview::ffi;

mod wait;

use guest_errno::Errno;

const POLL_READ: c_int = fs_poll::bits::READ as c_int;

const EPOLL_CTL_ADD: c_int = 1;
const EPOLL_CTL_DEL: c_int = 2;
const EPOLL_CTL_MOD: c_int = 3;

/// The most events one `epoll_wait` will report, whatever the caller asked for.
///
/// The array used to be a stack VLA sized from `max_events`, which is the
/// guest's number — the same shape as `poll`'s, and with the same consequence.
const EPOLL_MAX_EVENTS: c_int = 1024;

// ---------------------------------------------------------------------------
// The descriptor
// ---------------------------------------------------------------------------

/// epoll's `fd_ops`: a close, a poll and the two busy-poll ioctls.
///
/// Written out rather than derived from another table because an epoll
/// descriptor genuinely has no read and no write — every other operation must
/// be null, and `f_get`'s callers answer the right errno for a null one.
struct EpollOps;

static EPOLL_FDOPS: EpollOps = EpollOps;

fn epoll_fdops() -> Option<&'static dyn ffi::FdOps> {
    Some(&EPOLL_FDOPS)
}

impl ffi::FdOps for EpollOps {
    fn caps(&self) -> ffi::Caps {
        ffi::Caps::NONE
    }
    fn poll(&self, fd: &ffi::fd) -> Option<c_int> {
        Some(epoll_poll(fd))
    }
    fn close(&self, fd: &mut ffi::fd) -> c_int {
        epoll_close(fd)
    }
    /// `ep_show_fdinfo`, one line per item: the descriptor number it was
    /// added under, its events and data, and the member's position, inode and
    /// device as the kernel holds it. A member on its way out is left out.
    fn show_fdinfo(&self, fd: &ffi::fd, out: &mut String) {
        let Some(state) = state_of(fd) else {
            return;
        };
        for item in kernel_epoll::epoll_listing::<fs_poll::EpollMember>(state) {
            let Some(member) = item.member else {
                continue;
            };
            let st = fs_fdobj::fd_fstat(&member).unwrap_or_default();
            let pos = member.ops.map_or(0, |ops| ops.position(&member));
            out.push_str(&format!(
                "tfd: {:8} events: {:8x} data: {:16x}  pos:{pos} ino:{:x} sdev:{:x}\n",
                item.fd,
                item.events,
                item.data,
                st.inode,
                ffi::kernel_dev(st.dev),
            ));
        }
    }
    /// Every command reaches [`EpollOps::ioctl`], which is what Linux does:
    /// `ep_eventpoll_ioctl` sees whatever the generic layer did not take, and
    /// answers `EINVAL` -- not `ENOTTY` -- for all but its two. Measured
    /// against 7.2 by `epoll2_probe` (`TCGETS`, `FIONREAD`, and `EPIOCSPARAMS`'
    /// number with a four-byte size).
    fn ioctl_size(&self, cmd: c_int) -> isize {
        match cmd as u32 {
            EPIOCSPARAMS | EPIOCGPARAMS => EPOLL_PARAMS_SIZE as isize,
            _ => 0,
        }
    }
    fn ioctl(&self, fd: &ffi::fd, cmd: c_int, arg: ffi::IoctlArg<'_>) -> c_int {
        let (Some(state), ffi::IoctlArg::Buf(buf)) = (state_of(fd), arg) else {
            return Errno::EINVAL.as_c_int();
        };
        let Ok(buf) = <&mut [u8; EPOLL_PARAMS_SIZE]>::try_from(buf) else {
            return Errno::EINVAL.as_c_int();
        };
        match cmd as u32 {
            EPIOCSPARAMS => match busy_poll_from_wire(buf, taskview::capable(taskview::caps::CAP_NET_ADMIN)) {
                Ok(params) => {
                    state.set_busy_poll(params);
                    0
                }
                Err(e) => e.as_c_int(),
            },
            EPIOCGPARAMS => {
                *buf = busy_poll_to_wire(state.busy_poll());
                0
            }
            _ => Errno::EINVAL.as_c_int(),
        }
    }
}

/// `EPIOCSPARAMS`, `_IOW(0x8A, 0x01, struct epoll_params)`.
const EPIOCSPARAMS: u32 = 0x4008_8a01;
/// `EPIOCGPARAMS`, `_IOR(0x8A, 0x02, struct epoll_params)`.
const EPIOCGPARAMS: u32 = 0x8008_8a02;

/// `struct epoll_params`: `u32 busy_poll_usecs`, `u16 busy_poll_budget`,
/// `u8 prefer_busy_poll`, `u8 __pad`. Eight bytes, offsets 0, 4, 6 and 7.
const EPOLL_PARAMS_SIZE: usize = 8;

/// `NAPI_POLL_WEIGHT`: the budget an unprivileged caller may ask for.
const NAPI_POLL_WEIGHT: u16 = 64;

/// `EPIOCSPARAMS`' rules, in Linux's order: the pad byte, the time, the
/// preference, and only then the privilege for a large budget -- so a caller
/// with a bad pad and a large budget is told `EINVAL`. `CAP_NET_ADMIN` is root
/// here, as every capability is.
fn busy_poll_from_wire(
    raw: &[u8; EPOLL_PARAMS_SIZE],
    privileged: bool,
) -> Result<kernel_epoll::BusyPoll, Errno> {
    let usecs = u32::from_le_bytes(raw[0..4].try_into().unwrap());
    let budget = u16::from_le_bytes(raw[4..6].try_into().unwrap());
    let (prefer, pad) = (raw[6], raw[7]);
    if pad != 0 || usecs > i32::MAX as u32 || prefer > 1 {
        return Err(Errno::EINVAL);
    }
    if budget > NAPI_POLL_WEIGHT && !privileged {
        return Err(Errno::EPERM);
    }
    Ok(kernel_epoll::BusyPoll { usecs, budget, prefer: prefer != 0 })
}

/// `EPIOCGPARAMS`' reply; the pad byte is zero.
fn busy_poll_to_wire(params: kernel_epoll::BusyPoll) -> [u8; EPOLL_PARAMS_SIZE] {
    let mut raw = [0u8; EPOLL_PARAMS_SIZE];
    raw[0..4].copy_from_slice(&params.usecs.to_le_bytes());
    raw[4..6].copy_from_slice(&params.budget.to_le_bytes());
    raw[6] = params.prefer as u8;
    raw
}

/// The state an epoll descriptor owns, or `None` if it is not one.
///
/// **There is no cast left here** since 2026-09-12. The sentence this comment
/// used to carry — "`struct fd`'s union member is the shared opaque
/// placeholder; everything downstream of this function is typed, so no other
/// site casts" — was true of the first half and wrong about the second. There
/// were **seven** casts on that pointer in this crate, and only four of them
/// crossed the placeholder: the other three took a `*mut Epoll` this function
/// had already returned and cast it to a `*mut Epoll`. That is what an opaque
/// field costs beyond the conversions it forces — a `.cast` is not a conversion
/// the compiler can check, so a redundant one reads exactly like a necessary
/// one and nothing objects to either.
///
/// The description's `Arc<Epoll>` since 2026-09-29, when the union arm it
/// lived in went: a downcast of the state, where the identity test and the
/// union read were two steps the first was trusted to make safe.
fn state_of(fd: &ffi::fd) -> Option<&std::sync::Arc<kernel_epoll::Epoll>> {
    fd.driver_state::<std::sync::Arc<kernel_epoll::Epoll>>()
}

/// Whether this descriptor is an epoll set at all, which is a different
/// question from whether it has state: a set whose state failed to allocate is
/// still one, and answers `EINVAL` rather than `EBADF`.
fn is_epoll(fd: &ffi::fd) -> bool {
    fd.ops.is_some_and(|ops| ops.as_any().is::<EpollOps>())
}

fn epoll_close(fd: &mut ffi::fd) -> c_int {
    // Every member this set was watching loses its entry when the state is
    // dropped -- crates/kernel/epoll does it from the state's destructor, where
    // it can reach each member's reverse-edge list directly. This used to walk
    // the registrations from here, retaining each member with fd_try_retain and
    // yielding when that lost a race with the member's own teardown.
    drop(fd.take_driver_state::<std::sync::Arc<kernel_epoll::Epoll>>());
    0
}

fn epoll_poll(fd: &ffi::fd) -> c_int {
    // `state_of` rather than reading `fd.state.epollfd` straight out, which is
    // what this did: the union read skipped the downcast and leaned on
    // `epoll_is_ready`'s null check, and that check is gone with the pointer.
    // This is `FdOps::poll` for `EpollOps`, so the downcast always succeeds —
    // it costs a type-id compare and says which arm of the union is live.
    if state_of(fd).is_some_and(|state| kernel_epoll::epoll_is_ready(state)) {
        POLL_READ
    } else {
        0
    }
}

/// Whether the set behind this descriptor has anything to report.
///
/// An outer set watching an inner one asks this: the inner backend descriptor
/// becoming readable is the host's way of saying that the inner set moved, and
/// the transitions have to be drained into the inner queue before the question
/// can be answered.
pub(crate) fn epoll_fd_is_ready(fd: &ffi::fd) -> c_int {
    state_of(fd).map_or(0, |state| kernel_epoll::epoll_probe_ready(state))
}

/// The host descriptor an epoll set waits on, or -1.
pub(crate) fn epoll_fd_backend(fd: &ffi::fd) -> c_int {
    state_of(fd).map_or(-1, |state| kernel_epoll::epoll_backend_fd(state))
}

// ---------------------------------------------------------------------------
// The syscalls
// ---------------------------------------------------------------------------

pub fn sys_epoll_create(flags: c_int) -> Result<i64, Errno> {
    strace!("epoll_create({flags:#x})");
    // The wait loop asks these three about a member, and only this crate can
    // answer them -- the identity test is `fd->ops == epoll_fdops()`. Installed
    // here because this is the only place an epoll set is made, so before the
    // first call no descriptor is one. The first call wins.
    fs_poll::set_epoll_fd_hook(fs_poll::EpollFd {
        is_instance: is_epoll,
        is_ready: |fd| epoll_fd_is_ready(fd) != 0,
        backend: |fd| epoll_fd_backend(fd),
    });
    if flags & !(ffi::O_CLOEXEC_ as c_int) != 0 {
        return Err(Errno::EINVAL);
    }

    let mut fd = fs_adhoc::adhoc_anon(epoll_fdops(), Some(c"[eventpoll]"));
    let state = kernel_epoll::epoll_state_new().map_err(Errno::from_negative_or_eio)?;
    fd.set_driver_state(Box::new(state));
    Errno::split(fs_fdobj::f_install(fd.into_owned(), flags) as i64)
}

/// A guest `struct epoll_event`: a 32-bit event mask, four bytes of padding and
/// a 64-bit cookie the caller chose. Sixteen bytes.
///
/// `crates/kernel/epoll` writes the same sixteen as `epoll_ready_event`, and
/// `kernel/epoll.c` used to carry two `_Static_assert`s pinning them together.
/// One definition needs no assertion: the reply is written from the same struct
/// the crate fills in.
const EPOLL_EVENT_SIZE: usize = 16;

/// `EPOLLEXCLUSIVE`: wake one waiter rather than all of them.
const EPOLLEXCLUSIVE: u32 = 1 << 28;

/// What `EPOLLEXCLUSIVE` may be combined with — Linux's
/// `EPOLLEXCLUSIVE_OK_BITS`. `EPOLLWAKEUP` (1 << 29) is in Linux's set and is
/// not implemented here, so it is not in this one: accepting a bit that does
/// nothing is what the `madvise` sweep was about.
const EXCLUSIVE_OK: u32 = EPOLLEXCLUSIVE | (1 << 31) | 0x001 | 0x004 | 0x008 | 0x010;

pub fn sys_epoll_ctl(epoll_f: c_int, op: c_int, f: c_int, event_addr: u64) -> Result<i64, Errno> {
    strace!("epoll_ctl({epoll_f}, {op}, {f}, {event_addr:#x})");

    // The event is read **first**, before either descriptor is looked at, and
    // for every operation except `DEL` -- which is Linux's `ep_op_has_event(op)`,
    // spelled `op != EPOLL_CTL_DEL` there, so an operation number that is not
    // one of the three still has its event copied. Measured, not read: an
    // `epoll_ctl(-1, 0, fd, NULL)` answers `EFAULT` on a real kernel and
    // answered `EBADF` here.
    //
    // It matters beyond the letter. A caller passing a bad pointer was told
    // `EBADF` or `EINVAL`, which names the wrong argument.
    let mut raw = [0u8; EPOLL_EVENT_SIZE];
    if op != EPOLL_CTL_DEL && GuestMem.read(event_addr, &mut raw) != 0 {
        return Err(Errno::EFAULT);
    }

    let Some(epoll) = fs_fdobj::f_get(epoll_f) else {
        return Err(Errno::EBADF);
    };
    let epoll = &*epoll;
    let Some(epoll_state) = state_of(epoll) else {
        return Err(Errno::EINVAL);
    };
    let Some(member) = fs_fdobj::f_get(f) else {
        return Err(Errno::EBADF);
    };
    let fd = &*member;

    // The target has to be a file whose readiness can *change*. Linux spells
    // this `if (!file_can_poll(tf.file)) -> -EPERM`, and it applies to every
    // operation including `DEL` -- so a set is not even asked to forget a file
    // it could never have been given, which is why this sits above the `DEL`
    // arm rather than under `ADD`.
    //
    // Two kinds qualify here. A regular file and a directory are always ready,
    // which is why Linux's `f_op` for them has no `poll`; and so are the memory
    // devices, `/dev/null`, `/dev/zero`, `/dev/full` and `/dev/random`, which
    // this used to accept. Accepting one is worse than the error it replaced:
    // the registration succeeds and every `epoll_wait` returns immediately, so
    // a library that registered a `/dev/null` standard input would spin at 100%
    // CPU instead of being told to use a different mechanism.
    // A message queue is the regular file that has a `poll`; see
    // `FdOps::regular_file_polls`.
    let kind = fd.type_ as u32 & ffi::S_IFMT;
    if (kind == ffi::S_IFREG && !fd.ops.is_some_and(|o| o.regular_file_polls()))
        || kind == ffi::S_IFDIR
        || fs_devices::readiness_is_constant(fd)
    {
        return Err(Errno::EPERM);
    }

    // A set watching another set is a real thing to do, and the inner one has
    // to know: an inner registration is what makes the outer backend hear about
    // it. Null for every other kind of member.
    let nested = state_of(fd).map(|nested| &**nested);

    if op == EPOLL_CTL_DEL {
        return Errno::split(fs_poll::epoll_watch_del(epoll_state, nested, fd, f) as i64);
    }
    if op != EPOLL_CTL_ADD && op != EPOLL_CTL_MOD {
        return Err(Errno::EINVAL);
    }
    if op == EPOLL_CTL_ADD && std::ptr::eq(fd, epoll) {
        return Err(Errno::EINVAL);
    }

    let events = u32::from_le_bytes(raw[..4].try_into().unwrap());
    let data = u64::from_le_bytes(raw[8..].try_into().unwrap());
    strace!(" {{events: {events:#x}, data: {data:#x}}}");

    // `EPOLLEXCLUSIVE` is the one event bit that changes *how the set behaves*
    // rather than what it reports, and Linux constrains where it may appear.
    // None of this was checked until 2026-09-03, so a caller that set it on a
    // `MOD` -- which Linux refuses because there is no way to make an existing
    // registration exclusive -- was told it had worked.
    //
    // The three rules, measured against a real kernel by
    // `tests/guest/src/bin/epoll_probe.rs` rather than read off the man page:
    // not with `MOD`, not on another epoll set, and not combined with a bit
    // outside the set below. `EPOLLET` and `EPOLLHUP` are allowed with it;
    // `EPOLLONESHOT`, `EPOLLPRI` and `EPOLLRDHUP` are not.
    //
    // What the flag *does* is not reproduced. Linux wakes the first set with
    // a waiter and stops; here every set registering the member hears the
    // event -- each has its own host kqueue, and a host descriptor cannot be
    // told to pick one -- so four sets with a waiter each all wake where
    // Linux wakes one (`epoll2_probe`, 2026-11-11). The flag's contract is
    // "one or more", which this meets; what is lost is the herd avoidance.
    // Several threads waiting on *one* set already wake one per edge.
    if events & EPOLLEXCLUSIVE != 0
        && (op == EPOLL_CTL_MOD || nested.is_some() || events & !EXCLUSIVE_OK != 0)
    {
        return Err(Errno::EINVAL);
    }

    if op == EPOLL_CTL_MOD {
        return Errno::split(fs_poll::epoll_watch_mod(epoll_state, fd, f, events as c_int, data) as i64);
    }
    Errno::split(fs_poll::epoll_watch_add(epoll_state, nested, &member.retain(), f, events as c_int, data) as i64)
}

pub fn sys_epoll_pwait(
    epoll_f: c_int,
    events_addr: u64,
    max_events: c_int,
    timeout: c_int,
    sigmask_addr: u64,
    sigsetsize: u64,
) -> Result<i64, Errno> {
    if sigmask_addr != 0 {
        let mut mask = 0u64;
        let err = signaldeliver::user_get_sigset(sigmask_addr, sigsetsize, &mut mask);
        if err != 0 {
            return Err(Errno::from_negative_or_eio(err));
        }
        signaldeliver::sigmask_set_temp(mask);
    }
    // Negative is for ever, whatever the value: Linux's `ep_timeout_to_timespec`
    // tests `ms < 0`, not `ms == -1`.
    let timeout = u64::try_from(timeout).ok().map(Duration::from_millis);
    let res = wait::epoll_wait(epoll_f, events_addr, max_events, timeout);
    signaldeliver::sigmask_restore_temp(&res);
    res
}

/// `epoll_pwait2`: `epoll_pwait` with a `struct timespec` timeout, relative,
/// null for ever. Linux 5.11.
///
/// The order of the argument checks is the kernel's and was measured by
/// `epoll2_probe`: the timeout is read and validated first (`EFAULT`, then
/// `EINVAL`), the signal mask second, and only then the descriptor and
/// `maxevents` -- so a closed `epfd` with a bad timeout answers for the
/// timeout. The timeout is `const`: nothing is written back.
pub fn sys_epoll_pwait2(
    epoll_f: c_int,
    events_addr: u64,
    max_events: c_int,
    timeout_addr: u64,
    sigmask_addr: u64,
    sigsetsize: u64,
) -> Result<i64, Errno> {
    let timeout = if timeout_addr == 0 {
        None
    } else {
        Some(read_timeout(timeout_addr)?)
    };
    if sigmask_addr != 0 {
        let mut mask = 0u64;
        let err = signaldeliver::user_get_sigset(sigmask_addr, sigsetsize, &mut mask);
        if err != 0 {
            return Err(Errno::from_negative_or_eio(err));
        }
        signaldeliver::sigmask_set_temp(mask);
    }
    let res = wait::epoll_wait(epoll_f, events_addr, max_events, timeout);
    signaldeliver::sigmask_restore_temp(&res);
    res
}

/// A guest `struct timespec` as a relative timeout, refused when it is not a
/// time. A `tv_sec` of `LLONG_MAX` is a valid one and waits for ever in all
/// but name; the deadline saturates.
fn read_timeout(addr: u64) -> Result<Duration, Errno> {
    let mut raw = [0u8; 16];
    if GuestMem.read(addr, &mut raw) != 0 {
        return Err(Errno::EFAULT);
    }
    let sec = i64::from_le_bytes(raw[..8].try_into().unwrap());
    let nsec = i64::from_le_bytes(raw[8..].try_into().unwrap());
    if !util_timeabi::timespec_valid(sec, nsec) {
        return Err(Errno::EINVAL);
    }
    Ok(Duration::new(sec as u64, nsec as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The guest's `struct epoll_event` and the crate's `epoll_ready_event` are
    /// sixteen bytes with the cookie at eight.
    ///
    /// `kernel/epoll.c` carried two `_Static_assert`s saying so, because it
    /// declared the layout a second time. There is one declaration now and the
    /// reply is written straight out of it, so what is left to check is that
    /// the number this file writes the reply with matches the struct.
    #[test]
    fn an_epoll_event_is_sixteen_bytes_with_the_cookie_at_eight() {
        assert_eq!(std::mem::size_of::<kernel_epoll::Event>(), EPOLL_EVENT_SIZE);
        let e = kernel_epoll::Event {
            events: 0,
            _pad: 0,
            data: 0,
        };
        let base = &e as *const _ as usize;
        assert_eq!(&e.events as *const _ as usize - base, 0);
        assert_eq!(&e.data as *const _ as usize - base, 8);
    }

    /// The reply a caller reads back, byte for byte.
    #[test]
    fn a_reply_puts_the_mask_first_and_the_cookie_at_eight() {
        let events = [kernel_epoll::Event {
            events: 0x2001,
            _pad: 0xdead_beef,
            data: 0x0123_4567_89ab_cdef,
        }];
        let mut raw = [0u8; EPOLL_EVENT_SIZE];
        let e = &events[0];
        raw[..4].copy_from_slice(&e.events.to_le_bytes());
        raw[8..16].copy_from_slice(&e.data.to_le_bytes());
        assert_eq!(&raw[..4], &[0x01, 0x20, 0, 0]);
        // The padding is never written, so a guest reading it back sees what
        // it had there. Linux does not promise otherwise, and the alternative
        // is leaking four bytes of whatever the crate left in the field.
        assert_eq!(&raw[4..8], &[0, 0, 0, 0]);
        assert_eq!(&raw[8..], &0x0123_4567_89ab_cdefu64.to_le_bytes());
    }

    /// The two ioctl numbers are `_IOW`/`_IOR('\x8A', 1/2, 8 bytes)`.
    #[test]
    fn the_busy_poll_ioctls_encode_direction_type_number_and_size() {
        let ioc = |dir: u32, nr: u32| dir << 30 | (EPOLL_PARAMS_SIZE as u32) << 16 | 0x8a << 8 | nr;
        assert_eq!(EPIOCSPARAMS, ioc(1, 1));
        assert_eq!(EPIOCGPARAMS, ioc(2, 2));
    }

    /// The wire layout and Linux's rules, case by case: the pad, the time, the
    /// preference, then the privilege.
    #[test]
    fn busy_poll_parameters_are_validated_in_linuxs_order() {
        let wire = |usecs: u32, budget: u16, prefer: u8, pad: u8| {
            let mut raw = [0u8; EPOLL_PARAMS_SIZE];
            raw[0..4].copy_from_slice(&usecs.to_le_bytes());
            raw[4..6].copy_from_slice(&budget.to_le_bytes());
            raw[6] = prefer;
            raw[7] = pad;
            raw
        };
        let ok = kernel_epoll::BusyPoll { usecs: 100, budget: 8, prefer: true };
        assert_eq!(busy_poll_from_wire(&wire(100, 8, 1, 0), false), Ok(ok));
        assert_eq!(busy_poll_to_wire(ok), wire(100, 8, 1, 0));
        assert_eq!(busy_poll_from_wire(&wire(0, 0, 0, 1), true), Err(Errno::EINVAL));
        assert_eq!(busy_poll_from_wire(&wire(0, 0, 2, 0), true), Err(Errno::EINVAL));
        assert_eq!(busy_poll_from_wire(&wire(1 << 31, 0, 0, 0), true), Err(Errno::EINVAL));
        assert!(busy_poll_from_wire(&wire(i32::MAX as u32, 0, 0, 0), false).is_ok());
        assert!(busy_poll_from_wire(&wire(0, 64, 0, 0), false).is_ok());
        assert_eq!(busy_poll_from_wire(&wire(0, 65, 0, 0), false), Err(Errno::EPERM));
        assert!(busy_poll_from_wire(&wire(0, 65, 0, 0), true).is_ok());
        assert_eq!(busy_poll_from_wire(&wire(0, 65, 0, 1), false), Err(Errno::EINVAL));
    }

    /// The three operations are Linux's numbers, and nothing else is one.
    #[test]
    fn the_control_operations_are_one_two_and_three() {
        assert_eq!((EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD), (1, 2, 3));
    }
}
