//! Guest time, resource-limit, and lifecycle ABI layouts.

use crate::{qword_t, sqword_t, time_t_, timespec};

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct timeval_ {
    pub sec: time_t_,
    pub usec: sqword_t,
}
const _: () = {
    assert!(std::mem::size_of::<timeval_>() == 16, "Size of timeval_");
    assert!(
        std::mem::align_of::<timeval_>() == 8,
        "Alignment of timeval_"
    );
    assert!(
        std::mem::offset_of!(timeval_, sec) == 0,
        "Offset of field: timeval_::sec"
    );
    assert!(
        std::mem::offset_of!(timeval_, usec) == 8,
        "Offset of field: timeval_::usec"
    );
};
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct timespec_ {
    pub sec: time_t_,
    pub nsec: sqword_t,
}
const _: () = {
    assert!(std::mem::size_of::<timespec_>() == 16, "Size of timespec_");
    assert!(
        std::mem::align_of::<timespec_>() == 8,
        "Alignment of timespec_"
    );
    assert!(
        std::mem::offset_of!(timespec_, sec) == 0,
        "Offset of field: timespec_::sec"
    );
    assert!(
        std::mem::offset_of!(timespec_, nsec) == 8,
        "Offset of field: timespec_::nsec"
    );
};
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct itimerspec_ {
    pub interval: timespec_,
    pub value: timespec_,
}
const _: () = {
    assert!(
        std::mem::size_of::<itimerspec_>() == 32,
        "Size of itimerspec_"
    );
    assert!(
        std::mem::align_of::<itimerspec_>() == 8,
        "Alignment of itimerspec_"
    );
    assert!(
        std::mem::offset_of!(itimerspec_, interval) == 0,
        "Offset of field: itimerspec_::interval"
    );
    assert!(
        std::mem::offset_of!(itimerspec_, value) == 16,
        "Offset of field: itimerspec_::value"
    );
};
pub type rlim_t_ = qword_t;
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct rlimit_ {
    pub cur: rlim_t_,
    pub max: rlim_t_,
}
const _: () = {
    assert!(std::mem::size_of::<rlimit_>() == 16, "Size of rlimit_");
    assert!(std::mem::align_of::<rlimit_>() == 8, "Alignment of rlimit_");
    assert!(
        std::mem::offset_of!(rlimit_, cur) == 0,
        "Offset of field: rlimit_::cur"
    );
    assert!(
        std::mem::offset_of!(rlimit_, max) == 8,
        "Offset of field: rlimit_::max"
    );
};
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct rusage_ {
    pub utime: timeval_,
    pub stime: timeval_,
    pub maxrss: sqword_t,
    pub ixrss: sqword_t,
    pub idrss: sqword_t,
    pub isrss: sqword_t,
    pub minflt: sqword_t,
    pub majflt: sqword_t,
    pub nswap: sqword_t,
    pub inblock: sqword_t,
    pub oublock: sqword_t,
    pub msgsnd: sqword_t,
    pub msgrcv: sqword_t,
    pub nsignals: sqword_t,
    pub nvcsw: sqword_t,
    pub nivcsw: sqword_t,
}
const _: () = {
    assert!(std::mem::size_of::<rusage_>() == 144, "Size of rusage_");
    assert!(std::mem::align_of::<rusage_>() == 8, "Alignment of rusage_");
    assert!(
        std::mem::offset_of!(rusage_, utime) == 0,
        "Offset of field: rusage_::utime"
    );
    assert!(
        std::mem::offset_of!(rusage_, stime) == 16,
        "Offset of field: rusage_::stime"
    );
    assert!(
        std::mem::offset_of!(rusage_, maxrss) == 32,
        "Offset of field: rusage_::maxrss"
    );
    assert!(
        std::mem::offset_of!(rusage_, ixrss) == 40,
        "Offset of field: rusage_::ixrss"
    );
    assert!(
        std::mem::offset_of!(rusage_, idrss) == 48,
        "Offset of field: rusage_::idrss"
    );
    assert!(
        std::mem::offset_of!(rusage_, isrss) == 56,
        "Offset of field: rusage_::isrss"
    );
    assert!(
        std::mem::offset_of!(rusage_, minflt) == 64,
        "Offset of field: rusage_::minflt"
    );
    assert!(
        std::mem::offset_of!(rusage_, majflt) == 72,
        "Offset of field: rusage_::majflt"
    );
    assert!(
        std::mem::offset_of!(rusage_, nswap) == 80,
        "Offset of field: rusage_::nswap"
    );
    assert!(
        std::mem::offset_of!(rusage_, inblock) == 88,
        "Offset of field: rusage_::inblock"
    );
    assert!(
        std::mem::offset_of!(rusage_, oublock) == 96,
        "Offset of field: rusage_::oublock"
    );
    assert!(
        std::mem::offset_of!(rusage_, msgsnd) == 104,
        "Offset of field: rusage_::msgsnd"
    );
    assert!(
        std::mem::offset_of!(rusage_, msgrcv) == 112,
        "Offset of field: rusage_::msgrcv"
    );
    assert!(
        std::mem::offset_of!(rusage_, nsignals) == 120,
        "Offset of field: rusage_::nsignals"
    );
    assert!(
        std::mem::offset_of!(rusage_, nvcsw) == 128,
        "Offset of field: rusage_::nvcsw"
    );
    assert!(
        std::mem::offset_of!(rusage_, nivcsw) == 136,
        "Offset of field: rusage_::nivcsw"
    );
};
/* Three placeholders were here until 2026-09-11 and all three were a **second
 * rendering** of a type the tree already had under another name:
 *
 *   `group_stop`     -- `crates/kernel/taskview` had `groupstop` for the same
 *                       object, so `tgroup.stop` and `crates/fs/proc`'s
 *                       `GroupFields.stop` were two distinct zero-sized types
 *                       with a cast between them. It is
 *                       `kernel_groupstop::GroupStop`, re-exported from
 *                       `lib.rs`, and there is one name now.
 *   `posix_timers`   -- no reader at all. `tgroup.posix_timers` is
 *                       `*mut kernel_posixtimers::Timers` since 2026-09-29,
 *                       when `TaskRef` moved to `util-identity` and that
 *                       crate's closure stopped containing `kernel-taskview`.
 *   `vfork_handoff`  -- no reader at all. `task.vfork` has been
 *                       `*mut kernel_vforkhandoff::Handoff` since the real type
 *                       was named.
 *
 * Two zero-sized renderings of one object cannot disagree at runtime and
 * nothing could ever have caught it if they did, which is exactly the argument
 * CLAUDE.md makes about a type rendered twice. */

pub type timer_id_t = u64;
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
/// `value` is how long to wait until the next fire; `interval` is how long
/// after that to wait until the one after, when it is non-zero.
///
/// The shape is `setitimer`'s, because that is what it was written to
/// implement. `util/timer.h` called it "bizarre" and it is, but it is the ABI.
pub struct timer_spec {
    pub value: timespec,
    pub interval: timespec,
}
const _: () = {
    assert!(
        std::mem::size_of::<timer_spec>() == 32,
        "Size of timer_spec"
    );
    assert!(
        std::mem::align_of::<timer_spec>() == 8,
        "Alignment of timer_spec"
    );
    assert!(
        std::mem::offset_of!(timer_spec, value) == 0,
        "Offset of field: timer_spec::value"
    );
    assert!(
        std::mem::offset_of!(timer_spec, interval) == 16,
        "Offset of field: timer_spec::interval"
    );
};

plain::plain! {
    timespec_ { sec, nsec }
    itimerspec_ { interval, value }
}
