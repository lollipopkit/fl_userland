//! What the **host** can say about a thread's CPU time.
//!
//! A guest process is a set of host threads in one host process, so the host's
//! own process totals count every guest process at once and are useless here.
//! What is answerable is *this thread*, and everything above that — the group's
//! exited threads, its reaped children — is `crates/kernel/grouprusage`.
//!
//! # Zeroed, not merely declared
//!
//! Only the four time fields are filled in, and the other fourteen went to the
//! guest as whatever happened to be on the host stack: **112 of the 144 bytes**.
//! That is an information leak as well as nonsense in `ru_maxrss`, and it showed
//! up as two `getrusage` calls in a row disagreeing about `ru_nvcsw`.
//!
//! # The Mach port
//!
//! `mach_thread_self` hands back a send right the caller owns and must release.
//! Nothing did, so every `getrusage`, `times()` and CPU-time `clock_gettime`
//! leaked one — measured at exactly one user reference per call, and a shell
//! calls `times()` once per command. And `thread_info`'s result was never
//! looked at, so a failure left the struct uninitialised and the times were
//! stack too. Zero is the honest answer to a query that failed.


/// `struct timeval_`, the guest's.
///
/// `crates/kernel/grouprusage`'s, because it has the arithmetic and because
/// there was an identical copy here: `record_own_times` in
/// `crates/kernel/exitcalls` reads `Rusage::utime` out of this crate and hands
/// it to `GroupRusage::add_own`, where the conversion is explicit and typed.
pub use grouprusage::Timeval;

/// `struct rusage_`, 144 bytes. Sixteen fields, of which this crate fills two.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Rusage {
    pub utime: Timeval,
    pub stime: Timeval,
    pub maxrss: i64,
    pub ixrss: i64,
    pub idrss: i64,
    pub isrss: i64,
    pub minflt: i64,
    pub majflt: i64,
    pub nswap: i64,
    pub inblock: i64,
    pub oublock: i64,
    pub msgsnd: i64,
    pub msgrcv: i64,
    pub nsignals: i64,
    pub nvcsw: i64,
    pub nivcsw: i64,
}

plain::plain!(Rusage {
    utime, stime, maxrss, ixrss, idrss, isrss, minflt, majflt, nswap, inblock, oublock, msgsnd,
    msgrcv, nsignals, nvcsw, nivcsw,
});

// The two Mach entry points `libc` does not have. Declared rather than taking
// the `mach2` crate: they are stable symbols in libSystem and this is the only
// place in the tree that needs them, where a new third-party dependency in the
// product would be a bigger decision than two lines.
unsafe extern "C" {
    fn mach_port_deallocate(task: libc::mach_port_t, name: libc::mach_port_t) -> libc::c_int;
    /// `mach_task_self()` is a macro over this.
    static mach_task_self_: libc::mach_port_t;
}

/// The calling thread's user and system time, or zero if the host would not
/// say.
#[allow(deprecated)] // `libc::mach_thread_self`, which points at the mach2 crate.
pub fn thread_rusage() -> Rusage {
    // SAFETY: `mach_thread_self` hands out a send right, released here.
    unsafe {
        let thread = libc::mach_thread_self();
        let out = port_rusage(thread);
        mach_port_deallocate(mach_task_self_, thread);
        out
    }
}

/// Another host thread's user and system time, or zero if the host would not
/// say.
///
/// # Safety
/// `thread` is a pthread that has not exited: `pthread_mach_thread_np` reads
/// the pthread's own structure, which is freed when it ends. A guest task
/// found under `pids_lock` that is neither exiting nor a zombie qualifies:
/// `do_exit` marks it exiting under that lock, on its own thread, before the
/// pthread returns.
pub unsafe fn pthread_rusage(thread: libc::pthread_t) -> Rusage {
    // SAFETY: the caller's contract. The port is the pthread's own, borrowed
    // rather than a new right, so there is nothing to release.
    unsafe { port_rusage(libc::pthread_mach_thread_np(thread)) }
}

/// What `thread_info(THREAD_BASIC_INFO)` says about a thread port. A port
/// that names no live thread answers an error, which reads as zero.
fn port_rusage(thread: libc::mach_port_t) -> Rusage {
    let mut out = Rusage::default();
    // SAFETY: `info` and `count` are live locals of the size the call is told.
    unsafe {
        let mut info: libc::thread_basic_info = std::mem::zeroed();
        let mut count = libc::THREAD_BASIC_INFO_COUNT;
        let kr = libc::thread_info(
            thread,
            libc::THREAD_BASIC_INFO as u32,
            (&raw mut info).cast(),
            &mut count,
        );
        if kr == libc::KERN_SUCCESS {
            out.utime = Timeval {
                sec: info.user_time.seconds as i64,
                usec: info.user_time.microseconds as i64,
            };
            out.stime = Timeval {
                sec: info.system_time.seconds as i64,
                usec: info.system_time.microseconds as i64,
            };
        }
    }
    out
}

/// Return the calling host thread's resource usage.
pub fn rusage_get_thread() -> Rusage {
    thread_rusage()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 144 bytes and `ru_maxrss` at 32, which is what the guest reads them at.
    #[test]
    fn the_guest_layout() {
        assert_eq!(std::mem::size_of::<Rusage>(), 144);
        assert_eq!(std::mem::offset_of!(Rusage, maxrss), 32);
        assert_eq!(std::mem::size_of::<Timeval>(), 16);
    }

    /// Everything but the two times is zero. Fourteen fields, 112 of the 144
    /// bytes, went to the guest as host stack.
    #[test]
    fn nothing_but_the_times_is_filled_in() {
        let r = thread_rusage();
        assert_eq!(r.maxrss, 0);
        assert_eq!(r.minflt, 0);
        assert_eq!(r.majflt, 0);
        assert_eq!(r.nvcsw, 0);
        assert_eq!(r.nivcsw, 0);
        assert_eq!(r.inblock, 0);
        assert_eq!(r.oublock, 0);
        assert_eq!(r.nsignals, 0);
    }

    /// Two calls in a row agree about the fourteen. That is the shape the
    /// uninitialised struct failed: `ru_nvcsw` differed between them because
    /// each read a different piece of stack.
    #[test]
    fn two_calls_agree_about_what_is_not_measured() {
        let a = thread_rusage();
        let b = thread_rusage();
        assert_eq!(
            Rusage {
                utime: Timeval::default(),
                stime: Timeval::default(),
                ..a
            },
            Rusage {
                utime: Timeval::default(),
                stime: Timeval::default(),
                ..b
            },
        );
    }

    /// And the time does not go backwards, which is the weakest true statement
    /// about a CPU-time counter and the one that catches a swapped
    /// seconds/microseconds pair.
    #[test]
    fn the_time_does_not_go_backwards() {
        let a = thread_rusage();
        // Something to account.
        let mut n = 0u64;
        for i in 0..2_000_000u64 {
            n = n.wrapping_add(i);
        }
        assert_ne!(n, 1);
        let b = thread_rusage();
        let us = |t: Timeval| t.sec * 1_000_000 + t.usec;
        assert!(
            us(b.utime) >= us(a.utime),
            "{:?} then {:?}",
            a.utime,
            b.utime
        );
        assert!(us(b.stime) >= us(a.stime));
        assert!(us(a.utime) >= 0 && us(a.stime) >= 0);
    }
    // ------------------------------------------------- the thread port leak
    //
    // `tests/unit/rusage_test.c` until 2026-09-08. It is the half of that file
    // the tests above do not cover: they say the *struct* is right, and this
    // says the *host* is left as it was found.
    //
    // `mach_thread_self()` hands back a send right the caller owns and must
    // release. Nothing released it, so every `getrusage`, `times()` and
    // CPU-time `clock_gettime` leaked one user reference on the thread port --
    // measured at exactly one per call. A shell calls `times()` once per
    // command.

    unsafe extern "C" {
        fn mach_port_get_refs(
            task: libc::mach_port_t,
            name: libc::mach_port_t,
            right: libc::c_int,
            refs: *mut libc::c_uint,
        ) -> libc::c_int;
    }

    /// `MACH_PORT_RIGHT_SEND`.
    const RIGHT_SEND: libc::c_int = 0;

    /// The thread port's send-right count, without changing it:
    /// `mach_thread_self` takes a reference of its own, so this gives it back.
    #[allow(deprecated)] // `libc::mach_thread_self`, which points at mach2.
    fn thread_send_refs() -> u32 {
        let mut refs = 0;
        // SAFETY: `mach_thread_self` answers a right this thread owns, and the
        // deallocate below is the release that pairs with it.
        unsafe {
            let thread = libc::mach_thread_self();
            mach_port_get_refs(mach_task_self_, thread, RIGHT_SEND, &mut refs);
            mach_port_deallocate(mach_task_self_, thread);
        }
        refs
    }

    const CALLS: usize = 500;

    #[test]
    fn thread_rusage_does_not_leak_a_thread_port() {
        let before = thread_send_refs();
        for _ in 0..CALLS {
            let r = thread_rusage();
            std::hint::black_box(r);
        }
        let after = thread_send_refs();
        assert_eq!(
            after,
            before,
            "{CALLS} calls leaked {} send rights on the thread port",
            after as i64 - before as i64
        );
    }

    /// The measurement has to be able to *see* a leak, or the test above passes
    /// against anything.
    #[test]
    fn the_control_a_leak_would_show_up_as() {
        let before = thread_send_refs();
        // SAFETY: each right taken here is given back below.
        #[allow(deprecated)]
        let leaked: Vec<libc::mach_port_t> = (0..16)
            .map(|_| unsafe { libc::mach_thread_self() })
            .collect();
        assert_eq!(thread_send_refs() as i64 - before as i64, 16);
        for name in leaked {
            // SAFETY: each is a send right this thread took above.
            unsafe { mach_port_deallocate(mach_task_self_, name) };
        }
        assert_eq!(thread_send_refs(), before);
    }
}
