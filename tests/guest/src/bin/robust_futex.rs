//! `set_robust_list`, and what the kernel owes a mutex whose owner died.
//!
//! A thread registers a **robust list head** and libc links every robust mutex
//! it takes onto it. If the thread then dies without unlocking — killed,
//! faulted, or out through the raw `exit` syscall rather than `pthread_exit` —
//! the kernel walks that list and, for each futex whose owner is the dying
//! thread, sets `FUTEX_OWNER_DIED` and wakes a waiter. The next `lock` then
//! reports `EOWNERDEAD` instead of blocking on an owner that is gone.
//!
//! Nothing else can do it: libc's own unwinding runs on the orderly path only,
//! which is the path where nothing went wrong. So storing the list and never
//! walking it is a **hang**, not a wrong answer.
//!
//! # The protocol is built by hand here
//!
//! The first version of this test went through `pthread_mutex_t` with
//! `PTHREAD_MUTEX_ROBUST`, and it failed *against a real kernel* — musl's
//! robust protocol is its own and the mutex was never marked. That said
//! nothing about `set_robust_list`; it said the probe was measuring musl.
//!
//! What is built below is the ABI itself, out of the three structures the
//! kernel actually reads:
//!
//! ```text
//! robust_list_head { list: *entry, futex_offset: isize, pending: *entry }
//! entry           { next: *entry }        // the futex is at entry+futex_offset
//! ```
//!
//! and the futex word must hold the dying thread's TID in its low 30 bits, or
//! the kernel leaves it alone — it only disowns what that thread owned.

use guest_tests::{Harness, check};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

/// Set by the kernel on a futex whose owner died. Bit 30.
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;

/// `struct robust_list_head`, exactly as the kernel reads it.
#[repr(C)]
struct RobustListHead {
    list: u64,
    futex_offset: i64,
    pending: u64,
}

/// One entry, with its futex immediately after — so `futex_offset` is 8.
#[repr(C)]
struct Entry {
    next: u64,
    futex: AtomicU32,
    _pad: u32,
}

static HEAD: std::sync::Mutex<()> = std::sync::Mutex::new(());
static READY: AtomicI32 = AtomicI32::new(0);
static mut STATE: Option<Box<(RobustListHead, Entry)>> = None;

fn gettid() -> u32 {
    unsafe { libc::syscall(libc::SYS_gettid) as u32 }
}

extern "C" fn holder(_: *mut libc::c_void) -> *mut libc::c_void {
    unsafe {
        let st = (&raw mut STATE).as_mut().unwrap().as_mut().unwrap();
        let entry = &raw mut st.1;

        // Own the futex: the kernel disowns only what this thread held.
        st.1.futex.store(gettid(), Ordering::SeqCst);
        st.0.list = entry as u64;
        st.0.futex_offset = 8;
        st.0.pending = 0;

        let r = libc::syscall(
            libc::SYS_set_robust_list,
            &raw mut st.0,
            std::mem::size_of::<RobustListHead>(),
        );
        READY.store(if r == 0 { 1 } else { -1 }, Ordering::SeqCst);
        // Raw exit, so nothing in userspace gets a chance to tidy up. This is
        // the whole point: only the kernel can act from here.
        libc::syscall(libc::SYS_exit, 0);
        unreachable!()
    }
}

fn main() {
    let mut h = Harness::new();
    let _g = HEAD.lock();

    h.group("set-and-get");
    let mut head = RobustListHead { list: 0, futex_offset: 8, pending: 0 };
    let r = unsafe {
        libc::syscall(
            libc::SYS_set_robust_list,
            &raw mut head,
            std::mem::size_of::<RobustListHead>(),
        )
    };
    check!(h, r == 0, "set_robust_list is accepted: {r} errno {}", guest_tests::sys::errno());

    let mut got: u64 = 0;
    let mut len: usize = 0;
    let r = unsafe {
        libc::syscall(libc::SYS_get_robust_list, 0, &raw mut got, &raw mut len)
    };
    check!(h, r == 0, "get_robust_list is accepted: {r}");
    check!(h, got == (&raw mut head) as u64, "and reports the head that was set");
    check!(
        h,
        len == std::mem::size_of::<RobustListHead>(),
        "with the size of a robust_list_head: {len}"
    );
    // A length that is not exactly that size is EINVAL: the kernel reads a
    // fixed shape and a caller disagreeing about it has to be told.
    let r = unsafe { libc::syscall(libc::SYS_set_robust_list, &raw mut head, 16usize) };
    check!(
        h,
        r == -1 && guest_tests::sys::errno() == libc::EINVAL,
        "a length that is not sizeof(robust_list_head) is EINVAL: {r}"
    );

    h.group("owner-died");
    unsafe {
        STATE = Some(Box::new((
            RobustListHead { list: 0, futex_offset: 8, pending: 0 },
            Entry { next: 0, futex: AtomicU32::new(0), _pad: 0 },
        )));
        // A self-terminated list: the entry points back at the head, which is
        // how libc builds it and where the kernel stops walking.
        let st = (&raw mut STATE).as_mut().unwrap().as_mut().unwrap();
        st.1.next = (&raw mut st.0) as u64;

        let mut tid: libc::pthread_t = std::ptr::null_mut();
        let r = libc::pthread_create(&mut tid, std::ptr::null(), holder, std::ptr::null_mut());
        check!(h, r == 0, "start the thread that will die owning the futex: {r}");

        let mut spins = 0;
        while READY.load(Ordering::SeqCst) == 0 && spins < 20_000 {
            libc::usleep(100);
            spins += 1;
        }
        check!(h, READY.load(Ordering::SeqCst) == 1, "it registered its robust list");
        // Let the exit be processed.
        libc::usleep(100_000);

        let st = (&raw mut STATE).as_mut().unwrap().as_mut().unwrap();
        let word = st.1.futex.load(Ordering::SeqCst);
        check!(
            h,
            word & FUTEX_OWNER_DIED != 0,
            "the kernel disowned the futex on exit: {word:#x}, wanted bit 30 set"
        );
    }

    std::process::exit(h.finish());
}
