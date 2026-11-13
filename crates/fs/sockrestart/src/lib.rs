//! Rebuilding listening sockets that iOS tore down while the app was suspended.
//!
//! iOS frees the socket part of a listening file when an app goes to the
//! background. The descriptor stays, but it is no longer a socket: every
//! operation on it fails immediately and anyone blocked in `accept` never
//! wakes. See Apple's [TN2277].
//!
//! So the shape is: keep track of the listening sockets and of the threads
//! waiting on one. On suspend, record each socket's name and configuration. On
//! resume, open replacements, reconfigure them, `dup2` them onto the
//! descriptors the guest already holds, and get every waiting thread to go
//! round its loop again.
//!
//! [TN2277]: https://developer.apple.com/library/archive/technotes/tn2277/_index.html
//!
//! # This is an embedder hook, not dead code
//!
//! [`sockrestart_on_suspend`] and [`sockrestart_on_resume`] have no caller in
//! this tree and are not supposed to: there is no iOS app here, only the engine
//! an app links. They belong to the host application's lifecycle — an embedder
//! calls them from `applicationDidEnterBackground` and
//! `applicationWillEnterForeground`, the way it calls `fakefs_bind_mount` or
//! sets `uname_hostname_override`.
//!
//! It matters that the rest of the machinery is live whether or not an embedder
//! wires these up: the registrations are what make the wiring a two-line change
//! rather than a feature.
//!
//! # Two collections, one lock, no intrusive lists
//!
//! `struct fd` carried a `struct list` and a backlog, and `struct task` carried
//! a list node, a count and a flag. Both are gone. The listening sockets are a
//! `Vec` — a process has a handful, and removal by scan costs less than the
//! field did — and the waiting threads are a `Vec` of handles a thread keeps a
//! reference to for its own lifetime.
//!
//! The count is per-thread and only ever compared against zero, so it is a
//! `thread_local` rather than anything shared. That is what makes the poll path
//! affordable: it used to walk every member of the set before *every* wait and
//! take this global lock once per socket, so a server polling 1800 sockets took
//! it 1800 times a pass.
//!
//! # The flag outlives the registration
//!
//! `sockrestart_should_restart_listen_wait` is called **after**
//! `sockrestart_end_listen_wait`, by every caller. So a thread's handle is
//! created once and kept for the life of the thread; only its membership of the
//! waiting set comes and goes. Dropping the handle at the end of the wait would
//! throw away the punt that the resume had just set, which is the one thing the
//! whole mechanism exists to deliver.

#![deny(unsafe_op_in_unsafe_fn)]

/// Closing a descriptor and waking a blocked host call, chosen at **compile
/// time**.
///
/// The tests drive fake pointers the real functions would dereference, and
/// until 2026-09-06 they substituted by defining `#[no_mangle]` doubles -- a
/// *second definition of the symbol* that `ld` warns about and then picks
/// between, deciding what the tests measured with nothing in the source saying
/// which. A `use` behind a `cfg` is the substitution the compiler resolves.
use logline::printk;
use std::any::TypeId;
use std::ffi::c_int;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
#[cfg(test)]
use stubs::task_interrupt_host_call;
#[cfg(not(test))]
use taskcalls::task_interrupt_host_call;

/// `struct fd` and `struct fd_ops`, which are `crates/kernel/taskview`'s own
/// Rust -- the generated file's only other content was the declaration below.
use taskview::ffi;

/// Which driver a socket descriptor has, which is how this crate tells one
/// from any other.
///
/// A hook. `crates/fs/sock` calls this crate's bracket around every blocking
/// accept, so a direct call the other way is a cycle — it was a
/// `socket_fdops_get` declared in an `extern "C"` block until 2026-09-09, the
/// same call resolved by the linker.
///
/// **Empty before anything installs it, which is the truth rather than a
/// fallback**: `fs/sock` installs it when it builds the driver, which is the
/// first time a socket can exist, and until then no descriptor is one.
///
/// A `TypeId` rather than the table's *address*, which is what it was until
/// 2026-09-11. A driver is a type now and the question this asks is about the
/// type; two values of one type are the same kind whether or not the linker
/// gave them one address.
static SOCKET_FDOPS: OnceLock<TypeId> = OnceLock::new();

/// Install it. See [`SOCKET_FDOPS`].
pub fn set_socket_fdops(ops: &'static dyn ffi::FdOps) {
    let _ = SOCKET_FDOPS.set(ops.as_any().type_id());
}

/// Whether it has been installed — for the test in `crates/fs/sock`. Before the
/// first socket exists, `is_socket` answers false for every descriptor either
/// way, so no assertion distinguishes them.
pub fn socket_fdops_installed() -> bool {
    SOCKET_FDOPS.get().is_some()
}

/// One listening socket, as `listen()` last described it.
///
/// A `(FdPtr, c_int, c_int)` until 2026-09-16 — three unnamed fields, scanned
/// with `|(f, _, _)|`, where two of the three are small integers that mean
/// entirely different things.
///
/// `sock` is an identity and never a pointer: nothing here dereferences it, it
/// is compared against the socket a `listen`/`close` names and read back at
/// suspend time to open a replacement. `FdPtr(usize)` — this crate's own
/// address-as-an-integer — is [`ffi::FdId`], which is that property with the
/// `Send` and the `unsafe` borrow written down in one place. Its doc here said
/// the registry "holds a reference on each one from `fd_retain` while it is in
/// `saved`", which stopped being true on 2026-09-12 when [`Saved::fd`] became
/// an owning `fs_fdobj::Owned`.
#[derive(Clone)]
struct Listening {
    sock: ffi::FdId,
    /// The description, without keeping it alive: the suspend upgrades it,
    /// which answers `None` for one whose last reference has gone.
    weak: std::sync::Weak<ffi::fd>,
    backlog: c_int,
    /// Recorded here rather than read off the descriptor at suspend time; see
    /// [`Registry::listening`].
    protocol: c_int,
}

/// One thread's flag, and the task a resume has to interrupt.
struct Waiter {
    /// The thread to signal, so that its blocking host call returns, or `None`
    /// for a caller with no task.
    ///
    /// **A `usize` until 2026-09-16**, under a comment at the use site saying
    /// it was "carried as a `usize` on purpose -- see the `Send` note on
    /// `Waiter`". There was no such note: the reason was real and had never
    /// been written, so what the reader found was a pointer to nothing. It is
    /// below, and it is the whole of why this is not a plain `*mut`.
    ///
    /// **`Option`, because the `None` is reachable and is not an invalid
    /// state.** `taskview::current()` is a `thread_local!` and is null on a
    /// host thread that has no task -- which the `usize` spelled as `0`, and
    /// the resume's `task_interrupt_host_call` tested for and returned. Such a
    /// thread still has a `punt` flag worth setting and is still registered;
    /// it just has nothing to signal. The first attempt at this made
    /// `my_waiter` answer `None` instead and skipped the registration, and
    /// four of this crate's own tests said so -- they exercise the flag in a
    /// test binary, where `current()` is null.
    task: Option<NonNull<ffi::task>>,
    /// Set by a resume, taken by the thread's next look at it.
    punt: AtomicBool,
    /// The listener this thread is blocked in a host `accept` on, if it is --
    /// so that shutting that listener down can wake exactly these threads.
    /// See [`wait::sockrestart_wake_accepting`].
    accepting: Mutex<Option<ffi::FdId>>,
}

// SAFETY: `task` is an address this crate only ever hands to
// `task_interrupt_host_call`, which reads the task's pthread id and signals it.
// What makes that sound across threads is not this impl but the registration
// protocol: a `Waiter` is in `Registry::waiting` only between
// `begin_listen_wait` and `end_listen_wait`, both of which run **on the thread
// the task belongs to**, so the task cannot exit while it is reachable here.
unsafe impl Send for Waiter {}
// SAFETY: as `Send`. `punt` is atomic and `task` is never written.
unsafe impl Sync for Waiter {}

/// What a suspend recorded about one listening socket.
struct Saved {
    /// **Owning**, since 2026-09-12. It was an `FdPtr` -- which is `Copy`, the
    /// one property an owner must not have -- with a comment saying it was
    /// "held with a reference from `fd_retain`, given back on resume", and the
    /// giving back was a `release(..)` helper called from two places. Object
    /// model step 9.7.
    ///
    /// **Where the drop happens is still load-bearing** and the code still says
    /// so: the set is moved out from under the registry's mutex *before* it
    /// goes, because the last reference reaches `sockrestart_end_listen`, which
    /// takes that same non-recursive lock. Releasing it under the lock
    /// deadlocked the resume exactly when the guest had closed the socket while
    /// suspended.
    fd: fs_fdobj::Owned,
    ty: rustix::net::SocketType,
    proto: c_int,
    backlog: c_int,
    /// `getsockname`'s answer. A `SocketAddrAny` since 2026-10-17, which knows
    /// its own family and length: it was 128 bytes and a length, and the family
    /// was read back by casting the bytes to `libc::sockaddr`.
    name: rustix::net::SocketAddrAny,
}

#[derive(Default)]
struct Registry {
    /// Every listening socket, with the backlog its last `listen` asked for
    /// and the protocol it was created with.
    ///
    /// The protocol is recorded here rather than read off the descriptor at
    /// suspend time, which is what this did until 2026-09-05: a socket's state
    /// belongs to `crates/fs/sock` and that crate is the caller, so it is the
    /// one that knows. The host cannot be asked instead — `SO_PROTOCOL` is
    /// Linux's and Darwin has no equivalent.
    listening: Vec<Listening>,
    /// The threads currently inside a wait on a socket.
    waiting: Vec<Arc<Waiter>>,
    /// What a suspend recorded, until the matching resume.
    saved: Vec<Saved>,
}

fn registry() -> &'static Mutex<Registry> {
    static R: OnceLock<Mutex<Registry>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(Registry::default()))
}

mod wait;
pub use wait::{
    sockrestart_begin_listen, sockrestart_begin_listen_wait, sockrestart_begin_listen_wait_bare,
    sockrestart_end_listen, sockrestart_end_listen_wait, sockrestart_end_listen_wait_bare,
    sockrestart_is_socket, sockrestart_should_restart_listen_wait, sockrestart_wake_accepting,
};

mod lifecycle;
pub use lifecycle::{sockrestart_on_resume, sockrestart_on_suspend};

/// What this crate calls that a test must not reach: one function, the
/// interrupt of a host call, selected by a `cfg` on the `use` above. It was
/// five `#[no_mangle]` doubles of C symbols; the rest went as each became a
/// Rust call, and each note below says why.
#[cfg(test)]
mod stubs {
    /* A `#[no_mangle] task_self` answering a non-null dummy was here until
     * 2026-09-30. Nothing in this crate reaches the symbol -- `my_waiter`
     * reads `taskview::current()`, a `thread_local!` that is null in a test
     * binary -- so the double was never linked, and the test comment that
     * relied on it being non-null described a harness that did not exist. */

    // Signatures match the real ones exactly, which the `cfg`-selected `use`
    // is what enforces: with a `#[no_mangle]` double, a mismatch here was
    // completely silent.
    pub(super) unsafe fn task_interrupt_host_call(_task: *mut taskview::ffi::task) {}
    /* A `fd_close` stub was here until 2026-09-12. `Saved::fd` is an
     * `fs_fdobj::Owned` now and its `Drop` reaches the real release, so a
     * `cfg`-selected `use` could not intercept it even if one were wanted --
     * and no test in this module builds a `Saved`, which is what makes that
     * safe rather than merely true. */
    /* A `#[no_mangle] socket_fdops_get` returning null was here. There is no
     * symbol to stand in for since 2026-09-09: `crates/fs/sock` installs the
     * table through `set_socket_fdops`, and a test that installs nothing gets
     * the same null the double returned. */
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether *this thread* is in the waiting set.
    ///
    /// The registry is process-wide and cargo runs these on threads of one
    /// process, so a test asserting on its length would be asserting about the
    /// other tests. Membership is the question anyway.
    fn registered() -> bool {
        let me = wait::my_waiter();
        registry()
            .lock()
            .unwrap()
            .waiting
            .iter()
            .any(|w| Arc::ptr_eq(w, &me))
    }

    #[test]
    fn the_depth_only_ever_answers_whether_it_is_zero() {
        sockrestart_begin_listen_wait_bare();
        assert!(registered());
        // Nested: sys_accept brackets its own wait and the poll loop brackets
        // its, and one registration says as much as two.
        sockrestart_begin_listen_wait_bare();
        assert!(registered());
        sockrestart_end_listen_wait_bare();
        assert!(registered(), "the outer wait is still running");
        sockrestart_end_listen_wait_bare();
        assert!(!registered());
    }

    #[test]
    fn an_unbalanced_end_does_not_leave_the_count_below_zero() {
        // The C decremented unconditionally, so this left it at -1 and the next
        // begin registered nothing -- a thread that then slept through a
        // resume. The count is unsigned here and the end is a no-op.
        sockrestart_end_listen_wait_bare();
        sockrestart_begin_listen_wait_bare();
        assert!(registered());
        sockrestart_end_listen_wait_bare();
        assert!(!registered());
    }

    #[test]
    fn the_punt_survives_the_end_of_the_wait() {
        // Every caller asks `should_restart` *after* `end_listen_wait`, so a
        // handle dropped at the end of the wait would throw away the answer.
        sockrestart_begin_listen_wait_bare();
        wait::my_waiter().punt.store(true, Ordering::SeqCst);
        sockrestart_end_listen_wait_bare();
        assert!(sockrestart_should_restart_listen_wait());
        assert!(
            !sockrestart_should_restart_listen_wait(),
            "and it is taken, not merely read"
        );
    }

    /// A driver whose only job is to be a distinct type, so that `is_socket`
    /// answers true for the descriptors below -- and, for the one description
    /// [`GATED`] names, a `close` that parks until the test lets it go, and
    /// then deregisters as `sock_close` does.
    struct FakeSocketFd;

    impl ffi::FdOps for FakeSocketFd {
        fn caps(&self) -> ffi::Caps {
            ffi::Caps::NONE
        }

        fn close(&self, fd: &mut ffi::fd) -> c_int {
            // Claimed, not compared: the gated description is freed before its
            // test clears `GATED`, and a parallel test's descriptor allocated at
            // the same address then parked here for good, its `Closing` having
            // overwritten the `Released` that would have let it go.
            let me = std::ptr::from_mut(fd) as usize;
            if GATED.compare_exchange(me, 0, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                let (state, changed) = &GATE;
                let mut s = state.lock().unwrap();
                *s = Gate::Closing;
                changed.notify_all();
                while *s != Gate::Released {
                    s = changed.wait(s).unwrap();
                }
                drop(s);
                sockrestart_end_listen(fd);
            }
            0
        }
    }

    static FAKE: FakeSocketFd = FakeSocketFd;

    #[derive(PartialEq)]
    enum Gate {
        Idle,
        Closing,
        Released,
    }
    static GATED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    static GATE: (std::sync::Mutex<Gate>, std::sync::Condvar) =
        (std::sync::Mutex::new(Gate::Idle), std::sync::Condvar::new());

    /// The suspend and resume tests, one at a time: the registry is
    /// process-wide, so one test's suspend would save the other's listener.
    static LIFECYCLE: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A loopback listener's descriptor, published.
    fn listening() -> (fs_fdobj::Owned, std::net::SocketAddr) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
        let addr = listener.local_addr().unwrap();
        let mut new = fs_fdobj::NewFd::new(Some(&FAKE));
        new.real_fd = Some(std::os::fd::OwnedFd::from(listener));
        (new.into_owned(), addr)
    }

    /// A suspend that lands while the guest is closing a listener -- its count
    /// gone to zero, its finalizer running, and `sock_close`'s deregistration
    /// not yet reached -- skips it. It retained it, which on a description
    /// whose count is zero is `process::abort`: an app backgrounded at the
    /// wrong moment died.
    #[test]
    fn a_listener_closing_during_a_suspend_is_skipped() {
        let _serial = LIFECYCLE.lock().unwrap_or_else(|e| e.into_inner());
        set_socket_fdops(&FAKE);
        let (sock, _) = listening();
        GATED.store(sock.as_ptr() as usize, Ordering::SeqCst);
        sockrestart_begin_listen(&sock, 5, 6);

        let closer = std::thread::spawn(move || drop(sock));
        let (state, changed) = &GATE;
        {
            let mut s = state.lock().unwrap();
            while *s != Gate::Closing {
                s = changed.wait(s).unwrap();
            }
        }
        sockrestart_on_suspend();
        *state.lock().unwrap() = Gate::Released;
        changed.notify_all();
        closer.join().unwrap();
        sockrestart_on_resume();
        *state.lock().unwrap() = Gate::Idle;
    }

    /// How many entries in the registry name this descriptor.
    ///
    /// The registry is process-wide and cargo runs these on threads of one
    /// process, so a count of the whole vector would be a count of the other
    /// tests' sockets too -- the same reason `registered` asks about
    /// membership.
    fn listed(fd: &ffi::fd) -> Vec<(c_int, c_int)> {
        let id = ffi::FdId::of(fd);
        registry()
            .lock()
            .unwrap()
            .listening
            .iter()
            .filter(|l| l.sock == id)
            .map(|l| (l.backlog, l.protocol))
            .collect()
    }

    /// **A second `listen()` on one socket updates its record**, and does not
    /// add a second.
    ///
    /// This is the defect `sockrestart_begin_listen`'s doc comment is about --
    /// "the C used an intrusive node and a second insertion would have
    /// self-linked it, leaving a dangling registry head on close" -- and
    /// nothing tested it. Found when the registration changed shape on
    /// 2026-09-16: the `find`-then-update is what the property lives in, and
    /// the two `|(f, _, _)|` closures it replaced had no coverage either.
    ///
    /// It is also what says the identity is the *description*: with a key that
    /// compared wrongly, `end_listen` would leave the entry behind and a
    /// suspend would then retain a freed descriptor.
    #[test]
    fn a_second_listen_on_one_socket_updates_its_record() {
        set_socket_fdops(&FAKE);
        let fd = fs_fdobj::NewFd::new(Some(&FAKE)).into_owned();

        assert_eq!(listed(&fd), vec![], "not listening yet");
        sockrestart_begin_listen(&fd, 5, 6);
        assert_eq!(listed(&fd), vec![(5, 6)]);

        // The second call is the one the C got wrong.
        sockrestart_begin_listen(&fd, 128, 6);
        assert_eq!(listed(&fd), vec![(128, 6)], "updated, not appended");

        sockrestart_end_listen(&fd);
        assert_eq!(listed(&fd), vec![], "and the close removes it");
    }

    /// Two sockets are two records. The registration is keyed on the
    /// description's address, so this is what says the key distinguishes them.
    #[test]
    fn two_sockets_are_two_records() {
        set_socket_fdops(&FAKE);
        let fake = || fs_fdobj::NewFd::new(Some(&FAKE)).into_owned();
        let (a, b) = (fake(), fake());

        sockrestart_begin_listen(&a, 1, 0);
        sockrestart_begin_listen(&b, 2, 0);
        assert_eq!(listed(&a), vec![(1, 0)]);
        assert_eq!(listed(&b), vec![(2, 0)]);

        sockrestart_end_listen(&a);
        assert_eq!(listed(&a), vec![], "one closed");
        assert_eq!(listed(&b), vec![(2, 0)], "and the other did not");
        sockrestart_end_listen(&b);
    }

    /// A descriptor that is not a socket is not registered, which is what the
    /// `is_socket` guard at the top of each is for: `listen()` reaches this
    /// crate through `fs/sock` only, but the poll bracket asks about every
    /// member of a set.
    #[test]
    fn a_descriptor_that_is_not_a_socket_is_not_registered() {
        set_socket_fdops(&FAKE);
        // No `ops`, so not this crate's socket driver.
        let fd = fs_fdobj::NewFd::new(None).into_owned();
        assert!(!sockrestart_is_socket(&fd));
        sockrestart_begin_listen(&fd, 5, 6);
        assert_eq!(listed(&fd), vec![], "nothing was recorded");
    }

    #[test]
    fn a_thread_that_never_waited_has_nothing_to_restart() {
        assert!(!sockrestart_should_restart_listen_wait());
    }

    /// The whole suspend and resume, on a real host listener: what iOS does to
    /// a backgrounded app is close its sockets under it, and what the resume
    /// owes the guest is the same descriptor listening at the same address.
    ///
    /// Written on 2026-10-17 with the move of this path onto `rustix`, which
    /// had no test: the two lifecycle calls have no caller in this tree.
    #[test]
    fn a_suspended_listener_is_rebuilt_at_the_same_address() {
        use std::os::fd::{AsFd, AsRawFd};
        let _serial = LIFECYCLE.lock().unwrap_or_else(|e| e.into_inner());
        set_socket_fdops(&FAKE);
        let (sock, addr) = listening();

        sockrestart_begin_listen(&sock, 5, 6);
        sockrestart_on_suspend();
        // The listener dies under the descriptor, which keeps its number: a
        // fresh, unbound socket takes its place, as a reclaimed one would.
        let host = sock.host().expect("a host socket");
        let dead = rustix::net::socket(
            rustix::net::AddressFamily::INET,
            rustix::net::SocketType::STREAM,
            None,
        )
        .unwrap();
        // SAFETY: both are live descriptors; the target is the description's
        // own, which it keeps owning.
        assert!(unsafe { libc::dup2(dead.as_raw_fd(), host.as_raw_fd()) } >= 0);
        drop(dead);
        assert!(
            std::net::TcpStream::connect(addr).is_err(),
            "nothing listens there while suspended"
        );

        sockrestart_on_resume();
        let host = sock.host().expect("a host socket");
        let name = rustix::net::getsockname(host.as_fd()).unwrap();
        assert_eq!(
            std::net::SocketAddr::try_from(name).ok(),
            Some(addr),
            "the same address"
        );
        assert!(std::net::TcpStream::connect(addr).is_ok(), "and listening on it");

        sockrestart_end_listen(&sock);
    }

    #[test]
    fn a_resume_punts_every_thread_that_is_waiting() {
        // A resume rebuilds whatever the last suspend saved, so without the
        // lock this one consumed the listener test's saved set between its
        // suspend and its resume.
        let _serial = LIFECYCLE.lock().unwrap_or_else(|e| e.into_inner());
        sockrestart_begin_listen_wait_bare();
        sockrestart_on_resume();
        sockrestart_end_listen_wait_bare();
        assert!(sockrestart_should_restart_listen_wait());
    }
}
