//! One transient `poll()`/`select()` set: its members, its host batch and its
//! wait.
//!
//! The set belongs to the thread making the syscall — it is built, waited on
//! once and destroyed without ever being published — so it holds no lock. The
//! only shared object is the [`Waiter`], and descriptors reach it through their
//! own [`Watchers`] list rather than through the set.
//!
//! Members are typed handles whose concrete type is supplied by [`Members`].
//! Everything that has to look inside one is a method of that trait, which
//! `crates/fs/poll` implements; this crate never dereferences a member.

use crate::waiter::{Waiter, Watchers};
use std::ffi::{c_int, c_short};
use std::sync::Arc;

use guest_errno::c_int_::ENOMEM;

/// Everything the set needs to know about a member descriptor, and the two
/// host-wait policies that belong to the socket layer.
///
/// A trait rather than a `#[repr(C)]` table of `Option<unsafe extern "C" fn>`,
/// which is what it was until 2026-09-09 — because `fs/poll.c` filled one in,
/// and the shape outlived the file. There is one implementation,
/// `crates/fs/poll`'s, and a table of eleven nullable function pointers said
/// eleven times that there might not be.
///
/// Associated functions rather than methods: the handle is the state, and the
/// implementor is a marker type.
///
/// **A safe trait since 2026-10-01.** `Fd` was `Copy` -- a raw pointer -- and
/// the set called `retain` on add and `release` on drop, so implementing the
/// trait asserted that a handle between the two stayed valid, which is what
/// let the other methods be safe. `Fd` is an owned handle now: the caller
/// hands the set a reference, dropping the member gives it back, and a method
/// is handed a borrow of it. There is nothing left to assert.
pub trait Members {
    /// The member, opaque here: an owned reference, released when dropped.
    type Fd;

    /// The descriptor's own readiness, in guest `POLL_*` terms.
    fn poll(fd: &Self::Fd) -> c_int;
    /// A host descriptor that answers for this one, or -1.
    fn host_fd(fd: &Self::Fd) -> c_int;
    /// The host `poll(2)` events to ask for. Only called when `host_fd` >= 0.
    fn host_events(fd: &Self::Fd) -> c_short;
    /// Turn host `revents` into guest `POLL_*` bits, or -1 to ask
    /// [`Members::poll`] instead.
    fn host_fixup(fd: &Self::Fd, revents: c_short) -> c_int;
    fn is_socket(fd: &Self::Fd) -> bool;

    /// The guest errno for the current host `errno`. The implementor's,
    /// because mapping `EPIPE` raises a guest signal.
    fn map_errno() -> c_int;

    /// Bracket for a blocking wait that includes at least one socket. Taken
    /// once per wait rather than once per socket: the count only ever answers
    /// "is it zero", and the lock behind it is one every thread shares.
    fn begin_listen_wait();
    fn end_listen_wait();
    fn should_restart_listen_wait() -> bool;
}

struct Member<M: Members> {
    fd: M::Fd,
    /// A clone of the descriptor's waiter list. Held so that deregistration
    /// works whether the set or the descriptor goes away first.
    watchers: Arc<Watchers>,
    /// What the guest asked to hear about.
    types: c_int,
    /// The guest's cookie for this member: a descriptor number for `select`,
    /// a description pointer for `poll`. Opaque here.
    info: u64,
    /// The host descriptor answering for this member on the current pass, or
    /// -1. Re-asked every pass: an epoll set's backend is created lazily, so
    /// this is not a property of the member that can be cached at add time.
    host_fd: c_int,
    /// Where this member's answer is in the host array for the current pass,
    /// or -1 if it has no host descriptor or the array could not hold it.
    slot: i32,
}

pub struct PollSet<M: Members> {
    /// The bits a member is told about whether or not it asked — `POLL_ERR`
    /// and `POLL_HUP`. Passed in so the `POLL_*` numbering has one definition,
    /// in `fs/poll.h`.
    always_reported: c_int,
    members: Vec<Member<M>>,
    /// Reused across passes. A blocking wait goes round its one-second slices
    /// many times and must not allocate on each.
    host: Vec<libc::pollfd>,
    /// Host slots filled by the level scan, and then the count the blocking
    /// wait polls — the scan's members plus the wake pipe. The pipe is
    /// appended immediately before the wait rather than kept in the batch,
    /// because a set whose waiter released has no pipe and the stale number
    /// would be some other file by then.
    active: usize,
    waiter: Arc<Waiter>,
    sockets: usize,
}

const EMPTY: libc::pollfd = libc::pollfd {
    fd: -1,
    events: 0,
    revents: 0,
};

impl<M: Members> PollSet<M> {
    pub fn new(always_reported: c_int) -> PollSet<M> {
        PollSet {
            always_reported,
            members: Vec::new(),
            host: Vec::new(),
            active: 0,
            waiter: Waiter::new(),
            sockets: 0,
        }
    }

    /// Register one member.
    ///
    /// **Safe since 2026-09-09.** It was `unsafe` because it handed a
    /// `*mut c_void` to a function pointer out of a table -- which is what
    /// `clippy::not_unsafe_ptr_arg_deref` says about a `pub fn`, and
    /// `PollSet` is `pub use`d out of a private module, so it was safe API
    /// another crate could call with any address. `M::Fd` is the implementor's
    /// own owned handle now, so there is no address to get wrong.
    pub fn add(&mut self, fd: M::Fd, watchers: Arc<Watchers>, types: c_int, info: u64) -> c_int {
        if self.members.try_reserve(1).is_err() {
            return ENOMEM;
        }
        if !watchers.add_waiter(&self.waiter) {
            return ENOMEM;
        }
        // `fd` is a strong reference for as long as the member is in the set.
        // The two callers hold one anyway for the whole syscall, but making it
        // the set's own is what lets the descriptor's teardown stop caring
        // about transient polls at all.
        if M::is_socket(&fd) {
            self.sockets += 1;
        }
        self.members.push(Member {
            fd,
            watchers,
            types,
            info,
            host_fd: -1,
            slot: -1,
        });
        0
    }

    pub fn has_socket(&self) -> bool {
        self.sockets != 0
    }

    pub fn acquire(&self) -> c_int {
        self.waiter.acquire(M::map_errno)
    }

    pub fn release(&self) {
        self.waiter.release();
    }

    pub fn drain(&self) {
        self.waiter.drain();
    }

    /// Grow the host array to `want` entries, keeping what is already there.
    fn reserve(&mut self, want: usize) -> bool {
        if self.host.len() >= want {
            return true;
        }
        if self.host.try_reserve(want - self.host.len()).is_err() {
            return false;
        }
        self.host.resize(want, EMPTY);
        true
    }

    /// Ask the host about every host-backed member at once, then report each
    /// member's readiness through `callback`.
    ///
    /// One host call, not one per member. `realfs_poll` does an `fcntl` and a
    /// `poll()` per descriptor and the scan runs on every pass, so profiling a
    /// guest `poll()` over 256 descriptors put 1442 of 1520 samples inside
    /// that one host call. Everything without a host descriptor — a tty, an
    /// eventfd, a timerfd — still answers through its own poll operation,
    /// which costs a function call.
    ///
    /// Returns the sum of what `callback` returned, which is how many guest
    /// entries it made ready.
    pub fn scan(&mut self, mut callback: impl FnMut(c_int, u64) -> c_int) -> c_int {
        self.gather();
        if self.active > 0 {
            // Zero timeout: this is the level check, not the wait.
            unsafe { libc::poll(self.host.as_mut_ptr(), self.active as libc::nfds_t, 0) };
        }
        let mut ready = 0;
        for member in &self.members {
            let mut types = -1;
            if member.slot >= 0 {
                let revents = self.host[member.slot as usize].revents;
                types = M::host_fixup(&member.fd, revents);
            }
            if types < 0 {
                types = M::poll(&member.fd);
            }
            types &= member.types | self.always_reported;
            if types != 0 {
                ready += callback(types, member.info);
            }
        }
        ready
    }

    /// Fill the host array with this pass's host-backed members.
    fn gather(&mut self) {
        self.active = 0;
        let mut wanted = 0;
        for member in &mut self.members {
            member.slot = -1;
            member.host_fd = M::host_fd(&member.fd);
            if member.host_fd >= 0 {
                wanted += 1;
            }
        }
        // One spare for the wake pipe the blocking wait appends.
        if !self.reserve(wanted + 1) && !self.reserve(1) {
            // Out of memory. Every member falls back to its own poll operation
            // and the wait below runs on the wake pipe alone, or on nothing.
            return;
        }
        let mut index = 0;
        for member in &mut self.members {
            if member.host_fd < 0 || index >= self.host.len() {
                continue;
            }
            self.host[index] = libc::pollfd {
                fd: member.host_fd,
                events: M::host_events(&member.fd),
                revents: 0,
            };
            member.slot = index as i32;
            index += 1;
        }
        self.active = index;
    }

    /// Sleep until a member's host descriptor moves, a wake arrives, or the
    /// slice runs out.
    ///
    /// Returns what the host `poll()` returned; on a negative result
    /// `out_errno` holds the host errno, which the caller needs to tell an
    /// interrupted wait from a failed one.
    pub fn block(&mut self, timeout_ms: c_int, out_errno: &mut c_int) -> c_int {
        let mut count = self.active;
        let notify = self.waiter.read_fd();
        if notify >= 0 && count < self.host.len() {
            self.host[count] = libc::pollfd {
                fd: notify,
                events: libc::POLLIN,
                revents: 0,
            };
            count += 1;
        }
        let bracketed = self.sockets != 0;
        if bracketed {
            M::begin_listen_wait();
        }
        let pointer = if count == 0 {
            std::ptr::null_mut()
        } else {
            self.host.as_mut_ptr()
        };
        let result = loop {
            let result = unsafe { libc::poll(pointer, count as libc::nfds_t, timeout_ms) };
            if result >= 0 {
                *out_errno = 0;
                break result;
            }
            *out_errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if *out_errno != libc::EINTR {
                break result;
            }
            // A host signal that only meant "look again" for a socket the
            // restart machinery is tracking. Anything else leaves the loop and
            // the caller decides whether the guest hears EINTR.
            if !M::should_restart_listen_wait() {
                break result;
            }
        };
        if bracketed {
            M::end_listen_wait();
        }
        result
    }
}

impl<M: Members> Drop for PollSet<M> {
    fn drop(&mut self) {
        for member in self.members.drain(..) {
            member.watchers.remove_waiter(&self.waiter);
            // And `member.fd` goes with it, which is the release.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // A fake descriptor. `fd` names a host pipe read end when it has one;
    // `types` is what the descriptor's own poll operation answers.
    #[repr(C)]
    struct Fake {
        host: c_int,
        types: c_int,
        socket: bool,
    }

    static RETAINED: AtomicUsize = AtomicUsize::new(0);
    static LISTEN_WAITS: AtomicUsize = AtomicUsize::new(0);

    fn fake_poll(fd: *mut Fake) -> c_int {
        unsafe { (*fd).types }
    }
    fn fake_host_fd(fd: *mut Fake) -> c_int {
        unsafe { (*fd).host }
    }
    fn fake_host_events(_: *mut Fake) -> c_short {
        libc::POLLIN
    }
    fn fake_host_fixup(_: *mut Fake, revents: c_short) -> c_int {
        if revents & libc::POLLIN != 0 { 1 } else { -1 }
    }
    fn fake_is_socket(fd: *mut Fake) -> bool {
        unsafe { (*fd).socket }
    }
    fn fake_retain(_: *mut Fake) {
        RETAINED.fetch_add(1, Ordering::SeqCst);
    }
    fn fake_release(_: *mut Fake) {
        RETAINED.fetch_sub(1, Ordering::SeqCst);
    }
    fn fake_map_errno() -> c_int {
        -5
    }
    fn fake_begin_listen_wait() {
        LISTEN_WAITS.fetch_add(1, Ordering::SeqCst);
    }
    fn fake_end_listen_wait() {
        LISTEN_WAITS.fetch_sub(1, Ordering::SeqCst);
    }
    fn fake_should_restart() -> bool {
        false
    }

    /// The test's member handle: a `Fake` the test keeps alive for the set's
    /// lifetime, counted in [`RETAINED`] from `new` to `Drop` as a real
    /// reference would be.
    struct Handle(*mut Fake);

    impl Handle {
        fn new(fd: *mut Fake) -> Handle {
            fake_retain(fd);
            Handle(fd)
        }
    }

    impl Drop for Handle {
        fn drop(&mut self) {
            fake_release(self.0);
        }
    }

    struct Fakes;

    impl Members for Fakes {
        type Fd = Handle;

        fn poll(fd: &Handle) -> c_int {
            fake_poll(fd.0)
        }
        fn host_fd(fd: &Handle) -> c_int {
            fake_host_fd(fd.0)
        }
        fn host_events(fd: &Handle) -> c_short {
            fake_host_events(fd.0)
        }
        fn host_fixup(fd: &Handle, revents: c_short) -> c_int {
            fake_host_fixup(fd.0, revents)
        }
        fn is_socket(fd: &Handle) -> bool {
            fake_is_socket(fd.0)
        }
        fn map_errno() -> c_int {
            fake_map_errno()
        }
        fn begin_listen_wait() {
            fake_begin_listen_wait();
        }
        fn end_listen_wait() {
            fake_end_listen_wait();
        }
        fn should_restart_listen_wait() -> bool {
            fake_should_restart()
        }
    }

    struct Collected(Vec<(c_int, u64)>);

    /// Held by every test that adds a member, because adding one moves
    /// [`RETAINED`] and one of them asserts on its value.
    fn retain_serial() -> std::sync::MutexGuard<'static, ()> {
        static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn set() -> PollSet<Fakes> {
        PollSet::new(8 | 16)
    }

    fn collected(set: &mut PollSet<Fakes>) -> Vec<(c_int, u64)> {
        let mut out = Collected(Vec::new());
        set.scan(|types, info| {
            out.0.push((types, info));
            1
        });
        out.0
    }

    /// A pipe whose read end can be made readable on demand.
    struct Pipe(std::os::fd::OwnedFd, std::os::fd::OwnedFd);
    impl Pipe {
        fn new() -> Pipe {
            let (read, write) = rustix::pipe::pipe().unwrap();
            Pipe(read, write)
        }
        fn fill(&self) {
            assert_eq!(rustix::io::write(&self.1, &[0]), Ok(1));
        }
        fn read_end(&self) -> c_int {
            std::os::fd::AsRawFd::as_raw_fd(&self.0)
        }
    }

    #[test]
    fn a_member_without_a_host_descriptor_answers_through_its_own_poll() {
        let _serial = retain_serial();
        let mut fake = Fake {
            host: -1,
            types: 1,
            socket: false,
        };
        let waiters = Arc::new(Watchers::default());
        let mut set = set();
        assert_eq!(set.add(Handle::new(&raw mut fake), Arc::clone(&waiters), 1, 42), 0);
        assert_eq!(collected(&mut set), vec![(1, 42)]);
    }

    #[test]
    fn one_host_call_answers_for_every_host_backed_member() {
        let _serial = retain_serial();
        let first = Pipe::new();
        let second = Pipe::new();
        first.fill();
        let mut ready = Fake {
            host: first.read_end(),
            types: 0,
            socket: false,
        };
        let mut quiet = Fake {
            host: second.read_end(),
            types: 0,
            socket: false,
        };
        let waiters = Arc::new(Watchers::default());
        let mut set = set();
        assert_eq!(set.add(Handle::new(&raw mut ready), Arc::clone(&waiters), 1, 1), 0);
        assert_eq!(set.add(Handle::new(&raw mut quiet), Arc::clone(&waiters), 1, 2), 0);
        assert_eq!(collected(&mut set), vec![(1, 1)]);
    }

    /// The host answering "nothing" is not the same as the descriptor being
    /// quiet: an epoll set whose ready queue was filled by a member with no
    /// host descriptor has nothing for the host to report.
    #[test]
    fn a_quiet_host_descriptor_still_asks_the_description_itself() {
        let _serial = retain_serial();
        let pipe = Pipe::new();
        let mut fake = Fake {
            host: pipe.read_end(),
            types: 1,
            socket: false,
        };
        let waiters = Arc::new(Watchers::default());
        let mut set = set();
        assert_eq!(set.add(Handle::new(&raw mut fake), Arc::clone(&waiters), 1, 7), 0);
        assert_eq!(collected(&mut set), vec![(1, 7)]);
    }

    #[test]
    fn a_member_hears_only_about_what_it_asked_for_plus_err_and_hup() {
        let _serial = retain_serial();
        let mut asked = Fake {
            host: -1,
            types: 1 | 4,
            socket: false,
        };
        let mut unasked = Fake {
            host: -1,
            types: 4,
            socket: false,
        };
        let mut hup = Fake {
            host: -1,
            types: 16,
            socket: false,
        };
        let waiters = Arc::new(Watchers::default());
        let mut set = set();
        assert_eq!(set.add(Handle::new(&raw mut asked), Arc::clone(&waiters), 1, 1), 0);
        assert_eq!(set.add(Handle::new(&raw mut unasked), Arc::clone(&waiters), 1, 2), 0);
        assert_eq!(set.add(Handle::new(&raw mut hup), Arc::clone(&waiters), 1, 3), 0);
        assert_eq!(collected(&mut set), vec![(1, 1), (16, 3)]);
    }

    #[test]
    fn the_set_holds_a_reference_to_every_member_until_it_is_dropped() {
        // RETAINED is process-wide -- fd_retain is a C ABI stub and there is
        // one of it -- and cargo runs the tests in this binary on several
        // threads. So `store(0)` then `load() == 1` raced every other test that
        // adds a member, and this failed about one run in twenty while passing
        // every time it was run alone. Counting a global is only a measurement
        // if nothing else is counting at the same time.
        let _serial = retain_serial();
        RETAINED.store(0, Ordering::SeqCst);
        let mut fake = Fake {
            host: -1,
            types: 0,
            socket: false,
        };
        let waiters = Arc::new(Watchers::default());
        {
            let mut set = set();
            assert_eq!(set.add(Handle::new(&raw mut fake), Arc::clone(&waiters), 1, 1), 0);
            assert_eq!(RETAINED.load(Ordering::SeqCst), 1);
            assert_eq!(waiters.waiters(), 1);
        }
        assert_eq!(RETAINED.load(Ordering::SeqCst), 0);
        assert_eq!(waiters.waiters(), 0);
    }

    #[test]
    fn a_wake_ends_a_blocking_wait_that_no_member_would_have_ended() {
        let _serial = retain_serial();
        let mut fake = Fake {
            host: -1,
            types: 0,
            socket: false,
        };
        let waiters = Arc::new(Watchers::default());
        let mut set = set();
        assert_eq!(set.add(Handle::new(&raw mut fake), Arc::clone(&waiters), 1, 1), 0);
        assert_eq!(set.acquire(), 0);
        assert!(collected(&mut set).is_empty());
        waiters.notify(1);
        let mut errno = 0;
        assert_eq!(set.block(5000, &mut errno), 1);
        set.drain();
        set.release();
    }

    #[test]
    fn a_wait_with_nothing_to_wait_for_times_out() {
        let mut set = set();
        assert_eq!(set.acquire(), 0);
        assert!(collected(&mut set).is_empty());
        let mut errno = 0;
        assert_eq!(set.block(0, &mut errno), 0);
        set.release();
    }

    #[test]
    fn the_listen_wait_bracket_is_taken_once_per_wait_not_once_per_socket() {
        let _serial = retain_serial();
        LISTEN_WAITS.store(0, Ordering::SeqCst);
        let mut first = Fake {
            host: -1,
            types: 0,
            socket: true,
        };
        let mut second = Fake {
            host: -1,
            types: 0,
            socket: true,
        };
        let waiters = Arc::new(Watchers::default());
        let mut set = set();
        assert_eq!(set.add(Handle::new(&raw mut first), Arc::clone(&waiters), 1, 1), 0);
        assert_eq!(set.add(Handle::new(&raw mut second), Arc::clone(&waiters), 1, 2), 0);
        assert!(set.has_socket());
        assert_eq!(set.acquire(), 0);
        collected(&mut set);
        let mut errno = 0;
        set.block(0, &mut errno);
        assert_eq!(LISTEN_WAITS.load(Ordering::SeqCst), 0);
        set.release();
    }
}
