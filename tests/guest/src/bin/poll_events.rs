//! The event bits a guest may ask for that are not `POLLIN`/`POLLOUT`.
//!
//! `fs/poll.h`'s `POLL_*` are the guest's own values used directly, so there is
//! no translation step — and no place where an unknown bit is noticed either.
//! `POLLRDNORM` is what a `poll()` caller gets from many libraries, and
//! `EPOLLRDHUP` is how a server sees a half-close.

use guest_tests::{Harness, check};

const POLLRDNORM: i16 = 0x040;
const POLLWRNORM: i16 = 0x100;
const EPOLLRDHUP: u32 = 0x2000;

fn main() {
    let mut h = Harness::new();

    // A pipe with a byte in it: the read end is readable, the write end is
    // writable. Nothing here depends on timing.
    let mut fds = [0i32; 2];
    unsafe { libc::pipe(fds.as_mut_ptr()) };
    let (r, w) = (fds[0], fds[1]);
    unsafe { libc::write(w, b"x".as_ptr().cast(), 1) };

    h.group("pollrdnorm");
    // The control first: POLLIN sees it.
    let mut p = libc::pollfd { fd: r, events: libc::POLLIN, revents: 0 };
    let n = unsafe { libc::poll(&mut p, 1, 0) };
    check!(h, n == 1 && (p.revents & libc::POLLIN) != 0,
        "control: POLLIN sees a readable pipe: n={n} revents={:#x}", p.revents);

    h.group("duplicate pollfd entries");
    // The host wait is merged by open-file description, but poll's result is
    // the number of array entries with nonzero revents. Both entries therefore
    // count even though one readiness check can fill them together.
    let mut duplicate = [
        libc::pollfd { fd: r, events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: r, events: libc::POLLIN, revents: 0 },
    ];
    let n = unsafe { libc::poll(duplicate.as_mut_ptr(), duplicate.len() as _, 0) };
    check!(h, n == 2,
        "two ready entries count twice even for one description: n={n} revents={:#x}/{:#x}",
        duplicate[0].revents, duplicate[1].revents);
    check!(h, duplicate.iter().all(|p| p.revents & libc::POLLIN != 0),
        "both duplicate entries report POLLIN: revents={:#x}/{:#x}",
        duplicate[0].revents, duplicate[1].revents);

    // POSIX has POLLRDNORM as "normal data may be read", which for a pipe is
    // the same condition as POLLIN. Linux reports both.
    let mut p = libc::pollfd { fd: r, events: POLLRDNORM, revents: 0 };
    let n = unsafe { libc::poll(&mut p, 1, 0) };
    check!(h, n == 1 && (p.revents & POLLRDNORM) != 0,
        "POLLRDNORM sees a readable pipe: n={n} revents={:#x}", p.revents);

    let mut p = libc::pollfd { fd: w, events: POLLWRNORM, revents: 0 };
    let n = unsafe { libc::poll(&mut p, 1, 0) };
    check!(h, n == 1 && (p.revents & POLLWRNORM) != 0,
        "POLLWRNORM sees a writable pipe: n={n} revents={:#x}", p.revents);

    // And asking for POLLIN must still report POLLIN, not only RDNORM.
    let mut p = libc::pollfd { fd: r, events: libc::POLLIN | POLLRDNORM, revents: 0 };
    let n = unsafe { libc::poll(&mut p, 1, 0) };
    check!(h, n == 1 && (p.revents & libc::POLLIN) != 0,
        "asking for both still reports POLLIN: n={n} revents={:#x}", p.revents);

    h.group("pollrdnorm-on-a-mount-that-answers-for-itself");
    // A pty is not backed by a host descriptor, so its readiness comes from
    // `fd->ops->poll` rather than from the batched host poll. The two paths
    // apply the aliases separately and a test that only uses pipes and sockets
    // covers neither of them twice.
    // O_NOCTTY: a session leader with no controlling terminal acquires one
    // by opening a pty, and closing that pty then hangs up its own session.
    // The emulator's pid 1 is such a leader; in a container this program is
    // not, so without the flag the two environments disagree about whether
    // the test survives its own cleanup.
    let master = unsafe {
        libc::open(guest_tests::cpath("/dev/ptmx").as_ptr(), libc::O_RDWR | libc::O_NOCTTY)
    };
    check!(h, master >= 0, "opening a pty master");
    if master >= 0 {
        unsafe {
            libc::grantpt(master);
            libc::unlockpt(master);
        }
        let name = unsafe { libc::ptsname(master) };
        let slave = if name.is_null() {
            -1
        } else {
            let path = unsafe { std::ffi::CStr::from_ptr(name) }.to_string_lossy().into_owned();
            unsafe { libc::open(guest_tests::cpath(&path).as_ptr(), libc::O_RDWR | libc::O_NOCTTY) }
        };
        check!(h, slave >= 0, "opening the pty slave");
        if slave >= 0 {
            unsafe { libc::write(slave, b"x".as_ptr().cast(), 1) };
            std::thread::sleep(std::time::Duration::from_millis(50));
            let mut p = libc::pollfd { fd: master, events: POLLRDNORM, revents: 0 };
            let n = unsafe { libc::poll(&mut p, 1, 200) };
            check!(h, n == 1 && (p.revents & POLLRDNORM) != 0,
                "POLLRDNORM sees a readable pty master: n={n} revents={:#x}", p.revents);
            unsafe { libc::close(slave) };
        }
        unsafe { libc::close(master) };
    }

    h.group("epollrdhup");
    // A socketpair, so one side can shut down for writing.
    let mut sv = [0i32; 2];
    let ok = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
    check!(h, ok == 0, "a socketpair");
    if ok == 0 {
        let ep = unsafe { libc::epoll_create1(0) };
        check!(h, ep >= 0, "epoll_create1");
        let mut ev = libc::epoll_event { events: libc::EPOLLIN as u32 | EPOLLRDHUP, u64: 7 };
        let r2 = unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, sv[0], &mut ev) };
        check!(h, r2 == 0, "epoll_ctl ADD with EPOLLRDHUP is accepted: r={r2}");

        // The peer half-closes. Linux reports EPOLLRDHUP without EPOLLHUP,
        // because the local end can still write.
        unsafe { libc::shutdown(sv[1], libc::SHUT_WR) };
        let mut out = [libc::epoll_event { events: 0, u64: 0 }; 4];
        let n = unsafe { libc::epoll_wait(ep, out.as_mut_ptr(), 4, 200) };
        check!(h, n >= 1, "epoll_wait reports the half-close at all: n={n}");
        if n >= 1 {
            check!(h, (out[0].events & EPOLLRDHUP) != 0,
                "and reports it as EPOLLRDHUP: events={:#x}", out[0].events);
            check!(h, (out[0].events & libc::EPOLLHUP as u32) == 0,
                "a peer half-close is not a full EPOLLHUP: events={:#x}", out[0].events);
        }
        unsafe { libc::close(ep); }

        let ep = unsafe { libc::epoll_create1(0) };
        let mut only_rdhup = libc::epoll_event { events: EPOLLRDHUP, u64: 8 };
        let r3 = unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, sv[0], &mut only_rdhup) };
        check!(h, r3 == 0, "EPOLLRDHUP-only registration is accepted: r={r3}");
        let mut only_out = [libc::epoll_event { events: 0, u64: 0 }; 1];
        let only_n = unsafe { libc::epoll_wait(ep, only_out.as_mut_ptr(), 1, 200) };
        check!(h, only_n == 1 && (only_out[0].events & EPOLLRDHUP) != 0,
            "EPOLLRDHUP alone installs the host read-side watch: n={only_n} events={:#x}",
            only_out[0].events);
        unsafe { libc::close(ep); }

        // And a caller that did *not* ask for EPOLLRDHUP must not be given it:
        // Linux reports it only on request, because a program that does not
        // know the bit would not know what to do with it.
        let mut sv2 = [0i32; 2];
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv2.as_mut_ptr()) };
        let ep = unsafe { libc::epoll_create1(0) };
        let mut ev = libc::epoll_event { events: libc::EPOLLIN as u32, u64: 9 };
        unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, sv2[0], &mut ev) };
        unsafe { libc::shutdown(sv2[1], libc::SHUT_WR) };
        let mut out2 = [libc::epoll_event { events: 0, u64: 0 }; 4];
        let n2 = unsafe { libc::epoll_wait(ep, out2.as_mut_ptr(), 4, 200) };
        if n2 >= 1 {
            check!(h, (out2[0].events & EPOLLRDHUP) == 0,
                "a caller that did not ask for EPOLLRDHUP is not given it: events={:#x}",
                out2[0].events);
        } else {
            check!(h, false, "epoll_wait saw nothing for the control: n={n2}");
        }
        unsafe { libc::close(sv2[0]); libc::close(sv2[1]); }
        unsafe { libc::close(ep); libc::close(sv[0]); libc::close(sv[1]); }
    }

    unsafe { libc::close(r); libc::close(w); }
    std::process::exit(h.finish());
}
