//! Does a `read` into memory the caller cannot write destroy what was queued?
//!
//! # One question, seven subjects
//!
//! Every descriptor whose read *consumes* has the same hazard: the kernel takes
//! the data out of its queue, fails to copy it to the caller, and answers
//! `EFAULT`. Whether the data is still there afterwards is not something a
//! man page says, it is a decision each driver makes, and getting it wrong
//! silently loses a byte the caller can never ask for again.
//!
//! This kernel bounces every read through a host buffer and copies to the guest
//! *after* the driver has been called, so the answer here is structural rather
//! than per-driver — which is exactly why it is worth asking of seven drivers at
//! once. `fs_conformance` is the same shape: one set of assertions against three
//! unrelated implementations, where a difference between them is the finding.
//!
//! A partially mapped buffer is asked about too, because it is a different
//! question with a different answer: there, some of the data *can* be delivered,
//! and a kernel may report the short count instead of refusing.
//!
//! # How "is it still there" is asked
//!
//! With `poll`, which consumes nothing. Reading again to find out would answer
//! the question and destroy the evidence at the same time for any case where
//! the answer is "yes, partly".

use std::io::Write;

fn say(what: &str, s: String) {
    println!("  {what:<52} {s}");
    let _ = std::io::stdout().flush();
}

fn errname(e: i32) -> String {
    match e {
        1 => "EPERM", 4 => "EINTR", 9 => "EBADF", 11 => "EAGAIN", 14 => "EFAULT",
        22 => "EINVAL", 29 => "ESPIPE",
        _ => return format!("errno {e}"),
    }
    .into()
}

/// The result of a `read`, as a word: a count, or the errno.
fn rd(fd: i32, buf: *mut u8, len: usize) -> String {
    let n = unsafe { libc::read(fd, buf.cast(), len) };
    if n < 0 {
        format!("-{}", errname(unsafe { *libc::__errno_location() }))
    } else {
        n.to_string()
    }
}

fn pending(fd: i32) -> bool {
    let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    unsafe { libc::poll(&mut pfd, 1, 0) == 1 && pfd.revents & libc::POLLIN != 0 }
}

/// Two pages, of which only the first is mapped: writing across the boundary
/// delivers something and then faults.
///
/// Reserved as one four-page span and then cut, so the hole is certain. A
/// separate `mmap` for each half can be placed anywhere.
fn split_buffer() -> *mut u8 {
    unsafe {
        let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let span = libc::mmap(
            std::ptr::null_mut(),
            page * 4,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert!(span != libc::MAP_FAILED);
        // Drop the second page, leaving the first mapped and what follows it not.
        assert_eq!(libc::munmap(span.byte_add(page), page), 0);
        span.cast()
    }
}

/// One subject: arrange something to read, then ask the three questions.
///
/// `arrange` puts exactly one item in the queue and is called again before the
/// partial case, because the first case may have consumed it — which is the
/// finding, so it cannot be assumed either way.
fn subject(name: &str, fd: i32, item_len: usize, mut arrange: impl FnMut()) {
    println!("## {name}");
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    let mut good = vec![0u8; page * 2];

    // Empty before each arrangement, so a phase reports on what that phase put
    // there. Without it the second phase inherits whatever the first left, which
    // is *itself* the thing under test — and the two sides then differ about a
    // residue rather than about the question. It read as a second finding.
    let drain = |fd: i32| {
        let mut sink = vec![0u8; page * 2];
        while unsafe { libc::read(fd, sink.as_mut_ptr().cast(), page * 2) } > 0 {}
    };

    // Every line names its subject, so an allowlist entry in
    // `tests/integration/probe_diff.sh` can be about one descriptor type. The
    // first version printed "still pending" seven times and one entry would have
    // covered all seven, which is exactly what an allowlist must not do.
    let line = |what: &str| format!("{name}: {what}");

    drain(fd);
    arrange();
    say(&line("something is pending"), format!("{}", pending(fd)));
    // 0x10 is a legal user address and an unmapped one, so `access_ok` passes
    // and the copy is what fails -- which is the case Linux's drivers differ on.
    say(&line("read into an unmapped buffer"), rd(fd, 0x10 as *mut u8, item_len.max(64)));
    say(&line("  still pending"), format!("{}", pending(fd)));
    say(&line("read into a good buffer"), rd(fd, good.as_mut_ptr(), page * 2));

    // The partial case: the read is asked for more than one page, the first
    // page is writable and the second is not, and the item is small enough to
    // fit in what is writable. A kernel that checks the whole span up front
    // refuses; one that copies until it faults delivers.
    drain(fd);
    arrange();
    let split = split_buffer();
    say(&line("something is pending again"), format!("{}", pending(fd)));
    say(&line("read across a mapped/unmapped boundary"), rd(fd, split, page * 2));
    say(&line("  still pending after that"), format!("{}", pending(fd)));
    say(&line("read into a good buffer after that"), rd(fd, good.as_mut_ptr(), page * 2));
    unsafe { libc::munmap(split.cast(), page) };
}

fn main() {
    println!("## a read whose destination cannot be written");

    // A pipe. The one subject where Linux is documented to deliver a partial
    // count, because a pipe read is a copy out of pages it already holds.
    unsafe {
        let mut fds = [0i32; 2];
        assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
        libc::fcntl(fds[0], libc::F_SETFL, libc::O_NONBLOCK);
        subject("pipe", fds[0], 8, || {
            let msg = b"12345678";
            libc::write(fds[1], msg.as_ptr().cast(), 8);
        });
        libc::close(fds[0]);
        libc::close(fds[1]);
    }

    // An eventfd. Eight bytes and a counter, so "still pending" and "the value
    // survived" are the same question.
    unsafe {
        let fd = libc::eventfd(0, libc::EFD_NONBLOCK);
        subject("eventfd", fd, 8, || {
            let v: u64 = 7;
            libc::write(fd, (&raw const v).cast(), 8);
        });
        // What the counter is *now* is the other half: a lost read of an
        // eventfd loses a count that no later read can recover.
        let mut v = [0u8; 8];
        say("eventfd: the counter afterwards", rd(fd, v.as_mut_ptr(), 8));
        libc::close(fd);
    }

    // A signalfd, whose record is 128 bytes: big enough that a partial copy
    // across a page boundary is a *torn* record rather than a short one.
    unsafe {
        let mut mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, libc::SIGUSR1);
        libc::sigprocmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut());
        let fd = libc::signalfd(-1, &mask, libc::SFD_NONBLOCK);
        let me = libc::getpid();
        subject("signalfd", fd, 128, || {
            libc::kill(me, libc::SIGUSR1);
        });
        libc::close(fd);
        libc::sigprocmask(libc::SIG_UNBLOCK, &mask, std::ptr::null_mut());
    }

    // A unix socket, which is a queue of datagrams: a lost read loses a whole
    // message rather than some bytes.
    unsafe {
        let mut fds = [0i32; 2];
        assert_eq!(
            libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()),
            0
        );
        libc::fcntl(fds[0], libc::F_SETFL, libc::O_NONBLOCK);
        subject("unix datagram socket", fds[0], 8, || {
            let msg = b"12345678";
            libc::write(fds[1], msg.as_ptr().cast(), 8);
        });
        libc::close(fds[0]);
        libc::close(fds[1]);
    }

    // An inotify instance. The record is variable-length and self-describing,
    // so a torn one cannot be walked at all.
    unsafe {
        let dir = c"/tmp/faultread-inotify";
        libc::mkdir(dir.as_ptr(), 0o755);
        let fd = libc::inotify_init1(libc::IN_NONBLOCK);
        // IN_CREATE alone, not IN_ALL_EVENTS. Creating a file with `open` is
        // three events on a real kernel — create, open, close-write — and this
        // probe is about what survives a fault, not about how many events a
        // create is. Watching for one of them makes each arrangement exactly one
        // record, which is what `subject` promises.
        libc::inotify_add_watch(fd, dir.as_ptr(), libc::IN_CREATE);
        let mut n = 0;
        subject("inotify", fd, 32, || {
            n += 1;
            let path = std::ffi::CString::new(format!(
                "/tmp/faultread-inotify/f{n}"
            ))
            .unwrap();
            let f = libc::open(path.as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o644);
            if f >= 0 {
                libc::close(f);
            }
        });
        libc::close(fd);
        let _ = std::fs::remove_dir_all("/tmp/faultread-inotify");
    }

    // Which argument is judged first. A kernel that checks the destination
    // before the descriptor answers EFAULT for a call whose real problem is the
    // descriptor, and sends the caller looking in the wrong place --
    // `table_probe` found nineteen syscalls doing exactly that.
    println!("## which argument is judged first");
    unsafe {
        say("read(-1, unmapped, 64)", rd(-1, 0x10 as *mut u8, 64));
        let f = libc::open(c"/tmp".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
        say("read(a directory, unmapped, 64)", rd(f, 0x10 as *mut u8, 64));
        libc::close(f);
        say("read(a closed descriptor, unmapped, 64)", rd(f, 0x10 as *mut u8, 64));
        // A zero-length read never touches the buffer, so a bad one is not an
        // error -- on either side, and for a bad descriptor it is still EBADF.
        say("read(-1, unmapped, 0)", rd(-1, 0x10 as *mut u8, 0));
        let mut fds = [0i32; 2];
        libc::pipe(fds.as_mut_ptr());
        libc::fcntl(fds[0], libc::F_SETFL, libc::O_NONBLOCK);
        say("read(an empty pipe, unmapped, 0)", rd(fds[0], 0x10 as *mut u8, 0));
        say("read(an empty pipe, unmapped, 64)", rd(fds[0], 0x10 as *mut u8, 64));
        // An address above the address space aliases rather than faulting, so
        // it has to be refused by arithmetic before any page is looked at.
        say("read(an empty pipe, 1 << 60, 64)", rd(fds[0], (1u64 << 60) as *mut u8, 64));
        // Readable but not writable is a fault for a *read*: the direction is
        // half the question and a check that only asks "is it mapped" passes.
        let ro = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        let msg = b"12345678";
        libc::write(fds[1], msg.as_ptr().cast(), 8);
        say("read(a pipe, a read-only page, 64)", rd(fds[0], ro.cast(), 64));
        say("  still pending", format!("{}", pending(fds[0])));
        libc::munmap(ro, 4096);
        libc::close(fds[0]);
        libc::close(fds[1]);
    }

    // The blocking form of the same question, which is where the two kernels
    // can legitimately part: Linux waits for data before it copies, so a
    // blocking read into an unwritable buffer does not answer until there is
    // something to fault on. In a child with an alarm, because the right answer
    // may be "it never returns".
    unsafe {
        let mut fds = [0i32; 2];
        libc::pipe(fds.as_mut_ptr());
        let pid = libc::fork();
        if pid == 0 {
            libc::alarm(1);
            let n = libc::read(fds[0], 0x10 as *mut libc::c_void, 64);
            let e = if n < 0 { *libc::__errno_location() } else { 0 };
            libc::_exit(if n < 0 { e } else { 100 });
        }
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
        let how = if libc::WIFSIGNALED(st) {
            "blocked (alarmed)".to_string()
        } else {
            let c = libc::WEXITSTATUS(st);
            if c == 100 { "0".into() } else { format!("-{}", errname(c)) }
        };
        say("blocking read(an empty pipe, unmapped, 64)", how);
        libc::close(fds[0]);
        libc::close(fds[1]);
    }

    // A regular file, for the contrast: nothing is consumed, so the only
    // question is what the offset does.
    unsafe {
        let path = c"/tmp/faultread-file";
        let f = libc::open(path.as_ptr(), libc::O_CREAT | libc::O_RDWR | libc::O_TRUNC, 0o644);
        let data = [b'x'; 64];
        libc::write(f, data.as_ptr().cast(), 64);
        libc::lseek(f, 0, libc::SEEK_SET);
        println!("## regular file");
        say("read into an unmapped buffer", rd(f, 0x10 as *mut u8, 64));
        say("  the offset afterwards", libc::lseek(f, 0, libc::SEEK_CUR).to_string());
        let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let split = split_buffer();
        libc::lseek(f, 0, libc::SEEK_SET);
        say("read across a mapped/unmapped boundary", rd(f, split, page * 2));
        say("  the offset afterwards", libc::lseek(f, 0, libc::SEEK_CUR).to_string());
        libc::munmap(split.cast(), page);
        libc::close(f);
        libc::unlink(path.as_ptr());
    }
}
