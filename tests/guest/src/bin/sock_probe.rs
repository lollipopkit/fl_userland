//! What the socket syscalls answer at their edges.
//!
//! **A report, not a check.** One line per case, never fails, so the same
//! binary runs here and in an arm64 container and the two outputs are diffed.
//! `mmap_probe` found four differences that way, one of them dangerous.
//!
//! **Two differences recorded here as "known and not fixed" are gone**, and
//! nothing said so: `bind` with a `sun_path` that has no terminator in its 108
//! bytes, and `bind` with a `sun_family` that is not `AF_UNIX` on a unix
//! socket. Both were `ENAMETOOLONG`/`EAFNOSUPPORT` here against Linux's
//! `EINVAL`; both agree now, and the whole of this probe's output has been
//! byte-identical to an arm64 container's since 2026-09-14. A note saying a
//! difference is known tells the next reader not to look, so it has to come
//! out when the difference does — which is the shape CLAUDE.md records about
//! written-down blockers.
//!
//! `AF_UNIX` throughout: it is the family this kernel implements completely,
//! and it is the one a container answers for without a network namespace
//! getting in the way. A container's answer is the container's — see the
//! `clock_settime` note in CLAUDE.md — and `AF_INET` behind Docker's default
//! seccomp profile would be measuring the profile.

use std::mem::size_of;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn name(e: i32) -> String {
    let s = match e {
        0 => "-",
        libc::EINVAL => "EINVAL",
        libc::EAFNOSUPPORT => "EAFNOSUPPORT",
        libc::EPROTONOSUPPORT => "EPROTONOSUPPORT",
        libc::ESOCKTNOSUPPORT => "ESOCKTNOSUPPORT",
        libc::EPROTOTYPE => "EPROTOTYPE",
        libc::ENOPROTOOPT => "ENOPROTOOPT",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        libc::ENOTCONN => "ENOTCONN",
        libc::EISCONN => "EISCONN",
        libc::EADDRINUSE => "EADDRINUSE",
        libc::ENOENT => "ENOENT",
        libc::ECONNREFUSED => "ECONNREFUSED",
        libc::EBADF => "EBADF",
        libc::ENOTSOCK => "ENOTSOCK",
        libc::EFAULT => "EFAULT",
        libc::EDESTADDRREQ => "EDESTADDRREQ",
        libc::EPIPE => "EPIPE",
        libc::EAGAIN => "EAGAIN",
        libc::EINTR => "EINTR",
        libc::ENAMETOOLONG => "ENAMETOOLONG",
        libc::EACCES => "EACCES",
        libc::EMSGSIZE => "EMSGSIZE",
        _ => return format!("errno {e}"),
    };
    s.into()
}

fn report(what: &str, r: i64) {
    if r < 0 {
        println!("{what:<50} -> {}", name(errno()));
    } else {
        println!("{what:<50} -> ok");
    }
}

/// A `sockaddr_un` with `path` in it, and the length to pass.
fn unix_addr(path: &str) -> (libc::sockaddr_un, libc::socklen_t) {
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sa.sun_family = libc::AF_UNIX as u16;
    for (i, b) in path.bytes().enumerate() {
        sa.sun_path[i] = b as libc::c_char;
    }
    let len = (size_of::<u16>() + path.len() + 1) as libc::socklen_t;
    (sa, len)
}

/// A NUL-terminated copy of `path`, for the `libc::unlink` calls below.
fn cstr(path: &str) -> std::ffi::CString {
    std::ffi::CString::new(path).expect("no interior NUL")
}

fn socket(domain: i32, ty: i32, proto: i32) -> i64 {
    unsafe { libc::socket(domain, ty, proto) as i64 }
}

fn main() {
    let dir = "/tmp/sock_probe.d";
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).expect("mkdir");

    println!("## socket(domain, type, protocol)");
    report("socket(AF_UNIX, SOCK_STREAM, 0)", socket(libc::AF_UNIX, libc::SOCK_STREAM, 0));
    report("socket(AF_UNIX, SOCK_DGRAM, 0)", socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0));
    report(
        "socket(AF_UNIX, SOCK_SEQPACKET, 0)",
        socket(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0),
    );
    report("socket(AF_UNIX, SOCK_RAW, 0)", socket(libc::AF_UNIX, libc::SOCK_RAW, 0));
    report("socket(AF_UNIX, STREAM, proto=1)", socket(libc::AF_UNIX, libc::SOCK_STREAM, 1));
    report("socket(AF_UNIX, type=99, 0)", socket(libc::AF_UNIX, 99, 0));
    report("socket(domain=99, STREAM, 0)", socket(99, libc::SOCK_STREAM, 0));
    report("socket(domain=-1, STREAM, 0)", socket(-1, libc::SOCK_STREAM, 0));
    // The two type flags, and a bit that is neither.
    report(
        "socket(STREAM|NONBLOCK|CLOEXEC)",
        socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        ),
    );
    report(
        "socket(STREAM|0x1000000)",
        socket(libc::AF_UNIX, libc::SOCK_STREAM | 0x1000000, 0),
    );

    println!("## bind");
    let s = socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) as i32;
    let (sa, len) = unix_addr(&format!("{dir}/a"));
    report("bind(a)", unsafe {
        libc::bind(s, &sa as *const _ as *const _, len) as i64
    });
    report("bind(a) again on the same socket", unsafe {
        libc::bind(s, &sa as *const _ as *const _, len) as i64
    });
    let s2 = socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) as i32;
    report("bind(a) from another socket", unsafe {
        libc::bind(s2, &sa as *const _ as *const _, len) as i64
    });
    // Lengths.
    report("bind(len=0)", unsafe {
        libc::bind(s2, &sa as *const _ as *const _, 0) as i64
    });
    report("bind(len=1)", unsafe {
        libc::bind(s2, &sa as *const _ as *const _, 1) as i64
    });
    report("bind(len=2, family only)", unsafe {
        libc::bind(s2, &sa as *const _ as *const _, 2) as i64
    });
    report("bind(len=huge)", unsafe {
        libc::bind(s2, &sa as *const _ as *const _, 4096) as i64
    });
    report("bind(NULL)", unsafe {
        libc::bind(s2, std::ptr::null(), 16) as i64
    });
    // A path with no NUL in the whole 108 bytes.
    let mut full: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    full.sun_family = libc::AF_UNIX as u16;
    for i in 0..full.sun_path.len() {
        full.sun_path[i] = b'x' as libc::c_char;
    }
    // Its **own** socket. `s2` is bound by the time this runs, and a bind on an
    // already-bound socket is `EINVAL` whatever the address is -- so on a shared
    // socket this case measures the socket's state and not the address at all.
    report("bind(path with no terminator)", unsafe {
        let s = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        let r = libc::bind(
            s,
            &full as *const _ as *const _,
            size_of::<libc::sockaddr_un>() as libc::socklen_t,
        ) as i64;
        libc::close(s);
        // The bind creates a file, and a second run of this probe would answer
        // `EADDRINUSE` for it. `sun_path` is full, so the name is all 108
        // bytes and the C string needs its own terminator.
        let mut name = [b'x' as libc::c_char; 109];
        name[108] = 0;
        libc::unlink(name.as_ptr());
        r
    });
    // The same length, terminated: this is what says whether the case above is
    // about the missing terminator or simply about a long name.
    let mut longname: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    longname.sun_family = libc::AF_UNIX as u16;
    for i in 0..100 {
        longname.sun_path[i] = b'x' as libc::c_char;
    }
    report("bind(a 100-character path, terminated)", unsafe {
        let s = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        let r = libc::bind(
            s,
            &longname as *const _ as *const _,
            size_of::<libc::sockaddr_un>() as libc::socklen_t,
        ) as i64;
        libc::close(s);
        libc::unlink(longname.sun_path.as_ptr());
        r
    });
    // Family that is not AF_UNIX on a unix socket. Its own socket too, for the
    // reason above.
    let mut wrong = sa;
    wrong.sun_family = libc::AF_INET as u16;
    report("bind(family=AF_INET on a unix socket)", unsafe {
        libc::bind(s2, &wrong as *const _ as *const _, len) as i64
    });

    // ------------------------------------------------------------------
    // A second bind, which is two different orders in the two namespaces
    // ------------------------------------------------------------------
    //
    // Linux's `unix_bind_bsd` creates the node **first** and maps the `EEXIST`
    // from a path that is already there to `EADDRINUSE`, then takes the
    // socket's `bindlock` and refuses an already-bound socket with `EINVAL`,
    // unlinking what it made. `unix_bind_abstract` and `unix_autobind` take
    // the lock **first**, so for them the socket's state is what decides.
    //
    // So "a bind on an already-bound socket is EINVAL whatever the address is"
    // -- which is what the note above says -- is true of the abstract
    // namespace and not of the filesystem one. These cases are what says which
    // is which, and the `## bind` section above measures only one of them.
    println!("## bind on a socket that already has a name");
    let held = format!("{dir}/held");
    let free = format!("{dir}/free");
    let taken = format!("{dir}/taken");
    let bound = unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        let (a, l) = unix_addr(&held);
        libc::bind(fd, &a as *const _ as *const _, l);
        fd
    };
    let holder = unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        let (a, l) = unix_addr(&taken);
        libc::bind(fd, &a as *const _ as *const _, l);
        fd
    };
    let (freea, freel) = unix_addr(&free);
    report("path: bind(a free path) when already bound", unsafe {
        libc::bind(bound, &freea as *const _ as *const _, freel) as i64
    });
    // Whether the refused call left a socket node behind. Linux creates one
    // and unlinks it again, so there is nothing there either way -- which is
    // the observable this reports, not the window.
    println!(
        "{:<50} -> {}",
        "  ...and the free path now exists",
        std::path::Path::new(&free).exists()
    );
    let (takena, takenl) = unix_addr(&taken);
    report("path: bind(a taken path) when already bound", unsafe {
        libc::bind(bound, &takena as *const _ as *const _, takenl) as i64
    });
    let (helda, heldl) = unix_addr(&held);
    report("path: bind(the same path) when already bound", unsafe {
        libc::bind(bound, &helda as *const _ as *const _, heldl) as i64
    });
    report("path: autobind when already bound", unsafe {
        let mut any: libc::sockaddr_un = std::mem::zeroed();
        any.sun_family = libc::AF_UNIX as u16;
        libc::bind(bound, &any as *const _ as *const _, 2) as i64
    });

    // The abstract namespace. The names are global to a network namespace on
    // Linux and per-process here, so they are picked not to collide.
    let abs = |n: &str| {
        let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        sa.sun_family = libc::AF_UNIX as u16;
        let bytes = n.as_bytes();
        for (i, b) in bytes.iter().enumerate() {
            sa.sun_path[i + 1] = *b as libc::c_char;
        }
        (sa, (size_of::<u16>() + 1 + bytes.len()) as libc::socklen_t)
    };
    let (ah, ahl) = abs("shellbox-probe-held");
    let (af, afl) = abs("shellbox-probe-free");
    let (at, atl) = abs("shellbox-probe-taken");
    let abound = unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        libc::bind(fd, &ah as *const _ as *const _, ahl);
        fd
    };
    let aholder = unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        libc::bind(fd, &at as *const _ as *const _, atl);
        fd
    };
    report("abstract: bind(a free name) when already bound", unsafe {
        libc::bind(abound, &af as *const _ as *const _, afl) as i64
    });
    report("abstract: bind(a taken name) when already bound", unsafe {
        libc::bind(abound, &at as *const _ as *const _, atl) as i64
    });
    report("abstract: bind(the same name) when already bound", unsafe {
        libc::bind(abound, &ah as *const _ as *const _, ahl) as i64
    });
    report("abstract: autobind when already bound", unsafe {
        let mut any: libc::sockaddr_un = std::mem::zeroed();
        any.sun_family = libc::AF_UNIX as u16;
        libc::bind(abound, &any as *const _ as *const _, 2) as i64
    });
    // Whether the names the refused calls named are free once every socket
    // above is closed. A refusal that claimed a name anyway leaves it taken
    // for the life of the process, which nothing else here can see.
    unsafe {
        libc::close(abound);
        libc::close(aholder);
        libc::close(bound);
        libc::close(holder);
        libc::unlink(cstr(&held).as_ptr());
        libc::unlink(cstr(&taken).as_ptr());
        libc::unlink(cstr(&free).as_ptr());
    }
    for (what, (sa, l)) in [
        ("the name it held", (ah, ahl)),
        ("the free name it was refused", (af, afl)),
        ("the taken name it was refused", (at, atl)),
    ] {
        report(&format!("abstract: rebind {what} after every close"), unsafe {
            let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
            let r = libc::bind(fd, &sa as *const _ as *const _, l) as i64;
            libc::close(fd);
            r
        });
    }

    println!("## listen");
    report("listen(backlog=0)", unsafe { libc::listen(s, 0) as i64 });
    report("listen(backlog=-1)", unsafe { libc::listen(s, -1) as i64 });
    report("listen(backlog=huge)", unsafe {
        libc::listen(s, 1 << 30) as i64
    });
    let dgram = socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) as i32;
    let (dsa, dlen) = unix_addr(&format!("{dir}/d"));
    unsafe { libc::bind(dgram, &dsa as *const _ as *const _, dlen) };
    report("listen(on a datagram socket)", unsafe {
        libc::listen(dgram, 5) as i64
    });
    let unbound = socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) as i32;
    report("listen(unbound)", unsafe { libc::listen(unbound, 5) as i64 });

    println!("## connect");
    let c = socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) as i32;
    let (nosa, nolen) = unix_addr(&format!("{dir}/nothing"));
    report("connect(a name nothing is bound to)", unsafe {
        libc::connect(c, &nosa as *const _ as *const _, nolen) as i64
    });
    report("connect(a listening socket)", unsafe {
        libc::connect(c, &sa as *const _ as *const _, len) as i64
    });
    report("connect(again, already connected)", unsafe {
        libc::connect(c, &sa as *const _ as *const _, len) as i64
    });
    // What a client knows about its peer *before* anyone accepts: Linux
    // copies the listener's credentials and address onto the client at
    // connect, so SO_PEERCRED and getpeername answer straight away. The
    // listener is this process.
    {
        let mut cred = [0i32; 3];
        let mut clen = 12 as libc::socklen_t;
        let r = unsafe {
            libc::getsockopt(
                c,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                cred.as_mut_ptr().cast(),
                &mut clen,
            )
        };
        report("getsockopt(SO_PEERCRED) before accept", r as i64);
        println!("{:<50} -> {}", "  pid is the listener's", cred[0] == unsafe { libc::getpid() });
        println!("{:<50} -> {}", "  uid is the listener's", cred[1] as u32 == unsafe { libc::getuid() });
        let mut peer: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        let mut plen = size_of::<libc::sockaddr_un>() as libc::socklen_t;
        let r = unsafe { libc::getpeername(c, &mut peer as *mut _ as *mut _, &mut plen) };
        report("getpeername before accept", r as i64);
        let path: Vec<u8> = peer.sun_path.iter().take_while(|&&b| b != 0).map(|&b| b as u8).collect();
        let bound: Vec<u8> = sa.sun_path.iter().take_while(|&&b| b != 0).map(|&b| b as u8).collect();
        println!("{:<50} -> {}", "  the path is the one connected to", path == bound);
        println!("{:<50} -> {}", "  the length is the name's", plen as usize == 2 + bound.len() + 1);
    }
    let c2 = socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) as i32;
    report("connect(to a datagram name from a stream)", unsafe {
        libc::connect(c2, &dsa as *const _ as *const _, dlen) as i64
    });

    println!("## shutdown");
    report("shutdown(SHUT_RD)", unsafe {
        libc::shutdown(c, libc::SHUT_RD) as i64
    });
    report("shutdown(SHUT_RDWR)", unsafe {
        libc::shutdown(c, libc::SHUT_RDWR) as i64
    });
    report("shutdown(how=99)", unsafe { libc::shutdown(c, 99) as i64 });
    report("shutdown(how=-1)", unsafe { libc::shutdown(c, -1) as i64 });
    let never = socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) as i32;
    report("shutdown(never connected)", unsafe {
        libc::shutdown(never, libc::SHUT_RDWR) as i64
    });

    println!("## sockopt");
    let mut val = 0i32;
    let mut olen = size_of::<i32>() as libc::socklen_t;
    report("getsockopt(SO_TYPE)", unsafe {
        libc::getsockopt(
            s,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut val as *mut _ as *mut _,
            &mut olen,
        ) as i64
    });
    println!("{:<50} -> {}", "  SO_TYPE value is SOCK_STREAM", val == libc::SOCK_STREAM);
    report("getsockopt(level=99)", unsafe {
        libc::getsockopt(s, 99, 1, &mut val as *mut _ as *mut _, &mut olen) as i64
    });
    report("getsockopt(SOL_SOCKET, optname=9999)", unsafe {
        libc::getsockopt(
            s,
            libc::SOL_SOCKET,
            9999,
            &mut val as *mut _ as *mut _,
            &mut olen,
        ) as i64
    });
    let mut zero = 0 as libc::socklen_t;
    report("getsockopt(SO_TYPE, len=0)", unsafe {
        libc::getsockopt(
            s,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut val as *mut _ as *mut _,
            &mut zero,
        ) as i64
    });
    let one = 1i32;
    report("setsockopt(SO_REUSEADDR, 1)", unsafe {
        libc::setsockopt(
            s,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const _,
            size_of::<i32>() as libc::socklen_t,
        ) as i64
    });
    report("setsockopt(SO_REUSEADDR, len=0)", unsafe {
        libc::setsockopt(
            s,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const _,
            0,
        ) as i64
    });
    report("setsockopt(optname=9999)", unsafe {
        libc::setsockopt(
            s,
            libc::SOL_SOCKET,
            9999,
            &one as *const _ as *const _,
            size_of::<i32>() as libc::socklen_t,
        ) as i64
    });

    println!("## a blocking recv interrupted by a signal");
    // Linux's `sock_intr_errno`: a `recv` with no `SO_RCVTIMEO` is
    // `ERESTARTSYS`, so a handler installed with `SA_RESTART` sees it
    // restarted and the call goes on waiting; with a timeout it is `EINTR`,
    // because a restarted timed wait would never time out. The other end is
    // written one second after the signal, so a restarted recv answers with
    // data and an interrupted one with the errno.
    {
        extern "C" fn nothing(_: i32) {}
        let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
        act.sa_sigaction = nothing as *const () as usize;
        act.sa_flags = libc::SA_RESTART;
        unsafe {
            libc::sigemptyset(&mut act.sa_mask);
            libc::sigaction(libc::SIGALRM, &act, std::ptr::null_mut());
        }
        for (what, timeout_secs) in [("no SO_RCVTIMEO", 0i64), ("SO_RCVTIMEO of five seconds", 5)] {
            let mut pair = [0i32; 2];
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) };
            if timeout_secs > 0 {
                let tv = libc::timeval { tv_sec: timeout_secs, tv_usec: 0 };
                unsafe {
                    libc::setsockopt(
                        pair[0],
                        libc::SOL_SOCKET,
                        libc::SO_RCVTIMEO,
                        &tv as *const libc::timeval as *const _,
                        size_of::<libc::timeval>() as libc::socklen_t,
                    );
                }
            }
            let writer = pair[1];
            let t = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(2));
                unsafe { libc::write(writer, b"x".as_ptr().cast(), 1) };
            });
            unsafe { libc::alarm(1) };
            let mut byte = 0u8;
            let r = unsafe { libc::recv(pair[0], (&mut byte as *mut u8).cast(), 1, 0) };
            let e = errno();
            unsafe { libc::alarm(0) };
            let shown = if r == 1 { "restarted, got the byte".to_string() } else { name(e) };
            println!("{:<50} -> {}", format!("recv with SA_RESTART, {what}"), shown);
            t.join().unwrap();
            unsafe {
                libc::close(pair[0]);
                libc::close(pair[1]);
            }
        }
    }

    println!("## sockopt read-back");
    // Options this kernel has no host equivalent for. What matters is what a
    // program reads back after setting one: Linux stores some and derives
    // others, and a program probing its own settings compares the two.
    {
        let t = socket(libc::AF_INET, libc::SOCK_STREAM, 0) as i32;
        for (what, level, opt, set) in [
            ("SO_PRIORITY", libc::SOL_SOCKET, libc::SO_PRIORITY, 6i32),
            ("TCP_USER_TIMEOUT", libc::IPPROTO_TCP, libc::TCP_USER_TIMEOUT, 5000),
            ("TCP_DEFER_ACCEPT", libc::IPPROTO_TCP, libc::TCP_DEFER_ACCEPT, 3),
            ("TCP_QUICKACK", libc::IPPROTO_TCP, libc::TCP_QUICKACK, 0),
        ] {
            let r = unsafe {
                libc::setsockopt(t, level, opt, &set as *const i32 as *const _, size_of::<i32>() as libc::socklen_t)
            };
            report(&format!("setsockopt({what}, {set})"), r as i64);
            let mut got = -1i32;
            let mut glen = size_of::<i32>() as libc::socklen_t;
            let r = unsafe { libc::getsockopt(t, level, opt, &mut got as *mut i32 as *mut _, &mut glen) };
            if r == 0 {
                println!("{:<50} -> {}", format!("  getsockopt({what})"), got);
            } else {
                report(&format!("  getsockopt({what})"), r as i64);
            }
        }
        unsafe { libc::close(t) };
    }

    println!("## socketpair");
    let mut sv = [0i32; 2];
    report("socketpair(AF_UNIX, STREAM)", unsafe {
        libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) as i64
    });
    report("socketpair(AF_UNIX, DGRAM)", unsafe {
        libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, sv.as_mut_ptr()) as i64
    });
    report("socketpair(domain=99)", unsafe {
        libc::socketpair(99, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) as i64
    });
    report("socketpair(proto=1)", unsafe {
        libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 1, sv.as_mut_ptr()) as i64
    });

    println!("## shutdown of a listener another thread is accepting on");
    // What ends a blocked `accept`. `sock_race` hung on its own teardown on
    // 2026-09-30: two threads polled one listener, both saw the connection,
    // one accepted it and the other blocked -- and the `shutdown` meant to
    // release it did not. The wait is bounded here so that the probe reports
    // a thread that stays blocked rather than hanging on it; the thread is
    // taken down with the process.
    for (what, how) in [("SHUT_RDWR", libc::SHUT_RDWR), ("SHUT_RD", libc::SHUT_RD), ("SHUT_WR", libc::SHUT_WR)] {
        let path = format!("{dir}/accepting-{what}");
        let (sa, len) = unix_addr(&path);
        let l = socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) as i32;
        unsafe {
            libc::bind(l, &sa as *const _ as *const _, len);
            libc::listen(l, 5);
        }
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let r = unsafe { libc::accept(l, std::ptr::null_mut(), std::ptr::null_mut()) };
            let _ = tx.send(if r < 0 { name(errno()) } else { "a connection".to_string() });
        });
        std::thread::sleep(std::time::Duration::from_millis(300));
        report(&format!("shutdown(listener, {what})"), unsafe { libc::shutdown(l, how) as i64 });
        let shown = rx
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap_or_else(|_| "still blocked".to_string());
        println!("{:<50} -> {}", format!("  the blocked accept, after {what}"), shown);
        // And one that starts blocking only now, on the listener that has
        // already been shut down.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let r = unsafe { libc::accept(l, std::ptr::null_mut(), std::ptr::null_mut()) };
            let _ = tx.send(if r < 0 { name(errno()) } else { "a connection".to_string() });
        });
        let shown = rx
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap_or_else(|_| "still blocked".to_string());
        println!("{:<50} -> {}", format!("  a new blocking accept, after {what}"), shown);
        // Non-blocking, so that a listener shutdown does not refuse is
        // reported as EAGAIN rather than hanging the probe. `accept4`'s
        // SOCK_NONBLOCK would not do: it is the *new* descriptor's flag.
        unsafe { libc::fcntl(l, libc::F_SETFL, libc::O_NONBLOCK) };
        let r = unsafe { libc::accept(l, std::ptr::null_mut(), std::ptr::null_mut()) };
        let after = if r < 0 { name(errno()) } else { "a connection".to_string() };
        println!("{:<50} -> {}", format!("  a new accept, after {what}"), after);
    }

    println!("## the wrong kind of descriptor");
    let f = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
    report("listen(a regular file)", unsafe { libc::listen(f, 5) as i64 });
    report("getsockopt(a regular file)", unsafe {
        libc::getsockopt(
            f,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut val as *mut _ as *mut _,
            &mut olen,
        ) as i64
    });
    report("shutdown(a regular file)", unsafe {
        libc::shutdown(f, libc::SHUT_RDWR) as i64
    });
    report("listen(a closed fd)", unsafe { libc::listen(4096, 5) as i64 });

    let _ = std::fs::remove_dir_all(dir);
}
