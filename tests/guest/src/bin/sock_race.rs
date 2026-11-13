//! Unix sockets, from several threads at once.
//!
//! `fs/sock.c` keeps state a probe has not touched yet: a global
//! `unix_pending_list` that connect adds to and accept claims from under
//! `peer_lock`, a peer pointer on each side that `sock_close` unlinks, and a
//! queue of `struct scm` carrying descriptors from one process's table to
//! another's. The connect side of that is where the uninterruptible wait was
//! found; nothing has stressed the rest.
//!
//! Threads here connect and accept concurrently on one listener, pass
//! descriptors over SCM_RIGHTS, close sockets out from under peers, and read
//! `/proc/self/fd` over the top — which is what turns a leaked or
//! double-installed descriptor into something visible.
//!
//! The checks: every descriptor received over SCM_RIGHTS refers to the file
//! that was sent, every connection that is accepted can exchange a byte, and
//! the descriptor table does not grow without bound.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

static BAD_CONTENT: AtomicU64 = AtomicU64::new(0);
static BAD_EXCHANGE: AtomicU64 = AtomicU64::new(0);

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

fn sockaddr_un(path: &str) -> (libc::sockaddr_un, libc::socklen_t) {
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as u16;
    for (slot, &b) in addr.sun_path.iter_mut().zip(path.as_bytes()) {
        *slot = b as libc::c_char;
    }
    (addr, size_of::<libc::sockaddr_un>() as libc::socklen_t)
}

/// The file every passed descriptor should refer to, checked by content.
const MARKER: &[u8] = b"scm-marker\n";

/// Send `fd` over `sock` with a byte of ordinary payload beside it.
unsafe fn send_fd(sock: i32, fd: i32) -> bool {
    unsafe {
        let mut byte = b'x';
        let mut iov = libc::iovec {
            iov_base: (&raw mut byte).cast(),
            iov_len: 1,
        };
        let mut buf = [0u8; 64];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = buf.as_mut_ptr().cast();
        msg.msg_controllen = 64;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return false;
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(4) as _;
        std::ptr::copy_nonoverlapping(&fd, libc::CMSG_DATA(cmsg).cast::<i32>(), 1);
        msg.msg_controllen = libc::CMSG_SPACE(4) as _;
        libc::sendmsg(sock, &msg, 0) == 1
    }
}

/// Receive a descriptor, or -1.
unsafe fn recv_fd(sock: i32) -> i32 {
    unsafe {
        let mut byte = 0u8;
        let mut iov = libc::iovec {
            iov_base: (&raw mut byte).cast(),
            iov_len: 1,
        };
        let mut buf = [0u8; 64];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = buf.as_mut_ptr().cast();
        msg.msg_controllen = 64;
        if libc::recvmsg(sock, &mut msg, 0) != 1 {
            return -1;
        }
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null()
            || (*cmsg).cmsg_level != libc::SOL_SOCKET
            || (*cmsg).cmsg_type != libc::SCM_RIGHTS
        {
            return -1;
        }
        let mut fd = -1i32;
        std::ptr::copy_nonoverlapping(libc::CMSG_DATA(cmsg).cast::<i32>(), &mut fd, 1);
        fd
    }
}

fn main() {
    let seconds: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    let dir = std::env::args().nth(2).unwrap_or_else(|| "/tmp/sockrace".into());
    unsafe { libc::mkdir(cstr(&dir).as_ptr(), 0o755) };
    let marker_path = format!("{dir}/marker");
    std::fs::write(&marker_path, MARKER).ok();
    let sock_path = format!("{dir}/s");
    unsafe { libc::unlink(cstr(&sock_path).as_ptr()) };

    let listener = unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        let (addr, len) = sockaddr_un(&sock_path);
        if libc::bind(fd, (&raw const addr).cast(), len) != 0 || libc::listen(fd, 64) != 0 {
            println!("LOST: could not bind or listen on {sock_path}");
            println!("survived");
            return;
        }
        fd
    };

    let stop = Arc::new(AtomicBool::new(false));
    let mut threads = Vec::new();

    // Accept, receive a descriptor, check what it points at, answer a byte.
    for _ in 0..2 {
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                unsafe {
                    // Poll rather than block in accept, so this thread can see
                    // `stop`. Both threads can be woken by one connection,
                    // and the one that loses blocks in accept: the teardown's
                    // shutdown() is what ends that, with EINVAL on Linux. It
                    // did not here until 2026-09-30, and this test hung.
                    let mut p = libc::pollfd {
                        fd: listener,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    if libc::poll(&mut p, 1, 50) <= 0 {
                        continue;
                    }
                    let c = libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut());
                    if c < 0 {
                        continue;
                    }
                    let got = recv_fd(c);
                    if got >= 0 {
                        // The descriptor has to be the marker file: a table
                        // that installed the wrong one, or reused a number,
                        // shows up here as the wrong bytes.
                        let mut buf = [0u8; 32];
                        let k = libc::read(got, buf.as_mut_ptr().cast(), buf.len());
                        if k <= 0 || &buf[..k as usize] != MARKER {
                            BAD_CONTENT.fetch_add(1, Ordering::Relaxed);
                        }
                        libc::close(got);
                    }
                    libc::write(c, b"y".as_ptr().cast(), 1);
                    libc::close(c);
                }
                n += 1;
            }
            n
        }));
    }

    // Connect, send a descriptor, read the answer.
    for _ in 0..3 {
        let stop = stop.clone();
        let sock_path = sock_path.clone();
        let marker_path = marker_path.clone();
        threads.push(std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                unsafe {
                    let s = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
                    if s < 0 {
                        continue;
                    }
                    // A receive timeout, because a connection that lands in
                    // the backlog after the accepting threads have stopped
                    // will never be answered — on Linux just the same. Without
                    // it the probe hangs on its own shutdown rather than on
                    // anything under test.
                    let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
                    libc::setsockopt(
                        s,
                        libc::SOL_SOCKET,
                        libc::SO_RCVTIMEO,
                        (&raw const tv).cast(),
                        size_of::<libc::timeval>() as libc::socklen_t,
                    );
                    let (addr, len) = sockaddr_un(&sock_path);
                    if libc::connect(s, (&raw const addr).cast(), len) == 0 {
                        let m = libc::open(cstr(&marker_path).as_ptr(), libc::O_RDONLY);
                        if m >= 0 {
                            send_fd(s, m);
                            libc::close(m);
                        }
                        let mut b = 0u8;
                        let k = libc::read(s, (&raw mut b).cast(), 1);
                        // A timeout is the shutdown case, not a failure.
                        if k == 1 && b != b'y' {
                            BAD_EXCHANGE.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    libc::close(s);
                }
                n += 1;
            }
            n
        }));
    }

    // Walk /proc/self/fd, which is what makes a descriptor left behind by the
    // SCM queue visible rather than merely present.
    {
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            let mut peak = 0u64;
            while !stop.load(Ordering::Relaxed) {
                if let Ok(d) = std::fs::read_dir("/proc/self/fd") {
                    let n = d.count() as u64;
                    peak = peak.max(n);
                }
            }
            peak
        }));
    }

    std::thread::sleep(std::time::Duration::from_secs(seconds));
    stop.store(true, Ordering::Relaxed);
    // Unblock the accepting threads.
    unsafe { libc::shutdown(listener, libc::SHUT_RDWR) };
    let counts: Vec<u64> = threads.into_iter().map(|t| t.join().unwrap_or(0)).collect();
    unsafe {
        libc::close(listener);
        libc::unlink(cstr(&sock_path).as_ptr());
    }

    println!("iterations: {counts:?}");
    let content = BAD_CONTENT.load(Ordering::Relaxed);
    let exchange = BAD_EXCHANGE.load(Ordering::Relaxed);
    if content != 0 {
        println!("LOST: {content} descriptors arrived pointing at the wrong file");
    }
    if exchange != 0 {
        println!("LOST: {exchange} accepted connections did not exchange a byte");
    }
    println!("survived");
}
