//! What `fstatfs` says a descriptor's filesystem is.
//!
//! Linux has three filesystems for descriptors that have no file behind them,
//! and `f_type` is how a program tells them apart: `anon_inodefs` for an
//! eventfd, a timerfd or an epoll set, `pipefs` for a pipe, `sockfs` for a
//! socket. This kernel reported `anon_inodefs` for all five — a `FIXME` on the
//! constant said it was "wrong for pipes and sockets", and it was right.
//!
//! The numbers here were measured against a real arm64 kernel, not read out of
//! a header, and this runs on both so the two have to agree.

use guest_tests::{Harness, check, sys};

const ANON_INODE_FS_MAGIC: i64 = 0x0904_1934;
const PIPEFS_MAGIC: i64 = 0x5049_5045;
const SOCKFS_MAGIC: i64 = 0x534f_434b;

/// `f_type` is the first field of `struct statfs` on aarch64, and 64 bits.
fn f_type(fd: i32) -> Option<i64> {
    let mut buf = [0u8; 120];
    let r = unsafe { libc::syscall(libc::SYS_fstatfs, fd, buf.as_mut_ptr()) };
    if r != 0 {
        return None;
    }
    Some(i64::from_le_bytes(buf[..8].try_into().unwrap()))
}

fn main() {
    let mut h = Harness::new();
    h.group("anon-inode");

    let ev = unsafe { libc::syscall(libc::SYS_eventfd2, 0, 0) as i32 };
    check!(h, ev >= 0, "an eventfd");
    check!(h, f_type(ev) == Some(ANON_INODE_FS_MAGIC),
        "an eventfd is on anon_inodefs: {:x?}", f_type(ev));

    let tf = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, 0) };
    check!(h, tf >= 0, "a timerfd");
    check!(h, f_type(tf) == Some(ANON_INODE_FS_MAGIC),
        "a timerfd is on anon_inodefs: {:x?}", f_type(tf));

    let ep = unsafe { libc::epoll_create1(0) };
    check!(h, ep >= 0, "an epoll set");
    check!(h, f_type(ep) == Some(ANON_INODE_FS_MAGIC),
        "an epoll set is on anon_inodefs: {:x?}", f_type(ep));

    h.group("pipefs");
    let mut p = [0i32; 2];
    check!(h, unsafe { libc::pipe(p.as_mut_ptr()) } == 0, "a pipe");
    check!(h, f_type(p[0]) == Some(PIPEFS_MAGIC),
        "a pipe is on pipefs, not anon_inodefs: {:x?}", f_type(p[0]));
    check!(h, f_type(p[1]) == Some(PIPEFS_MAGIC),
        "and so is its write end: {:x?}", f_type(p[1]));

    h.group("sockfs");
    let s = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    check!(h, s >= 0, "a unix socket: errno {}", sys::errno());
    check!(h, f_type(s) == Some(SOCKFS_MAGIC),
        "a socket is on sockfs: {:x?}", f_type(s));
    let sd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
    check!(h, sd < 0 || f_type(sd) == Some(SOCKFS_MAGIC),
        "and a datagram socket too: {:x?}", f_type(sd));

    h.group("they-are-distinct");
    // The point of the whole thing: a program telling them apart must get
    // different answers. One constant for all of them passed every check
    // above that named anon_inodefs and failed nothing.
    check!(h, f_type(p[0]) != f_type(ev), "a pipe and an eventfd differ");
    check!(h, f_type(s) != f_type(ev), "a socket and an eventfd differ");
    check!(h, f_type(s) != f_type(p[0]), "a socket and a pipe differ");

    unsafe {
        for fd in [ev, tf, ep, p[0], p[1], s, sd] {
            if fd >= 0 {
                libc::close(fd);
            }
        }
    }
    std::process::exit(h.finish());
}
