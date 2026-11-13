//! Where `splice` and `copy_file_range` leave their descriptors.
//!
//! Both move bytes through the same loop in this kernel, and both have the same
//! thing to get right: what the output did not take must not be consumed from
//! the input. A short write into a pipe that has run out of room leaves the
//! input past bytes nobody received, and a caller resuming from the reported
//! position — or from the offset written back to it — skips them silently.
//!
//! The return value is right either way, and so are the bytes that arrived.
//! Only the position shows it.

use guest_tests::{Harness, check, cpath};

/// `SPLICE_F_NONBLOCK`. Without it splice blocks when the pipe fills, whatever
/// the pipe's own O_NONBLOCK says -- the flag is about the *call*, not the
/// descriptor. The first version of this test hung a container for ten minutes
/// on exactly that.
const SPLICE_F_NONBLOCK: u32 = 0x02;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn open_rw(path: &str) -> i32 {
    unsafe { libc::open(cpath(path).as_ptr(), libc::O_RDWR) }
}

fn pos(fd: i32) -> i64 {
    unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) }
}

fn main() {
    let mut h = Harness::new();
    let src = "/tmp/copy_pos_src";
    let dst = "/tmp/copy_pos_dst";
    // Larger than a pipe holds, so a splice into one has to come up short for
    // the pipe's sake rather than because the file ran out. A test that cannot
    // tell those apart proves nothing -- sendfile's first probe could not.
    let payload: Vec<u8> = (0..300000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(src, &payload).expect("write the source");
    std::fs::write(dst, b"").expect("empty destination");

    let inf = open_rw(src);
    let outf = open_rw(dst);
    check!(h, inf >= 0 && outf >= 0, "opening both: in={inf} out={outf}");

    h.group("copy_file_range-with-explicit-offsets");
    // Neither descriptor may move, and both offsets come back advanced by
    // exactly what was copied.
    unsafe { libc::lseek(inf, 11, libc::SEEK_SET) };
    unsafe { libc::lseek(outf, 13, libc::SEEK_SET) };
    let mut off_in: libc::off64_t = 1000;
    let mut off_out: libc::off64_t = 0;
    let n = unsafe {
        libc::syscall(libc::SYS_copy_file_range, inf, &raw mut off_in,
                      outf, &raw mut off_out, 4096usize, 0u32)
    };
    let e = errno();
    check!(h, n == 4096, "copy_file_range copies: n={n} errno={e}");
    check!(h, off_in == 1000 + n, "off_in advances by exactly that: {off_in}");
    check!(h, off_out == n, "and off_out: {off_out}");
    check!(h, pos(inf) == 11, "the input descriptor has not moved: {}", pos(inf));
    check!(h, pos(outf) == 13, "nor the output: {}", pos(outf));
    let got = std::fs::read(dst).unwrap_or_default();
    check!(h, got.len() >= 4096 && got[..4096] == payload[1000..1000 + 4096],
        "and the bytes came from off_in: len={}", got.len());

    h.group("copy_file_range-with-null-offsets");
    // Both descriptors move by what was copied, and nothing else does.
    unsafe { libc::lseek(inf, 0, libc::SEEK_SET) };
    unsafe { libc::lseek(outf, 0, libc::SEEK_SET) };
    let n = unsafe {
        libc::syscall(libc::SYS_copy_file_range, inf, std::ptr::null_mut::<libc::off64_t>(),
                      outf, std::ptr::null_mut::<libc::off64_t>(), 2048usize, 0u32)
    };
    check!(h, n == 2048, "copy_file_range with null offsets: n={n} errno={}", errno());
    check!(h, pos(inf) == n, "the input moved by what it copied: {}", pos(inf));
    check!(h, pos(outf) == n, "and the output: {}", pos(outf));

    h.group("splice-into-a-full-pipe-consumes-only-what-it-wrote");
    // The case both calls share. The pipe cannot take 200000 bytes; the file
    // has 300000, so anything short is the pipe's doing.
    let mut pipefd = [0i32; 2];
    check!(h, unsafe { libc::pipe(pipefd.as_mut_ptr()) } == 0, "a pipe");
    // Both ends non-blocking. The write end so a full pipe refuses rather than
    // waits, and the *read* end because the drain at the bottom reads until it
    // runs out -- on a blocking end that is a wait for more, which hung a
    // container for ten minutes.
    unsafe { libc::fcntl(pipefd[1], libc::F_SETFL, libc::O_NONBLOCK) };
    unsafe { libc::fcntl(pipefd[0], libc::F_SETFL, libc::O_NONBLOCK) };
    unsafe { libc::lseek(inf, 0, libc::SEEK_SET) };
    let asked = 200000usize;
    let n = unsafe {
        libc::syscall(libc::SYS_splice, inf, std::ptr::null_mut::<libc::off64_t>(),
                      pipefd[1], std::ptr::null_mut::<libc::off64_t>(), asked,
                      SPLICE_F_NONBLOCK)
    };
    let e = errno();
    check!(h, n > 0, "some of it goes through: n={n} errno={e}");
    check!(h, (n as usize) < asked, "and not all: n={n} of {asked}");
    check!(h, (n as usize) < payload.len(), "with the file still having more: n={n}");
    check!(h, pos(inf) == n,
        "the input is left exactly where the transfer stopped: pos={} n={n}", pos(inf));
    // Drain and check the bytes are the front of the file, in order.
    let mut drained = vec![0u8; n as usize];
    let mut got = 0usize;
    while got < n as usize {
        let r = unsafe {
            libc::read(pipefd[0], drained.as_mut_ptr().add(got).cast(), n as usize - got)
        };
        if r <= 0 {
            break;
        }
        got += r as usize;
    }
    check!(h, got == n as usize, "the pipe holds what was reported: {got} of {n}");
    check!(h, drained[..got] == payload[..got], "and the bytes are in order");

    h.group("splice-with-an-explicit-input-offset");
    // The same, with an offset instead of a position: the descriptor must not
    // move and the offset must come back at exactly what was transferred.
    unsafe { libc::lseek(inf, 17, libc::SEEK_SET) };
    let mut off_in: libc::off64_t = 5000;
    let n = unsafe {
        libc::syscall(libc::SYS_splice, inf, &raw mut off_in,
                      pipefd[1], std::ptr::null_mut::<libc::off64_t>(), asked,
                      SPLICE_F_NONBLOCK)
    };
    let e = errno();
    check!(h, n > 0, "some of it goes through: n={n} errno={e}");
    check!(h, off_in == 5000 + n, "the offset advances by exactly that: {off_in} n={n}");
    check!(h, pos(inf) == 17, "and the descriptor has not moved: {}", pos(inf));
    // Drain it so the pipe is not left full.
    let mut sink = vec![0u8; 65536];
    loop {
        let r = unsafe { libc::read(pipefd[0], sink.as_mut_ptr().cast(), sink.len()) };
        if r <= 0 {
            break;
        }
    }
    unsafe { libc::close(pipefd[0]) };
    unsafe { libc::close(pipefd[1]) };

    unsafe { libc::close(inf) };
    unsafe { libc::close(outf) };
    let _ = std::fs::remove_file(src);
    let _ = std::fs::remove_file(dst);
    std::process::exit(h.finish());
}
