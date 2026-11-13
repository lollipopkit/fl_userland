//! `sendfile`: what it moves, and where it leaves the input.
//!
//! The two positions are the whole ABI. With an explicit offset the input
//! descriptor must **not** move and the offset is written back; with a null
//! offset the descriptor moves by exactly what was transferred.
//!
//! The case worth building a test around is a **short write**: the output is a
//! pipe with less room than the request. Whatever is not written must not be
//! consumed from the input either — a loop that reads a block, writes part of
//! it, and stops has advanced the input past bytes nobody received, and the
//! caller resuming from the reported position skips them. Nothing reports that.

use guest_tests::{Harness, check, cpath};

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn open_rw(path: &str) -> i32 {
    unsafe { libc::open(cpath(path).as_ptr(), libc::O_RDWR) }
}

fn main() {
    let mut h = Harness::new();
    let src = "/tmp/sendfile_src";
    let dst = "/tmp/sendfile_dst";
    // A pattern rather than a constant, so a copy that lands at the wrong
    // offset is visible in the bytes. Larger than a pipe holds, which the
    // short-write group at the bottom depends on: at 40000 bytes the whole file
    // fitted, `n < asked` passed because the *file* ran out, and the group
    // proved nothing. Printing the numbers is what caught it.
    let payload: Vec<u8> = (0..300000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(src, &payload).expect("write the source");

    h.group("a-plain-copy");
    std::fs::write(dst, b"").expect("empty destination");
    let inf = open_rw(src);
    let outf = open_rw(dst);
    check!(h, inf >= 0 && outf >= 0, "opening both: in={inf} out={outf}");
    let n = unsafe { libc::sendfile(outf, inf, std::ptr::null_mut(), 1000) };
    check!(h, n == 1000, "sendfile moves what was asked: n={n} errno={}", errno());
    let pos = unsafe { libc::lseek(inf, 0, libc::SEEK_CUR) };
    check!(h, pos == 1000, "and the input is left at what it moved: {pos}");
    let opos = unsafe { libc::lseek(outf, 0, libc::SEEK_CUR) };
    check!(h, opos == 1000, "and so is the output: {opos}");
    let got = std::fs::read(dst).unwrap_or_default();
    check!(h, got == payload[..1000], "the bytes are the source's");

    h.group("with-an-explicit-offset");
    // The input descriptor must not move at all, and the offset comes back
    // advanced. That is what makes sendfile usable from two threads on one
    // descriptor.
    unsafe { libc::lseek(inf, 7, libc::SEEK_SET) };
    let mut off: libc::off_t = 2000;
    let n = unsafe { libc::sendfile(outf, inf, &mut off, 500) };
    check!(h, n == 500, "sendfile with an offset: n={n} errno={}", errno());
    check!(h, off == 2500, "the offset comes back advanced: {off}");
    let pos = unsafe { libc::lseek(inf, 0, libc::SEEK_CUR) };
    check!(h, pos == 7, "and the descriptor has not moved: {pos}");
    let got = std::fs::read(dst).unwrap_or_default();
    check!(h, got.len() == 1500 && got[1000..] == payload[2000..2500],
        "and the bytes came from the offset, not the position: len={}", got.len());

    h.group("bad-arguments");
    let mut bad: libc::off_t = -1;
    let n = unsafe { libc::sendfile(outf, inf, &mut bad, 10) };
    let e = errno();
    check!(h, n == -1 && e == libc::EINVAL, "a negative offset is EINVAL: n={n} errno={e}");
    let n = unsafe { libc::sendfile(outf, 9999, std::ptr::null_mut(), 10) };
    let e = errno();
    check!(h, n == -1 && e == libc::EBADF, "a closed input is EBADF: n={n} errno={e}");
    let n = unsafe { libc::sendfile(9999, inf, std::ptr::null_mut(), 10) };
    let e = errno();
    check!(h, n == -1 && e == libc::EBADF, "a closed output is EBADF: n={n} errno={e}");
    let mut zero: libc::off_t = 0;
    let n = unsafe { libc::sendfile(outf, inf, &mut zero, 0) };
    check!(h, n == 0, "a count of zero moves nothing: n={n}");
    check!(h, zero == 0, "and leaves the offset alone: {zero}");

    h.group("past-the-end");
    let mut past: libc::off_t = payload.len() as libc::off_t + 100;
    let n = unsafe { libc::sendfile(outf, inf, &mut past, 100) };
    check!(h, n == 0, "an offset past the end is end of file: n={n} errno={}", errno());

    h.group("a-short-write-consumes-only-what-it-wrote");
    // The output is a pipe with less room than the request. Whatever is not
    // written must not be consumed from the input either: a loop that reads a
    // block, writes part of it and stops has advanced the input past bytes
    // nobody received, and a caller resuming from the reported position skips
    // them.
    let mut pipefd = [0i32; 2];
    check!(h, unsafe { libc::pipe(pipefd.as_mut_ptr()) } == 0, "a pipe");
    unsafe { libc::fcntl(pipefd[1], libc::F_SETFL, libc::O_NONBLOCK) };
    unsafe { libc::lseek(inf, 0, libc::SEEK_SET) };
    // Far more than a pipe holds, so the write must come up short.
    let asked = 200000;
    let n = unsafe { libc::sendfile(pipefd[1], inf, std::ptr::null_mut(), asked) };
    let e = errno();
    check!(h, n > 0, "some of it goes through: n={n} errno={e}");
    // Not all of it, *and* not merely because the file ran out: the file is
    // 300000 bytes and the request is 200000, so anything short is the pipe.
    check!(h, n < asked as isize, "and not all: n={n} of {asked}");
    check!(h, (n as usize) < payload.len(), "with the file still having more: n={n}");
    let pos = unsafe { libc::lseek(inf, 0, libc::SEEK_CUR) };
    check!(h, pos == n as libc::off_t,
        "the input is left exactly where the transfer stopped: pos={pos} n={n}");
    // And what is in the pipe is the front of the file, in order.
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
    unsafe { libc::close(pipefd[0]) };
    unsafe { libc::close(pipefd[1]) };

    unsafe { libc::close(inf) };
    unsafe { libc::close(outf) };
    let _ = std::fs::remove_file(src);
    let _ = std::fs::remove_file(dst);
    std::process::exit(h.finish());
}
