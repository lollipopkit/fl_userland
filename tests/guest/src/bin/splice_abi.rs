//! `splice(2)`, which was registered in the syscall table and answered EINVAL
//! for every call.
//!
//! A guest was therefore told the call exists and then that its arguments were
//! wrong, whichever arguments it used. Callers that check for that fall back
//! to a read/write loop through userspace — which is what this kernel does
//! internally anyway, so the fallback was strictly worse: the same copies plus
//! two extra syscalls per chunk crossing the emulator boundary.
//!
//! What is asserted here is the *semantics*, not zero-copy. Linux does not
//! promise zero-copy either — `SPLICE_F_MOVE` has been a no-op there since
//! 2.6.21 — and this kernel cannot do it at all, because a guest file's
//! contents are host files reached through read and write.
//!
//! Every check is written to hold on a real kernel too; the two are compared
//! by `tests/integration/differential.sh`.

use guest_tests::{Harness, check, check_fails, cpath, sys};

const SPLICE_F_MOVE: u32 = 1;
const SPLICE_F_NONBLOCK: u32 = 2;
const SPLICE_F_MORE: u32 = 4;

fn splice(
    in_fd: i32,
    in_off: *mut i64,
    out_fd: i32,
    out_off: *mut i64,
    len: usize,
    flags: u32,
) -> i64 {
    unsafe {
        libc::syscall(
            libc::SYS_splice,
            in_fd,
            in_off,
            out_fd,
            out_off,
            len,
            flags,
        )
    }
}

/// A pipe whose read end never blocks.
///
/// Every read below is checking what a splice put there, so a splice that put
/// nothing must make the *check* fail rather than leave the read waiting for a
/// writer that is not coming. With a blocking read end this test hung instead
/// of failing when splice was stubbed back out to confirm it -- and a test
/// that hangs on failure is worse than one that fails, because a sweep has to
/// time it out to learn anything at all.
fn pipe() -> (i32, i32) {
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    unsafe { libc::fcntl(fds[0], libc::F_SETFL, libc::O_NONBLOCK) };
    (fds[0], fds[1])
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp/splice".into());
    let _ = std::fs::create_dir_all(&dir);
    let mut h = Harness::new();

    let src = format!("{dir}/src");
    let body: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&src, &body).expect("write the source");

    h.group("file-to-pipe");
    // A file into a pipe, with the file's offset given explicitly. The
    // descriptor's own position must not move when an offset is passed.
    let fd = unsafe { libc::open(cpath(&src).as_ptr(), libc::O_RDONLY) };
    check!(h, fd >= 0, "open the source");
    let (r, w) = pipe();
    let mut off: i64 = 0;
    let n = splice(fd, &mut off, w, std::ptr::null_mut(), 4096, 0);
    check!(h, n == 4096, "splice 4096 bytes from a file into a pipe: {n} errno {}", sys::errno());
    check!(h, off == 4096, "and advances the offset it was given: {off}");
    check!(
        h,
        unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) } == 0,
        "and leaves the descriptor's own position alone"
    );
    let mut got = vec![0u8; 4096];
    let rd = unsafe { libc::read(r, got.as_mut_ptr().cast(), got.len()) };
    check!(h, rd == 4096, "the pipe holds them: {rd}");
    check!(h, got == body[..4096], "and they are the right bytes");

    h.group("pipe-to-file");
    // And back out of a pipe into a file.
    let dst = format!("{dir}/dst");
    let out = unsafe {
        libc::open(cpath(&dst).as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644)
    };
    check!(h, out >= 0, "open the destination");
    let wr = unsafe { libc::write(w, body[..1024].as_ptr().cast(), 1024) };
    check!(h, wr == 1024, "fill the pipe: {wr}");
    let mut out_off: i64 = 0;
    let n = splice(r, std::ptr::null_mut(), out, &mut out_off, 1024, 0);
    check!(h, n == 1024, "splice out of a pipe into a file: {n} errno {}", sys::errno());
    check!(h, out_off == 1024, "and advances the file's offset: {out_off}");
    check!(
        h,
        std::fs::read(&dst).unwrap_or_default() == body[..1024],
        "and the file holds the right bytes"
    );

    h.group("no-offset");
    // With no offset on the file side, the descriptor's own position is used
    // and moves.
    unsafe { libc::lseek(fd, 100, libc::SEEK_SET) };
    let n = splice(fd, std::ptr::null_mut(), w, std::ptr::null_mut(), 64, 0);
    check!(h, n == 64, "splice with no offset uses the position: {n} errno {}", sys::errno());
    check!(
        h,
        unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) } == 164,
        "and moves it"
    );
    let mut got = [0u8; 64];
    unsafe { libc::read(r, got.as_mut_ptr().cast(), got.len()) };
    check!(h, got[..] == body[100..164], "from where it was pointing");

    h.group("refusals");
    // Neither end a pipe.
    let plain = unsafe { libc::open(cpath(&src).as_ptr(), libc::O_RDONLY) };
    check_fails!(
        h,
        splice(plain, std::ptr::null_mut(), out, std::ptr::null_mut(), 16, 0),
        libc::EINVAL,
        "splice with neither end a pipe"
    );
    // An offset for the pipe side has nothing to seek.
    let mut bad_off: i64 = 0;
    check_fails!(
        h,
        splice(fd, std::ptr::null_mut(), w, &mut bad_off, 16, 0),
        libc::ESPIPE,
        "an offset on the pipe side"
    );
    // An undefined flag is refused rather than ignored.
    check_fails!(
        h,
        splice(fd, std::ptr::null_mut(), w, std::ptr::null_mut(), 16, 0x40),
        libc::EINVAL,
        "an undefined flag"
    );
    // A bad descriptor.
    check_fails!(
        h,
        splice(-1, std::ptr::null_mut(), w, std::ptr::null_mut(), 16, 0),
        libc::EBADF,
        "a descriptor that is not open"
    );

    h.group("flags-that-are-hints");
    // MOVE and MORE are hints; a kernel that cannot use them must still do the
    // work rather than refuse. MOVE has been a no-op on Linux since 2.6.21.
    let n = splice(fd, std::ptr::null_mut(), w, std::ptr::null_mut(), 32,
                   SPLICE_F_MOVE | SPLICE_F_MORE);
    check!(h, n == 32, "SPLICE_F_MOVE|SPLICE_F_MORE still copies: {n} errno {}", sys::errno());
    let mut sink = [0u8; 32];
    unsafe { libc::read(r, sink.as_mut_ptr().cast(), sink.len()) };

    h.group("empty-and-eof");
    // An empty non-blocking pipe is EAGAIN, not a silent zero. A zero would be
    // read as end-of-stream and stop a copy loop early.
    let (er, ew) = pipe();
    let n = splice(er, std::ptr::null_mut(), out, std::ptr::null_mut(), 16,
                   SPLICE_F_NONBLOCK);
    let e = sys::errno();
    check!(h, n == -1 && e == libc::EAGAIN,
        "an empty non-blocking pipe is EAGAIN: {n} errno {e}");
    // At end of file, zero.
    unsafe { libc::close(ew) };
    let n = splice(er, std::ptr::null_mut(), out, std::ptr::null_mut(), 16, 0);
    check!(h, n == 0, "a pipe whose writer is gone splices zero: {n} errno {}", sys::errno());

    // A count of zero moves nothing and is not an error.
    let n = splice(fd, std::ptr::null_mut(), w, std::ptr::null_mut(), 0, 0);
    check!(h, n == 0, "a count of zero is zero, not an error: {n} errno {}", sys::errno());

    h.group("a-count-wider-than-32-bits");
    // `len` is a `size_t` and this kernel's transfer loop counts in 32 bits, so
    // a count of exactly 2^32 used to arrive as zero: the splice reported that
    // it had moved nothing, which is the end-of-input answer, and a caller
    // draining a file in a loop stopped on its first pass with no error. The
    // return value was right for the number the loop saw and wrong about the
    // one the guest passed.
    //
    // 2^32 and 2^32+16 are the two that separate a 64-bit count from a
    // truncated one: they behave as 0 and 16 under truncation and as "more than
    // there is" on a real kernel.
    let (br, bw) = pipe();
    let big = unsafe { libc::open(cpath(&src).as_ptr(), libc::O_RDONLY) };
    check!(h, big >= 0, "open the source again");
    let mut boff: i64 = 0;
    let n = splice(big, &mut boff, bw, std::ptr::null_mut(), 1usize << 32, 0);
    check!(
        h,
        n > 0,
        "a count of 2^32 splices something rather than reporting end of input: \
         {n} errno {}",
        sys::errno()
    );
    check!(h, boff == n, "and the offset advanced by what it moved: {boff} vs {n}");
    let mut drain = vec![0u8; 65536];
    while unsafe { libc::read(br, drain.as_mut_ptr().cast(), drain.len()) } > 0 {}

    let mut boff: i64 = 0;
    let n = splice(big, &mut boff, bw, std::ptr::null_mut(), (1usize << 32) | 16, 0);
    check!(
        h,
        n > 16,
        "and a count of 2^32+16 is not a count of 16: {n} errno {}",
        sys::errno()
    );
    while unsafe { libc::read(br, drain.as_mut_ptr().cast(), drain.len()) } > 0 {}

    // The other half of the same argument: a length that is negative as an
    // `ssize_t` is EINVAL, from `rw_verify_area` inside `do_splice_to`. This
    // kernel spliced the file instead -- the clamp alone would not produce it,
    // which is why the rule is two rules.
    let mut boff: i64 = 0;
    let n = splice(big, &mut boff, bw, std::ptr::null_mut(), usize::MAX, 0);
    let e = sys::errno();
    check!(
        h,
        n == -1 && e == libc::EINVAL,
        "a count that is negative as a signed value is EINVAL: {n} errno {e}"
    );
    while unsafe { libc::read(br, drain.as_mut_ptr().cast(), drain.len()) } > 0 {}
    unsafe {
        libc::close(br);
        libc::close(bw);
        libc::close(big);
    }

    unsafe {
        libc::close(fd);
        libc::close(plain);
        libc::close(r);
        libc::close(w);
        libc::close(er);
        libc::close(out);
    }
    std::process::exit(h.finish());
}
