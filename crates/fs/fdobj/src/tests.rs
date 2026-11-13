use super::*;

#[test]
fn draining_a_thread_without_syscall_references_is_a_noop() {
    // The set is made on the first descriptor lookup; ordinary syscalls
    // reach the dispatcher's drain with none.
    syscall_refs_drain();
    syscall_refs_drain();
}

#[test]
fn the_allocation_is_the_size_the_c_measures() {
    // `fd_create` calloc's by this. It says out loud that the number is
    // load-bearing rather than incidental -- there is nothing else holding
    // it in step now that `struct fd` is Rust's rather than generated.
    // 400 until 2026-09-05, when the socket member became a pointer to
    // crates/fs/sock's state like every other arm of the union: every
    // descriptor in the system was carrying a socket's forty-eight bytes.
    // 352 until 2026-09-07, when the embedded `struct statbuf` gained a
    // creation time -- eight bytes rather than twenty-four, because the two
    // 32-bit halves go in holes the existing timestamps leave and `btime`
    // goes where the struct is already 8-aligned. See `fs/stat.h`.
    // 360 until 2026-09-11, when `ops` became `Option<&dyn FdOps>` -- a trait
    // object is a fat pointer, so the driver is sixteen bytes where the
    // `*const fd_ops` it replaced was eight.
    // 368 until 2026-09-15: three `AtomicU32` for the attributes a driver may
    // change after the descriptor is published, plus four of padding. The
    // reasoning is in `crates/fs/adhoc`'s `struct_fd_is_where_the_c_says`,
    // which asserts the same number with its own copy of this history --
    // **two tests, two hand-maintained histories of one constant**, and this
    // one was found by running the suite rather than by grepping, which is
    // what a second copy costs.
    // 384 until 2026-09-29: `change_path` is an `Option<CString>`, sixteen
    // bytes where the `char *` was eight; 392 until `inotify_path` did too,
    // 400 until `fs_data` became an owned `OnceLock<Box<dyn Any>>`, 416
    // until `dir` became a `OnceLock<Box<HostDir>>`, 424 until the union of
    // driver states became one owned `Option<Box<dyn Any>>`.
    assert_eq!(size_of::<ffi::fd>(), 432);
}

use status::{Kind, SETFL_MASK, at_open, setfl};

#[test]
fn an_open_keeps_its_status_flags_and_gains_o_largefile() {
    // Every line is fcntl_probe's on a real arm64 kernel.
    assert_eq!(
        at_open(ffi::O_RDWR_ | ffi::O_APPEND_),
        ffi::O_RDWR_ | ffi::O_APPEND_ | ffi::O_LARGEFILE_
    );
    assert_eq!(at_open(ffi::O_RDONLY_), ffi::O_LARGEFILE_);
    assert_eq!(
        at_open(ffi::O_RDONLY_ | ffi::O_DIRECTORY_),
        ffi::O_DIRECTORY_ | ffi::O_LARGEFILE_
    );
}

#[test]
fn an_open_consumes_the_creation_flags_and_o_cloexec() {
    let asked = ffi::O_WRONLY_
        | ffi::O_CREAT_
        | ffi::O_EXCL_
        | ffi::O_TRUNC_
        | ffi::O_NOCTTY_
        | ffi::O_CLOEXEC_;
    assert_eq!(at_open(asked), ffi::O_WRONLY_ | ffi::O_LARGEFILE_);
    // ...and keeps the ones that are not consumed.
    let kept = ffi::O_NOFOLLOW_ | ffi::O_SYNC_ | ffi::O_NOATIME_ | ffi::O_NONBLOCK_;
    assert_eq!(at_open(kept), kept | ffi::O_LARGEFILE_);
}

#[test]
fn o_path_beats_everything_else() {
    // An O_PATH description is O_PATH, O_DIRECTORY and O_NOFOLLOW, and
    // nothing else -- not the access mode, not O_LARGEFILE.
    assert_eq!(
        at_open(ffi::O_PATH_ | ffi::O_RDWR_ | ffi::O_APPEND_),
        ffi::O_PATH_
    );
    assert_eq!(
        at_open(ffi::O_PATH_ | ffi::O_DIRECTORY_ | ffi::O_NOFOLLOW_ | ffi::O_CLOEXEC_),
        ffi::O_PATH_ | ffi::O_DIRECTORY_ | ffi::O_NOFOLLOW_
    );
}

#[test]
fn setfl_changes_the_four_status_bits_and_nothing_else() {
    assert_eq!(
        SETFL_MASK,
        ffi::O_APPEND_ | ffi::O_NONBLOCK_ | ffi::O_DIRECT_ | ffi::O_NOATIME_
    );
    let file = ffi::O_RDWR_ | ffi::O_APPEND_ | ffi::O_LARGEFILE_;
    // The access mode, O_CLOEXEC, O_CREAT and O_SYNC are all ignored.
    assert_eq!(
        setfl(
            Kind::Regular,
            file,
            ffi::O_RDONLY_ | ffi::O_CLOEXEC_ | ffi::O_CREAT_ | ffi::O_SYNC_
        ),
        Ok(ffi::O_RDWR_ | ffi::O_LARGEFILE_)
    );
    // F_SETFL(0) clears O_APPEND -- the mask is replaced, not ORed.
    assert_eq!(
        setfl(Kind::Regular, file, 0),
        Ok(ffi::O_RDWR_ | ffi::O_LARGEFILE_)
    );
    assert_eq!(
        setfl(Kind::Regular, file, ffi::O_NONBLOCK_ | ffi::O_NOATIME_),
        Ok(ffi::O_RDWR_ | ffi::O_LARGEFILE_ | ffi::O_NONBLOCK_ | ffi::O_NOATIME_)
    );
    // A bit that means nothing is dropped, not refused.
    assert_eq!(
        setfl(Kind::Regular, file, 0x4000_0000),
        Ok(ffi::O_RDWR_ | ffi::O_LARGEFILE_)
    );
}

#[test]
fn o_direct_is_for_files_and_pipes() {
    assert_eq!(
        setfl(Kind::Regular, ffi::O_RDWR_, ffi::O_DIRECT_),
        Ok(ffi::O_RDWR_ | ffi::O_DIRECT_)
    );
    assert_eq!(
        setfl(Kind::Fifo, ffi::O_WRONLY_, ffi::O_DIRECT_),
        Ok(ffi::O_WRONLY_ | ffi::O_DIRECT_)
    );
    assert_eq!(setfl(Kind::Socket, ffi::O_RDWR_, ffi::O_DIRECT_), Err(-22));
    assert_eq!(setfl(Kind::Other, ffi::O_RDWR_, ffi::O_DIRECT_), Err(-22));
    // Turning it *off* is fine anywhere, and so is leaving it on.
    assert_eq!(
        setfl(Kind::Other, ffi::O_RDWR_ | ffi::O_DIRECT_, ffi::O_DIRECT_),
        Ok(ffi::O_RDWR_ | ffi::O_DIRECT_)
    );
}

#[test]
fn o_async_is_kept_only_where_sigio_can_come_from() {
    assert_eq!(
        setfl(Kind::Socket, ffi::O_RDWR_, ffi::O_ASYNC_),
        Ok(ffi::O_RDWR_ | ffi::O_ASYNC_)
    );
    assert_eq!(
        setfl(Kind::Fifo, ffi::O_RDONLY_, ffi::O_ASYNC_),
        Ok(ffi::O_RDONLY_ | ffi::O_ASYNC_)
    );
    assert_eq!(
        setfl(Kind::Regular, ffi::O_RDWR_, ffi::O_ASYNC_),
        Ok(ffi::O_RDWR_)
    );
    // And F_SETFL without it takes it away again.
    assert_eq!(
        setfl(Kind::Socket, ffi::O_RDWR_ | ffi::O_ASYNC_, 0),
        Ok(ffi::O_RDWR_)
    );
}

#[test]
fn the_kind_is_read_from_the_s_ifmt_bits() {
    assert_eq!(Kind::of_mode(0o100644), Kind::Regular);
    assert_eq!(Kind::of_mode(0o010600), Kind::Fifo);
    assert_eq!(Kind::of_mode(0o140777), Kind::Socket);
    assert_eq!(Kind::of_mode(0o040755), Kind::Other);
    assert_eq!(Kind::of_mode(0o020620), Kind::Other);
}
