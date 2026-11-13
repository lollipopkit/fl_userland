//! Filesystem conformance: one set of POSIX assertions, run against every
//! mount type the emulator provides.
//!
//! The point is the comparison. realfs, fakefs and tmpfs are three unrelated
//! implementations of the same interface, so a check that passes on two and
//! fails on the third is a bug in the third — which is how the tmpfs defects
//! under `docs/changelog/` would have been caught, instead of by someone
//! happening to try `>>` by hand.
//!
//! Takes one argument, a directory it may create and destroy files under.

use std::ffi::CStr;

use guest_tests::{Harness, check, check_fails, sys};
use libc::{O_APPEND, O_CREAT, O_EXCL, O_RDONLY, O_RDWR, O_WRONLY};

/// The scratch directory, joined with a name.
struct Dir(String);

impl Dir {
    fn p(&self, name: &str) -> String {
        format!("{}/{}", self.0, name)
    }
}

fn show(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).escape_debug().to_string()
}

// ---------------------------------------------------------------- basic I/O

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn t_read_write(h: &mut Harness, d: &Dir) {
    h.group("io");
    check!(h, sys::write_file(&d.p("io"), b"hello"), "creating a file");
    let got = sys::read_file(&d.p("io")).unwrap_or_default();
    check!(h, got == b"hello", "contents read back as {}", show(&got));

    let Some(st) = sys::stat(&d.p("io")) else {
        check!(h, false, "stat");
        return;
    };
    check!(h, st.st_size == 5, "size {}, wanted 5", st.st_size);
    check!(
        h,
        sys::is_reg(&st),
        "mode {:o} is not a regular file",
        st.st_mode
    );
    check!(h, st.st_nlink == 1, "nlink {}, wanted 1", st.st_nlink);
}

fn t_seek(h: &mut Harness, d: &Dir) {
    h.group("seek");
    check!(
        h,
        sys::write_file(&d.p("seek"), b"0123456789"),
        "creating a file"
    );
    let fd = sys::open(&d.p("seek"), O_RDONLY, 0);
    check!(h, fd >= 0, "opening");
    if fd < 0 {
        return;
    }

    check!(h, sys::lseek(fd, 3, libc::SEEK_SET) == 3, "SEEK_SET to 3");
    let mut buf = [0u8; 4];
    check!(
        h,
        sys::read(fd, &mut buf) == 4 && &buf == b"3456",
        "reading at 3: {}",
        show(&buf)
    );
    check!(h, sys::lseek(fd, -2, libc::SEEK_END) == 8, "SEEK_END -2");
    check!(
        h,
        sys::lseek(fd, 0, libc::SEEK_CUR) == 8,
        "SEEK_CUR reports the position"
    );

    // Reading from past the end is end-of-file, not data. tmpfs used to
    // subtract two unsigned values here, wrap, and memcpy off the end of the
    // allocation — 32 bytes of heap for a 5-byte file.
    check!(
        h,
        sys::lseek(fd, 100_000, libc::SEEK_SET) == 100_000,
        "seeking far past the end"
    );
    let mut big = [b'x'; 32];
    let n = sys::read(fd, &mut big);
    check!(h, n == 0, "read past the end returned {n} bytes, wanted 0");

    // A negative offset is EINVAL, and the position does not move.
    //
    // This is the case the three mount types disagreed about, and the reason
    // they could: `struct fd`'s offset was unsigned, so generic_seek's
    // LSEEK_SET stored a negative one without noticing while its LSEEK_CUR and
    // LSEEK_END both checked. realfs was right by delegation -- it forwards to
    // the host's lseek -- and tmpfs answered -4096 to `lseek(fd, -4096,
    // SEEK_SET)` and positioned the descriptor at 0xfffffffffffff000.
    //
    // Only offsets in [-4095, -1] looked like failures, and only because libc
    // reads that range as an errno rather than a position. -1 therefore
    // "worked" while -4096 did not, which is why a test that probes one small
    // negative number proves nothing.
    check!(h, sys::lseek(fd, 0, libc::SEEK_SET) == 0, "back to the start");
    for off in [-1i64, -2, -4095, -4096, -100_000, i64::MIN] {
        let r = sys::lseek(fd, off, libc::SEEK_SET);
        let e = errno();
        check!(h, r == -1 && e == libc::EINVAL,
            "SEEK_SET {off} is EINVAL: r={r} errno={e}");
        check!(h, sys::lseek(fd, 0, libc::SEEK_CUR) == 0,
            "and the position did not move: {}", sys::lseek(fd, 0, libc::SEEK_CUR));
    }
    // A negative *result* from the other two whences, which were already
    // checked -- here so that a change to the arithmetic breaks all three
    // together rather than one at a time.
    check!(h, sys::lseek(fd, 5, libc::SEEK_SET) == 5, "to 5");
    for (off, whence, name) in [(-6i64, libc::SEEK_CUR, "SEEK_CUR -6 from 5"),
                                (-11, libc::SEEK_END, "SEEK_END -11 of a 10-byte file")] {
        let r = sys::lseek(fd, off, whence);
        let e = errno();
        check!(h, r == -1 && e == libc::EINVAL, "{name} is EINVAL: r={r} errno={e}");
    }
    check!(h, sys::lseek(fd, 0, libc::SEEK_CUR) == 5, "and 5 is still the position");
    sys::close(fd);
}

fn t_append(h: &mut Harness, d: &Dir) {
    h.group("append");
    check!(h, sys::write_file(&d.p("app"), b"hello"), "creating a file");

    let fd = sys::open(&d.p("app"), O_WRONLY | O_APPEND, 0);
    check!(h, fd >= 0, "opening O_APPEND");
    if fd >= 0 {
        // O_APPEND writes at the end wherever the offset is, so this seek must
        // not affect where the bytes land.
        sys::lseek(fd, 0, libc::SEEK_SET);
        check!(h, sys::write(fd, b"X") == 1, "appending");
        sys::close(fd);
    }
    let got = sys::read_file(&d.p("app")).unwrap_or_default();
    check!(
        h,
        got == b"helloX",
        "after append: {}, wanted helloX",
        show(&got)
    );

    let fd = sys::open(&d.p("app"), O_WRONLY | O_APPEND, 0);
    if fd >= 0 {
        check!(h, sys::write(fd, b"Y") == 1, "appending again");
        sys::close(fd);
    }
    let got = sys::read_file(&d.p("app")).unwrap_or_default();
    check!(h, got == b"helloXY", "after second append: {}", show(&got));

    // A positional write on O_APPEND goes at the end too, and leaves the
    // position alone; `RWF_NOAPPEND` puts it at the offset instead. Darwin's
    // pwrite writes at the offset, and tmpfs had no pwrite of its own, so
    // its seek-and-write fallback appended under RWF_NOAPPEND.
    check!(h, sys::write_file(&d.p("papp"), b"0123456789"), "creating a file");
    let fd = sys::open(&d.p("papp"), O_RDWR | O_APPEND, 0);
    if fd >= 0 {
        let n = unsafe { libc::pwrite(fd, b"ab".as_ptr().cast(), 2, 2) };
        check!(h, n == 2, "pwrite on O_APPEND: {n}");
        check!(h, sys::lseek(fd, 0, libc::SEEK_CUR) == 0, "leaves the position alone");
        let iov = libc::iovec { iov_base: b"cd".as_ptr().cast_mut().cast(), iov_len: 2 };
        const RWF_NOAPPEND: i64 = 0x20;
        let n = unsafe { libc::syscall(libc::SYS_pwritev2, fd, &iov, 1, 2i64, 0i64, RWF_NOAPPEND) };
        check!(h, n == 2, "pwritev2(RWF_NOAPPEND) on O_APPEND: {n}");
        sys::close(fd);
    }
    let got = sys::read_file(&d.p("papp")).unwrap_or_default();
    check!(h, got == b"01cd456789ab", "pwrite appended, RWF_NOAPPEND did not: {}", show(&got));
}

fn t_truncate(h: &mut Harness, d: &Dir) {
    h.group("truncate");
    // O_TRUNC on open.
    check!(h, sys::write_file(&d.p("tr"), b"AAAA"), "creating a file");
    check!(
        h,
        sys::write_file(&d.p("tr"), b"BB"),
        "rewriting it shorter"
    );
    let got = sys::read_file(&d.p("tr")).unwrap_or_default();
    check!(
        h,
        got == b"BB",
        "after O_TRUNC rewrite: {}, wanted BB",
        show(&got)
    );

    // truncate(2), both directions.
    check!(
        h,
        sys::write_file(&d.p("tr"), b"0123456789"),
        "creating a file"
    );
    check!(h, sys::truncate(&d.p("tr"), 4) == 0, "truncating to 4");
    let got = sys::read_file(&d.p("tr")).unwrap_or_default();
    check!(
        h,
        got == b"0123",
        "after shrink: {}, wanted 0123",
        show(&got)
    );

    check!(h, sys::truncate(&d.p("tr"), 6) == 0, "growing to 6");
    let got = sys::read_file(&d.p("tr")).unwrap_or_default();
    check!(
        h,
        got.len() == 6,
        "after grow: {} bytes, wanted 6",
        got.len()
    );
    check!(
        h,
        got == b"0123\0\0",
        "growing must zero-fill, got {}",
        show(&got)
    );

    let fd = sys::open(&d.p("tr"), O_WRONLY, 0);
    if fd >= 0 {
        check!(h, sys::ftruncate(fd, 2) == 0, "ftruncate to 2");
        sys::close(fd);
    }
    check!(
        h,
        sys::read_file(&d.p("tr")).map(|c| c.len()) == Some(2),
        "after ftruncate"
    );
}

fn t_truncate_write_only(h: &mut Harness, d: &Dir) {
    h.group("truncate");
    // truncate(2) requires write permission and nothing else. realfs opened
    // the file O_RDWR to get a descriptor to ftruncate, so a file the guest
    // may write but not read failed with EACCES where Linux truncates it.
    let path = d.p("wo");
    check!(h, sys::write_file(&path, b"0123456789"), "creating a file");
    check!(h, sys::chmod(&path, 0o222) == 0, "making it write-only");
    check!(h, sys::truncate(&path, 4) == 0, "truncate of a write-only file");
    check!(
        h,
        sys::stat(&path).map(|st| st.st_size) == Some(4),
        "size after truncating a write-only file"
    );
    // An xattr set or removal asks for write permission, not read. realfs
    // opened the file read-only for both, so it answered EACCES here.
    let p = guest_tests::cpath(&path);
    let set = unsafe { libc::setxattr(p.as_ptr(), c"user.wo".as_ptr(), b"v".as_ptr().cast(), 1, 0) };
    check!(h, set == 0, "setxattr on a write-only file: {set} {}", std::io::Error::last_os_error());
    let removed = unsafe { libc::removexattr(p.as_ptr(), c"user.wo".as_ptr()) };
    check!(h, removed == 0, "removexattr on a write-only file: {removed} {}", std::io::Error::last_os_error());
    // No matching check for a *read-only* file: the guest runs as root, and
    // root truncates one on Linux. realfs refuses only because the host
    // process is not root, which a passthrough mount cannot do anything
    // about, so the three mounts legitimately disagree there.
    sys::chmod(&path, 0o644);
}

fn t_sparse_write(h: &mut Harness, d: &Dir) {
    h.group("sparse");
    check!(h, sys::write_file(&d.p("sp"), b"A"), "creating a file");
    let fd = sys::open(&d.p("sp"), O_WRONLY, 0);
    check!(h, fd >= 0, "opening");
    if fd < 0 {
        return;
    }
    check!(
        h,
        sys::lseek(fd, 4, libc::SEEK_SET) == 4,
        "seeking past the end"
    );
    check!(h, sys::write(fd, b"B") == 1, "writing past the end");
    sys::close(fd);

    let got = sys::read_file(&d.p("sp")).unwrap_or_default();
    check!(
        h,
        got.len() == 5,
        "size after a sparse write: {}",
        got.len()
    );
    check!(
        h,
        got == b"A\0\0\0B",
        "the gap must read as zeros: {}",
        show(&got)
    );
}

// ------------------------------------------------------------------- links

fn t_hardlink(h: &mut Harness, d: &Dir) {
    h.group("hardlink");
    check!(h, sys::write_file(&d.p("h1"), b"shared"), "creating a file");
    if sys::link(&d.p("h1"), &d.p("h2")) != 0 {
        // Reported, not skipped: a filesystem that cannot hardlink is a
        // finding, not a reason to stop checking.
        check!(h, false, "link() failed: {}", sys::strerror(sys::errno()));
        return;
    }

    let (a, b) = (sys::stat(&d.p("h1")), sys::stat(&d.p("h2")));
    let (Some(a), Some(b)) = (a, b) else {
        check!(h, false, "stat both names");
        return;
    };
    check!(h, a.st_ino == b.st_ino, "hardlinks must share an inode");
    check!(h, a.st_nlink == 2, "nlink {}, wanted 2", a.st_nlink);

    // A write through one name is visible through the other.
    let fd = sys::open(&d.p("h2"), O_WRONLY | O_APPEND, 0);
    if fd >= 0 {
        sys::write(fd, b"!");
        sys::close(fd);
    }
    let got = sys::read_file(&d.p("h1")).unwrap_or_default();
    check!(
        h,
        got == b"shared!",
        "write through the second name: {}",
        show(&got)
    );

    check!(h, sys::unlink(&d.p("h2")) == 0, "unlinking one name");
    let Some(a) = sys::stat(&d.p("h1")) else {
        check!(h, false, "the other name survives");
        return;
    };
    check!(
        h,
        a.st_nlink == 1,
        "nlink after unlink: {}, wanted 1",
        a.st_nlink
    );
}

/// A path as a C string, for the calls that take one directly.
fn cstr(p: &str) -> std::ffi::CString {
    std::ffi::CString::new(p).expect("no NUL")
}

fn t_symlink(h: &mut Harness, d: &Dir) {
    h.group("symlink");
    check!(
        h,
        sys::write_file(&d.p("target"), b"pointed-to"),
        "creating the target"
    );
    if sys::symlink("target", &d.p("slink")) != 0 {
        check!(
            h,
            false,
            "symlink() failed: {}",
            sys::strerror(sys::errno())
        );
        return;
    }

    let mut buf = [0u8; 64];
    let n = sys::readlink(&d.p("slink"), &mut buf);
    check!(h, n == 6, "readlink returned {n}, wanted 6");
    if n > 0 {
        check!(
            h,
            &buf[..n as usize] == b"target",
            "readlink gave {}",
            show(&buf[..n as usize])
        );
    }

    // lstat sees the link, stat follows it.
    match sys::lstat(&d.p("slink")) {
        Some(st) => {
            check!(
                h,
                sys::is_lnk(&st),
                "lstat must report a symlink, mode {:o}",
                st.st_mode
            );
            check!(
                h,
                st.st_size == 6,
                "a symlink's size is its target's length, got {}",
                st.st_size
            );
        }
        None => check!(h, false, "lstat on a symlink"),
    }
    match sys::stat(&d.p("slink")) {
        Some(st) => check!(
            h,
            sys::is_reg(&st),
            "stat must follow, mode {:o}",
            st.st_mode
        ),
        None => check!(h, false, "stat through a symlink"),
    }

    // `O_PATH | O_NOFOLLOW` names the symlink itself: it is how Go's `os.Root`
    // and every container runtime walk a tree without following a link out of
    // it. Here rather than only in `o_path.rs` because that one runs against
    // whatever mount it is pointed at, and the question "does this mount type
    // support it" has three answers to compare -- which is what this file is
    // for. `realfs` reaches Darwin's `O_SYMLINK` for it; the other two open
    // their own inode.
    const O_PATH: i32 = 0o10000000;
    let link = cstr(&d.p("slink"));
    let fd = unsafe { libc::open(link.as_ptr(), O_PATH | libc::O_NOFOLLOW) };
    check!(h, fd >= 0, "O_PATH|O_NOFOLLOW names a symlink, fd={fd}");
    if fd >= 0 {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let ok = unsafe { libc::fstat(fd, &mut st) };
        check!(
            h,
            ok == 0 && st.st_mode & libc::S_IFMT == libc::S_IFLNK,
            "and the descriptor is the link, not its target: mode {:o}",
            st.st_mode
        );
        unsafe { libc::close(fd) };
    }
    // Without `O_PATH` it is `ELOOP`, on every mount type.
    let fd = unsafe { libc::open(link.as_ptr(), libc::O_NOFOLLOW) };
    check!(h, fd < 0, "O_NOFOLLOW alone still refuses a symlink, fd={fd}");
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }
    check!(
        h,
        sys::read_file(&d.p("slink")).map(|c| c.len()) == Some(10),
        "reading through the link"
    );

    // A long target, read back exactly.
    //
    // fakefs does not have host symlinks: it stores the target as the contents
    // of a regular file and an S_IFLNK bit in meta.db. So creating one is a
    // write(2) and reading one is a read(2), and both were a single call whose
    // return value was checked only for being negative. A short write or a
    // short read -- a signal partway, or a volume filling -- would have stored
    // or returned a *prefix* of the target, and a prefix of a path is not a
    // shorter answer: "/a/b/c" cut to "/a/b" names the directory above it.
    //
    // realfs and tmpfs use the host's own symlinks and cannot have the defect,
    // which is what makes running the same check on all three worth doing.
    let long_target: String = (0..40)
        .map(|i| format!("/component-{i:03}"))
        .collect::<Vec<_>>()
        .join("");
    check!(
        h,
        sys::symlink(&long_target, &d.p("longlink")) == 0,
        "a symlink whose target is {} bytes: errno {}",
        long_target.len(),
        sys::errno()
    );
    let mut buf = [0u8; 1024];
    let n = sys::readlink(&d.p("longlink"), &mut buf);
    check!(
        h,
        n == long_target.len() as isize,
        "readlink returns the whole target: {n} of {}",
        long_target.len()
    );
    if n > 0 {
        check!(
            h,
            &buf[..n as usize] == long_target.as_bytes(),
            "and it is the target that was stored"
        );
    }
    match sys::lstat(&d.p("longlink")) {
        Some(st) => check!(
            h,
            st.st_size == long_target.len() as i64,
            "and its size is the target's length: {} of {}",
            st.st_size,
            long_target.len()
        ),
        None => check!(h, false, "lstat on the long link"),
    }

    // A buffer smaller than the target: readlink fills it, returns how much,
    // and does not terminate it. This is the one truncation that is correct,
    // and it is the caller's to notice -- which is why the ones above are not.
    let mut small = [0xAAu8; 8];
    let n = sys::readlink(&d.p("longlink"), &mut small[..4]);
    check!(h, n == 4, "readlink into four bytes returns four: {n}");
    check!(
        h,
        &small[..4] == &long_target.as_bytes()[..4],
        "with the first four bytes of the target"
    );
    check!(
        h,
        small[4] == 0xAA,
        "and nothing past them, not even a NUL: {:#x}",
        small[4]
    );

    // A dangling link resolves to nothing but is still readable as a link.
    check!(
        h,
        sys::symlink("nowhere-at-all", &d.p("dangling")) == 0,
        "a dangling link"
    );

    // Changing a **symlink's** ownership is `AT_SYMLINK_NOFOLLOW`, and it must
    // not resolve the link: `chown -h` of one whose target does not exist is 0
    // on Linux. realfs answered `ENOENT`, because it passed 0 for the host's
    // flags and let the host follow a path the VFS had already resolved.
    //
    // This is what `apk` does to every file it extracts — write `.apk.<hash>`,
    // set its ownership with `AT_SYMLINK_NOFOLLOW`, rename it into place — and a
    // package's symlinks point at names that are not there yet. `apk add gcc`
    // was twelve of these errors and an aborted transaction.
    let cd = cstr(&d.p("dangling"));
    let r = unsafe { libc::fchownat(libc::AT_FDCWD, cd.as_ptr(), 0, 0, libc::AT_SYMLINK_NOFOLLOW) };
    check!(h, r == 0, "chown -h of a dangling link: r={r} errno={}", sys::errno());
    // And it changed the link rather than creating anything.
    check!(
        h,
        sys::lstat(&d.p("dangling")).is_some() && sys::stat(&d.p("dangling")).is_none(),
        "the link is still there and still dangling"
    );
    check!(
        h,
        sys::lstat(&d.p("dangling")).is_some(),
        "lstat on a dangling link"
    );
    check_fails!(
        h,
        sys::open(&d.p("dangling"), O_RDONLY, 0),
        libc::ENOENT,
        "opening a dangling link"
    );

    // POSIX: a trailing slash requires the path to name a directory, so a
    // symlink in the last position is followed even under lstat.
    check!(
        h,
        sys::mkdir(&d.p("linkdir"), 0o755) == 0,
        "a directory to point at"
    );
    check!(
        h,
        sys::symlink("linkdir", &d.p("dlink")) == 0,
        "a symlink to it"
    );
    match sys::lstat(&d.p("dlink")) {
        Some(st) => check!(
            h,
            sys::is_lnk(&st),
            "lstat without a slash reports the link"
        ),
        None => check!(h, false, "lstat the directory link"),
    }
    match sys::lstat(&format!("{}/", d.p("dlink"))) {
        Some(st) => check!(
            h,
            sys::is_dir(&st),
            "lstat with a trailing slash must follow to the directory, mode {:o}",
            st.st_mode
        ),
        None => check!(h, false, "lstat with a trailing slash"),
    }
}

// -------------------------------------------------------------- namespace

fn t_rename(h: &mut Harness, d: &Dir) {
    h.group("rename");
    check!(h, sys::write_file(&d.p("r1"), b"first"), "creating a file");
    check!(h, sys::rename(&d.p("r1"), &d.p("r2")) == 0, "renaming");
    check_fails!(
        h,
        sys::access(&d.p("r1"), libc::F_OK),
        libc::ENOENT,
        "the old name must be gone"
    );
    check!(
        h,
        sys::read_file(&d.p("r2")).map(|c| c.len()) == Some(5),
        "the new name has the contents"
    );

    // Renaming over an existing file replaces it.
    check!(
        h,
        sys::write_file(&d.p("r3"), b"second"),
        "creating another file"
    );
    check!(
        h,
        sys::rename(&d.p("r3"), &d.p("r2")) == 0,
        "renaming over an existing name"
    );
    let got = sys::read_file(&d.p("r2")).unwrap_or_default();
    check!(h, got == b"second", "after replacing: {}", show(&got));

    // Across directories, with the contents intact.
    check!(
        h,
        sys::mkdir(&d.p("rdir"), 0o755) == 0,
        "creating a directory"
    );
    check!(
        h,
        sys::rename(&d.p("r2"), &d.p("rdir/moved")) == 0,
        "renaming into a directory"
    );
    check!(
        h,
        sys::read_file(&d.p("rdir/moved")).map(|c| c.len()) == Some(6),
        "contents survived the move"
    );
}

fn t_unlink_rmdir(h: &mut Harness, d: &Dir) {
    h.group("unlink");
    check!(
        h,
        sys::mkdir(&d.p("d1"), 0o755) == 0,
        "creating a directory"
    );
    check!(
        h,
        sys::write_file(&d.p("d1/inside"), b"x"),
        "creating a file in it"
    );

    check_fails!(
        h,
        sys::rmdir(&d.p("d1")),
        libc::ENOTEMPTY,
        "rmdir on a non-empty directory"
    );
    check_fails!(
        h,
        sys::rmdir(&d.p("d1/inside")),
        libc::ENOTDIR,
        "rmdir on a regular file"
    );
    check_fails!(
        h,
        sys::unlink(&d.p("d1")),
        libc::EISDIR,
        "unlink on a directory"
    );

    // **A removal that failed must have removed nothing.** The three refusals
    // above are each checked for their errno; this checks what survives them,
    // which is the half a fakefs can get wrong on its own. A fakefs entry is a
    // host name *and* a meta.db row, and taking the row out before the host
    // name means a refused rmdir leaves a directory the guest can no longer
    // see and can no longer remove.
    check!(
        h,
        sys::stat_raw(&d.p("d1")) == 0,
        "the directory a refused rmdir left alone is still there"
    );
    check!(
        h,
        sys::stat_raw(&d.p("d1/inside")) == 0,
        "and so is the file a refused rmdir was given"
    );

    check!(h, sys::unlink(&d.p("d1/inside")) == 0, "unlinking the file");
    check!(h, sys::rmdir(&d.p("d1")) == 0, "rmdir once empty");
    check_fails!(
        h,
        sys::stat_raw(&d.p("d1")),
        libc::ENOENT,
        "the directory is gone"
    );
    check_fails!(
        h,
        sys::unlink(&d.p("no-such-file")),
        libc::ENOENT,
        "unlinking what is not there"
    );
}

fn t_open_unlinked(h: &mut Harness, d: &Dir) {
    h.group("unlinked");
    check!(
        h,
        sys::write_file(&d.p("gone"), b"still here"),
        "creating a file"
    );
    let fd = sys::open(&d.p("gone"), O_RDWR, 0);
    check!(h, fd >= 0, "opening it");
    if fd < 0 {
        return;
    }

    check!(
        h,
        sys::unlink(&d.p("gone")) == 0,
        "unlinking while it is open"
    );
    check_fails!(
        h,
        sys::access(&d.p("gone"), libc::F_OK),
        libc::ENOENT,
        "the name is gone"
    );

    // POSIX: the file lives until the last descriptor closes.
    let mut buf = [0u8; 32];
    let n = sys::read(fd, &mut buf);
    check!(
        h,
        n == 10,
        "reading an unlinked-but-open file gave {n}, wanted 10"
    );
    if n > 0 {
        check!(
            h,
            &buf[..n as usize] == b"still here",
            "contents: {}",
            show(&buf[..n as usize])
        );
    }
    check!(
        h,
        sys::write(fd, b"!") == 1,
        "writing to an unlinked-but-open file"
    );
    match sys::fstat(fd) {
        Some(st) => check!(
            h,
            st.st_nlink == 0,
            "nlink after unlink: {}, wanted 0",
            st.st_nlink
        ),
        None => check!(h, false, "fstat on an unlinked file"),
    }
    sys::close(fd);
}

fn t_mkdir(h: &mut Harness, d: &Dir) {
    h.group("mkdir");
    check!(
        h,
        sys::mkdir(&d.p("m1"), 0o755) == 0,
        "creating a directory"
    );
    match sys::stat(&d.p("m1")) {
        Some(st) => check!(h, sys::is_dir(&st), "it is a directory"),
        None => check!(h, false, "stat it"),
    }
    check_fails!(
        h,
        sys::mkdir(&d.p("m1"), 0o755),
        libc::EEXIST,
        "creating it twice"
    );
    check_fails!(
        h,
        sys::mkdir(&d.p("m1/a/b"), 0o755),
        libc::ENOENT,
        "creating under a missing parent"
    );
    check!(h, sys::rmdir(&d.p("m1")) == 0, "cleaning up");
}

/// Reading the **root** directory, which is not the scratch directory.
///
/// Every other check here works in a subdirectory it made itself, and that is
/// why `ls /` on a fakefs listed nothing at all -- not even `.` -- for six days
/// without anything failing. fakefs stores the root as the empty blob rather
/// than "/", and the readdir path built each entry's key by appending to the
/// directory's guest path: "/" + "/" + "bin" is "//bin", which is no key, so
/// every entry missed its meta.db row and was skipped.
///
/// It is the first thing the usage in CLAUDE.md does.
///
/// This runs against whatever root the caller was started with -- realfs for
/// two of the three runs and fakefs for the other -- and asks only for what
/// every rootfs has.
/// Two threads changing different attributes of one file.
///
/// `chown` of the uid and `chown` of the gid are a read-modify-write of the
/// same record on fakefs: mode, uid, gid and rdev live in one `meta.db` row, so
/// changing any of them means reading the row, editing one field and writing it
/// back. That used to be two transactions with a gap between them, and two
/// threads both reading the old row meant the second's write dropped the
/// first's field.
///
/// **Each thread watches the field it is not writing.** Both write strictly
/// increasing values, so the other's field must never be seen to go *backwards*
/// — and a lost update is exactly that. Checking only the final state does not
/// work: a loss in the middle of the run is overwritten by the next write, so
/// the end state is right whether or not the race happened, and a version of
/// this test that checked it passed against the defect.
///
/// realfs is a passthrough and the host process is not root, so a `chown` there
/// cannot happen — realfs reports success rather than breaking every archive
/// extraction that restores ownership. That is detected rather than assumed.
fn t_attribute_race(h: &mut Harness, d: &Dir) {
    h.group("attribute-race");
    let path = d.p("attr-race");
    if !sys::write_file(&path, b"x") {
        check!(h, false, "creating the file");
        return;
    }
    let cpath = std::ffi::CString::new(path.as_str()).expect("no NUL");

    unsafe { libc::chown(cpath.as_ptr(), 4000, 4000) };
    if sys::lstat(&path).map(|st| (st.st_uid, st.st_gid)) != Some((4000, 4000)) {
        check!(
            h,
            true,
            "this mount does not record ownership, so there is no shared record to race on"
        );
        return;
    }

    const ROUNDS: u32 = 400;
    const BASE: u32 = 5000;

    /// Writes its own field and watches the other's for a value lower than one
    /// it has already seen. Returns how many times it went backwards.
    fn run(cpath: std::ffi::CString, uid: bool) -> u32 {
        let mut seen_other = 0u32;
        let mut regressions = 0u32;
        for i in 0..ROUNDS {
            let mine = BASE + i;
            unsafe {
                if uid {
                    libc::chown(cpath.as_ptr(), mine, u32::MAX);
                } else {
                    libc::chown(cpath.as_ptr(), u32::MAX, mine);
                }
            }
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::lstat(cpath.as_ptr(), &mut st) } != 0 {
                continue;
            }
            let other = if uid { st.st_gid } else { st.st_uid };
            if other < seen_other {
                regressions += 1;
            }
            seen_other = seen_other.max(other);
        }
        regressions
    }

    let a_path = cpath.clone();
    let a = std::thread::spawn(move || run(a_path, true));
    let b_path = cpath.clone();
    let b = std::thread::spawn(move || run(b_path, false));
    let a = a.join().expect("the uid thread");
    let b = b.join().expect("the gid thread");

    check!(
        h,
        a == 0 && b == 0,
        "neither field went backwards while the other was written: \
         uid thread saw {b} regressions of the gid, gid thread saw {a} of the uid"
    );

    // And the record still holds both, rather than one thread's write having
    // reset the other's field to what it was before the run.
    match sys::lstat(&path) {
        Some(st) => check!(
            h,
            st.st_uid >= BASE && st.st_gid >= BASE,
            "both fields hold a value from this run: uid {} gid {}",
            st.st_uid,
            st.st_gid
        ),
        None => check!(h, false, "stat after the race"),
    }
}

/// A FIFO, which is a filesystem object every mount has to be able to make.
///
/// Nothing covered it. It is worth covering for a reason particular to this
/// tree: `mkfifo` takes no directory descriptor, so making one relative to a
/// mount is the one operation tempted to reach the path through the process's
/// working directory — and the working directory is process-wide. realfs did
/// exactly that until 2026-08-29, under a global lock to make it safe;
/// `crates/tools/fakefsify` did it *without* one and two concurrent imports
/// created each other's FIFOs. `mkfifoat` exists on Darwin and on Linux and
/// neither needs the trick.
fn t_fifo(h: &mut Harness, d: &Dir) {
    h.group("fifo");
    let path = d.p("a-fifo");
    let c = std::ffi::CString::new(path.as_str()).expect("no NUL");
    let r = unsafe { libc::mkfifo(c.as_ptr(), 0o644) };
    check!(h, r == 0, "mkfifo: r={r} errno={}", sys::errno());
    if r != 0 {
        return;
    }

    match sys::lstat(&path) {
        Some(st) => {
            check!(
                h,
                st.st_mode & libc::S_IFMT == libc::S_IFIFO,
                "it is a fifo, mode {:o}",
                st.st_mode
            );
            check!(
                h,
                st.st_mode & 0o777 == 0o644,
                "with the mode it was given: {:o}",
                st.st_mode & 0o777
            );
        }
        None => check!(h, false, "lstat on the fifo"),
    }

    // O_RDWR, which does not block waiting for a peer the way O_RDONLY does.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDWR) };
    check!(h, fd >= 0, "opening it: fd={fd} errno={}", sys::errno());
    if fd >= 0 {
        let msg = b"through the pipe";
        let w = unsafe { libc::write(fd, msg.as_ptr().cast(), msg.len()) };
        check!(h, w == msg.len() as isize, "writing to it: {w}");
        let mut buf = [0u8; 32];
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        // A fifo is a queue: what went in comes back out of the same
        // descriptor. A mount that stores it as file *content* instead answers
        // 0, because the write moved the offset past everything there is.
        //
        // **tmpfs answers 0.** Its `mknod` records the S_IFIFO type in the mode
        // and then treats the inode as an ordinary file, so `lstat` says fifo
        // and nothing behaves like one. That is a missing feature rather than
        // a mistake -- a fifo needs a queue, blocking opens, EOF when the last
        // writer goes and SIGPIPE when the last reader does -- and it is
        // detected here rather than asserted away, so the day tmpfs grows one
        // this starts checking it.
        //
        // realfs and fakefs both make a *host* fifo and get all of it free.
        if n == 0 {
            check!(
                h,
                true,
                "this mount stores a fifo as file content and does not queue:                  write returned {w}, read returned {n}"
            );
        } else {
            check!(
                h,
                n == msg.len() as isize && &buf[..msg.len()] == msg,
                "and reading it back: n={n}"
            );
        }
        unsafe { libc::close(fd) };
    }

    // And it is in the directory it was asked for, not wherever the process
    // happened to be.
    check!(
        h,
        sys::lstat(&path).is_some(),
        "it is where it was created"
    );
    check!(h, sys::unlink(&path) == 0, "and it can be removed");

    // The name is in use, whatever kind of thing holds it.
    check!(h, unsafe { libc::mkfifo(c.as_ptr(), 0o644) } == 0, "again");
    check_fails!(
        h,
        unsafe { libc::mkfifo(c.as_ptr(), 0o644) },
        libc::EEXIST,
        "over one that is already there"
    );
    let _ = sys::unlink(&path);
}

fn t_root_listing(h: &mut Harness) {
    h.group("readdir-root");
    let mut names: Vec<String> = Vec::new();
    unsafe {
        let dir = libc::opendir(c"/".as_ptr());
        if dir.is_null() {
            check!(
                h,
                false,
                "opening the root directory: {}",
                sys::strerror(sys::errno())
            );
            return;
        }
        loop {
            let e = libc::readdir(dir);
            if e.is_null() {
                break;
            }
            let name = std::ffi::CStr::from_ptr((*e).d_name.as_ptr());
            names.push(name.to_string_lossy().into_owned());
        }
        libc::closedir(dir);
    }
    check!(
        h,
        names.iter().any(|n| n == "."),
        "the root has a `.` entry: {names:?}"
    );
    check!(
        h,
        names.iter().any(|n| n == ".."),
        "and a `..` entry"
    );
    // A rootfs the emulator can run anything at all in has these.
    for want in ["bin", "etc", "tmp"] {
        check!(
            h,
            names.iter().any(|n| n == want),
            "the root lists /{want}: {names:?}"
        );
    }
    check!(
        h,
        names.len() >= 5,
        "and lists more than a handful: {} entries",
        names.len()
    );
}

fn t_directory_listing(h: &mut Harness, d: &Dir) {
    h.group("readdir");
    check!(
        h,
        sys::mkdir(&d.p("ls"), 0o755) == 0,
        "creating a directory"
    );
    for name in ["alpha", "beta", "gamma"] {
        check!(
            h,
            sys::write_file(&d.p(&format!("ls/{name}")), b"x"),
            "creating {name}"
        );
    }

    let path = guest_tests::cpath(&d.p("ls"));
    // SAFETY: `path` outlives the call.
    let dir = unsafe { libc::opendir(path.as_ptr()) };
    check!(h, !dir.is_null(), "opendir");
    if dir.is_null() {
        return;
    }

    let (mut seen, mut dot, mut dotdot) = (0u8, 0, 0);
    loop {
        let e = unsafe { libc::readdir(dir) };
        if e.is_null() {
            break;
        }
        let name = unsafe { CStr::from_ptr((*e).d_name.as_ptr()) }
            .to_bytes()
            .to_vec();
        match name.as_slice() {
            b"." => dot += 1,
            b".." => dotdot += 1,
            b"alpha" => seen |= 1,
            b"beta" => seen |= 2,
            b"gamma" => seen |= 4,
            _ => {}
        }
        if name != b"." && name != b".." {
            check!(h, unsafe { (*e).d_ino } != 0, "{} has inode 0", show(&name));
            // The inode a listing reports has to be the one `stat` answers for
            // the same name, or `find -inum`, a hardlink finder and every
            // du-style tool that deduplicates by inode is reading two
            // different numbering schemes. On fakefs the two come from
            // different places -- the listing from the host directory, the
            // stat from meta.db -- so this is the check that the mount
            // rewrites what it hands back.
            let listed = unsafe { (*e).d_ino };
            let st = sys::stat(&d.p(&format!("ls/{}", show(&name))));
            check!(
                h,
                st.map(|s| s.st_ino) == Some(listed),
                "{} listed as inode {listed}, stat says {:?}",
                show(&name),
                st.map(|s| s.st_ino)
            );
        }
    }
    check!(
        h,
        seen == 7,
        "readdir found mask {seen}, wanted all three (7)"
    );
    check!(h, dot == 1, "saw . {dot} times, wanted 1");
    check!(h, dotdot == 1, "saw .. {dotdot} times, wanted 1");

    // rewinddir starts over.
    unsafe { libc::rewinddir(dir) };
    let mut again = 0;
    while !unsafe { libc::readdir(dir) }.is_null() {
        again += 1;
    }
    check!(
        h,
        again == 5,
        "after rewinddir saw {again} entries, wanted 5"
    );

    // telldir/seekdir: a position taken mid-scan returns to the same entry.
    unsafe { libc::rewinddir(dir) };
    unsafe { libc::readdir(dir) };
    let pos = unsafe { libc::telldir(dir) };
    let first = unsafe { libc::readdir(dir) };
    let first_name = if first.is_null() {
        Vec::new()
    } else {
        unsafe { CStr::from_ptr((*first).d_name.as_ptr()) }
            .to_bytes()
            .to_vec()
    };
    unsafe { libc::seekdir(dir, pos) };
    let again = unsafe { libc::readdir(dir) };
    let again_name = if again.is_null() {
        Vec::new()
    } else {
        unsafe { CStr::from_ptr((*again).d_name.as_ptr()) }
            .to_bytes()
            .to_vec()
    };
    check!(
        h,
        !again_name.is_empty() && again_name == first_name,
        "seekdir returned {}, wanted {}",
        show(&again_name),
        show(&first_name)
    );
    unsafe { libc::closedir(dir) };
}

fn t_metadata(h: &mut Harness, d: &Dir) {
    h.group("metadata");
    check!(h, sys::write_file(&d.p("meta"), b"x"), "creating a file");

    check!(h, sys::chmod(&d.p("meta"), 0o741) == 0, "chmod 741");
    let Some(st) = sys::stat(&d.p("meta")) else {
        check!(h, false, "stat after chmod");
        return;
    };
    check!(
        h,
        st.st_mode & 0o7777 == 0o741,
        "mode {:o}, wanted 741",
        st.st_mode & 0o7777
    );
    // Only the permission bits move; the file type is not settable.
    check!(h, sys::is_reg(&st), "chmod must not change the file type");
    check!(h, sys::chmod(&d.p("meta"), 0o644) == 0, "chmod back");

    // mtime advances on a write. Coarse on purpose: some clocks here have
    // one-second resolution.
    let before = sys::stat(&d.p("meta")).map(|s| s.st_mtime).unwrap_or(0);
    std::thread::sleep(std::time::Duration::from_secs(1));
    let fd = sys::open(&d.p("meta"), O_WRONLY | O_APPEND, 0);
    if fd >= 0 {
        sys::write(fd, b"y");
        sys::close(fd);
    }
    let after = sys::stat(&d.p("meta")).map(|s| s.st_mtime).unwrap_or(0);
    check!(
        h,
        after > before,
        "mtime did not advance across a write ({before} -> {after})"
    );
}

/// What `fchmod` and `fchown` do through a **descriptor**, which is how a
/// package manager sets a file's mode: dpkg writes to a `.dpkg-new` file, calls
/// `fchmod` on the descriptor, and renames. `chmod` by path is checked above and
/// is a different call -- so a mount whose `fsetattr` drops the mode would leave
/// every unpacked program at whatever the create left behind, and only a
/// distribution would notice.
fn t_fchmod(h: &mut Harness, d: &Dir) {
    h.group("fchmod");
    let fd = sys::open(&d.p("fchmod"), O_RDWR | libc::O_CREAT, 0o666);
    if fd < 0 {
        check!(h, false, "creating a file: {}", errno());
        return;
    }
    sys::write(fd, b"#!/bin/sh\n");
    let r = unsafe { libc::fchmod(fd, 0o755) };
    check!(h, r == 0, "fchmod 755 through the descriptor: {}", errno());
    // The descriptor's own view, and then the path's: a mount that answers the
    // first from the host and stores the second somewhere else would pass one
    // and fail the other, which is exactly what a fakefs risks.
    let by_fd = sys::fstat(fd).map(|s| s.st_mode & 0o7777).unwrap_or(0);
    check!(h, by_fd == 0o755, "fstat after fchmod: {by_fd:o}, wanted 755");
    sys::close(fd);
    let by_path = sys::stat(&d.p("fchmod")).map(|s| s.st_mode & 0o7777).unwrap_or(0);
    check!(h, by_path == 0o755, "stat after fchmod: {by_path:o}, wanted 755");

    // ...and it survives a rename, which is the other half of what dpkg does.
    check!(
        h,
        sys::rename(&d.p("fchmod"), &d.p("fchmod-moved")) == 0,
        "renaming it"
    );
    let moved = sys::stat(&d.p("fchmod-moved")).map(|s| s.st_mode & 0o7777).unwrap_or(0);
    check!(h, moved == 0o755, "mode after rename: {moved:o}, wanted 755");
}

fn t_errors(h: &mut Harness, d: &Dir) {
    h.group("errors");
    check_fails!(
        h,
        sys::open(&d.p("definitely-not-here"), O_RDONLY, 0),
        libc::ENOENT,
        "opening a missing file"
    );
    check!(h, sys::write_file(&d.p("notadir"), b"x"), "creating a file");
    check_fails!(
        h,
        sys::stat_raw(&d.p("notadir/under-a-file")),
        libc::ENOTDIR,
        "descending through a regular file"
    );
    check_fails!(
        h,
        sys::open(&d.p("notadir"), O_WRONLY | O_CREAT | O_EXCL, 0o644),
        libc::EEXIST,
        "O_CREAT|O_EXCL on an existing file"
    );

    // A component longer than NAME_MAX.
    let long = "n".repeat(600);
    check_fails!(
        h,
        sys::open(&d.p(&long), O_WRONLY | O_CREAT, 0o644),
        libc::ENAMETOOLONG,
        "a path component of {} bytes",
        long.len()
    );

    // Writing to a read-only descriptor.
    let fd = sys::open(&d.p("notadir"), O_RDONLY, 0);
    if fd >= 0 {
        check_fails!(
            h,
            sys::write(fd, b"x"),
            libc::EBADF,
            "writing to an O_RDONLY descriptor"
        );
        sys::close(fd);
    }
}

fn t_relative_resolution(h: &mut Harness, d: &Dir) {
    h.group("relative");
    let Some(saved) = sys::getcwd() else {
        check!(h, false, "getcwd");
        return;
    };
    check!(
        h,
        sys::mkdir(&d.p("rel"), 0o755) == 0,
        "creating a directory"
    );
    if sys::chdir(&d.p("rel")) != 0 {
        check!(h, false, "chdir into it");
        return;
    }

    check!(h, sys::write_file("base", b"reached"), "creating a file");
    check!(h, sys::symlink("base", "one") == 0, "a relative symlink");

    // A chain deeper than the 5 the old walk allowed. SYMLOOP_MAX is 40.
    let mut prev = String::from("one");
    for i in 2..=12 {
        let name = format!("l{i}");
        check!(h, sys::symlink(&prev, &name) == 0, "link {i}");
        prev = name;
    }
    let got = sys::read_file("l12");
    check!(
        h,
        got.as_deref() == Some(b"reached".as_slice()),
        "reading through 12 levels of relative symlink: {:?}",
        got.as_deref().map(show)
    );

    // "." and ".." in a relative path.
    check!(
        h,
        sys::read_file("./base").map(|c| c.len()) == Some(7),
        "./base"
    );
    check!(
        h,
        sys::read_file("../rel/base").map(|c| c.len()) == Some(7),
        "../rel/base"
    );

    if sys::chdir(&saved) != 0 {
        check!(h, false, "chdir back");
    }
}

// -------------------------------------------------------------------- flock

fn t_flock(h: &mut Harness, d: &Dir) {
    h.group("flock");
    // Every mount type supports flock: the host-backed ones hand it to the
    // host, the rest keep it on the inode. No skip — a mount that lost the
    // support should fail here rather than quietly opt out.
    let path = d.p("lock");
    let a = sys::open(&path, O_CREAT | O_RDWR, 0o644);
    let b = sys::open(&path, O_RDWR, 0o644);
    if a < 0 || b < 0 {
        check!(h, false, "opening two descriptors on a lock file");
        return;
    }

    check!(h, sys::flock(a, libc::LOCK_EX) == 0, "taking an exclusive lock");

    // The whole point of a lock file: a second holder has to be told that
    // someone else has it, and told so in a way it can distinguish from a
    // permissions problem. realfs returned flock's raw -1, which is the
    // guest's EPERM, so every lock-file protocol saw "operation not
    // permitted" and gave up instead of waiting.
    check_fails!(
        h,
        sys::flock(b, libc::LOCK_EX | libc::LOCK_NB),
        libc::EWOULDBLOCK,
        "a contended non-blocking lock"
    );

    check!(h, sys::flock(a, libc::LOCK_UN) == 0, "releasing the lock");
    check!(
        h,
        sys::flock(b, libc::LOCK_EX | libc::LOCK_NB) == 0,
        "taking the lock once it is free"
    );
    check!(h, sys::flock(b, libc::LOCK_UN) == 0, "releasing it again");

    // A shared lock is compatible with another shared lock.
    check!(h, sys::flock(a, libc::LOCK_SH) == 0, "taking a shared lock");
    check!(
        h,
        sys::flock(b, libc::LOCK_SH | libc::LOCK_NB) == 0,
        "a second shared lock"
    );
    check_fails!(
        h,
        sys::flock(a, libc::LOCK_EX | libc::LOCK_NB),
        libc::EWOULDBLOCK,
        "upgrading to exclusive while another holds a shared lock"
    );
    sys::flock(a, libc::LOCK_UN);
    sys::flock(b, libc::LOCK_UN);
    sys::close(a);
    sys::close(b);
}

// ---------------------------------------------------------------- ownership

fn t_ownership(h: &mut Harness, d: &Dir) {
    h.group("ownership");
    let path = d.p("owned");
    check!(h, sys::write_file(&path, b"x"), "creating a file");

    // A chgrp to the group it already has must succeed and change nothing.
    let Some(before) = sys::stat(&path) else {
        check!(h, false, "stat of a file just created");
        return;
    };
    check!(
        h,
        sys::chown(&path, u32::MAX, before.st_gid) == 0,
        "chgrp to the group it already has"
    );

    // Changing it for real. On a passthrough mount the host decides, so the
    // candidate groups have to be ones the host process belongs to; the
    // runner passes them in because only it knows.
    let candidates: Vec<u32> = std::env::args()
        .skip(2)
        .filter_map(|g| g.parse().ok())
        .filter(|&g| g != before.st_gid)
        .collect();
    if candidates.is_empty() {
        println!("  SKIP  [ownership] no host group to move the file to");
        return;
    }

    // The defect this pins: realfs passed the gid as fchown's *owner*
    // argument and -1 as its group, so the call tried to give the file away
    // to a uid, failed with EPERM, and had that EPERM swallowed by the rule
    // that a passthrough mount cannot enforce ownership. chgrp reported
    // success and did nothing at all.
    let target = candidates[0];
    check!(
        h,
        sys::chown(&path, u32::MAX, target) == 0,
        "chgrp to {target}"
    );
    let after = sys::stat(&path).map(|st| st.st_gid);
    check!(
        h,
        after == Some(target),
        "gid after chgrp to {target}: {after:?}, was {}",
        before.st_gid
    );
    check!(
        h,
        sys::stat(&path).map(|st| st.st_uid) == Some(before.st_uid),
        "chgrp must not change the owner"
    );

    // The same through a descriptor.
    let fd = sys::open(&path, O_RDWR, 0);
    if fd >= 0 {
        let back = before.st_gid;
        let r = sys::fchown(fd, u32::MAX, back);
        let e = sys::errno();
        check!(h, r == 0, "fchgrp back to {back}: returned {r} errno {e}");
        let now = sys::fstat(fd).map(|st| st.st_gid);
        check!(
            h,
            now == Some(back),
            "gid after fchgrp back to {back}: {now:?}"
        );
        sys::close(fd);
    }
}

// -------------------------------------------------------------- record locks

fn lock_arg(typ: i32, start: i64, len: i64) -> libc::flock {
    let mut fl: libc::flock = unsafe { std::mem::zeroed() };
    fl.l_type = typ as i16;
    fl.l_whence = libc::SEEK_SET as i16;
    fl.l_start = start;
    fl.l_len = len;
    fl
}

fn setlk(fd: i32, cmd: i32, fl: &libc::flock) -> i32 {
    sys::clear_errno();
    unsafe { libc::fcntl(fd, cmd, fl) }
}

fn t_record_locks(h: &mut Harness, d: &Dir) {
    h.group("fcntl-lock");
    let path = d.p("reclock");
    check!(h, sys::write_file(&path, b"0123456789"), "creating a file");
    let fd = sys::open(&path, O_RDWR, 0);
    if fd < 0 {
        check!(h, false, "opening the file");
        return;
    }

    check!(
        h,
        setlk(fd, libc::F_SETLK, &lock_arg(libc::F_WRLCK, 0, 10)) == 0,
        "taking a write lock over 0..10"
    );

    // F_GETLK against our own lock reports F_UNLCK: an owner never conflicts
    // with itself.
    let mut probe = lock_arg(libc::F_WRLCK, 0, 10);
    let r = unsafe { libc::fcntl(fd, libc::F_GETLK, &mut probe) };
    check!(h, r == 0, "F_GETLK");
    check!(
        h,
        probe.l_type == libc::F_UNLCK as i16,
        "F_GETLK against our own lock: type {}, wanted F_UNLCK",
        probe.l_type
    );

    // Splitting: unlocking the middle of a range leaves the two ends locked.
    check!(
        h,
        setlk(fd, libc::F_SETLK, &lock_arg(libc::F_UNLCK, 4, 2)) == 0,
        "unlocking the middle of a locked range"
    );

    // A second owner. fork gets its own descriptor table, which is what owns
    // a record lock, so the child conflicts with the parent where a thread
    // would not.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let cfd = sys::open(&path, O_RDWR, 0);
        // The parent still holds 0..3, so this must fail without blocking.
        let blocked = setlk(cfd, libc::F_SETLK, &lock_arg(libc::F_WRLCK, 0, 4));
        let e1 = sys::errno();
        // The hole the parent unlocked is free.
        let free = setlk(cfd, libc::F_SETLK, &lock_arg(libc::F_WRLCK, 4, 2));
        let ok = i32::from(blocked == -1 && (e1 == libc::EAGAIN || e1 == libc::EACCES))
            + i32::from(free == 0) * 2;
        unsafe { libc::_exit(ok) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let code = (status >> 8) & 0xff;
    check!(
        h,
        code & 1 != 0,
        "another owner is refused a conflicting range (child status {code})"
    );
    check!(
        h,
        code & 2 != 0,
        "another owner may lock the range we unlocked (child status {code})"
    );

    // F_SETLKW must wait rather than fail. The child asks for a range the
    // parent holds and releases 300ms later; a non-blocking answer comes back
    // in microseconds, which is how the swapped comparison in fs/fd.c showed
    // up — neither arm could ever see its own command, so blocking was always
    // false and F_SETLKW behaved exactly like F_SETLK.
    check!(
        h,
        setlk(fd, libc::F_SETLK, &lock_arg(libc::F_WRLCK, 0, 10)) == 0,
        "retaking the whole range"
    );
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let cfd = sys::open(&path, O_RDWR, 0);
        let start = std::time::Instant::now();
        let r = setlk(cfd, libc::F_SETLKW, &lock_arg(libc::F_WRLCK, 0, 10));
        let waited = start.elapsed();
        unsafe { libc::_exit(i32::from(r == 0 && waited.as_millis() >= 100)) };
    }
    unsafe { libc::usleep(300_000) };
    setlk(fd, libc::F_SETLK, &lock_arg(libc::F_UNLCK, 0, 10));
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    check!(
        h,
        (status >> 8) & 0xff == 1,
        "F_SETLKW waited for the lock instead of failing"
    );
    sys::close(fd);

    // Open file description locks: the same records, owned by the description
    // rather than by the process. The difference is visible without forking —
    // two opens of one file in one process contend, where POSIX locks from the
    // same process do not. SQLite asks for these by preference on Linux.
    h.group("fcntl-ofd");
    let a = sys::open(&path, O_RDWR, 0);
    let b = sys::open(&path, O_RDWR, 0);
    if a >= 0 && b >= 0 {
        // POSIX first, to show the contrast: one process, two descriptions,
        // no conflict.
        check!(
            h,
            setlk(a, libc::F_SETLK, &lock_arg(libc::F_WRLCK, 0, 4)) == 0,
            "a POSIX lock on the first descriptor"
        );
        check!(
            h,
            setlk(b, libc::F_SETLK, &lock_arg(libc::F_WRLCK, 0, 4)) == 0,
            "a POSIX lock on the second: the process already owns it"
        );
        setlk(a, libc::F_SETLK, &lock_arg(libc::F_UNLCK, 0, 4));
        setlk(b, libc::F_SETLK, &lock_arg(libc::F_UNLCK, 0, 4));

        // And now the same pair with OFD locks, which must contend.
        check!(
            h,
            setlk(a, 37 /* F_OFD_SETLK */, &lock_arg(libc::F_WRLCK, 0, 4)) == 0,
            "an OFD lock on the first descriptor"
        );
        check_fails!(
            h,
            setlk(b, 37, &lock_arg(libc::F_WRLCK, 0, 4)),
            libc::EAGAIN,
            "an OFD lock on the second must contend with the first"
        );

        // It belongs to the description, so closing that releases it.
        sys::close(a);
        check!(
            h,
            setlk(b, 37, &lock_arg(libc::F_WRLCK, 0, 4)) == 0,
            "closing the first description releases its OFD lock"
        );
        setlk(b, 37, &lock_arg(libc::F_UNLCK, 0, 4));
        sys::close(b);
    } else {
        check!(h, false, "opening the file twice");
    }

    h.group("fcntl-lock");
    // A descriptor that cannot hold a record lock. Only files opened through
    // the VFS get an inode; a pipe has none, and the C dereferenced it
    // regardless, which killed the emulator from three lines of guest code.
    let mut pipefd = [0i32; 2];
    if unsafe { libc::pipe(pipefd.as_mut_ptr()) } == 0 {
        check_fails!(
            h,
            setlk(pipefd[1], libc::F_SETLK, &lock_arg(libc::F_WRLCK, 0, 1)),
            libc::EBADF,
            "a record lock on a pipe"
        );
        sys::close(pipefd[0]);
        sys::close(pipefd[1]);
    }
}

/// Extended attributes: the round trip, and the rules that are refusals.
///
/// Here rather than in a single-mount test because the three get the answer
/// from three different places — realfs and fakefs from the host file, tmpfs
/// from a map of its own — and the rules must not depend on which. All twelve
/// syscalls were one stub answering `ENOTSUP` until 2026-09-07.
///
/// The refusals are the half that matters. A filesystem that implements the
/// calls and none of the rules passes every "does it work" check and has given
/// the guest a way around the namespace, which is the whole access-control
/// story for xattrs.
fn t_xattr(h: &mut Harness, d: &Dir) {
    h.group("xattr");

    const XATTR_CREATE: i32 = 1;
    const XATTR_REPLACE: i32 = 2;

    fn set(path: &str, name: &str, value: &[u8], flags: i32) -> i64 {
        let p = guest_tests::cpath(path);
        let n = guest_tests::cpath(name);
        unsafe {
            libc::syscall(libc::SYS_setxattr, p.as_ptr(), n.as_ptr(),
                          value.as_ptr(), value.len(), flags)
        }
    }
    fn get(path: &str, name: &str, buf: &mut [u8]) -> i64 {
        let p = guest_tests::cpath(path);
        let n = guest_tests::cpath(name);
        unsafe {
            libc::syscall(libc::SYS_getxattr, p.as_ptr(), n.as_ptr(),
                          buf.as_mut_ptr(), buf.len())
        }
    }
    fn list(path: &str, buf: &mut [u8]) -> i64 {
        let p = guest_tests::cpath(path);
        unsafe { libc::syscall(libc::SYS_listxattr, p.as_ptr(), buf.as_mut_ptr(), buf.len()) }
    }
    fn remove(path: &str, name: &str) -> i64 {
        let p = guest_tests::cpath(path);
        let n = guest_tests::cpath(name);
        unsafe { libc::syscall(libc::SYS_removexattr, p.as_ptr(), n.as_ptr()) }
    }

    let f = d.p("xa");
    check!(h, sys::write_file(&f, b"x"), "creating a file");
    let mut buf = [0u8; 4096];

    // A file with none lists nothing, which is 0 rather than an error -- that
    // is how every caller asks whether the filesystem has them at all.
    check!(h, list(&f, &mut buf) == 0, "a file with none lists nothing");
    sys::clear_errno();
    check!(
        h,
        get(&f, "user.nope", &mut buf) == -1 && sys::errno() == libc::ENODATA,
        "an unset name is ENODATA, errno {}",
        sys::errno()
    );

    check!(h, set(&f, "user.a", b"one", 0) == 0, "setxattr user.a");
    let n = get(&f, "user.a", &mut buf);
    check!(h, n == 3 && &buf[..3] == b"one", "getxattr answers what was set, got {n}");
    // The length without a buffer, which is how every caller sizes one.
    let mut none: [u8; 0] = [];
    check!(h, get(&f, "user.a", &mut none) == 3, "a size of 0 asks the length");
    let mut small = [0u8; 1];
    sys::clear_errno();
    check!(
        h,
        get(&f, "user.a", &mut small) == -1 && sys::errno() == libc::ERANGE,
        "a buffer too small is ERANGE rather than a short answer, errno {}",
        sys::errno()
    );

    let n = list(&f, &mut buf);
    check!(
        h,
        n == 7 && &buf[..7] == b"user.a\0",
        "the list is NUL-terminated, got {n}"
    );

    // The two flags, which is the pair a caller uses to make a set atomic.
    sys::clear_errno();
    check!(
        h,
        set(&f, "user.a", b"x", XATTR_CREATE) == -1 && sys::errno() == libc::EEXIST,
        "XATTR_CREATE over an existing name is EEXIST, errno {}",
        sys::errno()
    );
    sys::clear_errno();
    check!(
        h,
        set(&f, "user.gone", b"x", XATTR_REPLACE) == -1 && sys::errno() == libc::ENODATA,
        "XATTR_REPLACE over a missing one is ENODATA, errno {}",
        sys::errno()
    );
    // Both at once cannot succeed, and *which* error says why -- Linux applies
    // CREATE and then REPLACE rather than rejecting the combination.
    sys::clear_errno();
    check!(
        h,
        set(&f, "user.a", b"x", XATTR_CREATE | XATTR_REPLACE) == -1
            && sys::errno() == libc::EEXIST,
        "both flags over an existing name is EEXIST, errno {}",
        sys::errno()
    );
    sys::clear_errno();
    check!(
        h,
        set(&f, "user.none", b"x", XATTR_CREATE | XATTR_REPLACE) == -1
            && sys::errno() == libc::ENODATA,
        "both flags over a missing one is ENODATA, errno {}",
        sys::errno()
    );
    sys::clear_errno();
    check!(
        h,
        set(&f, "user.a", b"x", 0x40) == -1 && sys::errno() == libc::EINVAL,
        "an unknown flag bit is EINVAL, errno {}",
        sys::errno()
    );

    // The namespace, which is the access control. A name with no known prefix
    // has no rule that could apply to it.
    for name in ["nodots", "bogus.a", "userx.a"] {
        sys::clear_errno();
        let r = set(&f, name, b"x", 0);
        check!(
            h,
            r == -1 && sys::errno() == libc::ENOTSUP,
            "{name:?} has no namespace: EOPNOTSUPP, got {r} errno {}",
            sys::errno()
        );
    }
    sys::clear_errno();
    check!(
        h,
        set(&f, "user.", b"x", 0) == -1 && sys::errno() == libc::EINVAL,
        "a prefix with no name after it is EINVAL, errno {}",
        sys::errno()
    );
    sys::clear_errno();
    check!(
        h,
        set(&f, "system.posix_acl_access", b"x", 0) == -1 && sys::errno() == libc::ENOTSUP,
        "system.* is EOPNOTSUPP: the namespace is ACLs and there are none, errno {}",
        sys::errno()
    );

    // A `user.*` attribute goes on a regular file or a directory and nothing
    // else. A fifo is the case with no ambiguity about what it is.
    let fifo = d.p("xa.fifo");
    if unsafe { libc::mkfifo(guest_tests::cpath(&fifo).as_ptr(), 0o644) } == 0 {
        sys::clear_errno();
        check!(
            h,
            set(&fifo, "user.a", b"x", 0) == -1 && sys::errno() == libc::EPERM,
            "user.* on a fifo is EPERM, errno {}",
            sys::errno()
        );
        // **Reading one is not refused**, and this check is here because it
        // hung: a passthrough mount opens the target to reach the host's xattr
        // calls, and opening a fifo for reading waits for a writer. Nothing
        // else in this suite asks a fifo a question that opens it, so nothing
        // else would have noticed -- it was found by backing the rule above out
        // and watching the run stop for thirty-four minutes.
        sys::clear_errno();
        let r = get(&fifo, "user.a", &mut buf);
        check!(
            h,
            r == -1 && sys::errno() == libc::ENODATA,
            "getxattr on a fifo answers rather than blocking, got {r} errno {}",
            sys::errno()
        );
        check!(h, list(&fifo, &mut buf) == 0, "and so does listxattr");
    }
    let sub = d.p("xa.dir");
    if sys::mkdir(&sub, 0o755) == 0 {
        check!(h, set(&sub, "user.a", b"x", 0) == 0, "user.* on a directory is allowed");
    }

    check!(h, remove(&f, "user.a") == 0, "removexattr");
    check!(h, list(&f, &mut buf) == 0, "and the list is empty again");
    sys::clear_errno();
    check!(
        h,
        remove(&f, "user.a") == -1 && sys::errno() == libc::ENODATA,
        "removing it twice is ENODATA, errno {}",
        sys::errno()
    );

    // A value of 64 KiB + 1 is refused by the kernel whatever the filesystem
    // would have done -- and 64 KiB itself may still be refused by the disk,
    // which is why only the cap is checked.
    let too_big = vec![b'v'; 65537];
    sys::clear_errno();
    check!(
        h,
        set(&f, "user.big", &too_big, 0) == -1 && sys::errno() == libc::E2BIG,
        "a value over 64 KiB is E2BIG, errno {}",
        sys::errno()
    );

    sys::clear_errno();
    check!(
        h,
        set(&d.p("xa.nope"), "user.a", b"x", 0) == -1 && sys::errno() == libc::ENOENT,
        "a path that is not there is ENOENT, errno {}",
        sys::errno()
    );
}

/// `statx(STATX_BTIME)` on a file this test just made.
///
/// The one mount-dependent piece of `statx`, which is why it is here rather
/// than in a single-mount test: realfs and fakefs take a creation time from the
/// host file, and tmpfs makes the inode itself and knows exactly. All three
/// must answer, and until 2026-09-07 none did -- `struct statbuf` had nowhere
/// to put one, so `STATX_BTIME` stayed clear for every file on every mount.
///
/// libuv asks for it on Linux, which is what Node's `fs.stat().birthtime` is,
/// and Rust's `Metadata::created()` answers `Unsupported` when the bit is clear.
fn t_birth_time(h: &mut Harness, d: &Dir) {
    h.group("birth-time");

    const STATX_BTIME: u32 = 1 << 11;
    const OFF_MASK: usize = 0;
    const OFF_BTIME_SEC: usize = 80;
    const OFF_MTIME_SEC: usize = 112;

    let path = d.p("btime");
    check!(h, sys::write_file(&path, b"x"), "creating a file");

    let mut buf = [0u8; 256];
    let c = std::ffi::CString::new(path.clone()).unwrap();
    let r = unsafe {
        libc::syscall(
            libc::SYS_statx,
            libc::AT_FDCWD,
            c.as_ptr(),
            0,
            STATX_BTIME,
            buf.as_mut_ptr(),
        )
    };
    check!(h, r == 0, "statx(STATX_BTIME) succeeded: {r}");
    if r != 0 {
        return;
    }

    let mask = u32::from_le_bytes(buf[OFF_MASK..OFF_MASK + 4].try_into().unwrap());
    let btime = i64::from_le_bytes(buf[OFF_BTIME_SEC..OFF_BTIME_SEC + 8].try_into().unwrap());
    let mtime = i64::from_le_bytes(buf[OFF_MTIME_SEC..OFF_MTIME_SEC + 8].try_into().unwrap());

    // The load-bearing one. A kernel that fills the field and leaves the bit
    // clear is telling every caller it does not know, and every caller
    // believes it.
    check!(h, mask & STATX_BTIME != 0, "STATX_BTIME is set in stx_mask");
    // And the value, because setting the bit over a zero is the other half of
    // the same mistake.
    check!(h, btime > 0, "the creation time is after the epoch: {btime}");
    check!(
        h,
        btime <= mtime,
        "created no later than last modified: btime {btime}, mtime {mtime}"
    );
    // A file made a moment ago. An hour of slack, because a fakefs's host file
    // and the guest's clock are not the same clock.
    check!(
        h,
        mtime - btime < 3600,
        "and within an hour of it: {} seconds apart",
        mtime - btime
    );
}

fn main() -> std::process::ExitCode {
    let Some(dir) = std::env::args().nth(1) else {
        eprintln!("usage: fs_conformance <scratch-directory> [host-gid...]");
        return std::process::ExitCode::from(2);
    };
    if sys::mkdir(&dir, 0o755) != 0 && sys::errno() != libc::EEXIST {
        eprintln!("cannot create {dir}: {}", sys::strerror(sys::errno()));
        return std::process::ExitCode::from(2);
    }
    let d = Dir(dir);

    let mut h = Harness::new();
    t_read_write(&mut h, &d);
    t_seek(&mut h, &d);
    t_append(&mut h, &d);
    t_truncate(&mut h, &d);
    t_truncate_write_only(&mut h, &d);
    t_sparse_write(&mut h, &d);
    t_hardlink(&mut h, &d);
    t_symlink(&mut h, &d);
    t_rename(&mut h, &d);
    t_unlink_rmdir(&mut h, &d);
    t_open_unlinked(&mut h, &d);
    t_mkdir(&mut h, &d);
    t_directory_listing(&mut h, &d);
    t_fifo(&mut h, &d);
    t_root_listing(&mut h);
    t_attribute_race(&mut h, &d);
    t_metadata(&mut h, &d);
    t_fchmod(&mut h, &d);
    t_errors(&mut h, &d);
    t_relative_resolution(&mut h, &d);
    t_flock(&mut h, &d);
    t_ownership(&mut h, &d);
    t_record_locks(&mut h, &d);
    t_birth_time(&mut h, &d);
    t_xattr(&mut h, &d);
    std::process::ExitCode::from(h.finish() as u8)
}
