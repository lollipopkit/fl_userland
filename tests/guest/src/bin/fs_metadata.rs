//! File metadata: timestamps, access checks, filesystem statistics, and the
//! `renameat2` flags.
//!
//! A build system decides what to rebuild by comparing mtimes, `install` and
//! `cp -p` copy them, and an atomic-write pattern is `renameat2` with
//! `RENAME_NOREPLACE` or a plain rename onto the target. None of it was
//! covered, and timestamps in particular are a place where the three mounts
//! keep their state in three different ways: realfs on the host filesystem,
//! fakefs partly in `meta.db`, tmpfs entirely in memory.

use guest_tests::{Harness, check, check_fails, sys};

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

fn stat_of(path: &str) -> Option<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(cstr(path).as_ptr(), &mut st) } == 0 {
        Some(st)
    } else {
        None
    }
}

fn lstat_of(path: &str) -> Option<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(cstr(path).as_ptr(), &mut st) } == 0 {
        Some(st)
    } else {
        None
    }
}

fn t_utimensat(h: &mut Harness, dir: &str) {
    h.group("timestamps");
    let path = format!("{dir}/stamped");
    let _ = std::fs::write(&path, b"x");

    // An explicit time, set and read back. This is what `cp -p` does.
    let times = [
        libc::timespec { tv_sec: 1_000_000_000, tv_nsec: 123_456_789 },
        libc::timespec { tv_sec: 1_000_000_500, tv_nsec: 987_654_321 },
    ];
    let r = unsafe {
        libc::utimensat(libc::AT_FDCWD, cstr(&path).as_ptr(), times.as_ptr(), 0)
    };
    check!(h, r == 0, "utimensat with explicit times: errno {}", sys::errno());
    if let Some(st) = stat_of(&path) {
        check!(
            h,
            st.st_atime == 1_000_000_000,
            "the access time reads back: {} wanted 1000000000",
            st.st_atime
        );
        check!(
            h,
            st.st_mtime == 1_000_000_500,
            "the modification time reads back: {} wanted 1000000500",
            st.st_mtime
        );
        // Nanoseconds are what a build system with sub-second resolution
        // compares. A filesystem that drops them makes two files written in the
        // same second indistinguishable.
        check!(
            h,
            st.st_mtime_nsec == 987_654_321 || st.st_mtime_nsec == 0,
            "and the nanoseconds are kept or plainly zero, got {}",
            st.st_mtime_nsec
        );
    } else {
        check!(h, false, "stat after utimensat");
    }

    // UTIME_OMIT leaves one alone while setting the other.
    let omit = [
        libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT },
        libc::timespec { tv_sec: 1_500_000_000, tv_nsec: 0 },
    ];
    let r = unsafe {
        libc::utimensat(libc::AT_FDCWD, cstr(&path).as_ptr(), omit.as_ptr(), 0)
    };
    check!(h, r == 0, "utimensat with UTIME_OMIT: errno {}", sys::errno());
    if let Some(st) = stat_of(&path) {
        check!(
            h,
            st.st_atime == 1_000_000_000,
            "UTIME_OMIT left the access time alone, got {}",
            st.st_atime
        );
        check!(
            h,
            st.st_mtime == 1_500_000_000,
            "and the modification time was set, got {}",
            st.st_mtime
        );
    }

    // UTIME_NOW on both, which is what `touch` does.
    let now = [
        libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_NOW },
        libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_NOW },
    ];
    let r = unsafe {
        libc::utimensat(libc::AT_FDCWD, cstr(&path).as_ptr(), now.as_ptr(), 0)
    };
    check!(h, r == 0, "utimensat with UTIME_NOW: errno {}", sys::errno());
    if let Some(st) = stat_of(&path) {
        check!(
            h,
            st.st_mtime > 1_500_000_000,
            "UTIME_NOW moved the time forward, got {}",
            st.st_mtime
        );
    }

    // A NULL times pointer means "now" too.
    let r = unsafe {
        libc::utimensat(libc::AT_FDCWD, cstr(&path).as_ptr(), std::ptr::null(), 0)
    };
    check!(h, r == 0, "utimensat with a NULL times: errno {}", sys::errno());

    // futimens: the same thing through a descriptor.
    let fd = unsafe { libc::open(cstr(&path).as_ptr(), libc::O_RDWR, 0) };
    if fd >= 0 {
        let t = [
            libc::timespec { tv_sec: 1_234_567_890, tv_nsec: 0 },
            libc::timespec { tv_sec: 1_234_567_890, tv_nsec: 0 },
        ];
        let r = unsafe { libc::futimens(fd, t.as_ptr()) };
        check!(h, r == 0, "futimens: errno {}", sys::errno());
        if let Some(st) = stat_of(&path) {
            check!(
                h,
                st.st_mtime == 1_234_567_890,
                "and it reads back, got {}",
                st.st_mtime
            );
        }
        sys::close(fd);
    }

    // AT_SYMLINK_NOFOLLOW stamps the link, not its target.
    let target = format!("{dir}/stamp-target");
    let link = format!("{dir}/stamp-link");
    let _ = std::fs::write(&target, b"y");
    let _ = std::fs::remove_file(&link);
    unsafe { libc::symlink(cstr(&target).as_ptr(), cstr(&link).as_ptr()) };
    let before = stat_of(&target).map(|s| s.st_mtime).unwrap_or(0);
    let t = [
        libc::timespec { tv_sec: 900_000_000, tv_nsec: 0 },
        libc::timespec { tv_sec: 900_000_000, tv_nsec: 0 },
    ];
    let r = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            cstr(&link).as_ptr(),
            t.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if r == 0 {
        let after = stat_of(&target).map(|s| s.st_mtime).unwrap_or(0);
        check!(
            h,
            after == before,
            "AT_SYMLINK_NOFOLLOW left the target alone: {after} was {before}"
        );
        if let Some(ls) = lstat_of(&link) {
            check!(
                h,
                ls.st_mtime == 900_000_000,
                "and stamped the link itself, got {}",
                ls.st_mtime
            );
        }
    } else {
        // Some filesystems cannot stamp a symlink; ENOSYS/EOPNOTSUPP is an
        // honest answer, silently stamping the target is not.
        let e = sys::errno();
        check!(
            h,
            e == libc::ENOSYS || e == libc::EOPNOTSUPP || e == libc::EPERM,
            "AT_SYMLINK_NOFOLLOW refused clearly, errno {e}"
        );
        let after = stat_of(&target).map(|s| s.st_mtime).unwrap_or(0);
        check!(h, after == before, "and did not stamp the target instead");
    }

    check_fails!(
        h,
        unsafe {
            libc::utimensat(libc::AT_FDCWD, cstr(&format!("{dir}/nope")).as_ptr(),
                            times.as_ptr(), 0)
        },
        libc::ENOENT,
        "utimensat on a path that does not exist"
    );

    // A nanosecond field out of range is EINVAL, not a clamped time.
    let bad = [
        libc::timespec { tv_sec: 0, tv_nsec: 1_000_000_000 },
        libc::timespec { tv_sec: 0, tv_nsec: 0 },
    ];
    check_fails!(
        h,
        unsafe { libc::utimensat(libc::AT_FDCWD, cstr(&path).as_ptr(), bad.as_ptr(), 0) },
        libc::EINVAL,
        "a nanosecond field of 1000000000"
    );
}

fn t_access(h: &mut Harness, dir: &str) {
    h.group("access");
    let path = format!("{dir}/perm");
    let _ = std::fs::write(&path, b"x");
    unsafe { libc::chmod(cstr(&path).as_ptr(), 0o644) };

    check!(
        h,
        unsafe { libc::access(cstr(&path).as_ptr(), libc::F_OK) } == 0,
        "F_OK on a file that exists"
    );
    check!(
        h,
        unsafe { libc::access(cstr(&path).as_ptr(), libc::R_OK) } == 0,
        "R_OK on a readable file"
    );
    check_fails!(
        h,
        unsafe { libc::access(cstr(&format!("{dir}/absent")).as_ptr(), libc::F_OK) },
        libc::ENOENT,
        "F_OK on a file that does not"
    );

    // faccessat with AT_SYMLINK_NOFOLLOW on a dangling link: the link is there,
    // its target is not, so F_OK on the link itself succeeds.
    let dangling = format!("{dir}/dangling");
    let _ = std::fs::remove_file(&dangling);
    unsafe {
        libc::symlink(cstr(&format!("{dir}/nothing-here")).as_ptr(), cstr(&dangling).as_ptr())
    };
    check_fails!(
        h,
        unsafe { libc::access(cstr(&dangling).as_ptr(), libc::F_OK) },
        libc::ENOENT,
        "F_OK following a dangling symlink"
    );

    // An unknown mode bit is EINVAL rather than being ignored.
    check_fails!(
        h,
        unsafe { libc::access(cstr(&path).as_ptr(), 0x40) },
        libc::EINVAL,
        "an undefined access mode bit"
    );

    // Relative to a directory descriptor.
    let dfd = unsafe {
        libc::open(cstr(dir).as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY, 0)
    };
    if dfd >= 0 {
        check!(
            h,
            unsafe { libc::faccessat(dfd, cstr("perm").as_ptr(), libc::F_OK, 0) } == 0,
            "faccessat relative to a directory descriptor: errno {}",
            sys::errno()
        );
        sys::close(dfd);
    }
}

fn t_statfs(h: &mut Harness, dir: &str) {
    h.group("statfs");
    let mut sf: libc::statfs = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::statfs(cstr(dir).as_ptr(), &mut sf) };
    if r != 0 {
        check!(h, false, "statfs: errno {}", sys::errno());
        return;
    }
    // `df` divides by these, and a runtime checking for free space compares
    // them. A zero block size makes both divide by zero.
    check!(h, sf.f_bsize > 0, "the block size is positive, got {}", sf.f_bsize);
    check!(
        h,
        sf.f_blocks > 0,
        "the filesystem has some blocks, got {}",
        sf.f_blocks
    );
    check!(
        h,
        sf.f_bfree <= sf.f_blocks,
        "free {} does not exceed total {}",
        sf.f_bfree,
        sf.f_blocks
    );
    check!(
        h,
        sf.f_bavail <= sf.f_bfree,
        "available {} does not exceed free {}",
        sf.f_bavail,
        sf.f_bfree
    );
    check!(h, sf.f_namelen >= 255, "the name limit is at least 255, got {}", sf.f_namelen);

    // fstatfs on a descriptor must agree with statfs on its path.
    let fd = unsafe {
        libc::open(cstr(dir).as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY, 0)
    };
    if fd >= 0 {
        let mut fsf: libc::statfs = unsafe { std::mem::zeroed() };
        check!(
            h,
            unsafe { libc::fstatfs(fd, &mut fsf) } == 0,
            "fstatfs: errno {}",
            sys::errno()
        );
        check!(
            h,
            fsf.f_bsize == sf.f_bsize && fsf.f_blocks == sf.f_blocks,
            "and agrees with statfs on the same filesystem"
        );
        sys::close(fd);
    }

    check_fails!(
        h,
        unsafe { libc::statfs(cstr(&format!("{dir}/absent")).as_ptr(), &mut sf) },
        libc::ENOENT,
        "statfs on a path that does not exist"
    );
}

fn t_renameat2(h: &mut Harness, dir: &str) {
    h.group("renameat2");
    let a = format!("{dir}/r2a");
    let b = format!("{dir}/r2b");
    let _ = std::fs::write(&a, b"AAA");
    let _ = std::fs::write(&b, b"BBB");

    const RENAME_NOREPLACE: u32 = 1;
    const RENAME_EXCHANGE: u32 = 2;

    // NOREPLACE onto an existing name must fail with EEXIST, having changed
    // nothing. This is the atomic "create if absent" a lock file uses; a
    // silent overwrite loses whoever got there first.
    let r = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            cstr(&a).as_ptr(),
            libc::AT_FDCWD,
            cstr(&b).as_ptr(),
            RENAME_NOREPLACE,
        )
    };
    // Captured here, not inside check_fails!, which clears errno before it
    // evaluates its argument -- so handing it the already-computed `r` wiped
    // the errno the syscall had set and it reported 0. A rename cannot be
    // re-issued to get the errno back, since the first one may have moved the
    // file.
    let e = sys::errno();
    if r < 0 && (e == libc::ENOSYS || e == libc::EINVAL) {
        println!("  SKIP  [renameat2] not implemented: errno {e}");
    } else {
        check!(h, r < 0 && e == libc::EEXIST,
            "RENAME_NOREPLACE onto an existing name is EEXIST: returned {r} errno {e}");
        check!(
            h,
            std::fs::read(&a).unwrap_or_default() == b"AAA"
                && std::fs::read(&b).unwrap_or_default() == b"BBB",
            "and it changed nothing"
        );

        // NOREPLACE onto a free name works and is a plain rename.
        let c = format!("{dir}/r2c");
        let _ = std::fs::remove_file(&c);
        let r = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                cstr(&a).as_ptr(),
                libc::AT_FDCWD,
                cstr(&c).as_ptr(),
                RENAME_NOREPLACE,
            )
        };
        check!(h, r == 0, "RENAME_NOREPLACE onto a free name: {r} errno {}", sys::errno());
        check!(
            h,
            std::fs::read(&c).unwrap_or_default() == b"AAA",
            "and moved the contents"
        );

        // EXCHANGE swaps two names atomically, or says it cannot.
        let r = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                cstr(&c).as_ptr(),
                libc::AT_FDCWD,
                cstr(&b).as_ptr(),
                RENAME_EXCHANGE,
            )
        };
        if r == 0 {
            check!(
                h,
                std::fs::read(&c).unwrap_or_default() == b"BBB"
                    && std::fs::read(&b).unwrap_or_default() == b"AAA",
                "RENAME_EXCHANGE swapped them"
            );
        } else {
            let e = sys::errno();
            check!(
                h,
                e == libc::EINVAL || e == libc::ENOSYS || e == libc::EOPNOTSUPP,
                "RENAME_EXCHANGE refused clearly, errno {e}"
            );
            check!(
                h,
                std::fs::read(&c).unwrap_or_default() == b"AAA",
                "and changed nothing"
            );
        }

        // An undefined flag is EINVAL, not ignored -- being ignored turns a
        // NOREPLACE into an overwrite.
        check_fails!(
            h,
            unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    libc::AT_FDCWD,
                    cstr(&b).as_ptr(),
                    libc::AT_FDCWD,
                    cstr(&c).as_ptr(),
                    0x40u32,
                )
            },
            libc::EINVAL,
            "an undefined renameat2 flag"
        );

        // NOREPLACE and EXCHANGE together are contradictory.
        check_fails!(
            h,
            unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    libc::AT_FDCWD,
                    cstr(&b).as_ptr(),
                    libc::AT_FDCWD,
                    cstr(&c).as_ptr(),
                    RENAME_NOREPLACE | RENAME_EXCHANGE,
                )
            },
            libc::EINVAL,
            "RENAME_NOREPLACE and RENAME_EXCHANGE together"
        );
    }

    // Plain rename onto an existing file replaces it. This is the atomic write
    // every configuration writer uses.
    let _ = std::fs::write(&a, b"NEW");
    let _ = std::fs::write(&b, b"OLD");
    check!(
        h,
        unsafe { libc::rename(cstr(&a).as_ptr(), cstr(&b).as_ptr()) } == 0,
        "rename onto an existing file: errno {}",
        sys::errno()
    );
    check!(
        h,
        std::fs::read(&b).unwrap_or_default() == b"NEW",
        "and the target has the new contents"
    );
    check!(
        h,
        stat_of(&a).is_none(),
        "and the source is gone"
    );
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp/fsmeta".into());
    let _ = std::fs::remove_dir_all(&dir);
    unsafe { libc::mkdir(cstr(&dir).as_ptr(), 0o755) };
    let mut h = Harness::new();
    t_utimensat(&mut h, &dir);
    t_access(&mut h, &dir);
    t_statfs(&mut h, &dir);
    t_renameat2(&mut h, &dir);
    std::process::exit(h.finish());
}
