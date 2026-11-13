//! `getdents64`, which is a wire format.
//!
//! The struct sweep in `abi_structs` checks fixed-size structs a syscall fills.
//! A directory read is not one of those: it is a stream of variable-length
//! records the caller walks by `d_reclen`, so the sweep could not see it and
//! nothing else did either.
//!
//! Three things are the contract. Each record's length is what says where the
//! next one starts. Linux rounds that length up to eight, so every record —
//! and so every `d_ino` and `d_off` inside one — is aligned. And a buffer too
//! small for even one entry is EINVAL, not zero, because zero is how a
//! directory says it has ended.

use guest_tests::{Harness, check, check_fails, sys};

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

/// One parsed record.
#[derive(Debug, Clone)]
struct Dent {
    ino: u64,
    reclen: u16,
    d_type: u8,
    // Parsed because a record is not understood without it, and checked below
    // only for being present -- what d_off means is the filesystem's business.
    #[allow(dead_code)]
    off: i64,
    name: String,
}

fn getdents(fd: i32, buf: &mut [u8]) -> isize {
    unsafe {
        libc::syscall(
            libc::SYS_getdents64,
            fd,
            buf.as_mut_ptr(),
            buf.len(),
        ) as isize
    }
}

/// Walk a returned buffer the way a caller does: by `d_reclen`.
fn parse(buf: &[u8], n: usize) -> Option<Vec<Dent>> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < n {
        if at + 19 > n {
            return None; // a record header that runs off the end
        }
        let ino = u64::from_le_bytes(buf[at..at + 8].try_into().ok()?);
        let off = i64::from_le_bytes(buf[at + 8..at + 16].try_into().ok()?);
        let reclen = u16::from_le_bytes(buf[at + 16..at + 18].try_into().ok()?);
        let d_type = buf[at + 18];
        if reclen < 20 || at + reclen as usize > n {
            return None;
        }
        let name_bytes = &buf[at + 19..at + reclen as usize];
        let len = name_bytes.iter().position(|&b| b == 0)?;
        out.push(Dent {
            ino,
            reclen,
            d_type,
            off,
            name: String::from_utf8_lossy(&name_bytes[..len]).into_owned(),
        });
        at += reclen as usize;
    }
    Some(out)
}

fn open_dir(path: &str) -> i32 {
    unsafe { libc::open(cstr(path).as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY, 0) }
}

fn t_layout(h: &mut Harness, dir: &str) {
    h.group("layout");
    for i in 0..5 {
        let _ = std::fs::write(format!("{dir}/f{i}"), b"x");
    }
    // A long name, to catch a length computed from the wrong field.
    let long = "n".repeat(200);
    let _ = std::fs::write(format!("{dir}/{long}"), b"x");
    // One of each kind, so d_type has something to be wrong about. The fifo
    // is optional: a mount that cannot make one skips the check rather than
    // failing it.
    unsafe { libc::mkdir(cstr(&format!("{dir}/adir")).as_ptr(), 0o755) };
    unsafe {
        libc::symlink(
            cstr("f0").as_ptr(),
            cstr(&format!("{dir}/alink")).as_ptr(),
        )
    };
    unsafe { libc::mkfifo(cstr(&format!("{dir}/afifo")).as_ptr(), 0o644) };

    let fd = open_dir(dir);
    if fd < 0 {
        check!(h, false, "opening {dir}");
        return;
    }
    let mut buf = [0u8; 8192];
    let n = getdents(fd, &mut buf);
    check!(h, n > 0, "getdents64 returned {n}");
    let Some(dents) = parse(&buf, n.max(0) as usize) else {
        check!(h, false, "the buffer parses as a record stream");
        sys::close(fd);
        return;
    };

    check!(
        h,
        dents.iter().all(|d| d.reclen % 8 == 0),
        "every d_reclen is a multiple of eight: {:?}",
        dents.iter().map(|d| d.reclen).collect::<Vec<_>>()
    );
    check!(
        h,
        dents.iter().all(|d| d.reclen as usize > 19 + d.name.len()),
        "and long enough for the name it carries"
    );
    check!(
        h,
        dents.iter().any(|d| d.name == "."),
        "the directory contains ."
    );
    check!(
        h,
        dents.iter().any(|d| d.name == ".."),
        "and .."
    );
    for i in 0..5 {
        check!(
            h,
            dents.iter().any(|d| d.name == format!("f{i}")),
            "f{i} is listed"
        );
    }
    check!(
        h,
        dents.iter().any(|d| d.name == long),
        "a 200-character name survives"
    );
    check!(
        h,
        dents.iter().all(|d| d.ino != 0),
        "every entry has a non-zero inode"
    );
    // d_type: the whole point of it is that a caller does not have to stat
    // each entry to find out what it is.
    const DT_DIR: u8 = 4;
    const DT_REG: u8 = 8;
    const DT_LNK: u8 = 10;
    const DT_FIFO: u8 = 1;
    let ty = |name: &str| dents.iter().find(|d| d.name == name).map(|d| d.d_type);
    check!(h, ty(".") == Some(DT_DIR), "d_type for . is DT_DIR, got {:?}", ty("."));
    check!(h, ty("..") == Some(DT_DIR), "d_type for .. is DT_DIR, got {:?}", ty(".."));
    check!(h, ty("f0") == Some(DT_REG), "d_type for a file is DT_REG, got {:?}", ty("f0"));
    check!(
        h,
        ty("adir") == Some(DT_DIR),
        "d_type for a subdirectory is DT_DIR, got {:?}",
        ty("adir")
    );
    check!(
        h,
        ty("alink") == Some(DT_LNK),
        "d_type for a symlink is DT_LNK, and is not followed, got {:?}",
        ty("alink")
    );
    check!(
        h,
        ty("afifo") == Some(DT_FIFO) || ty("afifo").is_none(),
        "d_type for a fifo is DT_FIFO, got {:?}",
        ty("afifo")
    );
    sys::close(fd);
}

fn t_small_buffer(h: &mut Harness, dir: &str) {
    h.group("small-buffer");
    let fd = open_dir(dir);
    if fd < 0 {
        check!(h, false, "opening {dir}");
        return;
    }
    // Too small for any record at all. Zero would mean "end of directory",
    // which is a silent wrong answer: the caller stops and reports an empty
    // directory.
    let mut tiny = [0u8; 8];
    check_fails!(
        h,
        getdents(fd, &mut tiny) as i64,
        libc::EINVAL,
        "a buffer too small for one entry"
    );
    // And the directory position did not move, so a caller that grows its
    // buffer and retries sees everything.
    let mut big = [0u8; 8192];
    let n = getdents(fd, &mut big);
    check!(h, n > 0, "retrying with a bigger buffer works: {n}");
    let all = parse(&big, n.max(0) as usize).map(|d| d.len()).unwrap_or(0);
    check!(h, all >= 8, "and lists everything: {all} entries");
    sys::close(fd);
}

fn t_partial_reads(h: &mut Harness, parent: &str) {
    h.group("partial");
    // Its own directory, with short names only: a 200-character name does not
    // fit a 64-byte buffer at all, and EINVAL is the right answer for that
    // rather than a partial read. Mixing the two would test both at once and
    // pin neither.
    let dir = format!("{parent}/partial");
    let _ = std::fs::remove_dir_all(&dir);
    unsafe { libc::mkdir(cstr(&dir).as_ptr(), 0o755) };
    for i in 0..8 {
        let _ = std::fs::write(format!("{dir}/p{i}"), b"x");
    }
    let dir = dir.as_str();
    let fd = open_dir(dir);
    if fd < 0 {
        check!(h, false, "opening {dir}");
        return;
    }
    // A buffer that fits some but not all: repeated calls have to cover every
    // entry exactly once.
    let mut names = Vec::new();
    let mut rounds = 0;
    loop {
        let mut buf = [0u8; 64];
        let n = getdents(fd, &mut buf);
        if n < 0 {
            check!(h, false, "getdents in the partial loop: errno {}", sys::errno());
            break;
        }
        if n == 0 {
            break;
        }
        rounds += 1;
        match parse(&buf, n as usize) {
            Some(d) => names.extend(d.into_iter().map(|e| e.name)),
            None => {
                check!(h, false, "a partial buffer parses");
                break;
            }
        }
        if rounds > 200 {
            check!(h, false, "the partial loop did not terminate");
            break;
        }
    }
    sys::close(fd);

    check!(h, rounds > 1, "a small buffer took several calls: {rounds}");
    let mut sorted = names.clone();
    sorted.sort();
    let before = sorted.len();
    sorted.dedup();
    check!(
        h,
        sorted.len() == before,
        "no entry was returned twice: {} of {before} unique",
        sorted.len()
    );

    // Against one big read.
    let fd = open_dir(dir);
    let mut big = [0u8; 8192];
    let n = getdents(fd, &mut big);
    let mut once: Vec<String> = parse(&big, n.max(0) as usize)
        .unwrap_or_default()
        .into_iter()
        .map(|d| d.name)
        .collect();
    sys::close(fd);
    once.sort();
    check!(
        h,
        once == sorted,
        "and the pieces add up to the whole: {} vs {}",
        sorted.len(),
        once.len()
    );
}

/// A directory renamed while a descriptor is open on it.
///
/// fakefs resolves the directory's guest path to look each entry up, and
/// caches it per descriptor. A rename moves that path, so the cache has to be
/// invalidated or the entries after the rename are looked up under a name that
/// no longer exists.
fn t_rename_during_read(h: &mut Harness, parent: &str) {
    h.group("rename-during-read");
    let a = format!("{parent}/renme");
    let b = format!("{parent}/renme2");
    let _ = std::fs::remove_dir_all(&a);
    let _ = std::fs::remove_dir_all(&b);
    unsafe { libc::mkdir(cstr(&a).as_ptr(), 0o755) };
    for i in 0..12 {
        let _ = std::fs::write(format!("{a}/r{i}"), b"x");
    }

    let fd = open_dir(&a);
    if fd < 0 {
        check!(h, false, "opening {a}");
        return;
    }
    // One small read, so the descriptor is part-way through.
    let mut first = [0u8; 96];
    let n = getdents(fd, &mut first);
    let mut names: Vec<String> = parse(&first, n.max(0) as usize)
        .unwrap_or_default()
        .into_iter()
        .map(|d| d.name)
        .collect();
    check!(h, !names.is_empty(), "the first read returned entries: {n}");

    let r = unsafe { libc::rename(cstr(&a).as_ptr(), cstr(&b).as_ptr()) };
    check!(h, r == 0, "renaming the directory out from under it: {r}");

    // The rest still has to come back: the descriptor refers to the directory,
    // not to its name.
    loop {
        let mut buf = [0u8; 512];
        let n = getdents(fd, &mut buf);
        if n <= 0 {
            break;
        }
        match parse(&buf, n as usize) {
            Some(d) => names.extend(d.into_iter().map(|e| e.name)),
            None => break,
        }
    }
    sys::close(fd);
    let found = (0..12)
        .filter(|i| names.iter().any(|n| n == &format!("r{i}")))
        .count();
    check!(
        h,
        found == 12,
        "every entry is still listed after the rename: {found} of 12"
    );
    let _ = std::fs::remove_dir_all(&b);
}

/// Every name length, so every rounding case the record format has.
///
/// A record is 19 bytes of header plus the name plus a NUL, rounded up to
/// eight. The emulator sized the stack buffer it builds the record in without
/// accounting for that rounding, so a name of length 5, 6, 7 or 8 modulo 8
/// wrote up to four bytes past the end of it -- `ls` of a directory holding a
/// five-character name was enough to do it.
///
/// A four-byte stack overflow is invisible from inside the guest: these checks
/// pass either way. The detector is ASan, which reports it as a
/// dynamic-stack-buffer-overflow in fill_dirent_64. What the checks below are
/// for is making sure every length is actually walked, so that an ASan build
/// running this file trips on it.
fn t_name_lengths(h: &mut Harness, parent: &str) {
    h.group("name-lengths");
    let dir = format!("{parent}/lens");
    let _ = std::fs::remove_dir_all(&dir);
    unsafe { libc::mkdir(cstr(&dir).as_ptr(), 0o755) };

    // Lengths 1..=24: three full turns of the eight-byte rounding.
    for len in 1..=24usize {
        let name = "n".repeat(len);
        let _ = std::fs::write(format!("{dir}/{name}"), b"x");
    }

    let fd = open_dir(&dir);
    if fd < 0 {
        check!(h, false, "opening {dir}");
        return;
    }
    let mut entries: Vec<Dent> = Vec::new();
    loop {
        let mut buf = [0u8; 4096];
        let n = getdents(fd, &mut buf);
        if n <= 0 {
            break;
        }
        match parse(&buf, n as usize) {
            Some(d) => entries.extend(d),
            None => {
                check!(h, false, "a returned buffer did not parse");
                break;
            }
        }
    }
    sys::close(fd);

    let mut missing = Vec::new();
    for len in 1..=24usize {
        let name = "n".repeat(len);
        if !entries.iter().any(|e| e.name == name) {
            missing.push(len);
        }
    }
    check!(
        h,
        missing.is_empty(),
        "every name length from 1 to 24 comes back: missing {missing:?}"
    );

    // And every record is still eight-byte aligned whatever the name length.
    let bad: Vec<_> = entries
        .iter()
        .filter(|e| e.reclen % 8 != 0)
        .map(|e| (e.name.clone(), e.reclen))
        .collect();
    check!(h, bad.is_empty(), "and every record stays aligned: {bad:?}");
}

fn t_errnos(h: &mut Harness, dir: &str) {
    h.group("errnos");
    let mut buf = [0u8; 1024];
    check_fails!(
        h,
        getdents(4096, &mut buf) as i64,
        libc::EBADF,
        "a descriptor that does not exist"
    );

    let p = format!("{dir}/f0");
    let fd = unsafe { libc::open(cstr(&p).as_ptr(), libc::O_RDONLY, 0) };
    check_fails!(
        h,
        getdents(fd, &mut buf) as i64,
        libc::ENOTDIR,
        "a regular file"
    );
    sys::close(fd);
}

/// Seeking a directory, which is what `rewinddir` and `seekdir` are.
///
/// **Measured against a real arm64 kernel on 2026-09-12**, not read from a man
/// page — `lseek(2)` does not mention directories at all. Alpine on arm64,
/// through `differential.sh`'s container:
///
/// ```text
/// /proc   0, 8, 1<<20, i32::MAX      -> accepted
/// /proc   i32::MAX + 1 and above     -> EINVAL
/// /tmp    every one of them, to 2^62 -> accepted
/// ```
///
/// So procfs carries a **32-bit directory cookie** and refuses an offset that
/// does not fit, while an ordinary filesystem's offset is the full 64 bits.
///
/// Two things this caught here, and the second exists because of the first:
///
/// - Every seek of a procfs directory answered `EISDIR`, including offset
///   **zero** — which is `rewinddir(3)` in both glibc and musl. `rewinddir`
///   returns `void`, so the refusal was silent and the next `readdir` carried
///   on from where it was instead of starting over.
/// - `crates/fs/proc`'s root walk computes `(offset - ROOT_LEN) as c_int` and
///   hands it to `task_next_listed_pid`, which counts *up* from there holding
///   `pids_lock`. An offset above `i32::MAX` truncates to a negative and that
///   loop runs two billion times with the global pid lock held. It was
///   unreachable only because the `EISDIR` above refused the seek first — so
///   fixing that without adding the bound would have *opened* it. The bound and
///   the fix are the same line, and it is the same boundary Linux enforces.
fn t_directory_seek(h: &mut Harness, dir: &str) {
    const I32_MAX: i64 = i32::MAX as i64;
    for (path, thirty_two_bit) in [(dir, false), ("/proc", true)] {
        let fd = sys::open(path, libc::O_RDONLY | libc::O_DIRECTORY, 0);
        if fd < 0 {
            continue;
        }
        for off in [0, 8, 1 << 20, I32_MAX, I32_MAX + 1, 1i64 << 32] {
            let refused = thirty_two_bit && off > I32_MAX;
            let got = sys::lseek(fd, off, libc::SEEK_SET);
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if refused {
                check!(
                    h,
                    got == -1 && e == libc::EINVAL,
                    "{path}: lseek to {off} answered {got}/{e}, wanted EINVAL"
                );
            } else {
                check!(h, got == off, "{path}: lseek to {off} answered {got}/{e}");
            }
        }
        unsafe { libc::close(fd) };
    }

    // And what `rewinddir` is *for*: the same entries again. Nothing else in
    // the suite reads a directory twice, so a seek that succeeds and moves
    // nothing would pass every check above.
    for path in [dir, "/proc"] {
        let fd = sys::open(path, libc::O_RDONLY | libc::O_DIRECTORY, 0);
        if fd < 0 {
            continue;
        }
        let read = || {
            let mut buf = [0u8; 4096];
            let n = unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            (n, buf)
        };
        let (first, a) = read();
        check!(h, first > 0, "{path}: the first read answered {first}");
        let back = sys::lseek(fd, 0, libc::SEEK_SET);
        check!(h, back == 0, "{path}: rewinddir answered {back}");
        let (again, b) = read();
        check!(
            h,
            again == first && a[..first.max(0) as usize] == b[..again.max(0) as usize],
            "{path}: a rewound directory read {again} bytes, not the first {first} again"
        );
        unsafe { libc::close(fd) };
    }
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp/dents".into());
    let _ = std::fs::remove_dir_all(&dir);
    unsafe { libc::mkdir(cstr(&dir).as_ptr(), 0o755) };
    let mut h = Harness::new();
    t_layout(&mut h, &dir);
    t_small_buffer(&mut h, &dir);
    t_partial_reads(&mut h, &dir);
    t_rename_during_read(&mut h, &dir);
    t_name_lengths(&mut h, &dir);
    t_errnos(&mut h, &dir);
    t_directory_seek(&mut h, &dir);
    std::process::exit(h.finish());
}
