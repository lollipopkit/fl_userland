//! What an open descriptor survives when the namespace moves under it.
//!
//! A descriptor refers to a file, not to a name. Renaming, unlinking or
//! moving an ancestor must not change what it reads, what it writes, or what
//! it resolves relative paths against — and the emulator's filesystems keep
//! more state on a descriptor than the name suggests: tmpfs holds an
//! `Arc<Dirent>`, fakefs caches the directory's guest path to look entries up
//! in `meta.db`, and realfs holds a host descriptor plus a `DIR *`.
//!
//! Renaming a tmpfs directory used to detach every descriptor open on it —
//! found by exactly this kind of check, run against all three mounts at once.
//! This is that question asked properly.

use guest_tests::{Harness, check, sys};

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

fn open_dir(path: &str) -> i32 {
    unsafe { libc::open(cstr(path).as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY, 0) }
}

fn rename(a: &str, b: &str) -> i32 {
    unsafe { libc::rename(cstr(a).as_ptr(), cstr(b).as_ptr()) }
}

/// Every name a directory descriptor lists, through getdents64.
fn list(fd: i32) -> Vec<String> {
    let mut out = Vec::new();
    loop {
        let mut buf = [0u8; 4096];
        let n = unsafe {
            libc::syscall(libc::SYS_getdents64, fd, buf.as_mut_ptr(), buf.len()) as isize
        };
        if n <= 0 {
            break;
        }
        let mut at = 0usize;
        while at + 19 <= n as usize {
            let reclen =
                u16::from_le_bytes([buf[at + 16], buf[at + 17]]) as usize;
            if reclen < 20 || at + reclen > n as usize {
                break;
            }
            let name = &buf[at + 19..at + reclen];
            let len = name.iter().position(|&b| b == 0).unwrap_or(0);
            out.push(String::from_utf8_lossy(&name[..len]).into_owned());
            at += reclen;
        }
    }
    out
}

fn t_renamed_directory(h: &mut Harness, dir: &str) {
    h.group("renamed-dir");
    let a = format!("{dir}/da");
    let b = format!("{dir}/db");
    let _ = std::fs::remove_dir_all(&a);
    let _ = std::fs::remove_dir_all(&b);
    unsafe { libc::mkdir(cstr(&a).as_ptr(), 0o755) };
    for i in 0..6 {
        let _ = std::fs::write(format!("{a}/e{i}"), b"x");
    }

    let fd = open_dir(&a);
    if fd < 0 {
        check!(h, false, "opening {a}");
        return;
    }
    check!(h, rename(&a, &b) == 0, "renaming the directory");

    // Listing continues to work and covers everything.
    let names = list(fd);
    let found = (0..6).filter(|i| names.iter().any(|n| n == &format!("e{i}"))).count();
    check!(h, found == 6, "the descriptor still lists every entry: {found} of 6");

    // And it is still a directory to resolve relative paths against.
    let child = unsafe {
        libc::openat(fd, cstr("e3").as_ptr(), libc::O_RDONLY, 0)
    };
    check!(
        h,
        child >= 0,
        "openat relative to it still resolves: errno {}",
        sys::errno()
    );
    if child >= 0 {
        sys::close(child);
    }
    sys::close(fd);
    let _ = std::fs::remove_dir_all(&b);
}

fn t_renamed_ancestor(h: &mut Harness, dir: &str) {
    h.group("renamed-ancestor");
    let top = format!("{dir}/ta");
    let top2 = format!("{dir}/tb");
    let _ = std::fs::remove_dir_all(&top);
    let _ = std::fs::remove_dir_all(&top2);
    unsafe { libc::mkdir(cstr(&top).as_ptr(), 0o755) };
    unsafe { libc::mkdir(cstr(&format!("{top}/inner")).as_ptr(), 0o755) };
    for i in 0..4 {
        let _ = std::fs::write(format!("{top}/inner/x{i}"), b"y");
    }

    let inner = open_dir(&format!("{top}/inner"));
    let file = unsafe {
        libc::open(cstr(&format!("{top}/inner/x0")).as_ptr(), libc::O_RDONLY, 0)
    };
    if inner < 0 || file < 0 {
        check!(h, false, "opening the inner directory and a file");
        return;
    }
    // Move the grandparent, not the directory itself.
    check!(h, rename(&top, &top2) == 0, "renaming an ancestor");

    let names = list(inner);
    let found = (0..4).filter(|i| names.iter().any(|n| n == &format!("x{i}"))).count();
    check!(
        h,
        found == 4,
        "a descriptor below the renamed directory still lists everything: {found} of 4"
    );
    let mut buf = [0u8; 4];
    check!(
        h,
        sys::read(file, &mut buf) == 1 && buf[0] == b'y',
        "and an open file below it still reads"
    );
    sys::close(inner);
    sys::close(file);
    let _ = std::fs::remove_dir_all(&top2);
}

fn t_renamed_and_unlinked_file(h: &mut Harness, dir: &str) {
    h.group("file");
    let a = format!("{dir}/fa");
    let b = format!("{dir}/fb");
    let _ = std::fs::remove_file(&a);
    let _ = std::fs::remove_file(&b);
    let _ = std::fs::write(&a, b"hello");

    let fd = unsafe { libc::open(cstr(&a).as_ptr(), libc::O_RDWR, 0) };
    if fd < 0 {
        check!(h, false, "opening {a}");
        return;
    }
    let mut before: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::fstat(fd, &mut before) };

    check!(h, rename(&a, &b) == 0, "renaming the file");
    let mut buf = [0u8; 8];
    check!(
        h,
        sys::read(fd, &mut buf) == 5 && &buf[..5] == b"hello",
        "the descriptor still reads its contents"
    );
    let mut after: libc::stat = unsafe { std::mem::zeroed() };
    check!(
        h,
        unsafe { libc::fstat(fd, &mut after) } == 0 && after.st_ino == before.st_ino,
        "and fstat reports the same inode: {} vs {}",
        after.st_ino,
        before.st_ino
    );

    // Unlink it: still readable, and the link count says it is gone.
    check!(h, unsafe { libc::unlink(cstr(&b).as_ptr()) } == 0, "unlinking it");
    check!(
        h,
        unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } == 0,
        "seeking back"
    );
    check!(
        h,
        sys::read(fd, &mut buf) == 5,
        "an unlinked file is still readable through an open descriptor"
    );
    let mut gone: libc::stat = unsafe { std::mem::zeroed() };
    check!(
        h,
        unsafe { libc::fstat(fd, &mut gone) } == 0 && gone.st_nlink == 0,
        "and its link count is zero, got {}",
        gone.st_nlink
    );
    sys::close(fd);
}

fn t_rmdir_while_open(h: &mut Harness, dir: &str) {
    h.group("rmdir-open");
    let d = format!("{dir}/gone");
    let _ = std::fs::remove_dir_all(&d);
    unsafe { libc::mkdir(cstr(&d).as_ptr(), 0o755) };
    let fd = open_dir(&d);
    if fd < 0 {
        check!(h, false, "opening {d}");
        return;
    }
    check!(
        h,
        unsafe { libc::rmdir(cstr(&d).as_ptr()) } == 0,
        "removing a directory that is open: errno {}",
        sys::errno()
    );
    // Whatever it lists, it must not crash and must not invent entries.
    let names = list(fd);
    check!(
        h,
        names.iter().all(|n| n == "." || n == ".."),
        "a removed directory lists nothing but . and ..: {names:?}"
    );
    // And it is empty, so creating in it fails rather than succeeding into
    // something unreachable.
    let made = unsafe {
        libc::openat(fd, cstr("new").as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o644)
    };
    check!(
        h,
        made < 0,
        "creating inside a removed directory fails, got {made}"
    );
    if made >= 0 {
        sys::close(made);
    }
    sys::close(fd);
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp/fdsurv".into());
    let _ = std::fs::remove_dir_all(&dir);
    unsafe { libc::mkdir(cstr(&dir).as_ptr(), 0o755) };
    let mut h = Harness::new();
    t_renamed_directory(&mut h, &dir);
    t_renamed_ancestor(&mut h, &dir);
    t_renamed_and_unlinked_file(&mut h, &dir);
    t_rmdir_while_open(&mut h, &dir);
    std::process::exit(h.finish());
}
