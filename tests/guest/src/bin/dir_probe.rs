//! Reading a directory: `getdents64`, the record it produces, and seeking.
//!
//! **A report, not a check** — one line per case, never fails, run here and in
//! an arm64 container and diffed by `tests/integration/probe_diff.sh`.
//!
//! # Why this exists
//!
//! Every `ls`, every glob, every `find` and every `rm -r` is this call, and
//! the record format has had two defects already: entries a caller could not
//! walk because they were unaligned, and a length computed in two places that
//! disagreed. Both were found by reading. What had never been compared against
//! a real kernel is the part a caller *branches* on — the `d_type` of each kind
//! of file, what a buffer too small for one entry answers, and whether an
//! offset taken with `lseek` can be seeked back to.
//!
//! # Nothing here prints an inode number or an offset
//!
//! They are the filesystem's and differ between a fakefs and a container's
//! overlayfs for reasons that are not differences. What is printed is the
//! *shape*: which names came back, in what order relative to each other, what
//! type each carries, and whether a seek to a remembered offset lands where it
//! was taken.

use std::ffi::{c_int, CString};
use std::io::Write;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<52} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> String {
    match e {
        libc::EINVAL => "EINVAL",
        libc::EBADF => "EBADF",
        libc::ENOTDIR => "ENOTDIR",
        libc::EISDIR => "EISDIR",
        libc::EFAULT => "EFAULT",
        libc::ENOENT => "ENOENT",
        libc::EACCES => "EACCES",
        libc::ELOOP => "ELOOP",
        libc::EOVERFLOW => "EOVERFLOW",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

fn r(v: i64) -> String {
    if v < 0 { named(errno()) } else { v.to_string() }
}

const SYS_GETDENTS64: i64 = 61;

fn getdents(fd: c_int, buf: &mut [u8]) -> i64 {
    unsafe { libc::syscall(SYS_GETDENTS64, fd, buf.as_mut_ptr(), buf.len()) }
}

/// One record as the caller sees it: the name and its `d_type`.
struct Entry {
    name: String,
    kind: u8,
}

fn kind_name(t: u8) -> &'static str {
    match t {
        0 => "DT_UNKNOWN",
        1 => "DT_FIFO",
        2 => "DT_CHR",
        4 => "DT_DIR",
        6 => "DT_BLK",
        8 => "DT_REG",
        10 => "DT_LNK",
        12 => "DT_SOCK",
        _ => "DT_?",
    }
}

/// Walks the records in `buf[..n]`. Returns `None` if a record's length would
/// run past the end, which is what a caller cannot recover from and is
/// therefore worth reporting rather than trusting.
fn parse(buf: &[u8], n: usize) -> Option<Vec<Entry>> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < n {
        if at + 19 > n {
            return None;
        }
        let reclen = u16::from_le_bytes([buf[at + 16], buf[at + 17]]) as usize;
        if reclen < 19 || at + reclen > n {
            return None;
        }
        let kind = buf[at + 18];
        let name_bytes = &buf[at + 19..at + reclen];
        let end = name_bytes.iter().position(|b| *b == 0).unwrap_or(name_bytes.len());
        out.push(Entry {
            name: String::from_utf8_lossy(&name_bytes[..end]).into_owned(),
            kind,
        });
        at += reclen;
    }
    Some(out)
}

/// Every entry of an open directory, read to the end.
fn read_all(fd: c_int) -> Vec<Entry> {
    let mut all = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = getdents(fd, &mut buf);
        if n <= 0 {
            break;
        }
        match parse(&buf, n as usize) {
            Some(mut es) => all.append(&mut es),
            None => break,
        }
    }
    all
}

fn c(path: &str) -> CString {
    CString::new(path).unwrap()
}

fn main() {
    // Not `/tmp/dir_probe`: the probe's own binary is copied there, so the
    // directory and the program would be the same name -- `remove_dir_all`
    // then fails on a file and `create_dir_all` answers EEXIST.
    let dir = "/tmp/dir_probe.d";
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    populate(dir);

    contents(dir);
    types(dir);
    buffers(dir);
    seeking(dir);
    refusals(dir);

    let _ = std::fs::remove_dir_all(dir);
}

/// One of each kind this kernel can make in a directory.
fn populate(dir: &str) {
    let f = |n: &str| c(&format!("{dir}/{n}"));
    unsafe {
        let fd = libc::open(f("regular").as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o644);
        libc::write(fd, b"hello".as_ptr().cast(), 5);
        libc::close(fd);
        libc::mkdir(f("subdir").as_ptr(), 0o755);
        libc::symlink(c("regular").as_ptr(), f("link").as_ptr());
        libc::mkfifo(f("fifo").as_ptr(), 0o644);
        // A socket, bound so that it exists as a name.
        let s = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as _;
        let path = format!("{dir}/socket");
        for (i, b) in path.bytes().enumerate() {
            addr.sun_path[i] = b as _;
        }
        libc::bind(s, (&raw const addr).cast(), std::mem::size_of::<libc::sockaddr_un>() as u32);
        libc::close(s);
    }
}

/// What comes back, and what does not.
fn contents(dir: &str) {
    println!("## the entries");
    let fd = unsafe { libc::open(c(dir).as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    let all = read_all(fd);
    let mut names: Vec<&str> = all.iter().map(|e| e.name.as_str()).collect();
    names.sort_unstable();
    line("  the names, sorted", names.join(" "));
    line("  how many", all.len());
    // Order is the filesystem's, but *these two* are what every caller has to
    // skip and their presence is not optional.
    line("  . is there", all.iter().any(|e| e.name == ".").to_string());
    line("  .. is there", all.iter().any(|e| e.name == "..").to_string());
    // A second read after the end answers 0, not an error, and answers it
    // again: end of directory is a state, not an event.
    let mut buf = [0u8; 8192];
    line("  a read past the end", r(getdents(fd, &mut buf)));
    line("  and again", r(getdents(fd, &mut buf)));
    unsafe { libc::close(fd) };
}

/// `d_type` for each kind of file. A caller that trusts it skips a `stat` per
/// entry, which is what `find` and `rm -r` do.
fn types(dir: &str) {
    println!("## d_type");
    let fd = unsafe { libc::open(c(dir).as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    let all = read_all(fd);
    let mut pairs: Vec<String> = all
        .iter()
        .map(|e| format!("{}={}", e.name, kind_name(e.kind)))
        .collect();
    pairs.sort_unstable();
    for p in pairs {
        line(&format!("  {p}"), "");
    }
    unsafe { libc::close(fd) };
}

/// What a buffer that cannot hold a record answers.
fn buffers(dir: &str) {
    println!("## buffer sizes");
    let fd = unsafe { libc::open(c(dir).as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };

    // Too small for any record at all. Linux answers EINVAL rather than 0,
    // which is the difference between "there is nothing" and "ask again with
    // room" -- a caller that reads 0 stops.
    let mut tiny = [0u8; 1];
    line("  a one-byte buffer", r(getdents(fd, &mut tiny)));
    let mut small = [0u8; 18];
    line("  eighteen bytes, less than a header", r(getdents(fd, &mut small)));

    // A buffer that holds one record and not two: the call answers one, and
    // the entry that did not fit is still there for the next call. Reading it
    // in the smallest steps that work must produce the same set as one big
    // read -- which is the property a truncating implementation breaks.
    unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
    let mut collected = Vec::new();
    let mut calls = 0;
    loop {
        let mut one = [0u8; 40];
        let n = getdents(fd, &mut one);
        if n <= 0 {
            break;
        }
        calls += 1;
        if let Some(mut es) = parse(&one, n as usize) {
            collected.append(&mut es);
        }
        if calls > 64 {
            break;
        }
    }
    let mut names: Vec<&str> = collected.iter().map(|e| e.name.as_str()).collect();
    names.sort_unstable();
    line("  read forty bytes at a time, the names", names.join(" "));
    unsafe { libc::close(fd) };
}

/// Where a directory's offset points, and whether it can be returned to.
fn seeking(dir: &str) {
    println!("## seeking");
    let fd = unsafe { libc::open(c(dir).as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };

    // The offset before anything is read.
    let start = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
    line("  the offset before any read is zero", (start == 0).to_string());

    // Read one batch, remember where that left us, read the rest.
    let mut buf = [0u8; 40];
    let n = getdents(fd, &mut buf);
    let first: Vec<String> = parse(&buf, n.max(0) as usize)
        .unwrap_or_default()
        .into_iter()
        .map(|e| e.name)
        .collect();
    let mid = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
    line("  the offset moved after a read", (mid != start).to_string());
    let rest_a: Vec<String> = read_all(fd).into_iter().map(|e| e.name).collect();

    // Back to the remembered offset: the same remainder, again.
    unsafe { libc::lseek(fd, mid, libc::SEEK_SET) };
    let rest_b: Vec<String> = read_all(fd).into_iter().map(|e| e.name).collect();
    line("  seeking back to it repeats the remainder", (rest_a == rest_b).to_string());

    // And to the beginning: everything, including what the first batch had.
    unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
    let again: Vec<String> = read_all(fd).into_iter().map(|e| e.name).collect();
    let mut all_names: Vec<&String> = first.iter().chain(rest_a.iter()).collect();
    all_names.sort();
    let mut again_sorted: Vec<&String> = again.iter().collect();
    again_sorted.sort();
    line("  seeking to zero rewinds", (all_names == again_sorted).to_string());

    // An offset nothing was ever taken at. Linux takes it and the next read
    // answers whatever that offset means to the filesystem -- what is worth
    // reporting is that the seek itself is not refused.
    let rc = unsafe { libc::lseek(fd, 1, libc::SEEK_SET) };
    line("  lseek to 1", if rc < 0 { named(errno()) } else { "accepted".into() });
    let rc = unsafe { libc::lseek(fd, -1, libc::SEEK_SET) };
    line("  lseek to -1", if rc < 0 { named(errno()) } else { "accepted".into() });
    let rc = unsafe { libc::lseek(fd, 0, libc::SEEK_END) };
    line("  lseek to the end", if rc < 0 { named(errno()) } else { "accepted".into() });
    unsafe { libc::close(fd) };
}

/// The calls that must be refused, and with which errno.
fn refusals(dir: &str) {
    println!("## refusals");
    let mut buf = [0u8; 8192];

    // A regular file is not a directory, and the error names that rather than
    // the descriptor.
    let file = unsafe { libc::open(c(&format!("{dir}/regular")).as_ptr(), libc::O_RDONLY) };
    line("  getdents on a regular file", r(getdents(file, &mut buf)));
    unsafe { libc::close(file) };

    // A descriptor that is not open at all.
    line("  getdents on -1", r(getdents(-1, &mut buf)));
    line("  getdents on 999", r(getdents(999, &mut buf)));

    // An O_PATH descriptor names the directory without being able to read it.
    let opath = unsafe { libc::open(c(dir).as_ptr(), libc::O_PATH | libc::O_DIRECTORY) };
    line("  getdents on an O_PATH directory", r(getdents(opath, &mut buf)));
    unsafe { libc::close(opath) };

    // read(2) on a directory is EISDIR, which is how a program tells the two
    // interfaces apart.
    let fd = unsafe { libc::open(c(dir).as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), 8192) };
    line("  read(2) on a directory", r(n as i64));
    // ...and a write is worse.
    let n = unsafe { libc::write(fd, b"x".as_ptr().cast(), 1) };
    line("  write(2) on a directory", r(n as i64));
    // A buffer the caller does not own.
    let n = unsafe { libc::syscall(SYS_GETDENTS64, fd, 1u64, 8192u64) };
    line("  getdents into address 1", r(n));
    unsafe { libc::close(fd) };

    // O_DIRECTORY on something that is not one.
    let fd = unsafe { libc::open(c(&format!("{dir}/regular")).as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    line("  open(O_DIRECTORY) on a regular file", if fd < 0 { named(errno()) } else { "a descriptor".into() });
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }
    // Opening a directory for writing.
    let fd = unsafe { libc::open(c(dir).as_ptr(), libc::O_WRONLY) };
    line("  open(O_WRONLY) on a directory", if fd < 0 { named(errno()) } else { "a descriptor".into() });
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }
}
