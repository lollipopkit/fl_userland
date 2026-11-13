//! Resolving a path: trailing slashes, symlinks, `..`, and the two limits.
//!
//! **A report, not a check** — one line per case, never fails, run here and in
//! an arm64 container and diffed by `tests/integration/probe_diff.sh`.
//!
//! # Why this exists
//!
//! Every syscall that names a file goes through one walk, so a rule it gets
//! wrong is wrong everywhere at once — and the rules here are the ones nobody
//! remembers. A trailing slash is not decoration: `open("file/")` is `ENOTDIR`
//! and `creat("new/")` is `EISDIR`, and a program that builds paths by joining
//! strings produces both by accident. `..` past the root is the root and not an
//! error. A symlink chain is bounded at forty *in total*, not forty per
//! component.
//!
//! `fs_probe` asks what each syscall does with a path it can resolve; this asks
//! what the resolver does with a path it cannot.

use std::ffi::{c_int, CString};
use std::io::Write;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<56} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> String {
    match e {
        libc::ENOENT => "ENOENT",
        libc::ENOTDIR => "ENOTDIR",
        libc::EISDIR => "EISDIR",
        libc::ELOOP => "ELOOP",
        libc::ENAMETOOLONG => "ENAMETOOLONG",
        libc::EINVAL => "EINVAL",
        libc::EEXIST => "EEXIST",
        libc::EACCES => "EACCES",
        libc::EBADF => "EBADF",
        libc::ENOTEMPTY => "ENOTEMPTY",
        libc::EPERM => "EPERM",
        libc::EFAULT => "EFAULT",
        libc::EXDEV => "EXDEV",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

fn c(p: &str) -> CString {
    CString::new(p).unwrap()
}

/// `open` for reading, reported as "opened" or the errno. The descriptor is
/// closed, so a case cannot leak one into the next.
fn open_ro(path: &str) -> String {
    let fd = unsafe { libc::open(c(path).as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return named(errno());
    }
    unsafe { libc::close(fd) };
    "opened".into()
}

fn open_flags(path: &str, flags: c_int, mode: libc::mode_t) -> String {
    let fd = unsafe { libc::open(c(path).as_ptr(), flags, mode as c_int) };
    if fd < 0 {
        return named(errno());
    }
    unsafe { libc::close(fd) };
    "opened".into()
}

fn stat_it(path: &str) -> String {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(c(path).as_ptr(), &mut st) } < 0 {
        return named(errno());
    }
    match st.st_mode & libc::S_IFMT {
        libc::S_IFREG => "a regular file".into(),
        libc::S_IFDIR => "a directory".into(),
        libc::S_IFLNK => "a symlink".into(),
        _ => format!("mode {:o}", st.st_mode & libc::S_IFMT),
    }
}

fn lstat_it(path: &str) -> String {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(c(path).as_ptr(), &mut st) } < 0 {
        return named(errno());
    }
    match st.st_mode & libc::S_IFMT {
        libc::S_IFREG => "a regular file".into(),
        libc::S_IFDIR => "a directory".into(),
        libc::S_IFLNK => "a symlink".into(),
        _ => format!("mode {:o}", st.st_mode & libc::S_IFMT),
    }
}

fn rc(v: c_int) -> String {
    if v < 0 { named(errno()) } else { "0".into() }
}

fn main() {
    let dir = "/tmp/path_probe.d";
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    setup(dir);

    trailing_slash(dir);
    dots(dir);
    symlinks(dir);
    limits(dir);
    readlinks(dir);

    let _ = std::fs::remove_dir_all(dir);
}

fn setup(dir: &str) {
    unsafe {
        let fd = libc::open(c(&format!("{dir}/file")).as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o644);
        libc::write(fd, b"x".as_ptr().cast(), 1);
        libc::close(fd);
        libc::mkdir(c(&format!("{dir}/sub")).as_ptr(), 0o755);
        libc::symlink(c("file").as_ptr(), c(&format!("{dir}/to_file")).as_ptr());
        libc::symlink(c("sub").as_ptr(), c(&format!("{dir}/to_dir")).as_ptr());
        libc::symlink(c("nowhere").as_ptr(), c(&format!("{dir}/dangling")).as_ptr());
        // A loop of two, which is the shortest one a walk can meet.
        libc::symlink(c("loop_b").as_ptr(), c(&format!("{dir}/loop_a")).as_ptr());
        libc::symlink(c("loop_a").as_ptr(), c(&format!("{dir}/loop_b")).as_ptr());
    }
}

/// A trailing slash is a claim that the name is a directory.
fn trailing_slash(dir: &str) {
    println!("## a trailing slash");
    line("  open(dir/)", open_ro(&format!("{dir}/sub/")));
    line("  open(file/)", open_ro(&format!("{dir}/file/")));
    line("  open(file/.)", open_ro(&format!("{dir}/file/.")));
    line("  stat(file/)", stat_it(&format!("{dir}/file/")));
    line("  stat(dir/)", stat_it(&format!("{dir}/sub/")));
    line("  stat(to_file/)", stat_it(&format!("{dir}/to_file/")));
    line("  stat(to_dir/)", stat_it(&format!("{dir}/to_dir/")));
    // lstat of a symlink *with* a slash follows it, because the slash says
    // "the directory this names" and a symlink is not one.
    line("  lstat(to_file)", lstat_it(&format!("{dir}/to_file")));
    line("  lstat(to_file/)", lstat_it(&format!("{dir}/to_file/")));
    line("  lstat(to_dir/)", lstat_it(&format!("{dir}/to_dir/")));
    // Creating through one: the name cannot be a directory and a regular file
    // at once.
    line(
        "  open(new/, O_CREAT)",
        open_flags(&format!("{dir}/new/"), libc::O_CREAT | libc::O_WRONLY, 0o644),
    );
    line("  mkdir(newdir/)", rc(unsafe { libc::mkdir(c(&format!("{dir}/newdir/")).as_ptr(), 0o755) }));
    line("  rmdir(newdir/)", rc(unsafe { libc::rmdir(c(&format!("{dir}/newdir/")).as_ptr()) }));
    // Its own file: on a kernel that ignores the slash this *removes* it, and
    // every case after it would then be asking about a file that is not there.
    unsafe {
        let victim = c(&format!("{dir}/victim"));
        libc::close(libc::open(victim.as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o644));
    }
    line("  unlink(victim/)", rc(unsafe { libc::unlink(c(&format!("{dir}/victim/")).as_ptr()) }));
    line("  is victim still there", lstat_it(&format!("{dir}/victim")));
    line("  rmdir(file/)", rc(unsafe { libc::rmdir(c(&format!("{dir}/file/")).as_ptr()) }));
    // A rename whose destination claims to be a directory.
    // Also its own file, for the same reason: a kernel that ignores the slash
    // renames it away.
    unsafe {
        let moved = c(&format!("{dir}/moved"));
        libc::close(libc::open(moved.as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o644));
    }
    line(
        "  rename(moved, other/)",
        rc(unsafe {
            libc::rename(
                c(&format!("{dir}/moved")).as_ptr(),
                c(&format!("{dir}/other/")).as_ptr(),
            )
        }),
    );
    line("  is moved still there", lstat_it(&format!("{dir}/moved")));
    // Two slashes and a trailing one on the root, which every path joiner
    // produces sooner or later.
    line("  open(//)", open_ro("//"));
    line("  stat(dir//sub)", stat_it(&format!("{dir}//sub")));
    line("  stat(dir///sub///)", stat_it(&format!("{dir}///sub///")));
}

/// `.` and `..`, including past the root.
fn dots(dir: &str) {
    println!("## dots");
    line("  stat(/..)", stat_it("/.."));
    line("  stat(/../../..)", stat_it("/../../.."));
    line("  stat(/./.././.)", stat_it("/./.././."));
    line("  stat(dir/sub/..)", stat_it(&format!("{dir}/sub/..")));
    line("  stat(dir/file/..)", stat_it(&format!("{dir}/file/..")));
    line("  stat(dir/.)", stat_it(&format!("{dir}/.")));
    line("  open(., O_WRONLY)", open_flags(".", libc::O_WRONLY, 0));
    line("  open(.., O_RDONLY)", open_ro(".."));
    // An empty path is not the working directory.
    line("  stat(the empty path)", stat_it(""));
    line("  open(the empty path)", open_ro(""));
    // A name that does not exist, under one that is not a directory.
    line("  stat(file/x)", stat_it(&format!("{dir}/file/x")));
    line("  stat(file/x/y)", stat_it(&format!("{dir}/file/x/y")));
}

/// Following, not following, and the bound.
fn symlinks(dir: &str) {
    println!("## symlinks");
    line("  open(a symlink to a file)", open_ro(&format!("{dir}/to_file")));
    line("  open(a dangling symlink)", open_ro(&format!("{dir}/dangling")));
    line("  lstat(a dangling symlink)", lstat_it(&format!("{dir}/dangling")));
    line(
        "  open(a dangling symlink, O_CREAT)",
        open_flags(&format!("{dir}/dangling"), libc::O_CREAT | libc::O_WRONLY, 0o644),
    );
    line(
        "  open(a dangling symlink, O_CREAT|O_EXCL)",
        open_flags(
            &format!("{dir}/dangling2"),
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY,
            0o644,
        ),
    );
    let _ = std::fs::remove_file(format!("{dir}/nowhere"));
    line(
        "  open(a symlink, O_NOFOLLOW)",
        open_flags(&format!("{dir}/to_file"), libc::O_RDONLY | libc::O_NOFOLLOW, 0),
    );
    line(
        "  open(a symlink to a directory, O_NOFOLLOW)",
        open_flags(&format!("{dir}/to_dir"), libc::O_RDONLY | libc::O_NOFOLLOW, 0),
    );
    line("  open(a loop of two)", open_ro(&format!("{dir}/loop_a")));
    line("  stat(a loop of two)", stat_it(&format!("{dir}/loop_a")));
    line("  lstat(a loop of two)", lstat_it(&format!("{dir}/loop_a")));
    line(
        "  unlink(a loop of two), which resolves nothing",
        rc(unsafe { libc::unlink(c(&format!("{dir}/loop_a")).as_ptr()) }),
    );
    unsafe { libc::symlink(c("loop_b").as_ptr(), c(&format!("{dir}/loop_a")).as_ptr()) };

    // A chain. Linux allows forty links in one resolution and refuses the
    // forty-first, and the count is over the whole walk rather than per
    // component -- which is the rule a per-component implementation gets wrong.
    let chain = format!("{dir}/chain");
    let _ = std::fs::create_dir(&chain);
    unsafe {
        let target = c(&format!("{chain}/end"));
        let fd = libc::open(target.as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o644);
        libc::close(fd);
        for i in 0..45 {
            let from = c(&format!("{chain}/l{i}"));
            let to = if i == 0 { c("end") } else { c(&format!("l{}", i - 1)) };
            libc::symlink(to.as_ptr(), from.as_ptr());
        }
    }
    // l0 -> end is one link, so lN is N+1 links.
    for n in [38usize, 39, 40] {
        line(&format!("  a chain of {} links", n + 1), open_ro(&format!("{chain}/l{n}")));
    }
}

/// The two limits, and what is refused at each.
fn limits(dir: &str) {
    println!("## limits");
    let n255 = "n".repeat(255);
    let n256 = "n".repeat(256);
    line(
        "  create a 255-byte name",
        open_flags(&format!("{dir}/{n255}"), libc::O_CREAT | libc::O_WRONLY, 0o644),
    );
    line(
        "  create a 256-byte name",
        open_flags(&format!("{dir}/{n256}"), libc::O_CREAT | libc::O_WRONLY, 0o644),
    );
    line("  stat a 256-byte name", stat_it(&format!("{dir}/{n256}")));
    // A path at and past PATH_MAX. The kernel's limit counts the NUL, so 4095
    // bytes of path is the longest one that resolves.
    let deep = format!("{dir}/{}", "d".repeat(4096 - dir.len() - 2));
    line("  a 4095-byte path that does not exist", stat_it(&deep));
    let over = format!("{dir}/{}", "d".repeat(4096));
    line("  a path past PATH_MAX", stat_it(&over));
    // Components stacked rather than one long name: the same limit, reached a
    // different way.
    let many = (0..900).map(|_| "a").collect::<Vec<_>>().join("/");
    line("  900 one-byte components", stat_it(&format!("{dir}/{many}")));
    // And a *relative* path with more components than the walk can hold.
    let dots = (0..600).map(|_| "..").collect::<Vec<_>>().join("/");
    line("  600 dot-dots from the root", stat_it(&format!("/{dots}")));
}

/// `readlink`'s own rules, which are about the buffer as much as the path.
fn readlinks(dir: &str) {
    println!("## readlink");
    let mut buf = [0u8; 256];
    let link = c(&format!("{dir}/to_file"));
    let n = unsafe { libc::readlink(link.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    line(
        "  readlink(a symlink)",
        if n < 0 {
            named(errno())
        } else {
            format!("{} bytes {:?}", n, String::from_utf8_lossy(&buf[..n as usize]))
        },
    );
    // A buffer shorter than the target truncates and does **not** terminate.
    let mut small = [b'#'; 2];
    let n = unsafe { libc::readlink(link.as_ptr(), small.as_mut_ptr().cast(), 2) };
    line(
        "  readlink into two bytes",
        if n < 0 {
            named(errno())
        } else {
            format!("{} bytes {:?}", n, String::from_utf8_lossy(&small[..n.max(0) as usize]))
        },
    );
    let n = unsafe { libc::readlink(link.as_ptr(), buf.as_mut_ptr().cast(), 0) };
    line("  readlink into zero bytes", if n < 0 { named(errno()) } else { n.to_string() });
    // Not a symlink, and a trailing slash on one.
    let n = unsafe { libc::readlink(c(&format!("{dir}/file")).as_ptr(), buf.as_mut_ptr().cast(), 256) };
    line("  readlink(a regular file)", if n < 0 { named(errno()) } else { n.to_string() });
    let n = unsafe { libc::readlink(c(&format!("{dir}/sub")).as_ptr(), buf.as_mut_ptr().cast(), 256) };
    line("  readlink(a directory)", if n < 0 { named(errno()) } else { n.to_string() });
    let n = unsafe { libc::readlink(c(&format!("{dir}/to_file/")).as_ptr(), buf.as_mut_ptr().cast(), 256) };
    line("  readlink(a symlink with a trailing slash)", if n < 0 { named(errno()) } else { n.to_string() });
    let n = unsafe { libc::readlink(c(&format!("{dir}/dangling")).as_ptr(), buf.as_mut_ptr().cast(), 256) };
    line(
        "  readlink(a dangling symlink)",
        if n < 0 { named(errno()) } else { format!("{n} bytes") },
    );
    // The empty path, which is ENOENT rather than "this directory".
    let n = unsafe { libc::readlink(c("").as_ptr(), buf.as_mut_ptr().cast(), 256) };
    line("  readlink(the empty path)", if n < 0 { named(errno()) } else { n.to_string() });
}
