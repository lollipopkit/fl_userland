//! Bringing a guest up: mount, first task, `/dev`, working directory, exec.
//!
//! `xX_main_Xx.h` until 2026-09-03, and the order is the whole content — each
//! step needs the one before it. What changed in the move is the cleanup.
//!
//! # The `/dev` backing store is a guard
//!
//! When the root is an ordinary host directory, `/dev` gets a small fakefs of
//! its own in `TMPDIR`, because a device node needs a filesystem that can hold
//! one: realfs needs host root to `mknod` and tmpfs has no `mknod` at all.
//! Without it a guest has no `/dev` whatsoever, and the effect is worse than
//! things being absent — a shell redirecting to `/dev/null` does not write to a
//! device, it *creates a regular file at that path in the rootfs*. `dnf` died
//! on `std::random_device` with no `/dev/urandom`, `apt` could not start its
//! download methods, and every `2>/dev/null` left a file behind.
//!
//! The directory has to be removed on the way out, and the C called
//! `remove_dev_fakefs()` on each of six failure paths — one of which, the
//! `goto no_dev`, did not. It is [`DevFakefs`]'s `Drop` here, and the only way
//! to *keep* it is to say so with [`DevFakefs::keep`], which is what the last
//! line of a successful boot does.

use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::ffi;
use crate::opts::{self, Root};

/// Why a boot did not happen: a guest errno, and whether the reason has already
/// been printed.
///
/// The second half is the part worth having. Several steps know something the
/// errno does not — which path could not be resolved, which directory could not
/// be opened — and print it; without a way to say so, `main` prints a second,
/// vaguer line after it. The C did exactly that: `perror(root)` and then
/// `xX_main_Xx: No such file or directory`.
pub struct Failed {
    pub errno: i32,
    pub reported: bool,
}

impl Failed {
    /// The reason is the errno and nothing more.
    fn new(errno: i32) -> Failed {
        Failed {
            errno,
            reported: false,
        }
    }

    /// Something more specific has already been said.
    fn reported(errno: i32) -> Failed {
        Failed {
            errno,
            reported: true,
        }
    }
}

use guest_errno::c_int_::{E2BIG, EIO, ENAMETOOLONG, ENOENT};

/// What to print for an errno nobody has explained.
pub fn describe(e: i32) -> String {
    match e {
        ENOENT => "no program to run".into(),
        E2BIG => "argument list too long".into(),
        ENAMETOOLONG => "root path too long".into(),
        _ => format!("boot failed ({e})"),
    }
}

/// The `TMPDIR` fakefs backing `/dev`, removed when this is dropped.
///
/// Empty — and a no-op — when the root is already a filesystem that can hold a
/// device node.
struct DevFakefs {
    dir: Option<PathBuf>,
}

impl DevFakefs {
    fn none() -> DevFakefs {
        DevFakefs { dir: None }
    }

    /// Make one under `TMPDIR`, with a `meta.db`.
    ///
    /// **`mkdtemp`, not the pid.** The name used to be `iul-dev-<pid>`, and the
    /// directory is removed on exit — so a run that crashes or is killed leaves
    /// one behind, and the next run that happens to get that pid finds it.
    /// `fake_db_create` tolerates the directory existing and then opens the
    /// `meta.db` already in it, where creating the schema fails because the
    /// tables are there: `warning: no /dev for the guest (-5)`, and a guest
    /// with no `/dev/null`, `/dev/urandom` or `/dev/zero` at all. 158 of these
    /// had accumulated in one `TMPDIR` here, and one smoke run in four hit a
    /// recycled pid.
    fn create() -> Result<DevFakefs, i32> {
        let dir = make_temp_dir("iul-dev-XXXXXX")?;
        let me = DevFakefs {
            dir: Some(dir.clone()),
        };
        let c = cstring(&dir)?;
        // Drop removes what got made: the database is the last step, so a
        // failure here has already created the directory.
        fs_fake::db_create(&c)?;
        Ok(me)
    }

    fn data(&self) -> Option<PathBuf> {
        self.dir.as_ref().map(|d| d.join("data"))
    }

    /// Hand the directory to the exit handler, which removes it when the last
    /// guest process leaves. Nothing removes it after this returns.
    fn keep(mut self) {
        if let Some(d) = self.dir.take() {
            keep_until_exit(d);
        }
    }
}

impl Drop for DevFakefs {
    fn drop(&mut self) {
        if let Some(d) = self.dir.take() {
            remove_tree(&d);
        }
    }
}

/// The system temp directory, without the trailing slashes that are ordinary
/// on macOS and would give a path with a double slash — harmless — and a mount
/// source whose basename fakefs checks, which is not.
fn tmpdir() -> PathBuf {
    let tmp = std::env::var_os("TMPDIR").unwrap_or_default();
    let tmp = if tmp.is_empty() {
        PathBuf::from("/tmp")
    } else {
        PathBuf::from(tmp)
    };
    let s = tmp.as_os_str().as_bytes();
    let end = s.iter().rposition(|&b| b != b'/').map_or(1, |i| i + 1);
    PathBuf::from(std::ffi::OsStr::from_bytes(&s[..end.max(1)]))
}

/// A fresh directory under `TMPDIR` from a `mkdtemp` template.
fn make_temp_dir(template: &str) -> Result<PathBuf, i32> {
    let mut template = cstring(&tmpdir().join(template))?.into_bytes_with_nul();
    // SAFETY: a writable NUL-terminated buffer ending in six X's, which is
    // what `mkdtemp` requires.
    let made = unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) };
    if made.is_null() {
        return Err(-std::io::Error::last_os_error().raw_os_error().unwrap_or(5));
    }
    Ok(PathBuf::from(std::ffi::OsStr::from_bytes(
        CStr::from_bytes_until_nul(&template).unwrap().to_bytes(),
    )))
}

/// The directories the *exit handler* removes, once a boot has succeeded: the
/// fakefs behind `/dev`, and the host directory behind `/dev/shm`.
///
/// A run killed outright still leaves them behind; `mkdtemp` is what stops
/// that from breaking the next run rather than merely costing disk.
static TEMP_DIRS: std::sync::Mutex<Vec<PathBuf>> = std::sync::Mutex::new(Vec::new());

fn keep_until_exit(dir: PathBuf) {
    TEMP_DIRS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(dir);
}

/// `/dev/shm`: POSIX shared memory. `shm_open` is an `open` under it, and
/// `sem_open` in musl and glibc alike, so a process without it has no named
/// shared memory and no named semaphores — Python's `multiprocessing` and
/// PostgreSQL's dynamic shared memory both fail at once.
///
/// A **fakefs** over a fresh `TMPDIR` directory, like the one behind `/dev`,
/// and not a tmpfs, because the point of the directory is `mmap(MAP_SHARED)`
/// on what is in it: a fakefs keeps a file's bytes in a host file and maps it
/// through realfs, so a mapping is one set of pages for every guest process,
/// which are all threads of this one host process, and this kernel's tmpfs
/// has no `mmap`. Not a plain realfs either, which was the first version: a
/// realfs reports the **host's** ownership, so a file the guest's `postgres`
/// user made there belonged to uid 501 and its own `ftruncate` was refused
/// with "Permission denied" — `initdb` fails at its first dynamic shared
/// memory segment. A fakefs keeps ownership in `meta.db`, where it is the
/// guest's. The mode is 1777, as Linux's is, and the directory goes when the
/// last process does, with the one behind `/dev`.
fn mount_shm() {
    let dir = match make_temp_dir("iul-shm-XXXXXX") {
        Ok(d) => d,
        Err(e) => {
            eprintln!("warning: no /dev/shm for the guest ({e})");
            return;
        }
    };
    let (root, data) = match (cstring(&dir), cstring(&dir.join("data"))) {
        (Ok(r), Ok(d)) => (r, d),
        _ => {
            remove_tree(&dir);
            return;
        }
    };
    let mounted = fs_fake::db_create(&root).and_then(|()| {
        fs_generic::mkdir_at(ffi::At::Pwd, c"/dev/shm", 0o1777);
        fs_mount::mount(fs_fake::fakefs.0, &data, c"/dev/shm", c"", 0)
    });
    if let Err(err) = mounted {
        eprintln!("warning: /dev/shm did not mount ({err})");
        remove_tree(&dir);
        return;
    }
    // The mount's root is a fresh fakefs root; 1777 is what lets every user
    // create there and only the owner remove.
    let mode = ffi::Attr::Mode(0o1777);
    fs_generic::generic_setattrat(ffi::At::Pwd, c"/dev/shm", mode, true);
    keep_until_exit(dir);
}

/// A few kilobytes of sqlite in the system temp directory.
///
/// `std::fs::remove_dir_all` rather than `system("rm -rf ...")`: the path is
/// built from `TMPDIR`, and a `TMPDIR` holding a quote or a semicolon would
/// have been a command rather than a directory name. It does not follow
/// symlinks out of the tree it is deleting, which is what the C's `FTW_PHYS`
/// was for.
fn remove_tree(dir: &Path) {
    if let Err(e) = std::fs::remove_dir_all(dir) {
        eprintln!("note: could not remove {}: {e}", dir.display());
    }
}

fn cstring(p: &Path) -> Result<CString, i32> {
    CString::new(p.as_os_str().as_bytes()).map_err(|_| ENOENT)
}

/// What the last guest process leaves through.
///
/// Only init's: every other process is somebody's child and its exit is not
/// the run's.
extern "C" fn exit_handler(pid: i32, code: i32) {
    if pid != 1 {
        return;
    }
    ttyreal::real_tty_reset_term();
    let dirs = std::mem::take(&mut *TEMP_DIRS.lock().unwrap_or_else(|e| e.into_inner()));
    for d in dirs {
        remove_tree(&d);
    }
    if code & 0xff != 0 {
        // The guest died from a signal. Do not raise it on the host — the crash
        // handler would intercept it — just leave with the conventional
        // 128+signal.
        unsafe { libc::_exit(128 + (code & 0xff)) };
    }
    unsafe { libc::exit(code >> 8) };
}

/// Bring the guest up. Returns once the first task is ready to run.
pub fn boot(argv: &[String]) -> Result<(), Failed> {
    apple_case_sensitivity();

    let o = opts::parse(argv.iter().skip(1).cloned());
    for u in &o.unknown {
        eprintln!("iul: ignoring unknown option {u}");
    }
    for spec in &o.native {
        let c = CString::new(spec.as_str()).map_err(|_| Failed::new(ENOENT))?;
        if offloadexec::add(&c) < 0 {
            eprintln!("warning: ignoring -n {spec}");
        }
    }

    // `openlog` may keep the pointer rather than copy the string -- POSIX
    // does not say, and glibc keeps it -- so the ident lives as long as the
    // process. It was a temporary dropped at the end of this block.
    static IDENT: std::sync::OnceLock<CString> = std::sync::OnceLock::new();
    if let Some(name) = argv.first()
        && let Ok(c) = CString::new(name.as_str())
    {
        let ident = IDENT.get_or_init(|| c);
        // SAFETY: a NUL-terminated string that is never freed.
        unsafe { libc::openlog(ident.as_ptr(), 0, libc::LOG_USER) };
    }

    // The mount source is the *real* path: a relative one would be resolved
    // against whatever directory a later `chdir` left the host process in, and
    // `crates/util/fchdir` moves it.
    let (fs, mut source): (&'static ffi::FsHandle, PathBuf) = match &o.root {
        None => (&realfs::realfs, PathBuf::from("/")),
        Some((kind, path)) => {
            let real = std::fs::canonicalize(path).map_err(|e| {
                eprintln!("iul: {path}: {e}");
                Failed::reported(-e.raw_os_error().unwrap_or(2))
            })?;
            let fs: &'static ffi::FsHandle = match kind {
                Root::Real => &realfs::realfs,
                Root::Fake => &fs_fake::fakefs,
            };
            (fs, real)
        }
    };
    let is_fakefs = matches!(o.root, Some((Root::Fake, _)));
    if is_fakefs {
        // A fakefs directory is `data/` (the real files) plus `meta.db`.
        source.push("data");
    }
    if source.as_os_str().as_bytes().len() > ffi::MAX_PATH as usize {
        return Err(Failed::new(ENAMETOOLONG));
    }

    let c_source = cstring(&source).map_err(Failed::new)?;
    kernel_boot::mount_root_at(fs.0, &c_source).map_err(Failed::new)?;

    // Checked: it answers `_ENOMEM` or `_EAGAIN` if the first task cannot be
    // built, and everything below dereferences `current`.
    let err = kernel_boot::become_first_process();
    if err < 0 {
        return Err(Failed::new(err));
    }
    // Everything from here has to clean up after itself, which is what the
    // guard is: a failure drops it and the directory goes.
    let dev = if matches!(o.root, None | Some((Root::Real, _))) {
        match DevFakefs::create() {
            Ok(d) => d,
            Err(e) => {
                eprintln!("warning: no /dev for the guest ({e})");
                DevFakefs::none()
            }
        }
    } else {
        DevFakefs::none()
    };

    let mut have_dev = !is_fakefs && dev.dir.is_none();
    if let Some(data) = dev.data() {
        let c = cstring(&data).map_err(Failed::new)?;
        fs_generic::mkdir_at(ffi::At::Pwd, c"/dev", 0o755);
        let err = fs_mount::mount(fs_fake::fakefs.0, &c, c"/dev", c"", 0).err().unwrap_or(0);
        if err < 0 {
            eprintln!("warning: /dev did not mount ({err})");
        } else {
            have_dev = true;
        }
    }
    // A fakefs root can hold device nodes itself.
    if is_fakefs {
        have_dev = true;
    }

    if have_dev {
        make_devices();
        mount_shm();
    }

    // Where the guest starts. With no root and no `-d`, it is the host's
    // working directory, which is what makes `iul /bin/ls` list the directory
    // you ran it from.
    let workdir = match (&o.root, &o.workdir) {
        (_, Some(d)) => Some(d.clone()),
        (None, None) => std::env::current_dir()
            .ok()
            .map(|d| d.to_string_lossy().into_owned()),
        _ => None,
    };
    if let Some(d) = workdir {
        let c = CString::new(d.as_str()).map_err(|_| Failed::new(ENOENT))?;
        // `generic_openat`, not the `iul.h` entry point: this binary is an
        // embedder, but it is a *Rust* one, so it can have the `Result` the
        // layer below already produces rather than the `ERR_PTR` that exists
        // for a C caller.
        let pwd = match fs_generic::generic_openat(ffi::At::Pwd, &c, ffi::O_RDONLY_ as i32, 0) {
            Ok(fd) => fd,
            Err(e) => {
                eprintln!("iul: cannot open the working directory: {}", e.as_c_int());
                return Err(Failed::reported(EIO));
            }
        };
        // The first process was just made, and made with a context: `None`
        // here would be `become_first_process` answering success without one.
        let pwd = pwd;
        taskview::with_current_fs(move |context| context.chdir(pwd)).expect("the first process has a path context");
    }

    if o.command.is_empty() {
        return Err(Failed::new(ENOENT));
    }
    exec_first(&o.command).map_err(Failed::new)?;

    // The console driver, and the guest's stdio on it. A terminal when this
    // process has one on both ends, and a pipe otherwise — which is what makes
    // `iul ... | cat` work.
    fs_ttydev::enable_console();
    use std::io::IsTerminal;
    let both_tty = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let err = if both_tty {
        let c = CString::new(o.console.as_str()).map_err(|_| Failed::new(ENOENT))?;
        kernel_boot::open_stdio(&c, ffi::TTY_CONSOLE_MAJOR as i32, 1)
    } else {
        kernel_boot::create_piped_stdio()
    };
    if err < 0 {
        return Err(Failed::new(err));
    }

    // `/proc` and `/dev/pts`, which every guest expects and neither of which
    // the root filesystem provides. After the exec, because that is where the
    // C put them and `/proc/self` then names the process that will run.
    //
    // Not checked, as they were not before: a guest with no `/proc` is worse
    // off but still runs, and there is nothing to fall back to.
    let _ = fs_mount::mount(proc::procfs.0, c"proc", c"/proc", c"", 0);
    let _ = fs_mount::mount(devpts::devptsfs.0, c"devpts", c"/dev/pts", c"", 0);

    // Last, and only on success: from here the exit handler is what removes the
    // backing directory.
    exitcalls::set_exit_hook(exit_handler);
    dev.keep();
    Ok(())
}

/// The first `execve`, from the packed argument list `do_execve` takes.
///
/// **The V8 flags and the environment injection are not here.** They were, as a
/// second copy of the two lists in `crates/kernel/execcalls`, and the copy had
/// drifted; `do_execve` does the injection itself since 2026-09-03, so an
/// embedder that is not this CLI gets it too.
fn exec_first(command: &[String]) -> Result<(), i32> {
    let mut argv = Vec::new();
    for a in command {
        if argv.len() + a.len() + 2 > 4096 {
            return Err(E2BIG);
        }
        argv.extend_from_slice(a.as_bytes());
        argv.push(0);
    }
    argv.push(0);

    // What the guest inherits from the host, which is three variables and
    // whatever `TERM` says. Everything else this kernel forces on is
    // `crates/kernel/execcalls`'.
    let mut envp: Vec<u8> = Vec::new();
    if let Ok(term) = std::env::var("TERM") {
        envp.extend_from_slice(format!("TERM={term}").as_bytes());
        envp.push(0);
    }
    envp.extend_from_slice(b"HOME=/root\0");
    envp.extend_from_slice(b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\0");
    envp.push(0);

    let path = CString::new(command[0].as_str()).map_err(|_| ENOENT)?;
    let argv = execcalls::Args { buf: argv, count: command.len() };
    let envp = execcalls::Args { count: envp.iter().filter(|&&b| b == 0).count() - 1, buf: envp };
    let err = execcalls::execve_initial(&path, argv, envp);
    if err < 0 { Err(err) } else { Ok(()) }
}

/// The device nodes a guest cannot do without, and the three `/dev/std*`
/// symlinks.
///
/// `/dev/stdout` and its siblings point into `/proc`, which is mounted by the
/// time this runs. Without them a shell redirecting to `/dev/stdout` does not
/// write to its own output — it creates a file called `stdout`, which is the
/// same shape of bug as the missing `/dev` above. They resolve when the
/// descriptor behind them has a path; a piped stdio reads back as `unknown:[…]`
/// and the redirect fails, which is a better answer than the file.
fn make_devices() {
    let dev = |name: &CStr, major: u32, minor: u32| {
        let rdev = dev_make(major, minor);
        // What is already at this name. `mknod` answers EEXIST for anything,
        // so without asking, a **regular file** at a device path survives for
        // ever -- and that is the failure this whole module exists to prevent,
        // in its worst form: `/dev/null` that keeps what is written to it, or
        // `/dev/ptmx` that a pty library opens and gets EINVAL from. It is not
        // hypothetical. A distribution tarball ships entries under `/dev`, and
        // a guest that ran before these nodes existed leaves its own behind, so
        // a fakefs root reused between runs accumulates them: the ubuntu tree
        // here had a zero-byte `/dev/ptmx`, and `apt` reported "Unlocking the
        // slave of master fd 35 failed".
        //
        // Replaced rather than left: an entry that is not this device is not
        // something a guest can have meant to keep.
        let mut st = ffi::statbuf::default();
        let there = fs_generic::generic_statat(ffi::At::Pwd, name, &mut st, false);
        if there == 0 {
            if st.mode & ffi::S_IFMT == ffi::S_IFCHR && st.rdev == u64::from(rdev) {
                return;
            }
            fs_generic::generic_unlinkat(ffi::At::Pwd, name);
        }
        fs_generic::mknod_at(ffi::At::Pwd, name, (ffi::S_IFCHR | 0o666) as u16, rdev);
    };
    dev(c"/dev/null", ffi::MEM_MAJOR, ffi::DEV_NULL_MINOR);
    dev(c"/dev/zero", ffi::MEM_MAJOR, ffi::DEV_ZERO_MINOR);
    dev(c"/dev/full", ffi::MEM_MAJOR, ffi::DEV_FULL_MINOR);
    dev(c"/dev/random", ffi::MEM_MAJOR, ffi::DEV_RANDOM_MINOR);
    dev(c"/dev/urandom", ffi::MEM_MAJOR, ffi::DEV_URANDOM_MINOR);
    dev(c"/dev/tty", ffi::TTY_ALTERNATE_MAJOR, ffi::DEV_TTY_MINOR);
    dev(
        c"/dev/console",
        ffi::TTY_ALTERNATE_MAJOR,
        ffi::DEV_CONSOLE_MINOR,
    );
    dev(c"/dev/ptmx", ffi::TTY_ALTERNATE_MAJOR, ffi::DEV_PTMX_MINOR);
    // The console `-c` names by default. Without the node `create_stdio`
    // fell back to a descriptor with no path, so a guest on a terminal read
    // `anon_inode:[unknown]` at `/proc/self/fd/0` and `tty` answered "not a
    // tty" -- as does anything calling `ttyname`, which is how a shell or
    // `ssh` decides whether it has a terminal to name.
    dev(c"/dev/tty1", ffi::TTY_CONSOLE_MAJOR, 1);
    for (target, name) in [
        // `/dev/fd` is what a `#!` interpreter is handed for a script exec'd
        // by descriptor -- `execveat(fd, "", AT_EMPTY_PATH)` reports the
        // program as `/dev/fd/<n>` -- and `sh` then opens that name. Without
        // the link the shell said "can't open '/dev/fd/6'" and exited 2.
        (c"/proc/self/fd", c"/dev/fd"),
        (c"/proc/self/fd/0", c"/dev/stdin"),
        (c"/proc/self/fd/1", c"/dev/stdout"),
        (c"/proc/self/fd/2", c"/dev/stderr"),
    ] {
        fs_generic::symlink_at(target, ffi::At::Pwd, name);
    }
}

/* A hand-written `dev_make` was here until 2026-09-15 — the same masks as
 * `crates/fs/devices`', with the terms in a different order, which is a second
 * rendering that happened to agree. That crate's comment records the first
 * time this format had four copies and one of them was wrong. This binary
 * creates the device nodes a guest then opens, so a divergence here is a node
 * the kernel reads as a different device. */
use fs_devices::dev_make;

// `is_err_ptr` and `ptr_err` were written out here until 2026-09-14, as they
// were in eight other crates; then they became `crates/kernel/abi`'s, and then
// this file stopped needing them. It is a Rust embedder, so it calls
// `generic_openat` and reads a `Result`; `generic_open`'s `ERR_PTR` is for a C
// one.

/// Ask macOS for a case-sensitive view of the filesystem, and drop the setuid
/// bit that would have been needed to get it.
///
/// Either this process is root or it has the
/// `com.apple.private.iopol.case_sensitivity` entitlement, which is not
/// obtainable — so in practice it wants the setuid root bit, and dropping
/// privilege immediately afterwards is the whole reason this is the first thing
/// that happens.
fn apple_case_sensitivity() {
    unsafe {
        const IOPOL_TYPE_VFS_HFS_CASE_SENSITIVITY: i32 = 1;
        const IOPOL_SCOPE_PROCESS: i32 = 0;
        const FORCE_CASE_SENSITIVE: i32 = 1;
        unsafe extern "C" {
            fn setiopolicy_np(iotype: i32, scope: i32, policy: i32) -> i32;
        }
        if setiopolicy_np(
            IOPOL_TYPE_VFS_HFS_CASE_SENSITIVITY,
            IOPOL_SCOPE_PROCESS,
            FORCE_CASE_SENSITIVE,
        ) != 0
        {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EPERM) {
                eprintln!("could not enable case sensitivity: {e}");
            }
        }
        libc::setgid(libc::getgid());
        libc::setuid(libc::getuid());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `dev_make`, against the numbers the guest's `stat` reports. It is a
    /// macro in `fs/dev.h`, so this is the one copy of it in Rust and the only
    /// thing that can say it is right.
    #[test]
    fn a_device_number_packs_its_two_halves() {
        // /dev/null is major 1, minor 3.
        assert_eq!(dev_make(1, 3), (1 << 8) | 3);
        // A minor above 255 goes in the high field, which is what the twenty
        // bits of minor are for.
        assert_eq!(dev_make(1, 0x1_0000) & 0xff, 0);
        assert_ne!(dev_make(1, 0x1_0000), dev_make(1, 0));
        // The major is twelve bits and does not run into the minor.
        assert_eq!(dev_make(0xfff, 0) >> 8 & 0xfff, 0xfff);
    }

    // `an_error_pointer_is_told_from_a_real_one` was here until 2026-09-14 and
    // is `crates/kernel/abi`'s, where the definition is. What it asserted that
    // is worth keeping is in this file's `at_pwd`: the sentinel it answers is
    // -2, which `IS_ERR` calls an errno, and the two are told apart by which
    // functions are given which -- not by the values.
}
