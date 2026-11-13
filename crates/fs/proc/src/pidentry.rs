//! The `/proc/<pid>` directory: what is in it, and the entries that are not
//! files.
//!
//! The table was a C aggregate in `fs/proc/pid.c` pointing at a mixture of C and
//! Rust callbacks. It is Rust now, the way `/proc/iul`'s already is, and what is
//! left in C is the address-space readers — `auxv`, `cmdline`, `environ`,
//! `mem` — which walk `struct mm` and so wait for step 6.
//!
//! # Two locks, in one order, and never both across a path lookup
//!
//! Every entry here reaches a task through `proc_get_task`, which answers with
//! `pids_lock` held. What it does next is always the same: **retain, drop the
//! lock, then work**. `generic_getpath` takes the mount table's locks and the
//! real filesystem's, and holding `pids_lock` across it inverts the order
//! against every path that takes those first — an intermittent deadlock during
//! `claude-cli` startup, when twenty bun worker threads all scan
//! `/proc/self/fd` at once.
//!
//! The retain is not only about lock order. `fs->pwd` is replaced by `chdir`
//! and `chroot` under `fs`'s own lock, so a bare pointer carried out of it is
//! one another thread may close.
//!
//! # `readdir` answers `None` for a task that is gone
//!
//! Not an errno. `proc_pid_fd_readdir` used to `return _ESRCH`, which is -3 and
//! reads as **true**, so the VFS consumed a `next_entry` that was never filled
//! in and crashed in `proc_entry_getname`. No task is no more entries.
//!
//! **That defect is unwritable since 2026-09-16.** The callback answers
//! `Option<proc_entry>` rather than a `bool` beside an out-parameter, so
//! "there is a next entry" and "here it is" are one value: there is no `true`
//! to return without one, and an errno is not an `Option`.

use pagetable::memlock::Held;
use std::ffi::{c_int, c_ulong};
use std::sync::Arc;

use crate::ffi;
use crate::pidsnap::{Found, general_of};
use crate::root::{Children, Entry, blank};

use guest_errno::c_int_::{EACCES, ENOENT, ESRCH};

// The twelve `show` functions this table points at are all this crate's, in
// `crate::pidmem`, `crate::pid` and `crate::maps`. They were declared here in
// an `unsafe extern "C"` block naming `fs/proc/pid.c`, which has not existed
// since 2026-09-01: a table in one module reaching a function in the next
// through the linker, inside one crate.

fn pid_getname(entry: &mut ffi::proc_entry, buf: &mut [u8]) {
    crate::entry::put_name(buf, format!("{}", entry.pid).as_bytes());
}

fn fd_getname(entry: &mut ffi::proc_entry, buf: &mut [u8]) {
    crate::entry::put_name(buf, format!("{}", entry.fd).as_bytes());
}

fn task_getname(entry: &mut ffi::proc_entry, buf: &mut [u8]) {
    crate::entry::put_name(buf, format!("{}", entry.pid).as_bytes());
}

/// The descriptor table of the task this entry is about, retained, with
/// `pids_lock` released.
///
/// `None` for a task that is gone or on its way out: `do_exit` takes its
/// descriptors away under `pids_lock`, and the group-exit valve can take them
/// from a thread stuck in a host call. Dereferencing it anyway was half of the
/// crash the module comment records.
fn take_files(entry: &mut ffi::proc_entry) -> Option<Arc<ffi::fdtable>> {
    // Cloned under pids_lock, which `found` holds until the end of this
    // statement -- after the clone, which is the order that matters.
    Found::get(entry)?.task().files()
}

fn fd_readdir(entry: &mut ffi::proc_entry, index: &mut c_ulong) -> Option<ffi::proc_entry> {
    let files = take_files(entry)?;
    // One complete snapshot, taken under the table's mutex. It was a sizing
    // call and a filling one, with a retry loop for the table changing
    // between the two.
    let numbers = files.numbers().ok()?;
    drop(files);

    let at = numbers.iter().position(|&f| (f as c_ulong) >= *index)?;
    let f = numbers[at];
    *index = f as c_ulong + 1;
    Some(ffi::proc_entry {
        meta: Some(&PROC_PID_FD.0),
        pid: entry.pid,
        fd: f,
        ..ffi::proc_entry::default()
    })
}

/// `generic_getpath` on a descriptor.
///
/// **"Releasing it either way" used to be this function's whole doc comment**
/// and is the type's job now: an [`Owned`] releases when it goes out of scope,
/// on the error path and the success path alike, and the three callers below
/// each hand one over rather than a pointer plus an obligation. Object model
/// step 9.7.
fn path_of(fd: Option<fs_fdobj::Owned>, buf: &mut [u8]) -> c_int {
    let Some(fd) = fd else {
        return ENOENT;
    };
    fs_generic::generic_getpath(&fd, buf)
}

// `owned(fd) -> Option<Owned>` was written out here until 2026-09-14, and in
// two other crates by hand. It is `fs_fdobj::Owned::from_raw_or_null`, beside
// the type it makes.

fn fd_readlink(entry: &mut ffi::proc_entry, buf: &mut [u8]) -> c_int {
    let Some(files) = take_files(entry) else {
        return ESRCH;
    };
    // The table's own mutex is entered only after pids_lock is released; see
    // the module comment.
    // Answers with a reference taken, or null for a descriptor another
    // thread closed -- ENOENT, not a host crash.
    let fd = files.lookup_retain(entry.fd);
    drop(files);
    // The lookup answers an owning handle; `path_of` releases it on both paths.
    path_of(fd, buf)
}

/// `/proc/<pid>/fdinfo`: the same numbers as `fd`, each a file.
fn fdinfo_readdir(entry: &mut ffi::proc_entry, index: &mut c_ulong) -> Option<ffi::proc_entry> {
    let mut next = fd_readdir(entry, index)?;
    next.meta = Some(&PROC_PID_FDINFO.0);
    Some(next)
}

/// Linux's `ptrace_may_access(task, PTRACE_MODE_READ_FSCREDS)`, `EACCES`
/// otherwise: the one check behind every entry that hands out what a
/// debugger could read -- the address space (`maps`, `smaps`,
/// `smaps_rollup`, `mem`, `auxv`, `environ`), where the process runs from
/// (`exe`, `cwd`, `root`, `map_files`), its descriptors (`fdinfo`) and its
/// namespaces (`ns/*`). Asked where Linux asks it: at `open` for a file, at
/// `readlink` and when a link is followed, and on every lookup in a
/// directory. `stat` blanks its own fields with [`may_read`] instead, and
/// the entries that ask when they are read (`io`, `syscall`, `personality`)
/// ask `kernel_pids::Task::may_ptrace` themselves. `mem` is
/// `PTRACE_MODE_ATTACH` on Linux, which differs from read only under Yama.
///
/// Until 2026-11-12 only `fdinfo` asked, so any user could read another's
/// memory map and follow its `cwd` (`procaccess_probe`).
pub(crate) fn ptrace_guard(entry: &ffi::proc_entry) -> c_int {
    match Found::for_pid(entry.pid) {
        None => ESRCH,
        Some(found) if may_read(&found) => 0,
        Some(_) => EACCES,
    }
}

/// [`ptrace_guard`]'s question, for a task already found:
/// `kernel_pids::Task::may_ptrace`, the one rule every cross-process check
/// that is Linux's `ptrace_may_access` asks.
pub(crate) fn may_read(found: &Found) -> bool {
    found.task().may_ptrace(kernel_creds::PtraceMode::ReadFs)
}

/// Whether `found` is in the calling task's thread group: Linux's
/// `same_thread_group(task, current)`.
pub(crate) fn is_callers_group(found: &Found) -> bool {
    found.task().is_in_callers_group()
}

/// [`ffi::proc_dir_entry::own_group_passes`]: the entry lets its own thread
/// group in, and the caller is in it.
pub(crate) fn own_group_passes(entry: &ffi::proc_entry) -> bool {
    entry.meta.is_some_and(|m| m.own_group_passes) && Found::for_pid(entry.pid).is_some_and(|f| is_callers_group(&f))
}

/// `/proc/<pid>/fdinfo/<n>`: `seq_show` in Linux's `fs/proc/fd.c`.
///
/// Four lines every descriptor has -- the position, the status flags with
/// `O_CLOEXEC` added from the table, the mount id and the inode, the last two
/// what `statx` and `fstat` answer for it -- and then whatever its driver adds
/// ([`ffi::FdOps::show_fdinfo`]): an eventfd's count, an epoll set's members,
/// a pidfd's pid, which is what glibc's `pidfd_getpid` reads.
///
/// `ENOENT` for a number that was closed since the directory was listed, as
/// Linux's lookup answers. The task's `pids_lock` is released before the
/// descriptor is asked anything, for the reason the module comment gives.
///
/// Between the four and the driver's lines, the `lock:` lines Linux's
/// `show_fd_locks` adds for every lock the description holds.
fn fdinfo_show(entry: &mut ffi::proc_entry, buf: &mut ffi::proc_data) -> c_int {
    let Some(files) = take_files(entry) else {
        return ESRCH;
    };
    let fd = files.lookup_retain(entry.fd);
    let cloexec = files.cloexec(entry.fd).unwrap_or(false);
    // The table is the owner of this process's POSIX locks; an identity,
    // never dereferenced after `files` goes.
    let table = Arc::as_ptr(&files);
    drop(files);
    let Some(fd) = fd else {
        return ENOENT;
    };
    let flags = fd.flags() | if cloexec { ffi::O_CLOEXEC_ } else { 0 };
    let st = fs_fdobj::fd_fstat(&fd).unwrap_or_default();
    let pos = fd.ops.map_or(0, |ops| ops.position(&fd));
    let mut text = format!(
        "pos:\t{pos}\nflags:\t0{flags:o}\nmnt_id:\t{}\nino:\t{}\n",
        st.mount_id, st.inode
    );
    lock_lines(&fs_fdobj::locks_held_by(&fd, table), &st, &mut text);
    if let Some(ops) = fd.ops {
        ops.show_fdinfo(&fd, &mut text);
    }
    buf.append(text.as_bytes());
    0
}

/// Linux's `lock_get_status` for each, numbered from 1, with the device and
/// inode `stat` reports for the file.
fn lock_lines(locks: &[fs_fdobj::HeldLock], st: &ffi::statbuf, out: &mut String) {
    use std::fmt::Write as _;
    let (major, minor) = (fs_devices::dev_major(st.dev as u32), fs_devices::dev_minor(st.dev as u32));
    for (i, l) in locks.iter().enumerate() {
        let class = match l.class {
            fs_fdobj::LockClass::Flock => "FLOCK  ADVISORY  ",
            fs_fdobj::LockClass::Posix => "POSIX  ADVISORY  ",
            fs_fdobj::LockClass::Ofd => "OFDLCK ADVISORY  ",
        };
        let kind = if l.write { "WRITE" } else { "READ" };
        let _ = write!(out, "lock:\t{}: {class}{kind} {} {major:02x}:{minor:02x}:{} {} ", i + 1, l.pid, st.inode, l.start);
        let _ = match l.end {
            Some(end) => writeln!(out, "{end}"),
            None => writeln!(out, "EOF"),
        };
    }
}

/// The descriptor itself, when its link is not a path -- `pipe:[123]`,
/// `socket:[45]`, `anon_inode:[eventfd]` -- so that opening or stat-ing the
/// link reaches it, as Linux's `proc_fd_link` does. A descriptor with a path
/// is followed by that path instead.
fn fd_magic(entry: &mut ffi::proc_entry) -> Result<Option<fs_fdobj::Owned>, c_int> {
    let Some(fd) = take_files(entry).and_then(|files| files.lookup_retain(entry.fd)) else {
        return Ok(None);
    };
    let mut buf = vec![0u8; ffi::MAX_PATH as usize];
    Ok((fs_generic::generic_getpath(&fd, &mut buf) >= 0 && buf[0] != b'/').then_some(fd))
}

fn exe_readlink(entry: &mut ffi::proc_entry, buf: &mut [u8]) -> c_int {
    let Some(found) = Found::get(entry) else {
        return ESRCH;
    };
    // The space is retained under general_lock, which is what execve holds
    // while it swaps task->mm and releases the old one; the executable is then
    // read under the space's read lock, which its writer holds.
    //
    // Until 2026-10-16 `exefile` was read with no lock, justified because both
    // values a racing reader could see (null, or the descriptor) were valid.
    // An unsynchronised read racing a write is a data race whatever it reads,
    // and with `MmRef` retaining the space first is three lines.
    let mm = general_of(&found).mm();
    drop(found);
    let exe = mm.and_then(|mm| {
        let held = mm.read();
        held.image().exefile.clone()
    });
    path_of(exe, buf)
}

/// `cwd` and `root`: the descriptor, retained under `pids_lock` and released
/// before the path walk. `ENOENT` for a zombie, which has given its filesystem
/// state up -- Linux's `proc_cwd_link` answers the same for a task with no
/// `fs`.
fn fs_readlink(
    entry: &mut ffi::proc_entry,
    buf: &mut [u8],
    which: fn(&fsinfo::FsInfo) -> Option<fs_fdobj::Owned>,
) -> c_int {
    let Some(found) = Found::get(entry) else {
        return ESRCH;
    };
    // `pids_lock`, which `found` holds, keeps the task and so its context
    // alive across the retain.
    let fd = found.task().fs().and_then(which);
    drop(found);
    path_of(fd, buf)
}

fn cwd_readlink(entry: &mut ffi::proc_entry, buf: &mut [u8]) -> c_int {
    fs_readlink(entry, buf, fsinfo::FsInfo::pwd)
}

/// The same shape as `cwd`, and the same reason for retaining before letting
/// the lock go — `chroot` replaces `fs->root` under it.
fn root_readlink(entry: &mut ffi::proc_entry, buf: &mut [u8]) -> c_int {
    fs_readlink(entry, buf, fsinfo::FsInfo::root)
}

/// `/proc/<pid>/task`: one directory per thread of the group, named by tid.
///
/// Each is the same directory as `/proc/<pid>` -- without `task` -- with the
/// entry's `pid` set to the thread's, which is what every reader looks the
/// task up by; so `status` answers `Pid: <tid>`, `Tgid: <pid>`, the thread's
/// own name and its own signal masks, as Linux's does. Until 2026-09-04 this
/// listed the leader alone, as a symlink to `/proc/<pid>`, so `top -H`,
/// `ps -T` and anything else that enumerates a process's threads saw one.
///
/// A zombie has left its group's list and is listed on its own, which is the
/// one thread Linux still counts for it.
fn task_readdir(entry: &mut ffi::proc_entry, index: &mut c_ulong) -> Option<ffi::proc_entry> {
    let found = Found::get(entry)?;
    let i = *index;
    let task = found.task();
    let thread = if task.is_zombie() {
        (i == 0).then_some(task)
    } else {
        u32::try_from(i).ok().and_then(|i| found.group().thread(i))
    };
    let tid = thread.map_or(0, |t| t.pid());
    drop(found);
    if tid == 0 {
        return None;
    }
    *index = i + 1;
    Some(ffi::proc_entry {
        meta: Some(&PROC_PID_TASK.0),
        pid: tid,
        ..ffi::proc_entry::default()
    })
}

// ---------------------------------------------------------------------------
// The directory
// ---------------------------------------------------------------------------

static PROC_PID_FD: Entry = Entry(ffi::proc_dir_entry {
    mode: libc::S_IFLNK,
    getname: Some(fd_getname),
    readlink: Some(fd_readlink),
    magic: Some(fd_magic),
    jumps: true,
    ..blank()
});

static PROC_PID_FDINFO: Entry = Entry(ffi::proc_dir_entry {
    getname: Some(fd_getname),
    show: Some(fdinfo_show),
    ..blank()
});

/// `/proc/<pid>/task/<tid>`: a thread's directory, which is the process's
/// without `task`.
static PROC_PID_TASK: Entry = Entry(ffi::proc_dir_entry {
    mode: libc::S_IFDIR,
    getname: Some(task_getname),
    children: Some(proc_tid_children.as_slice()),
    ..blank()
});

const PID_LEN: usize = 28;
/// The thread directory has every entry but the `process_only` ones.
const TID_LEN: usize = thread_len(&PID_ENTRIES);

/// In alphabetical order, which is the order `readdir` reports them in.
///
/// Three of the modes are the access policy rather than a default, and each says
/// why: these entries carry the task's own uid, so a mode that is too generous
/// hands one user another user's secrets.
#[unsafe(no_mangle)]
pub static proc_pid_children: Children<PID_LEN> = Children(PID_ENTRIES);

/// The same entries for a thread, the `process_only` ones excepted: Linux's
/// `tid_base_stuff` is `tgid_base_stuff` without `task`, `map_files` and
/// `timerslack_ns`. One list, so that an entry added to the process's
/// directory reaches the thread's without anyone remembering to.
static proc_tid_children: Children<TID_LEN> = Children(thread_entries(PID_ENTRIES));

const fn thread_len(all: &[ffi::proc_dir_entry; PID_LEN]) -> usize {
    let (mut i, mut n) = (0, 0);
    while i < PID_LEN {
        if !all[i].process_only {
            n += 1;
        }
        i += 1;
    }
    n
}

const fn thread_entries(all: [ffi::proc_dir_entry; PID_LEN]) -> [ffi::proc_dir_entry; TID_LEN] {
    let mut out = [const { blank() }; TID_LEN];
    let (mut i, mut n) = (0, 0);
    while i < PID_LEN {
        if !all[i].process_only {
            out[n] = all[i];
            out[n].in_thread_dir = true;
            n += 1;
        }
        i += 1;
    }
    out
}

const PID_ENTRIES: [ffi::proc_dir_entry; PID_LEN] = [
    // 0400, as Linux's: a process that is not dumpable has its entries owned
    // by root, and this is how it keeps its own auxiliary vector from itself.
    ffi::proc_dir_entry {
        name: Some(c"auxv"),
        mode: libc::S_IFREG | 0o400,
        show: Some(crate::pidmem::proc_pid_auxv_show),
        guard: Some(ptrace_guard),
        ..blank()
    },
    ffi::proc_dir_entry {
        name: Some(c"cmdline"),
        show: Some(crate::pidmem::proc_pid_cmdline_show),
        ..blank()
    },
    ffi::proc_dir_entry {
        name: Some(c"comm"),
        mode: libc::S_IFREG | 0o644,
        show: Some(crate::pidmem::proc_pid_comm_show),
        update: Some(crate::pidmem::proc_pid_comm_update),
        ..blank()
    },
    ffi::proc_dir_entry {
        name: Some(c"cwd"),
        mode: libc::S_IFLNK,
        readlink: Some(cwd_readlink),
        jumps: true,
        guard: Some(ptrace_guard),
        ..blank()
    },
    // 0400 for the same reason as fd below: an environment holds tokens and
    // passwords as often as not, and Linux gates this one behind ptrace
    // access on top of the mode.
    ffi::proc_dir_entry {
        name: Some(c"environ"),
        mode: libc::S_IFREG | 0o400,
        show: Some(crate::pidmem::proc_pid_environ_show),
        guard: Some(ptrace_guard),
        ..blank()
    },
    ffi::proc_dir_entry {
        name: Some(c"exe"),
        mode: libc::S_IFLNK,
        readlink: Some(exe_readlink),
        jumps: true,
        guard: Some(ptrace_guard),
        ..blank()
    },
    // 0500, not the 0555 a directory defaults to. A listable fd directory
    // tells any user which files everyone else has open. Linux uses
    // dr-x------ for the same reason.
    ffi::proc_dir_entry {
        name: Some(c"fd"),
        mode: libc::S_IFDIR | 0o500,
        readdir: Some(fd_readdir),
        own_group_passes: true,
        ..blank()
    },
    // 0555, Linux's, with `ptrace_guard` behind it: without ptrace access to
    // the task, listing it and looking anything up in it is `EACCES`. It was
    // 0500 until 2026-11-12, the mode standing in for a check there was not.
    ffi::proc_dir_entry {
        name: Some(c"fdinfo"),
        mode: libc::S_IFDIR | 0o555,
        readdir: Some(fdinfo_readdir),
        guard: Some(ptrace_guard),
        ..blank()
    },
    // Linux asks ptrace access when it is read, not when it is opened.
    ffi::proc_dir_entry {
        name: Some(c"io"),
        mode: libc::S_IFREG | 0o400,
        show: Some(crate::pidstate::io_show),
        ..blank()
    },
    ffi::proc_dir_entry {
        name: Some(c"limits"),
        show: Some(crate::pid::proc_pid_limits_show),
        ..blank()
    },
    ffi::proc_dir_entry {
        name: Some(c"map_files"),
        mode: libc::S_IFDIR | 0o500,
        readdir: Some(crate::mapfiles::map_files_readdir),
        guard: Some(ptrace_guard),
        own_group_passes: true,
        process_only: true,
        ..blank()
    },
    ffi::proc_dir_entry {
        name: Some(c"maps"),
        show: Some(crate::maps::proc_pid_maps_show),
        guard: Some(ptrace_guard),
        ..blank()
    },
    // 0600, not the 0444 a regular file defaults to. World-readable, this
    // hands any user the whole address space of every process on the system
    // -- keys, tokens, anything a process has in memory. Linux is 0600 and
    // gates it behind ptrace access on top, which is `ptrace_guard`.
    ffi::proc_dir_entry {
        name: Some(c"mem"),
        mode: libc::S_IFREG | 0o600,
        guard: Some(ptrace_guard),
        show: Some(crate::pidmem::proc_pid_mem_show),
        pread: Some(crate::pidmem::proc_pid_mem_pread),
        pwrite: Some(crate::pidmem::proc_pid_mem_pwrite),
        ..blank()
    },
    // The mount table, per process. This kernel has one mount namespace,
    // so every process sees the same table -- which is what makes these
    // two the root's own formatters rather than a per-pid answer.
    // `findmnt`, `df` and every container runtime read `mountinfo` in
    // preference to `/proc/mounts`, because it carries the mount ids.
    ffi::proc_dir_entry {
        name: Some(c"mountinfo"),
        show: Some(crate::root::proc_mountinfo_show),
        ..blank()
    },
    ffi::proc_dir_entry {
        name: Some(c"mounts"),
        show: Some(crate::root::proc_mounts_show),
        ..blank()
    },
    // dr-x--x--x: anyone may look a name up, the links ask the rest.
    ffi::proc_dir_entry {
        name: Some(c"ns"),
        mode: libc::S_IFDIR | 0o511,
        children: Some(crate::pidns::NS_CHILDREN.as_slice()),
        ..blank()
    },
    ffi::proc_dir_entry {
        name: Some(c"oom_adj"),
        mode: 0o644,
        show: Some(crate::oom::legacy_show),
        update: Some(crate::oom::legacy_update),
        ..blank()
    },
    ffi::proc_dir_entry {
        name: Some(c"oom_score_adj"),
        mode: 0o644,
        show: Some(crate::oom::adj_show),
        update: Some(crate::oom::adj_update),
        ..blank()
    },
    ffi::proc_dir_entry {
        name: Some(c"personality"),
        mode: libc::S_IFREG | 0o400,
        show: Some(crate::pidstate::personality_show),
        ..blank()
    },
    ffi::proc_dir_entry {
        name: Some(c"root"),
        mode: libc::S_IFLNK,
        readlink: Some(root_readlink),
        jumps: true,
        guard: Some(ptrace_guard),
        ..blank()
    },
    // How much of each mapping is really there, and who else has it. The
    // reason it exists is that Redis reads it before doing anything else on
    // arm64 and exits when it is not there -- see the module comment in
    // `crate::smaps`.
    ffi::proc_dir_entry {
        name: Some(c"smaps"),
        show: Some(crate::smaps::proc_pid_smaps_show),
        guard: Some(ptrace_guard),
        ..blank()
    },
    ffi::proc_dir_entry {
        name: Some(c"smaps_rollup"),
        show: Some(crate::smaps::proc_pid_smaps_rollup_show),
        guard: Some(ptrace_guard),
        ..blank()
    },
    ffi::proc_dir_entry {
        name: Some(c"stat"),
        show: Some(crate::pid::proc_pid_stat_show),
        ..blank()
    },
    ffi::proc_dir_entry {
        name: Some(c"statm"),
        show: Some(crate::pid::proc_pid_statm_show),
        ..blank()
    },
    ffi::proc_dir_entry {
        name: Some(c"status"),
        show: Some(crate::pid::proc_pid_status_show),
        ..blank()
    },
    ffi::proc_dir_entry {
        name: Some(c"syscall"),
        mode: libc::S_IFREG | 0o400,
        show: Some(crate::pidstate::syscall_show),
        ..blank()
    },
    ffi::proc_dir_entry {
        name: Some(c"task"),
        mode: libc::S_IFDIR,
        readdir: Some(task_readdir),
        links: ffi::Links::Threads,
        process_only: true,
        ..blank()
    },
    // 0666, and the test is the task itself or CAP_SYS_NICE, on read and on
    // write alike.
    ffi::proc_dir_entry {
        name: Some(c"timerslack_ns"),
        mode: libc::S_IFREG | 0o666,
        show: Some(crate::pidstate::timerslack_show),
        update: Some(crate::pidstate::timerslack_update),
        process_only: true,
        ..blank()
    },
];

/// `/proc/<pid>` itself. The root directory's readdir points every numbered
/// entry at this one.
#[unsafe(no_mangle)]
pub static proc_pid: Entry = Entry(ffi::proc_dir_entry {
    mode: libc::S_IFDIR,
    getname: Some(pid_getname),
    children: Some(proc_pid_children.as_slice()),
    ..blank()
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_entry_has_a_name_and_something_to_do() {
        assert_eq!(proc_pid_children.0.len(), PID_LEN);
        for e in &proc_pid_children.0 {
            assert!(e.name.is_some());
            let name = e.name.unwrap_or(c"");
            assert!(
                e.show.is_some() || e.readlink.is_some() || e.readdir.is_some() || e.children.is_some(),
                "{name:?} does nothing"
            );
        }
    }

    /// Lines captured from a real arm64 kernel by `fdinfo_probe`, with its
    /// pid and `major:minor:inode` filled in.
    #[test]
    fn a_lock_line_is_linuxs() {
        use fs_fdobj::{HeldLock, LockClass};
        let st = ffi::statbuf { dev: (0x2e << 8) | 0x01, inode: 5678, ..Default::default() };
        let mut out = String::new();
        lock_lines(
            &[
                HeldLock { class: LockClass::Flock, write: false, pid: 12, start: 0, end: None },
                HeldLock { class: LockClass::Posix, write: true, pid: 12, start: 20, end: None },
                HeldLock { class: LockClass::Ofd, write: false, pid: -1, start: 10, end: Some(14) },
            ],
            &st,
            &mut out,
        );
        assert_eq!(
            out,
            "lock:\t1: FLOCK  ADVISORY  READ 12 2e:01:5678 0 EOF\n\
             lock:\t2: POSIX  ADVISORY  WRITE 12 2e:01:5678 20 EOF\n\
             lock:\t3: OFDLCK ADVISORY  READ -1 2e:01:5678 10 14\n"
        );
    }

    #[test]
    fn the_entries_are_in_alphabetical_order() {
        // readdir walks the table in order and a caller sorting its own output
        // would not notice, but `ls` does not sort what /proc hands it.
        let names: Vec<_> = proc_pid_children
            .0
            .iter()
            .map(|e| e.name.unwrap_or(c"").to_owned())
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }

    /// A thread's directory is the process's without `task`, and nothing
    /// else: the two are one list.
    #[test]
    fn a_threads_directory_is_the_processs_without_three() {
        assert_eq!(proc_tid_children.0.len(), TID_LEN);
        let name = |e: &ffi::proc_dir_entry| e.name.unwrap_or(c"").to_owned();
        let pid: Vec<_> = proc_pid_children.0.iter().map(name).collect();
        let tid: Vec<_> = proc_tid_children.0.iter().map(name).collect();
        let only: [&[u8]; 3] = [b"map_files", b"task", b"timerslack_ns"];
        let kept: Vec<_> = pid.iter().filter(|n| !only.contains(&n.to_bytes())).cloned().collect();
        assert_eq!(tid, kept, "tid_base_stuff is tgid_base_stuff without these");
        assert_eq!(PID_LEN - TID_LEN, only.len());
        assert!(proc_tid_children.0.iter().all(|e| e.in_thread_dir));
        assert!(!proc_pid_children.0.iter().any(|e| e.in_thread_dir));
        // And the thread directory is a directory, pointing at that list.
        assert_eq!(PROC_PID_TASK.0.mode, libc::S_IFDIR);
        // The *same slice*, which is a comparison the pointer version could
        // only make by address.
        assert_eq!(
            PROC_PID_TASK.0.children.map(<[_]>::as_ptr),
            Some(proc_tid_children.as_slice().as_ptr())
        );
    }

    #[test]
    fn the_entries_that_carry_secrets_are_not_world_readable() {
        // These carry the task's own uid, so the mode in the table *is* the
        // access policy. environ and mem were 0444 and fd was 0555 once.
        for (name, mode) in [
            ("auxv", libc::S_IFREG | 0o400),
            ("environ", libc::S_IFREG | 0o400),
            ("fd", libc::S_IFDIR | 0o500),
            ("fdinfo", libc::S_IFDIR | 0o555),
            ("mem", libc::S_IFREG | 0o600),
        ] {
            let e = proc_pid_children
                .0
                .iter()
                .find(|e| e.name.unwrap_or(c"").to_bytes() == name.as_bytes())
                .expect(name);
            assert_eq!(e.mode, mode, "{name}");
        }
    }
}
