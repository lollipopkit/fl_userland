//! Closing a descriptor frees the state Rust allocated for it.
//!
//! Not comparable to a real kernel, and in its own binary for that reason.
//! `/proc/iul/objects` is this emulator's own accounting; Linux has nothing to
//! count because its eventfd state is not a thing this repository allocates.
//!
//! It exists because moving a descriptor's state to Rust introduces a way to
//! leak that the C did not have. eventfd's counter used to be two fields in a
//! union, with nothing to allocate and nothing to free -- `eventfd_ops` had no
//! `close` at all. pidfd's is worse: its registry entry outlives the
//! descriptor unless close removes it, so a leak there is a map that grows for
//! the life of the process *and* a wakeup delivered to a descriptor that is
//! gone. Reading `fd_close` and believing it is not a check.
//!
//! The side tables are the same failure by a different route. A `struct task`
//! or a `struct tgroup` is C's to free, and `crates/kernel/proctree` keeps an
//! entry keyed by its address — so a free that does not say so leaves an entry
//! behind, and the next allocation at that address inherits it. The intrusive
//! lists they replaced could not have the problem: their links were *in* the
//! freed memory. `proctree_stale` counts how often an address has arrived that
//! was still registered, and is always zero.
//!
//! One group per kind, so adding the next object is one more group.

use guest_tests::{Harness, check, sys};

fn eventfd(initval: u32, flags: i32) -> i32 {
    unsafe { libc::syscall(libc::SYS_eventfd2, initval, flags) as i32 }
}

fn pidfd_open(pid: i32) -> i32 {
    unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 }
}

fn epoll_create() -> i32 {
    unsafe { libc::syscall(libc::SYS_epoll_create1, 0) as i32 }
}

/// How many of `kind` the emulator has allocated.
fn live(kind: &str) -> Option<i64> {
    let s = std::fs::read_to_string("/proc/iul/objects").ok()?;
    let prefix = format!("{kind} ");
    s.lines()
        .find_map(|l| l.strip_prefix(prefix.as_str()))?
        .trim()
        .parse()
        .ok()
}

fn main() {
    let mut h = Harness::new();
    h.group("close-frees-the-state");

    let Some(before) = live("eventfd") else {
        check!(
            h,
            false,
            "/proc/iul/objects is present and contains eventfd accounting"
        );
        std::process::exit(h.finish());
    };

    let mut fds = Vec::new();
    for _ in 0..64 {
        let f = eventfd(0, 0);
        if f >= 0 {
            fds.push(f);
        }
    }
    check!(h, fds.len() == 64, "opened 64 eventfds, got {}", fds.len());

    let during = live("eventfd").unwrap_or(-1);
    check!(
        h,
        during == before + 64,
        "each one allocated: {before} -> {during}"
    );

    for f in &fds {
        unsafe { libc::close(*f) };
    }
    let after = live("eventfd").unwrap_or(-1);
    check!(
        h,
        after == before,
        "and closing them all freed every one: {before} -> {during} -> {after}"
    );

    h.group("epoll-state");
    let before = live("epoll").unwrap_or(-1);
    let mut epolls = Vec::new();
    for _ in 0..32 {
        let fd = epoll_create();
        if fd >= 0 {
            epolls.push(fd);
        }
    }
    check!(
        h,
        epolls.len() == 32,
        "opened 32 epolls, got {}",
        epolls.len()
    );
    let during = live("epoll").unwrap_or(-1);
    check!(
        h,
        during == before + epolls.len() as i64,
        "each epoll allocated one Rust state: {before} -> {during}"
    );
    let duplicate = unsafe { libc::dup(epolls[0]) };
    check!(h, duplicate >= 0, "dup one epoll: {duplicate}");
    unsafe { libc::close(epolls[0]) };
    check!(
        h,
        live("epoll") == Some(during),
        "closing one alias keeps the shared epoll state"
    );
    for fd in epolls.iter().skip(1) {
        unsafe { libc::close(*fd) };
    }
    unsafe { libc::close(duplicate) };
    let after = live("epoll").unwrap_or(-1);
    check!(
        h,
        after == before,
        "closing every epoll freed its state: {before} -> {during} -> {after}"
    );

    h.group("epoll-resource-exhaustion");
    let before = live("epoll").unwrap_or(-1);
    let mut old_limit: libc::rlimit = unsafe { std::mem::zeroed() };
    let got_limit = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut old_limit) };
    check!(h, got_limit == 0, "read RLIMIT_NOFILE: {got_limit}");
    let low_limit = libc::rlimit {
        rlim_cur: old_limit.rlim_cur.min(96),
        rlim_max: old_limit.rlim_max,
    };
    let set_limit = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const low_limit) };
    check!(
        h,
        set_limit == 0,
        "lower RLIMIT_NOFILE to {}: {set_limit}",
        low_limit.rlim_cur
    );

    let mut held = Vec::new();
    loop {
        sys::clear_errno();
        let fd = epoll_create();
        if fd < 0 {
            break;
        }
        held.push(fd);
    }
    let exhaustion_errno = sys::errno();
    check!(
        h,
        !held.is_empty() && exhaustion_errno == libc::EMFILE,
        "epoll_create reaches the per-process descriptor limit: opened {} errno {exhaustion_errno}",
        held.len()
    );

    // EMFILE also prevents opening /proc/iul/objects. Free one slot before
    // asking for the accounting, and remove that object from the expected count.
    if let Some(fd) = held.pop() {
        unsafe { libc::close(fd) };
    }
    let during = live("epoll").unwrap_or(-1);
    check!(
        h,
        during == before + held.len() as i64,
        "every successful exhaustion-shape open is accounted: {before} -> {during}"
    );
    for fd in held {
        unsafe { libc::close(fd) };
    }
    let restore_limit = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const old_limit) };
    check!(
        h,
        restore_limit == 0,
        "restore RLIMIT_NOFILE: {restore_limit}"
    );
    let after = live("epoll").unwrap_or(-1);
    check!(
        h,
        after == before,
        "closing the exhaustion-shape set frees every epoll: {before} -> {during} -> {after}"
    );

    h.group("pidfd-registry");
    // A pidfd's registry entry outlives the descriptor unless close removes
    // it. Leaking one is worse than leaking an eventfd: the map grows for the
    // life of the process, and an exit wakes a descriptor that is gone.
    let before = live("pidfd").unwrap_or(-1);
    let mut pfds = Vec::new();
    for _ in 0..32 {
        let f = pidfd_open(1);
        if f >= 0 {
            pfds.push(f);
        }
    }
    check!(h, !pfds.is_empty(), "opened {} pidfds on pid 1", pfds.len());
    let during = live("pidfd").unwrap_or(-1);
    check!(
        h,
        during == before + pfds.len() as i64,
        "each one registered: {before} -> {during}"
    );
    for f in &pfds {
        unsafe { libc::close(*f) };
    }
    let after = live("pidfd").unwrap_or(-1);
    check!(
        h,
        after == before,
        "and closing them all deregistered every one: {before} -> {during} -> {after}"
    );

    h.group("proctree-side-table");
    // A process that exits and is reaped must leave nothing behind. The
    // accounting is read from a child, because reading it here would count
    // this process too and the arithmetic would be about the reader.
    let before_tasks = live("task").unwrap_or(-1);
    let before_groups = live("tgroup").unwrap_or(-1);
    check!(
        h,
        before_tasks >= 1 && before_groups >= 1,
        "this process is registered: {before_tasks} tasks, {before_groups} groups"
    );
    for _ in 0..32 {
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
    }
    let after_tasks = live("task").unwrap_or(-1);
    let after_groups = live("tgroup").unwrap_or(-1);
    check!(
        h,
        after_tasks == before_tasks,
        "32 forks that exited and were reaped leave no task: {before_tasks} -> {after_tasks}"
    );
    check!(
        h,
        after_groups == before_groups,
        "and no thread group: {before_groups} -> {after_groups}"
    );
    // The one that says a freed address was reused. Zero, always -- and a
    // non-zero here is the shape this whole group exists to catch, not a
    // count that drifts.
    check!(
        h,
        live("proctree_stale") == Some(0),
        "no address arrived that was still registered: {:?}",
        live("proctree_stale")
    );

    h.group("task-structs");
    // **The structs, which is a different question from the entries above.**
    // `task`, `tgroup` and `proctree_stale` count `crates/kernel/proctree`'s
    // registry, and an entry is forgotten a *step before* its struct is freed
    // — a whole round before, for `struct task`, which `task_destroy` defers.
    // So a leak of the allocation is invisible to that group and was invisible
    // to everything until the four became `Box`es on 2026-09-12.
    //
    // Four allocations per forked process: the task, its thread group, the
    // 288 KB software TLB and the cleanup handoff. A leak of any one of them
    // is 200 of it after this loop.
    let names = ["task_struct", "tgroup_struct", "tlb", "task_cleanup"];
    let before: Vec<i64> = names.iter().map(|n| live(n).unwrap_or(-1)).collect();
    check!(
        h,
        before.iter().all(|n| *n >= 1),
        "/proc/iul/objects counts all four: {names:?} = {before:?}"
    );
    const FORKS: i64 = 200;
    for _ in 0..FORKS {
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
    }
    // **`waitpid` returning is not the host thread having finished**, which is
    // why this waits rather than reading straight away. A reaped child's task
    // is destroyed by the reaper, and its TLB and cleanup struct are freed by
    // the child's *own* pthread on its way out — so the two counts trail the
    // wait by however long that thread takes to unwind. A leak does not
    // converge; a lag does, which is what the loop distinguishes.
    let settle = |want: &[i64]| -> Vec<i64> {
        for _ in 0..100 {
            let now: Vec<i64> = names.iter().map(|n| live(n).unwrap_or(-1)).collect();
            if now.iter().zip(want).all(|(a, b)| a <= b) {
                return now;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        names.iter().map(|n| live(n).unwrap_or(-1)).collect()
    };
    // The slack is one allocation each, and it is `struct task`'s deferred
    // round: `task_destroy` frees the *previous* task it destroyed, so one is
    // always held back. The other three have no such delay and the same bound
    // is simply loose for them.
    let want: Vec<i64> = before.iter().map(|n| n + 1).collect();
    let after = settle(&want);
    for (i, name) in names.iter().enumerate() {
        check!(
            h,
            after[i] <= before[i] + 1,
            "{FORKS} forks that exited and were reaped leak no {name}: {} -> {} (at most {})",
            before[i],
            after[i],
            before[i] + 1
        );
    }

    h.group("inode-table");
    // Every filesystem's inodes go through one table, keyed by (mount, number)
    // and refcounted. An inode appears on the first reference and goes on the
    // last, so opening and closing the same files must return the count to
    // where it started -- and a count that only grows is a reference nobody
    // released, at the rate the workload opens files.
    //
    // It is the oldest hand-rolled collection left in the tree: a 1024-bucket
    // array of intrusive lists. Nothing counted it until now.
    let before = live("inode").unwrap_or(-1);
    check!(h, before >= 0, "/proc/iul/objects counts inodes: {before}");
    let mut held = Vec::new();
    for i in 0..32 {
        let path = format!("/tmp/inode-leak-{i}");
        let _ = std::fs::write(&path, b"x");
        let f = unsafe {
            libc::open(
                std::ffi::CString::new(path.as_str()).expect("no NUL").as_ptr(),
                libc::O_RDONLY,
            )
        };
        if f >= 0 {
            held.push((f, path));
        }
    }
    check!(h, held.len() == 32, "opened 32 files, got {}", held.len());
    let during = live("inode").unwrap_or(-1);
    check!(
        h,
        during > before,
        "holding them takes inodes: {before} -> {during}"
    );
    for (fd, path) in &held {
        unsafe { libc::close(*fd) };
        let _ = std::fs::remove_file(path);
    }
    let after = live("inode").unwrap_or(-1);
    check!(
        h,
        after == before,
        "and closing them all released every one: {before} -> {during} -> {after}"
    );

    h.group("unixpeer-side-table");
    // An AF_UNIX socket's endpoint is the same shape: a table entry that
    // sock_close has to remove.
    let before = live("unixpeer").unwrap_or(-1);
    let mut socks = Vec::new();
    for _ in 0..32 {
        let mut pair = [0i32; 2];
        if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) } == 0 {
            socks.push(pair);
        }
    }
    check!(h, socks.len() == 32, "32 socketpairs, got {}", socks.len());
    let during = live("unixpeer").unwrap_or(-1);
    check!(
        h,
        during == before + 64,
        "each socket has an endpoint: {before} -> {during}"
    );
    for pair in &socks {
        unsafe {
            libc::close(pair[0]);
            libc::close(pair[1]);
        }
    }
    let after = live("unixpeer").unwrap_or(-1);
    check!(
        h,
        after == before,
        "and closing them all removed every one: {before} -> {during} -> {after}"
    );
    check!(
        h,
        live("unixpeer_pending") == Some(0),
        "with no handshake left outstanding: {:?}",
        live("unixpeer_pending")
    );

    h.group("open-refusals");
    // An open that the mount performs and `generic_openat` then refuses --
    // ENOTDIR for `O_DIRECTORY` on a file, EISDIR for a directory opened for
    // writing -- has already made a description, and a host descriptor behind
    // it. Neither is in any table, so a refusal that forgets to release them is
    // invisible to `/proc/self/fd` and to `RLIMIT_NOFILE`: the whole guest suite
    // passed with one release backed out. `fd` is the count of descriptions.
    let file = c"/tmp/open-refusal-file";
    let dir = c"/tmp/open-refusal-dir";
    let _ = std::fs::write("/tmp/open-refusal-file", b"x");
    let _ = std::fs::create_dir("/tmp/open-refusal-dir");
    let before = live("fd").unwrap_or(-1);
    check!(h, before > 0, "/proc/iul/objects counts descriptions: {before}");
    let mut refused = [0usize; 2];
    for _ in 0..64 {
        sys::clear_errno();
        if unsafe { libc::open(file.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) } < 0
            && sys::errno() == libc::ENOTDIR
        {
            refused[0] += 1;
        }
        sys::clear_errno();
        if unsafe { libc::open(dir.as_ptr(), libc::O_WRONLY) } < 0 && sys::errno() == libc::EISDIR {
            refused[1] += 1;
        }
    }
    check!(h, refused == [64, 64], "every open was refused as asked: {refused:?}");
    let after = live("fd").unwrap_or(-1);
    check!(
        h,
        after == before,
        "and none of the refusals kept its description: {before} -> {after}"
    );
    let _ = std::fs::remove_file("/tmp/open-refusal-file");
    let _ = std::fs::remove_dir("/tmp/open-refusal-dir");

    h.group("a-clone-refused-for-its-pidfd");
    // `clone(CLONE_PIDFD)` makes the child, and only then the descriptor that
    // names it. With the descriptor table full the second step fails and the
    // clone answers EMFILE -- and the child it had made must go completely:
    // its thread group was registered in the process-group index and the
    // thread list, and a group left there names a freed task as its leader.
    let before_groups = live("tgroup").unwrap_or(-1);
    let before_structs = live("tgroup_struct").unwrap_or(-1);
    let before_pages = live("anon_pages").unwrap_or(-1);
    let mut filled = Vec::new();
    loop {
        let fd = unsafe { libc::dup(0) };
        if fd < 0 {
            break;
        }
        filled.push(fd);
    }
    check!(h, sys::errno() == libc::EMFILE, "the table filled: errno {}", sys::errno());
    let mut pidfd: i32 = -1;
    sys::clear_errno();
    // The legacy call: flags, stack, the pidfd's address (where
    // CLONE_PARENT_SETTID would store the tid), tls, child tid.
    let r = unsafe {
        libc::syscall(
            libc::SYS_clone,
            0x1000 | libc::SIGCHLD as u64, // CLONE_PIDFD
            0u64,
            (&raw mut pidfd) as u64,
            0u64,
            0u64,
        )
    };
    if r == 0 {
        unsafe { libc::_exit(0) };
    }
    let err = sys::errno();
    for fd in filled {
        unsafe { libc::close(fd) };
    }
    if r > 0 {
        let mut status = 0;
        unsafe { libc::waitpid(r as i32, &mut status, 0) };
    }
    check!(h, r < 0 && err == libc::EMFILE, "the clone was refused with EMFILE: {r}, errno {err}");
    check!(
        h,
        live("tgroup") == Some(before_groups),
        "and left no thread group registered: {before_groups} -> {:?}",
        live("tgroup")
    );
    check!(
        h,
        live("tgroup_struct") == Some(before_structs),
        "and no thread group allocated: {before_structs} -> {:?}",
        live("tgroup_struct")
    );
    check!(
        h,
        live("anon_pages") == Some(before_pages),
        "and no copy of the address space: {before_pages} -> {:?}",
        live("anon_pages")
    );
    // A signal to this process group walks every group in it, and a group left
    // behind would hand it a freed leader.
    unsafe { libc::signal(libc::SIGUSR2, libc::SIG_IGN) };
    check!(h, unsafe { libc::kill(0, libc::SIGUSR2) } == 0, "a signal to the process group");

    std::process::exit(h.finish());
}
