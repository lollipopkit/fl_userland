//! Allocation and rollback of a newly constructed guest task.

use std::sync::atomic::Ordering;
use super::*;
use guest_errno::Errno;

// --------------------------------------------------------- building the task

/// A task built far enough to have its own thread group, and not published.
///
/// Dropping it gives back what it holds and then the task. It kept a flag per
/// object installed until 2026-10-17; an empty slot says the same thing.
struct Partial(Option<taskcalls::NewTask>);

impl Partial {
    fn task(&self) -> &taskcalls::NewTask {
        self.0.as_ref().expect("an unpublished task")
    }
}

impl Drop for Partial {
    fn drop(&mut self) {
        let Some(mut task) = self.0.take() else {
            return;
        };
        // Released here, outside `pids_lock`, rather than by the destroy below,
        // which runs the fields' drops under it: closing the root and tearing
        // down an address space take locks of their own. Empty slots answer
        // `None`, so whichever of them was installed is what goes.
        let t = task.get_mut();
        drop(t.fs.take());
        drop(t.files.take());
        // `cpu.mmu` points into the address space; cleared with it.
        t.cpu.get_mut().mmu = std::ptr::null_mut();
        drop(t.mm.take());
        let pids = kernel_pids::PidsGuard::take();
        let group = task.group.swap(std::ptr::null_mut(), Ordering::AcqRel);
        // SAFETY: the group `construct_task` made for this task, which no
        // table names until the task is published.
        unsafe { kernel_tgroup::tgroup_free_new(pids.held(), group) };
        // Before the task goes: its drop takes the lock again.
        drop(pids);
        drop(task);
    }
}

/// A new process.
///
/// A `Result` since 2026-09-14, and an `ERR_PTR` before that: `task_create_`
/// tells `EAGAIN` — the user's `RLIMIT_NPROC`, or every pid number taken —
/// from `ENOMEM`, and a fork must report which, so "null on failure" was never
/// enough. Nothing in C names either function, so neither needs the encoding.
pub(super) fn construct_task(parent: *mut ffi::task) -> Result<taskcalls::Unstarted, Errno> {
    let mut task = unsafe { taskcalls::task_create_(parent) }?;
    let ptr = task.as_ptr();
    {
        let t = task.get_mut();
        // A fresh process, not a fork: task_create_ copied the parent, and
        // become_new_init_child passes a real parent -- init -- so without
        // this the embedder's new process would start under init's thread
        // name, personality and no_new_privs.
        t.attr.get_mut().init();
        // Nor init's signal state: a new process starts with nothing
        // blocked, pending or waited for.
        t.signals.get_mut().clear();

        // `None` to inherit nothing: this is a process with no parent as far
        // as its group is concerned, even when become_new_init_child passes
        // one as the task's. Registered with the task, at the bottom.
        let group = kernel_tgroup::tgroup_new(None, ptr).as_ptr();
        t.group.store(group, Ordering::Release);
        t.tgid.store(t.pid(), Ordering::Relaxed);

        // The address space and the pointer the gadgets reach the page table
        // through, both or neither. `cpu.mmu` is a cached interior pointer
        // because the gadgets follow it on every guest memory access and
        // cannot make a call.
        let mm = mmapcalls::mm::mm_new_from(None);
        t.cpu.get_mut().mmu = (&raw const mm.mem.mmu).cast_mut();
        t.mm.set(Some(mm));

        // Drops whatever `task_create_` cloned from the parent.
        t.sighand.set(Some(kernel_sighand::SigHand::new()));
    }
    let mut partial = Partial(Some(task));
    let t = partial.task();

    // An `Option`, so there is no third answer. This used to test
    // `is_null() || is_err()`, from a C `fdtable_new` that answered with an
    // ERR_PTR rather than null — a `== NULL` check passed an encoded errno
    // through as a table and every later `f_get` read fields off it.
    let Some(files) = fdtable::Table::new(3, FDTABLE_OPS) else {
        return Err(Errno::ENOMEM);
    };
    t.files.set(Some(files));

    // A reference of this function's own, so the context is reached without
    // going back through the task.
    let fs = fsinfo::fs_info_new();
    fs.set_umask(0o022);
    t.fs.set(Some(std::sync::Arc::clone(&fs)));

    // `current` has to be this task for the open, and restored on the way out
    // *either way*: returning from here left it pointing at a half-built task,
    // so whatever ran next on this thread did so as a process with no root and
    // no group.
    let old_current = taskview::current();
    // SAFETY: `ptr` is the task being built, which `partial` keeps live, and
    // `old_current` is whatever this thread was already running -- also live,
    // because it is this thread's and this thread is here.
    unsafe { taskview::bind_current(ptr) };
    // `generic_openat`, not the `iul.h` entry point beside it: this is a Rust
    // caller and the layer below answers a `Result`.
    let root = fs_generic::generic_openat(ffi::At::Pwd, c"/", ffi::O_RDONLY_ as c_int, 0);
    unsafe { taskview::set_current(old_current) };
    let root = root?;
    fs.chdir(root.clone());
    fs.chroot(root);

    // Complete: make it reachable -- its pid, its place in the tree, its
    // group's thread list, its count among the group's host threads and its
    // session, under one `pids_lock` hold. `task_create_` published it at the
    // top of this function until 2026-09-30, so an embedder starting a session
    // while other guest processes ran published a task whose group, address
    // space and descriptor table were still being made. The same move as
    // `crates/kernel/forkcalls`' `publish`.
    let pids = kernel_pids::PidsGuard::take();
    let new = partial.0.take().expect("an unpublished task");
    // SAFETY: the caller's parent, live or null, under the lock.
    let parent = unsafe { kernel_pids::Task::from_raw(pids.held(), parent) };
    let task = match new.publish(pids.held(), parent) {
        Ok(task) => task,
        Err(new) => {
            drop(pids);
            partial.0 = Some(new);
            return Err(Errno::ENOMEM);
        }
    };
    let group = task.handle(pids.held()).group().expect("its group, made above");
    proctree::group_add_new(group.raw(), ptr);
    // The one thread this new process starts with. `publish` does the same
    // for every later one.
    task.hosts.set(Some(group.tgroup().hosts.started()));
    // A new session, which is also what registers the group in the
    // process-group and session index. The first process cannot already lead
    // a session, so the only error this can answer is unreachable here.
    let _ = groupcalls::group_setsid(pids.held(), group);
    drop(pids);
    Ok(task)
}
