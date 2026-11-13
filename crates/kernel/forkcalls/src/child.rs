//! Child resource setup and rollback for fork-like syscalls.

use std::sync::atomic::Ordering;
use super::*;

/// What has been given to the child so far, so that a failure gives it back.
///
/// The C had a five-label `goto` chain, and the one thing it got wrong was the
/// group: the task is in the group's thread list by the time the `user_put`s
/// run, and `sys_clone` destroys the task on error — leaving that list pointing
/// at freed memory and a newly copied `tgroup` with nothing in it. Here each
/// step is recorded as it succeeds and undone in reverse, so the unwind cannot
/// disagree with what was done.
#[derive(Default)]
#[must_use = "a child that is not started has to be given back with `undo`"]
pub(super) struct Given {
    mm: bool,
    files: bool,
    fs: bool,
    /// There was a `sighand` here until 2026-09-12. The child owns an `Arc`
    /// from `task_create_` onwards whatever this function does to it, so there
    /// was never a moment the flag described correctly — and `task_destroy`,
    /// which `sys_clone` runs on this path, is the one release.
    /// The group the task had before, when this clone made a new one.
    /// Address of the task's previous group, kept only until the clone setup
    /// either completes or is rolled back.
    old_group: Option<*mut ffi::tgroup>,
    in_group: bool,
}

impl Given {
    /// # Safety
    /// `task` is the child these were given to, not started.
    pub(super) unsafe fn undo(self, task: &ffi::task) {
        let ptr = std::ptr::from_ref(task).cast_mut();
        // The thread list is only joined by `publish`; a new group is made by
        // `copy_task` whether or not it got that far.
        if self.in_group || self.old_group.is_some() {
            let pids = Pids::take();
            if self.in_group {
                proctree::group_remove(task.group.load(Ordering::Acquire), ptr);
            }
            if let Some(old) = self.old_group {
                unsafe {
                    kernel_tgroup::tgroup_free_new(pids.held(), task.group.load(Ordering::Acquire));
                    task.tgid.store((*(*old).leader()).tgid.load(Ordering::Relaxed), Ordering::Relaxed);
                }
                task.group.store(old, Ordering::Release);
            }
        }
        // **Out of the fields before they are released, and under
        // `pids_lock`.** This read the three words and released what they
        // named, leaving the pointers where they were.
        //
        // The task **may be published** by the time this runs: `sys_clone`
        // undoes after `publish` when the pidfd cannot be made. (Until
        // 2026-09-30 it always was, because `task_create_` published before
        // `copy_task` was entered.) So
        // between here and the `task_destroy` on the next line of `sys_clone`
        // there is a live pid whose `files`, `fs` and `mm` name freed objects,
        // and `/proc/<pid>/fd`, `/proc/<pid>/statm` and `/proc/net/tcp` all
        // reach a task by pid under `pids_lock` and then retain one of the
        // three. `pids_lock` is the lock that makes reading-then-retaining
        // safe -- it is what
        // `docs/changelog/2026-08-22-proc-fd-read-a-dying-tasks-table.md` is
        // about -- and this function did not take it.
        //
        // `do_exit`'s `release_guest_memory` is the same three releases and has
        // taken the lock and swapped since it was written; this is that shape,
        // one function over. See
        // `docs/changelog/2026-09-12-a-failed-clone-released-a-published-tasks-objects.md`
        // for why it is unreproducible and was found by reading.
        let (fs, files, mm) = {
            let _pids = Pids::take();
            (
                if self.fs { task.fs.take() } else { None },
                if self.files { task.files.take() } else { None },
                // Under general_lock too: the task may be published, and a
                // `/proc` reader retains the slot under that lock.
                if self.mm {
                    let _held = taskcalls::GeneralGuard::of(task);
                    task.mm.take()
                } else {
                    None
                },
            )
        };
        drop(fs);
        drop(files);
        if mm.is_some() {
                // `cpu.mmu` aliases into the `mm` allocation and outlives it
                // otherwise. Nothing can read it here -- the child has no host
                // thread and never reached the run loop -- but
                // `crates/kernel/boot`'s `Partial::drop` clears it beside the
                // same release, and one of the two being right by accident is
                // how the next reader gets it wrong.
            unsafe { (*task.cpu.get()).mmu = std::ptr::null_mut() };
            drop(mm);
        }
    }
}

/// Turn the copy `task_create_` made into a child of the requested shape.
///
/// Answers what it gave the child, which the caller gives back with
/// [`Given::undo`] if the clone fails after this returns -- before
/// 2026-09-30 it did not, and the two failures after this (the vfork
/// handoff and the pidfd) released the task and nothing it held.
pub(super) fn copy_task(
    task: &mut taskcalls::NewTask,
    flags: u64,
    stack: u64,
    ptid_addr: u64,
    tls_addr: u64,
    ctid_addr: u64,
) -> Result<Given, i64> {
    let mut given = Given::default();
    match copy_task_steps(task, flags, stack, tls_addr, ptid_addr, ctid_addr, &mut given) {
        Ok(()) => Ok(given),
        Err(e) => {
            // SAFETY: what was given to this task, which has not started.
            unsafe { given.undo(task) };
            Err(e)
        }
    }
}

fn copy_task_steps(
    task: &mut taskcalls::NewTask,
    flags: u64,
    stack: u64,
    tls_addr: u64,
    ptid_addr: u64,
    ctid_addr: u64,
    given: &mut Given,
) -> Result<(), i64> {
    // **Exclusive until the guest-memory writes at the end**, which reach the
    // task through its address; nothing uses `t` after them.
    let ptr = task.as_ptr();
    let t = task.get_mut();
    t.vfork.set(None);
    let cpu = t.cpu.get_mut();
    if stack != 0 {
        cpu.sp = stack;
    }
    if flags & clone::SETTLS != 0 {
        // On aarch64 the TLS argument is the TPIDR_EL0 value itself, not a
        // pointer to a descriptor as on x86.
        cpu.tls_ptr = tls_addr;
    }

    // `task_create_` gave the field a counted share of the parent's address
    // space, which is what `CLONE_VM` asks for. Otherwise the share is
    // replaced by a copy, and dropped by the replacement.
    if flags & clone::VM == 0 {
        let parent = t.mm.get_mut().expect("a forking task has an address space");
        let new_mm = mmapcalls::mm::mm_copy(parent);
        t.cpu.get_mut().mmu = (&raw const new_mm.mem.mmu).cast_mut();
        t.mm.set(Some(new_mm));
    }
    given.mm = true;

    // `task_create_` gave the field a counted share of the parent's table,
    // which is what `CLONE_FILES` asks for. Otherwise the share is replaced by
    // a copy, and dropped by the replacement.
    if flags & clone::FILES == 0 {
        match t.files.get_mut().and_then(fdtable::Table::copy) {
            Some(copied) => t.files.set(Some(copied)),
            None => {
                t.files.set(None);
                return Err(ENOMEM);
            }
        }
    }
    given.files = true;

    // As `files`: `CLONE_FS` keeps the share `task_create_` gave it.
    if flags & clone::FS == 0 {
        let copied = t.fs.get_mut().map(|fs| std::sync::Arc::new(fs.duplicate()));
        if copied.is_none() {
            return Err(ENOMEM);
        }
        t.fs.set(copied);
    }
    given.fs = true;

    // `CLONE_SIGHAND` is the case with **nothing to do**, since 2026-09-12:
    // `task_create_` gave the child its own `Arc::clone` of the parent's table
    // the moment it copied the parent's bytes, which is what sharing one is.
    // It was `sighand_retain` here -- and before that
    // `task->sighand->refcount++` in C, a non-atomic increment of an
    // `atomic_uint` that two threads cloning at once could lose.
    if flags & clone::SIGHAND == 0 {
        // CLONE_CLEAR_SIGHAND gives the child a table with every signal at its
        // default rather than a copy of the parent's -- a fork with the
        // handlers dropped, not a fresh process.
        //
        // The assignment **drops** the clone `task_create_` made, which is the
        // release this used to owe the parent and no longer has to remember.
        let parent = t.sighand.get_mut().expect("a forking task has a disposition table");
        let fresh = if flags & clone::CLEAR_SIGHAND != 0 {
            parent.fork_cleared()
        } else {
            parent.fork_copy()
        };
        t.sighand.set(Some(fresh));
    }

    // The alternate signal stack is the *thread's*, and `task_create_` copied
    // the parent's into the child's queue, which is fork(2)'s rule. A thread
    // does not inherit one -- Linux's copy_process:
    //
    //     if ((clone_flags & (CLONE_VM|CLONE_VFORK)) == CLONE_VM)
    //             sas_ss_reset(p);
    //
    // Every Go thread registers its own with sigaltstack the moment it starts,
    // so this is not observable there; a C program that does not would
    // otherwise take a signal on a stack another thread is using.
    if flags & (clone::VM | clone::VFORK) == clone::VM {
        t.signals.get_mut().on_new_thread();
    }

    // A process gets a group of its own, made here and registered by
    // `publish`. A thread joins its creator's, which is what the copy already
    // names.
    if flags & clone::THREAD == 0 {
        // The copy names the parent's group, and the parent is the caller.
        let old_group = t.group.load(Ordering::Acquire);
        let group = taskview::with_current_group(|g| kernel_tgroup::tgroup_new(Some(g), ptr))
            .expect("a forking task has a group")
            .as_ptr();
        // SCHED_RESET_ON_FORK: a new process does not inherit a negative nice
        // value from a parent that asked for that -- Linux's sched_fork. The
        // niceness is the group's here, so a thread, which joins the group,
        // has nothing to reset.
        let reset = Pids::take().me().is_some_and(|me| me.attr().sched_reset_on_fork());
        // SAFETY: the group was made just above and nothing else can see it.
        let new_group = unsafe { &*group };
        if reset && new_group.nice() < 0 {
            new_group.set_nice(0);
        }
        t.group.store(group, Ordering::Release);
        t.tgid.store(t.pid(), Ordering::Relaxed);
        t.io = kernel_observe::IoAccounting::new_process();
        given.old_group = Some(old_group);
    }
    if flags & clone::CHILD_CLEARTID != 0 {
        t.clear_tid.store(ctid_addr, Ordering::Relaxed);
    }
    t.exit_signal.store((flags & clone::CSIGNAL) as c_int, Ordering::Relaxed);
    let pid = t.pid();

    // Neither store is checked. Linux's are `put_user`s whose result is
    // dropped -- the parent's in kernel_clone after the child exists, the
    // child's in schedule_tail as it starts -- so a bad pointer leaves the
    // number unwritten and the child running. This used to unwind the child
    // and answer EFAULT for either, which is an answer a program written
    // against Linux has never had to handle.
    if flags & clone::CHILD_SETTID != 0 {
        // The child's own space, which nothing else can reach yet.
        if let Some(mm) = t.mm.get_mut() {
            let _ = mmapcalls::usermem::write_held(
                &mut pagetable::memlock::ReadGuard::of(&mm.mem),
                ctid_addr,
                &pid.to_ne_bytes(),
            );
        }
    }
    if flags & clone::PARENT_SETTID != 0 {
        let _ = usercopy::GuestMem.write(ptid_addr, &pid.to_le_bytes());
    }
    // TODO: CLONE_SYSVSEM is accepted and does nothing; there are no SysV
    // semaphores here for it to share.
    Ok(())
}

/// Make the child reachable, once it is complete: its pid, its place in the
/// process tree, its thread group's place in the process-group index and the
/// group's thread list, and its count among the group's host threads -- all
/// under one `pids_lock` hold, so that nothing sees it in one table and not
/// another. `Err` when a table could not record it, with nothing recorded;
/// the caller then gives back `given` and drops the task.
///
/// Until 2026-09-30 `task_create_` published the task before `copy_task` ran,
/// and `copy_task` registered the group half-way through, so for the whole of
/// `copy_task` a `kill` or a `/proc/<pid>` read reached a task whose fields
/// were still being written -- and a group whose leader was not built yet.
pub(super) fn publish(task: taskcalls::NewTask, given: &mut Given) -> Result<taskcalls::Unstarted, taskcalls::NewTask> {
    let pids = Pids::take();
    let parent = current();
    let task = task.publish(pids.held(), kernel_pids::Task::current(pids.held()))?;
    let raw = task.as_ptr();
    let group = task.group.load(Ordering::Acquire);
    match given.old_group {
        // _add_new for a group that has just been allocated, so that an
        // address whose previous owner was freed without
        // proctree_group_forget is noticed rather than joined -- the new
        // group would inherit its threads.
        Some(old) => {
            kernel_tgroup::tgroup_publish(pids.held(), group, old);
            proctree::group_add_new(group, raw);
        }
        // A thread joining a group that is already there. A thread is not
        // a child; see the module comment. CLONE_PARENT is not
        // implemented, so CLONE_THREAD is the whole condition.
        None => {
            // Linux sizes the address space's private futex hash on each
            // `CLONE_THREAD | CLONE_VM`, from the threads it already has --
            // which is this count, taken before the new one joins. What
            // `PR_FUTEX_HASH` reports; see `crates/kernel/futexcalls`' `hash`.
            let threads = proctree::group_len(group);
            taskview::with_current_mm(|mm| futexcalls::hash::thread_created(&mm.futex_hash, threads));
            proctree::group_add(group, raw);
            proctree::set_parent(raw, proctree::parent(parent));
        }
    }
    given.in_group = true;
    // Counted under the same pids_lock that put it in the group: a task
    // that exists is counted, so there is no window in which exit_group
    // could decide the group is quiet while a thread is on its way to
    // running.
    // SAFETY: the task's group, live under the lock.
    task.hosts.set(Some(unsafe { &*group }.hosts.started()));
    Ok(task)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Whatever [`Given::undo`] releases, it must first take **out** of the
    /// task.
    ///
    /// The task may be published by the time `undo` runs -- `sys_clone`'s pidfd
    /// failure is after `publish`. So a field still naming a released object is
    /// a live pid naming
    /// freed memory, and `/proc/<pid>/fd`, `/proc/<pid>/statm` and
    /// `/proc/net/tcp` all reach a task by pid and then retain one of these
    /// three.
    ///
    /// **What this asserts is the invariant, not the race.** The race needs an
    /// allocation failure inside `clone` and a `/proc` walk over the new pid in
    /// the same few instructions, and nothing in this tree can arrange either;
    /// see the changelog entry, which says the defect was found by reading. The
    /// field being empty afterwards is the property that makes the race
    /// impossible, and it is checkable in one line per field.
    ///
    /// Backing the `files` swap out — releasing from a `load` as this did until
    /// 2026-09-12 — leaves the pointer in place and the assertion below is red
    /// with a non-null field. The `mm` arm is the same line and is not covered
    /// here, because building an address space needs the emulator booted.
    #[test]
    fn undoing_a_failed_clone_empties_every_field_it_releases() {
        // One field since 2026-09-12: an entry owns its reference, so the
        // table releases what it holds and only the record-lock hook is left.
        let ops = fdtable::Ops { remove_locks: None };
        let table = fdtable::Table::new(0, ops).expect("a table with no slots allocates");
        // A second share, so that `undo`'s release is not the last one and the
        // count below has something to say.
        let keep = table.clone();
        let fs = fsinfo::fs_info_new();

        // A task with every field at its fresh value. `undo` with no group
        // reads nothing else. It was `mem::zeroed()`, which is a valid
        // `struct task` only for as long as every field's zero is.
        let task: *mut ffi::task = Box::into_raw(Box::new(taskcalls::blank_task()));
        unsafe {
            (*task).files.set(Some(table));
            (*task).fs.set(Some(fs));
        }

        let given = Given {
            files: true,
            fs: true,
            ..Default::default()
        };
        unsafe { given.undo(&*task) };

        unsafe {
            assert!(
                (*task).files.as_ptr().is_null(),
                "the released table is still named by a published task"
            );
            assert!(
                (*task).fs.as_ptr().is_null(),
                "the released fs_info is still named by a published task"
            );
        }
        assert_eq!(
            Arc::strong_count(&keep),
            1,
            "the share the field held was not released"
        );
        drop(unsafe { Box::from_raw(task) });
    }
}
