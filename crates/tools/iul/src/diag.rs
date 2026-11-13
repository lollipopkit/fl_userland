//! The CLI's own diagnostics: the exit dumps, the SIGTERM dump, and the poller.
//!
//! Everything they print is `crates/asbestos/diag`'s; what is here is when to
//! ask for it, which is a property of *this* program rather than of the engine.

use asbestos_diag::{dump_pc_hist, dump_pc_trace, dump_wx_stats};
use pagetable::fault::mem_watch_peek32_mem;

use crate::dump_gadget_profile_if_built;

/// Print the pc histogram and the W^X statistics on the way out.
///
/// `atexit` rather than a `Drop`: the guest's last thread leaves through
/// `_exit` or `exit` from inside the exit handler, and no destructor of `main`'s
/// runs on either path.
///
/// # Safety
/// Called from `main` before any thread exists.
pub(crate) unsafe fn install_exit_dumps() {
    // `atexit` is the one caller that needs the C convention, so all three
    // wrappers are here rather than on the functions themselves: each of the
    // three is also an ordinary Rust call -- `sigterm_dump` below makes two of
    // them -- and wearing `extern "C"` for this one call site would pin
    // `crates/asbestos/diag`'s signatures for it. At exit there is one thread,
    // which is the whole precondition of all three.
    extern "C" fn pc_hist() {
        dump_pc_hist()
    }
    extern "C" fn wx_stats() {
        dump_wx_stats()
    }
    extern "C" fn gadget_profile() {
        dump_gadget_profile_if_built()
    }
    unsafe {
        libc::atexit(pc_hist);
        libc::atexit(wx_stats);
        // Unconditional: the build flag gates whether the ring exists, which
        // is `asbestos/asbestos.c`'s business, not the call's.
        libc::atexit(gadget_profile);
    }
}

extern "C" fn sigterm_dump(_sig: i32) {
    // SAFETY: a signal handler, and these three are what the C did here. They
    // are not async-signal-safe and this path ends in `_exit` regardless: the
    // point of it is a microbenchmark killed from outside, where the
    // alternative is no numbers at all.
    unsafe {
        dump_pc_hist();
        dump_pc_trace();
        // Every guest thread's microbench counter, which lives in x21.
        //
        // `try_take`, not `take`: this runs on whichever thread took the
        // signal, and that thread may be the one holding `pids_lock` -- where
        // blocking for it is a deadlock and the dump never appears. Until
        // 2026-09-16 the walk below took nothing at all and raced every
        // fork and exit in the guest; skipping the per-thread counters when
        // the lock is busy is the trade, and it is stated rather than silent.
        match kernel_pids::PidsGuard::try_take() {
            Some(pids) => {
                for pid in 1..8 {
                    let t = taskcalls::pid_get_task(pids.held(), pid);
                    if !t.is_null() && (*(*t).cpu.get()).regs[21] != 0 {
                        let line = format!("guest_pid={pid}  x21={}\n", (*(*t).cpu.get()).regs[21]);
                        libc::write(libc::STDERR_FILENO, line.as_ptr().cast(), line.len());
                    }
                }
            }
            None => {
                let line = b"pids_lock busy: no per-thread x21 counters\n";
                libc::write(libc::STDERR_FILENO, line.as_ptr().cast(), line.len());
            }
        }
        libc::_exit(0);
    }
}

/// `IUL_DUMP_ON_SIGTERM`: dump and leave on SIGTERM or SIGINT.
///
/// The normal `halt_system` path does not run when `iul` is killed from
/// outside, which is how a microbenchmark on an infinite-loop guest ends.
///
/// # Safety
/// Called from `main` before any thread exists.
pub(crate) unsafe fn install_sigterm_dump() {
    if !util_iulenv::dump_on_sigterm() {
        return;
    }
    // SAFETY: the dump ends in `_exit`; see `sigterm_dump`.
    unsafe {
        util_hostsig::install(
            &[libc::SIGTERM, libc::SIGINT],
            util_hostsig::Handler::Plain(sigterm_dump),
            &[],
            false,
        )
    };
}

/// `IUL_POLL_ADDR`: sample a guest word from the host every millisecond and log
/// it when it changes.
///
/// **Zero perturbation**, which is the point: unlike the store watchpoint this
/// makes no guest store slower, so it cannot scare a timing-sensitive race
/// away. It is what was left when the watchpoint's own overhead turned out to
/// hide the thing being looked for.
///
/// # Safety
/// Called from `main` before any thread exists.
pub(crate) unsafe fn start_poller() {
    let addr = util_iulenv::poll_addr();
    if addr == 0 {
        return;
    }
    std::thread::spawn(move || {
        let start = std::time::Instant::now();
        let mut last = 0xdead_beefu32;
        loop {
            // Pid 1's address space. Null before it exists and after it goes,
            // and this thread outlives neither event by design: it is a
            // diagnostic and the process is about to end either way.
            let mut v = 0xdead_0003u32;
            // Held across the lookup *and* the read, which is `PidsGuard`'s
            // contract: without it init can exit and be freed between the two.
            // An ordinary thread, so `take` rather than the handler's
            // `try_take` above.
            let pids = kernel_pids::PidsGuard::take();
            if let Some(init) = pids.find_live(1) {
                let mem = taskview::mem_of(init.task());
                if !mem.is_null() {
                    // SAFETY: init's address space, kept by `pids`; the helper
                    // reads a guest word through the page table without
                    // faulting.
                    v = unsafe { mem_watch_peek32_mem(mem, addr) };
                }
            }
            if v != last {
                eprintln!(
                    "[poll] t={:.4}s [{addr:#x}] = {v:#x} (was {last:#x})",
                    start.elapsed().as_secs_f64()
                );
                last = v;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    });
}
