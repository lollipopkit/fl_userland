//! Forward guest signals to native offloaded processes and handlers.

use libc::c_int;

use logline::printk;

use crate::ffi;

/// Tell `crates/kernel/signaldeliver` how to forward a signal to a host process
/// running an offloaded binary.
///
/// Called from both registration entry points, which are the only two ways a
/// task can come to be running one — so a signal cannot reach a proxy before
/// this has run, and there is no ordering to get wrong. Idempotent after the
/// first, which is an acquire load that fails.
///
/// It is a hook because the alternative is a cycle: this crate ends a finished
/// offload with `do_exit`, so it depends on `kernel-exitcalls`, which depends on
/// `signaldeliver` for the five signals an exit sends. Delivery declared
/// [`native_offload_forward_signal`] in an `extern "C"` block until 2026-09-09
/// for that reason.
pub(super) fn arm_signal_forwarding() {
    signaldeliver::set_offload_forward_hook(native_offload_forward_signal);
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

/// Forward a guest signal to whatever is running natively for this task,
/// covering **both** offload shapes: a `posix_spawn` proxy gets a `kill` on its
/// host pid, and an in-process handler gets its registered abort callback.
/// Answers whether one of those consumed it.
///
/// The handler branch is the addition. Before it, this answered false for every
/// in-process handler, so a `kill` on a wedged ffmpeg queued a signal nobody
/// would ever read.
///
/// Not exported: `iul.h` does not declare it and `crates/kernel/signaldeliver`
/// reaches it through [`arm_signal_forwarding`]'s hook since 2026-09-09.
pub fn native_offload_forward_signal(task: &ffi::task, sig: c_int) -> bool {
    // Shape 1: a posix_spawn proxy. A real host pid exists, so signal it.
    if let Some(native_pid) = task.native_pid.get() {
        // Which *host* signal a guest one forwards as. Linux and macOS
        // agree on 1..6, 8, 9, 11, 13..15, 21, 22 and 24..28 and disagree
        // everywhere else; this used to pass the number through, so eight
        // signals arrived as a different signal and a guest SIGUSR1 to an
        // offloaded ffmpeg arrived as SIGBUS, whose default action is to
        // dump core.
        let host_sig = hostsignal::to_host(sig).and_then(rustix::process::Signal::from_named_raw);
        if let (Some(pid), Some(host_sig)) = (rustix::process::Pid::from_raw(native_pid), host_sig) {
            let _ = rustix::process::kill_process(pid, host_sig);
        }
        return true;
    }

    // Shape 2: an in-process handler. There is no host pid to signal -- the
    // handler is running on this task's *own* thread, which is parked inside
    // host code and will never look at the guest signal queue. Ask the handler
    // to stop instead.
    //
    // Only terminating signals do this. A handler is not a general signal
    // target: forwarding a SIGWINCH or a SIGCHLD as "abort" would turn a
    // routine notification into a killed transcode.
    // `Option<&'static Entry>`: the null test and the deref that stood here
    // are the accessor's, and the load is atomic -- this runs on the
    // *signalling* thread while the task's own thread sets and clears it.
    let Some(entry) = task.native_offload_entry.get() else {
        return false;
    };
    let Some(abort_fn) = entry.abort() else {
        return false;
    };
    let terminating = [
        ffi::SIGKILL_,
        ffi::SIGTERM_,
        ffi::SIGINT_,
        ffi::SIGQUIT_,
        ffi::SIGHUP_,
    ];
    if !terminating.contains(&(sig as u32)) {
        return false;
    }

    // Deliberately **not** consuming the signal: the abort only asks the
    // handler to unblock. The handler then returns normally and the exec path
    // calls do_exit -- but that runs on the task's own thread, and only the
    // guest signal machinery knows the right exit status for a killed task.
    // Letting the signal continue to normal delivery keeps `kill -9` reporting
    // the usual killed-by-signal status rather than the handler's return code.
    let aborting = abort_fn(sig);
    printk(&format!(
        "native_offload: signal {sig} -> in-process handler {} abort ({})",
        entry.name().to_string_lossy(),
        if aborting { "accepted" } else { "declined" }
    ));
    false
}
