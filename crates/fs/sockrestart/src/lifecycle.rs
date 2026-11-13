//! Host suspend/resume socket reconstruction.

use std::os::fd::AsRawFd;
use super::*;

// ------------------------------------------------------------ suspend and resume

/// The host is about to suspend the process: record every listening socket.
///
/// Called by the embedder. See the module comment.
pub fn sockrestart_on_suspend() {
    let mut r = registry().lock().unwrap();
    if !r.saved.is_empty() {
        // A suspend with no resume between. The C asserted here, which turns a
        // host lifecycle this engine does not control into an abort; releasing
        // the stale set is the only thing that can be done about it and is what
        // the resume would have done.
        printk("sockrestart: a second suspend with no resume; dropping the first");
        let stale = std::mem::take(&mut r.saved);
        drop(r);
        // Out from under the lock first; see `Saved::fd`.
        drop(stale);
        r = registry().lock().unwrap();
    }

    let listening = r.listening.clone();
    // References a probe could not use, given back after the lock: the last
    // one reaches `sockrestart_end_listen`, which takes it.
    let mut unusable = Vec::new();
    for l in listening {
        // Retained so the descriptor cannot be freed while suspended; given
        // back at the end of the resume. Through the registration's `Weak`, so
        // a listener the guest is closing -- no strong count left, its
        // finalizer on the way to deregistering it -- is refused rather than
        // brought back. Retaining it by address was `process::abort` until
        // 2026-10-17: an app backgrounded in that window died.
        let Some(fd) = fs_fdobj::Owned::upgrade(&l.weak) else {
            printk("sockrestart: skipped a listening socket that is closing");
            continue;
        };
        let probed = (|| -> Result<_, &str> {
            let host = fd.host().ok_or("type")?;
            let ty = rustix::net::sockopt::socket_type(host).map_err(|_| "type")?;
            let name = rustix::net::getsockname(host).map_err(|_| "name")?;
            Ok((ty, name))
        })();
        match probed {
            Ok((ty, name)) => r.saved.push(Saved {
                fd,
                ty,
                proto: l.protocol,
                backlog: l.backlog,
                name,
            }),
            Err(what) => {
                printk(&format!("sockrestart: skipped a listening socket: could not read its {what}"));
                unusable.push(fd);
            }
        }
    }
    drop(r);
    drop(unusable);
}

/// The host has resumed: rebuild what was recorded and wake everyone waiting.
///
/// Called by the embedder. See the module comment.
pub fn sockrestart_on_resume() {
    let mut r = registry().lock().unwrap();
    let saved = std::mem::take(&mut r.saved);
    for s in &saved {
        rebuild(s);
    }
    // Everyone inside a wait is told to make it again. The signal is what ends
    // a blocking host `accept`; the flag is what stops the thread treating the
    // resulting EINTR as an answer.
    for w in &r.waiting {
        w.punt.store(true, Ordering::SeqCst);
        // A waiter with no task has nothing to signal -- its flag above is
        // the whole of what a resume can do for it.
        if let Some(task) = w.task {
            // SAFETY: the task is the thread's own and is registered only
            // while that thread is inside a wait; see the `Send` impl on
            // `Waiter`.
            unsafe { task_interrupt_host_call(task.as_ptr()) };
        }
    }
    drop(r);

    // Outside the lock. `fd_close` on the last reference reaches `sock_close`,
    // which calls `sockrestart_end_listen` and takes this same non-recursive
    // lock -- so releasing here deadlocked the resume path exactly when the
    // retained reference was the final one, which is the case whenever the
    // guest closed the socket while suspended.
    drop(saved);
}

/// Open a replacement for one recorded socket and put it where the guest's
/// descriptor points.
fn rebuild(s: &Saved) {
    let family = s.name.address_family();
    let protocol = std::num::NonZeroU32::new(s.proto as u32).map(rustix::net::Protocol::from_raw);
    // An `OwnedFd`, so it closes as it drops on every path out of here,
    // including the last: the `dup2` below duplicates it onto the descriptor
    // the guest already holds, and the original is then one host descriptor
    // nobody names. Leaked, every suspend/resume cycle cost one, until
    // socket() started failing.
    let new = match rustix::net::socket(family, s.ty, protocol) {
        Ok(new) => new,
        Err(e) => {
            printk(&format!(
                "sockrestart: socket({family:?}, {:?}, {}) failed: {e}",
                s.ty, s.proto
            ));
            return;
        }
    };
    if let Err(e) = rustix::net::bind(&new, &s.name) {
        printk(&format!("sockrestart: rebinding failed: {e}"));
        return;
    }
    if let Err(e) = rustix::net::listen(&new, s.backlog) {
        printk(&format!("sockrestart: listen({}) failed: {e}", s.backlog));
        return;
    }
    if let Some(real) = s.fd.host() {
        // Onto a descriptor this does not own, which `dup2` is the one call
        // for: the description keeps its number and gains the new socket.
        // rustix's `dup2` asks for the target as an `&mut OwnedFd`, which a
        // description lending its host descriptor cannot give.
        // SAFETY: both descriptors are open; the call touches no memory.
        unsafe { libc::dup2(new.as_raw_fd(), real.as_raw_fd()) };
    }
}
