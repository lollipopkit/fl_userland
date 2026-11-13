//! What an ordinary `execve` leaves behind, asked of whatever kernel is
//! running it.
//!
//! A probe rather than a test: it asserts nothing and prints one line per
//! attribute, and `probe_diff.sh` runs it here and in an arm64 Linux container
//! and reports the differences. That is the point — `prctl(2)` and
//! `execve(2)` between them describe some of these and are silent about
//! others, and a rule written from a man page is a rule nobody has checked.
//!
//! `tests/guest/src/bin/setid_exec.rs` covers the **privileged** exec, which
//! needs a setuid binary and so cannot be compared against a container. This
//! covers the ordinary one, which needs nothing.
//!
//! Every value is printed by the *new* image, after the exec, so what appears
//! is what survived.

use std::ffi::CString;

fn cstr(s: &str) -> CString {
    CString::new(s).expect("no NUL")
}

/// The attributes, read where the exec left them.
fn report() {
    let mut pdeath = -1i32;
    let r = unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &mut pdeath) };
    println!(
        "{:<44} -> {}",
        "PR_GET_PDEATHSIG after an ordinary exec",
        if r < 0 { -1 } else { pdeath }
    );
    println!(
        "{:<44} -> {}",
        "PR_GET_KEEPCAPS after an ordinary exec",
        unsafe { libc::prctl(libc::PR_GET_KEEPCAPS) }
    );
    println!(
        "{:<44} -> {}",
        "PR_GET_DUMPABLE after an ordinary exec",
        unsafe { libc::prctl(libc::PR_GET_DUMPABLE) }
    );

    // The blocked mask survives an exec on Linux — a shell blocking SIGINT
    // around a child depends on it — and nothing says so out loud.
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigprocmask(libc::SIG_SETMASK, std::ptr::null(), &mut set) };
    println!(
        "{:<44} -> {}",
        "SIGUSR2 still blocked after an exec",
        unsafe { libc::sigismember(&set, libc::SIGUSR2) }
    );

    // An ignored signal stays ignored; a handled one goes back to SIG_DFL,
    // because the code the handler pointed at is gone.
    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    unsafe { libc::sigaction(libc::SIGUSR1, std::ptr::null(), &mut act) };
    println!(
        "{:<44} -> {}",
        "SIGUSR1 was handled, and is now",
        if act.sa_sigaction == libc::SIG_DFL {
            "SIG_DFL"
        } else if act.sa_sigaction == libc::SIG_IGN {
            "SIG_IGN"
        } else {
            "a handler"
        }
    );
    unsafe { libc::sigaction(libc::SIGTERM, std::ptr::null(), &mut act) };
    println!(
        "{:<44} -> {}",
        "SIGTERM was ignored, and is now",
        if act.sa_sigaction == libc::SIG_DFL {
            "SIG_DFL"
        } else if act.sa_sigaction == libc::SIG_IGN {
            "SIG_IGN"
        } else {
            "a handler"
        }
    );

    // The alternate signal stack is **not** asked about here, and the reason is
    // worth writing down because it is not obvious: Rust's runtime installs one
    // of its own before `main`, for stack-overflow detection. So the new image
    // always reports an alternate stack whatever the kernel did with the old
    // one -- the first version of this probe read 12288 bytes back after
    // setting 65536, which is `std`'s and not the kernel's answer.
    //
    // crates/kernel/sigdisp's `on_exec` clears it and has a unit test; there is
    // nothing for a probe to see from inside a Rust program.
}

extern "C" fn handler(_: libc::c_int) {}

fn main() {
    let mut args = std::env::args();
    let me = args.next().unwrap_or_default();
    if args.next().as_deref() == Some("after") {
        report();
        return;
    }

    // Everything the exec is supposed to act on, set here and read back there.
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGUSR1);
        libc::prctl(libc::PR_SET_KEEPCAPS, 1);
        libc::prctl(libc::PR_SET_DUMPABLE, 1);

        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGUSR2);
        libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());

        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = handler as *const () as usize;
        libc::sigaction(libc::SIGUSR1, &act, std::ptr::null_mut());
        act.sa_sigaction = libc::SIG_IGN;
        libc::sigaction(libc::SIGTERM, &act, std::ptr::null_mut());

        let p = cstr(&me);
        let arg = cstr("after");
        let argv = [p.as_ptr(), arg.as_ptr(), std::ptr::null()];
        libc::execv(p.as_ptr(), argv.as_ptr());
    }
    // Only reached if the exec failed, and then the six lines above are
    // missing entirely — which the tool reports as one side dying early rather
    // than as a difference in any of them.
    eprintln!("execv failed");
}
