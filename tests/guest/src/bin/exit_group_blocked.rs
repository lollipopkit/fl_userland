//! `exit_group` with a thread parked in a blocking host call.
//!
//! # What this does and does not check
//!
//! It checks that a group whose other thread is blocked in a host `read` still
//! ends, rather than hanging. That is a real property and this is the only
//! thing in the tree that exercises it directly.
//!
//! It was **written to check something else and does not**: that the `SIGUSR1`
//! handler's installation is what interrupts the blocked call. Backing the
//! `sigaction` out entirely leaves this passing, because
//! `crates/kernel/exitcalls`' valve calls `cpu_poke` before `pthread_kill` and
//! the poke is enough on this path. So the handler's necessity is **not**
//! established here, and saying so is worth more than a check that passes
//! either way.
//!
//! What *is* established about the handler is narrower and came from reading:
//! its `siglongjmp` was unreachable. The only thing that ever set
//! `should_unwind` was `sigunwind_start`, which had no caller after `wait_for`
//! became `crates/util/waitfor` on 2026-09-03 — so the body was dead and the
//! installation, which is what POSIX ties `EINTR` to, is unchanged.
//!
//! It fails by **hanging**, so a timeout is the assertion. Run it by hand:
//!
//! ```text
//! ./build/iul -r <rootfs> /tmp/exit_group_blocked
//! ```

use std::io::Read;
use std::os::unix::io::FromRawFd;

fn main() {
    // A pipe nobody writes to: a read on it blocks in the host until something
    // interrupts it. Two descriptors, and the write end is deliberately kept
    // open so the read cannot end by EOF.
    let mut fds = [0i32; 2];
    // SAFETY: a two-element array, which is what pipe(2) takes.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        println!("pipe failed; nothing to test");
        return;
    }
    let (read_end, _write_end) = (fds[0], fds[1]);

    let parked = std::thread::spawn(move || {
        // SAFETY: this thread owns the descriptor for as long as it runs.
        let mut f = unsafe { std::fs::File::from_raw_fd(read_end) };
        let mut buf = [0u8; 1];
        // Blocks. Either the read is interrupted and returns, or the process
        // ends underneath it — both are the emulator doing its job.
        let _ = f.read(&mut buf);
    });

    // Let it get into the read before ending the group.
    std::thread::sleep(std::time::Duration::from_millis(150));

    println!("exit_group interrupted a blocked thread");
    // `exit_group`, not a return from main: the point is that the *other*
    // thread is parked in a host call when the group ends.
    drop(parked);
    std::process::exit(0);
}
