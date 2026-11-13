//! Pipe forwarding between native processes and guest file descriptors.

use super::*;

// ---------------------------------------------------------------------------
// Forwarding a pipe to where the guest's output goes
// ---------------------------------------------------------------------------

/// Where a forwarding thread writes.
pub(super) enum Sink {
    /// A guest descriptor, written through its `fd_ops` — which is the tty
    /// driver, and on iOS is what reaches the terminal UI. Held by the
    /// thread and released when it ends.
    Guest(fs_fdobj::Owned),
}

/// Read a pipe until EOF and write everything to `sink`, converting a bare
/// `\r` to `\n` so progress-bar output does not overwrite itself.
///
/// Consumes `pipe_rd` however it ends. The C had this as a `pthread_t` the
/// caller compared against 0, with neither the allocation nor the
/// `pthread_create` checked — a failed malloc was a null dereference on the
/// next line, and a failed create left the struct and the pipe end leaked and
/// handed back an uninitialised `pthread_t` to join.
pub(super) fn start_pipe_forward(pipe_rd: OwnedFd, sink: Sink) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let sink = sink;
        let mut pipe = std::fs::File::from(pipe_rd);
        let mut buf = [0u8; 4096];
        loop {
            let n = match std::io::Read::read(&mut pipe, &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            for i in 0..n {
                // `\r\n` is fine; a lone `\r` becomes a newline.
                if buf[i] == b'\r' && !(i + 1 < n && buf[i + 1] == b'\n') {
                    buf[i] = b'\n';
                }
            }
            write_all(&sink, &buf[..n]);
        }
        // The read end closes with `pipe`, and a `Sink::Guest`'s reference
        // goes with `sink`.
    })
}

fn write_all(sink: &Sink, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        let w = match sink {
            Sink::Guest(fd) => match fd.ops.filter(|ops| ops.caps().write) {
                Some(ops) => ops.write(fd, bytes),
                None => break,
            },
        };
        if w <= 0 {
            break;
        }
        bytes = &bytes[w as usize..];
    }
}

/// A pipe, read end then write end, or nothing if the host refused one.
///
/// `OwnedFd`s since 2026-09-29. The two ends were `c_int`s closed by hand in
/// four places across two files, one per path out of a spawn.
///
/// Close-on-exec, both ends: a spawned child gets the write end as its
/// stdout or stderr through `dup2`, which clears the flag on the copy, and
/// must not inherit the read end, which would keep the pipe open past its
/// own exit.
pub(super) fn make_pipe() -> Option<(OwnedFd, OwnedFd)> {
    let (rd, wr) = rustix::pipe::pipe().ok()?;
    for end in [&rd, &wr] {
        rustix::io::fcntl_setfd(end, rustix::io::FdFlags::CLOEXEC).ok()?;
    }
    Some((rd, wr))
}
