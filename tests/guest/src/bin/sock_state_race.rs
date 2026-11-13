//! Two threads mutating one socket's per-descriptor state.
//!
//! `crates/fs/sock` keeps a `SocketState` behind `fd->state.socket` and reaches
//! it through `state_of(fd) -> &'a mut SocketState` — a `&mut` whose lifetime
//! the caller picks, from a pointer every thread of the process holds. None of
//! `bind`, `connect`, `listen` or `setsockopt` takes `fd->lock`, so two threads
//! calling any of them on one descriptor hold two live `&mut` to one object.
//! `Sock::state` carries `#[allow(clippy::mut_from_ref)]` and a contract saying
//! "no other borrow of this socket's state is live", which is a thing its
//! callers cannot check.
//!
//! What that reaches, in the order this probes it:
//!
//! - **`hold_inode` and `hold_abstract` overwrite.** A second `bind` stores its
//!   name over the first without releasing it, so the first name stays claimed
//!   for the life of the process: a later `bind` to it answers `EADDRINUSE` for
//!   a socket that no longer exists.
//! - **`drop_names` is a read-modify-write.** Two threads that both read
//!   `unix_name_inode != 0` both call `inode_release`, and both `Box::from_raw`
//!   the abstract handle. The comment above it records what a second release
//!   already cost once: "a second one corrupted the allocator's free list".
//! - **`stored_opts` is an array two threads write.**
//!
//! Linux has no race here because `bind`, `connect` and `listen` all take
//! `lock_sock()`, and the socket's address is set under it.
//!
//! The check is that the emulator survives and that a name a closed socket held
//! can be bound again — a leaked claim is otherwise invisible.

use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

/// An abstract address: the leading NUL is part of the name.
fn sockaddr_abstract(name: &[u8]) -> (libc::sockaddr_un, libc::socklen_t) {
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (slot, b) in addr.sun_path.iter_mut().zip(name) {
        *slot = *b as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + name.len()) as libc::socklen_t;
    (addr, len)
}

/// A filesystem address, for the binds that are meant to fail.
fn sockaddr_path(path: &str) -> (libc::sockaddr_un, libc::socklen_t) {
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (slot, b) in addr.sun_path.iter_mut().zip(path.as_bytes()) {
        *slot = *b as libc::c_char;
    }
    (addr, std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t)
}

fn bind(fd: RawFd, addr: &libc::sockaddr_un, len: libc::socklen_t) -> i32 {
    unsafe { libc::bind(fd, (addr as *const libc::sockaddr_un).cast(), len) }
}

fn socket() -> Option<RawFd> {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    (fd >= 0).then_some(fd)
}

/// Two threads, one socket, one `bind` each, released together.
///
/// `make` builds the address each thread binds; `after` is given the descriptor
/// once both have returned, before it is closed.
fn race_bind(
    rounds: usize,
    mut make: impl FnMut(usize, usize) -> (libc::sockaddr_un, libc::socklen_t),
) -> usize {
    let gate = Arc::new(Barrier::new(3));
    let shared = Arc::new(AtomicI32::new(-1));
    let round = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let ok = Arc::new(AtomicUsize::new(0));

    // Each thread's address differs in its last byte, so the two `bind`s claim
    // different names and the overwrite has something to lose.
    let addrs: Vec<_> = (0..rounds)
        .flat_map(|r| [make(r, 0), make(r, 1)])
        .collect();
    let addrs = Arc::new(addrs);

    let threads: Vec<_> = (0..2)
        .map(|which| {
            let (gate, shared, round, stop, ok, addrs) = (
                gate.clone(),
                shared.clone(),
                round.clone(),
                stop.clone(),
                ok.clone(),
                addrs.clone(),
            );
            std::thread::spawn(move || {
                loop {
                    gate.wait();
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let fd = shared.load(Ordering::Relaxed);
                    let (addr, len) = addrs[round.load(Ordering::Relaxed) * 2 + which];
                    if bind(fd, &addr, len) == 0 {
                        ok.fetch_add(1, Ordering::Relaxed);
                    }
                    gate.wait();
                }
            })
        })
        .collect();

    for r in 0..rounds {
        let Some(fd) = socket() else {
            println!("out of descriptors at round {r}");
            std::process::exit(1);
        };
        round.store(r, Ordering::Relaxed);
        shared.store(fd, Ordering::Relaxed);
        gate.wait();
        gate.wait();
        unsafe { libc::close(fd) };
    }
    stop.store(true, Ordering::Relaxed);
    gate.wait();
    for t in threads {
        t.join().expect("thread");
    }
    ok.load(Ordering::Relaxed)
}

fn main() {
    let rounds: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(400);

    // ---- abstract names, which succeed: the overwrite and the leak ----
    println!("{rounds} rounds of two threads binding one socket to two abstract names");
    let bound = race_bind(rounds, |r, w| {
        sockaddr_abstract(format!("\0shellbox-race-{r}-{w}").as_bytes())
    });
    println!("{bound} of {} binds succeeded", rounds * 2);

    // Every socket above is closed, so every name it claimed is free. A name
    // that a second `bind` overwrote without releasing is still claimed, and
    // this is the only way to see that from the guest.
    let mut still_claimed = 0;
    for r in 0..rounds {
        for w in 0..2 {
            let Some(fd) = socket() else {
                println!("out of descriptors while rebinding");
                std::process::exit(1);
            };
            let (addr, len) = sockaddr_abstract(format!("\0shellbox-race-{r}-{w}").as_bytes());
            let e = bind(fd, &addr, len);
            if e != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EADDRINUSE) {
                still_claimed += 1;
            }
            unsafe { libc::close(fd) };
        }
    }
    println!("{still_claimed} names are still claimed by sockets that are closed");

    // ---- a bind that fails, which is what runs `drop_names` twice ----
    println!("{rounds} rounds of two threads failing one socket's bind together");
    let ok = race_bind(rounds, |r, w| {
        sockaddr_path(&format!("/tmp/shellbox-no-such-dir/{r}-{w}"))
    });
    println!("{ok} of {} binds unexpectedly succeeded", rounds * 2);

    // ---- setsockopt, which writes an array ----
    let fd = socket().expect("socket");
    let gate = Arc::new(Barrier::new(2));
    let opt: Vec<_> = (0..2)
        .map(|which| {
            let gate = gate.clone();
            std::thread::spawn(move || {
                gate.wait();
                for _ in 0..rounds * 10 {
                    let v: libc::c_int = which;
                    unsafe {
                        libc::setsockopt(
                            fd,
                            libc::SOL_SOCKET,
                            12, // SO_PRIORITY on Linux
                            (&v as *const libc::c_int).cast(),
                            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                        )
                    };
                }
            })
        })
        .collect();
    for t in opt {
        t.join().expect("thread");
    }
    unsafe { libc::close(fd) };

    if still_claimed != 0 {
        println!("LEAKED {still_claimed} abstract names");
        std::process::exit(1);
    }
    println!("survived");
}
