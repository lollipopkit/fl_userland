//! The terminal.
//!
//! `fs/tty.c`, `fs/pty.c` and `fs/tty-real.c` were 1460 lines of C around four
//! Rust crates — the line discipline, the job-control rules, the registry of
//! which terminal is at which number, and the reverse edge a wakeup travels.
//! The object joining them was the part that stayed: a `struct tty` with two
//! condition variables, a lock, a refcount, an intrusive list of descriptors,
//! and a union whose contents depended on which of three drivers owned it.
//!
//! Here the object is Rust and two things are not:
//!
//! - **The task side**, in [`ops::Task`]. Whose terminal this is, which group
//!   is in its foreground, who gets stopped for reading from the background:
//!   all of that is about *processes*.
//! - **The console driver**, in [`ops::Console`]. A host device, and the one
//!   driver that is not this crate's own. An embedder enables it with
//!   `iul_enable_console`.
//!
//! The lock is [`util_guestlock::GuestLock`]: the primitive is C's, because the
//! only interruptible wait here is `wait_for` and a guest asleep on a Rust
//! condvar could not be killed, and the state behind it is this crate's.

pub mod ioctl;
pub mod ops;
pub mod pty;
pub mod tty;

pub mod abi;

#[cfg(test)]
mod tests;
