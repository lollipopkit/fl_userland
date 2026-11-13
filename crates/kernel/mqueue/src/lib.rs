//! POSIX message queues: the queue itself, and the numbers it is judged by.
//!
//! The syscalls, the descriptor and the name space are
//! `crates/kernel/mqueuecalls`; what is here needs no task -- the wire formats
//! (`struct mq_attr`, `struct sigevent`), the limits, the name rules, the
//! status line, and [`Queue`], which owns the messages and the blocking.
//!
//! # Split the way eventfd is
//!
//! The decisions are pure functions with tests of their own, and the queue's
//! waiting is tested against the real `wait_for` -- `GuestLock`'s wait is the
//! one a guest signal interrupts, which nothing in `std` is. Delivering a
//! notification needs the process table and a socket, so [`Queue`] answers a
//! [`Delivery`] and the caller sends it once the queue's lock is dropped:
//! the fourth way `CLAUDE.md` lists of keeping a lower crate from acting on
//! something above it.

extern crate util_timeabi as timeabi;

pub mod abi;
mod queue;

pub use queue::{Deadline, Delivery, How, Inode, Messages, POLL_IN, POLL_OUT, Queue, Registration, State};
