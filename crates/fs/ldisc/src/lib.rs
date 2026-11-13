//! The terminal input buffer.
//!
//! The buffer and the line discipline around it: character translation, echo,
//! the erase and kill rules, the signal characters. What is left in C is what
//! this cannot do — block when the buffer is full, and deliver a signal to a
//! process group — and both are handed back to the caller rather than done
//! here. See [`discipline`].
//!
//! # It had a C ABI, and nothing called it
//!
//! Sixteen `extern "C"` functions — `ldisc_new`, `ldisc_push`, `ldisc_read`
//! and the rest — from when `fs/tty.c` drove this directly. `crates/fs/tty`
//! took the terminal over and uses the Rust API, so the whole layer became
//! unreachable: no C in the tree named one of them and no header declared one,
//! which means a C caller could not have called them even by accident.
//!
//! They are gone. A C ABI that nobody crosses is not a boundary, it is a
//! second interface to keep in step with the first.
//!
//! The buffer is a ring rather than the flat array with a parallel
//! `bool[4096]` it replaces; see [`buffer`].

mod buffer;
/// The termios flags and control characters this interprets. `crates/fs/tty`
/// needs the same numbering for the ones it interprets itself.
pub mod discipline;

pub use buffer::{LineBuffer, SIZE};
pub use discipline::{BOTHER, CBAUD, Discipline, Outcome, Step, Termios, Termios2};
