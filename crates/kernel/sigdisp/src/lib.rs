//! What each signal is set to do, and the rules around changing it.
//!
//! `struct sighand` carried `struct sigaction_ action[NUM_SIGS]` and an
//! alternate stack, and eight files reached into the array directly. The rules
//! around it were `switch` statements and `if` chains spread across
//! `kernel/signal.c`, and three of them were wrong on 2026-08-23:
//!
//! - the default-action table had `SIGIO` in the ignore set. Linux's
//!   `SIG_KERNEL_IGNORE_MASK` has exactly four entries and that is not one of
//!   them, so a process with no handler for it survived a signal that should
//!   have killed it.
//! - `sigaction` refused `SIGKILL` and `SIGSTOP` whether or not anything was
//!   being installed. Linux's condition is `act && sig_kernel_only(sig)`, and
//!   the `act &&` is the whole difference.
//! - `do_sigaction` took the signal number as `int` where it arrives as a
//!   `dword_t`, so `0x80000000` compared *below* the upper bound and indexed
//!   the array at a wild negative offset. That one crashed the emulator.
//!
//! A table is where one wrong entry is silent. Here it is one function with a
//! test per row, taken from what a real kernel answered rather than from a
//! header.
//!
//! # What this owns
//!
//! The dispositions — everything in `struct sighand` except its reference
//! count and its lock — and the rules for an alternate signal stack, as a type
//! the **task** holds. Every entry point runs under sighand's lock.
//!
//! The alternate stack was a field of the table until 2026-09-04, which made it
//! one per *thread group* where Linux's `sigaltstack` is one per **thread**.
//! Go registers a separate stack on every thread it starts and takes its
//! preemption signal on many of them at once; with one slot, two threads
//! handling a signal in the same instant wrote their frames onto the same
//! stack, and `go build` died of `SIGSEGV` about one run in two.

use std::ffi::c_int;

/// The guest's `struct sigaction`, which is what `rt_sigaction` moves in and
/// out of guest memory. Packed, and the offsets are asserted below: every
/// defect this tree has had in a guest ABI struct was an offset.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Disposition {
    pub handler: u64,
    pub flags: u32,
    pub restorer: u64,
    pub mask: u64,
}

const _: () = {
    assert!(std::mem::size_of::<Disposition>() == 28);
    assert!(std::mem::offset_of!(Disposition, handler) == 0);
    assert!(std::mem::offset_of!(Disposition, flags) == 8);
    assert!(std::mem::offset_of!(Disposition, restorer) == 12);
    assert!(std::mem::offset_of!(Disposition, mask) == 20);
};

pub const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;

/// aarch64 Linux has signals 1..=64, and these arrays are indexed by the number
/// itself. It was a count of 64 once, which made the usable range 1..63 and
/// answered `EINVAL` for the one signal a program asking for `SIGRTMAX` names
/// first.
pub const MAX_SIG: c_int = 64;
pub const NUM_SIGS: usize = MAX_SIG as usize + 1;

pub const SIGKILL: c_int = 9;
pub const SIGSTOP: c_int = 19;

const SIGCHLD: c_int = 17;
const SIGCONT: c_int = 18;
const SIGTSTP: c_int = 20;
const SIGTTIN: c_int = 21;
const SIGTTOU: c_int = 22;
const SIGURG: c_int = 23;
const SIGWINCH: c_int = 28;

pub const SA_ONSTACK: u32 = 0x08000000;

/// `stack_t`'s flags.
pub const SS_ONSTACK: u32 = 1;
pub const SS_DISABLE: u32 = 2;
/// Linux's aarch64 value.
pub const MINSIGSTKSZ: u64 = 6144;

/// What happens to a process that has installed nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Default_ {
    /// Discarded. Linux's `SIG_KERNEL_IGNORE_MASK`, which is four signals.
    Ignore,
    /// The process stops.
    Stop,
    /// The process dies.
    Terminate,
}

/// What a signal does when nothing is installed for it.
///
/// Every row was read off a real arm64 kernel by
/// `tests/guest/src/bin/signal_defaults.rs` — fork a child that has installed
/// nothing, send the signal, see what became of it — rather than taken from a
/// header.
pub(crate) fn default_action(sig: c_int) -> Default_ {
    match sig {
        SIGCHLD | SIGCONT | SIGURG | SIGWINCH => Default_::Ignore,
        SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => Default_::Stop,
        _ => Default_::Terminate,
    }
}

/// Is this a number a signal at all?
///
/// `c_int`, and the caller must pass what it received: the number arrives in a
/// 64-bit register and is a `dword_t`, so a value with the top bit set is a
/// large negative `int` and passes any check written as `sig > MAX_SIG` alone.
pub fn valid(sig: c_int) -> bool {
    (1..=MAX_SIG).contains(&sig)
}

/// `SIGKILL` and `SIGSTOP`: they may not be caught, ignored or blocked.
pub fn kernel_only(sig: c_int) -> bool {
    sig == SIGKILL || sig == SIGSTOP
}

/// Linux's `SIG_KERNEL_COREDUMP_MASK`: the default action dumps core. Such a
/// signal is acted on by the thread that takes it, never at send time, since
/// the dump is of that thread (`complete_signal`; `sigfatal_probe`).
pub fn dumps_core(sig: c_int) -> bool {
    // SIGQUIT SIGILL SIGTRAP SIGABRT SIGBUS SIGFPE SIGSEGV SIGXCPU SIGXFSZ SIGSYS
    matches!(sig, 3 | 4 | 5 | 6 | 7 | 8 | 11 | 24 | 25 | 31)
}

/// The mask a `sigprocmask` request actually produces.
///
/// The two unblockable signals are dropped **without an error**, which is the
/// other half of `kernel_only` and is what Linux does.
pub fn maskable(set: u64) -> u64 {
    set & !(sig_bit(SIGKILL) | sig_bit(SIGSTOP))
}

fn sig_bit(sig: c_int) -> u64 {
    1u64 << (sig - 1)
}

/// What happens when a signal arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Action {
    Ignore = 0,
    Stop = 1,
    Terminate = 2,
    Handler = 3,
}

/// One process's dispositions.
#[derive(Debug, Clone, Copy)]
pub struct Table {
    actions: [Disposition; NUM_SIGS],
}

impl Default for Table {
    fn default() -> Table {
        Table {
            actions: [Disposition::default(); NUM_SIGS],
        }
    }
}

impl Table {
    pub fn new() -> Table {
        Table::default()
    }

    pub fn get(&self, sig: c_int) -> Option<Disposition> {
        valid(sig).then(|| self.actions[sig as usize])
    }

    pub fn set(&mut self, sig: c_int, d: Disposition) -> bool {
        if !valid(sig) {
            return false;
        }
        self.actions[sig as usize] = d;
        true
    }

    pub fn handler(&self, sig: c_int) -> u64 {
        self.get(sig).map(|d| d.handler).unwrap_or(SIG_DFL)
    }

    pub fn flags(&self, sig: c_int) -> u32 {
        self.get(sig).map(|d| d.flags).unwrap_or(0)
    }

    pub fn mask(&self, sig: c_int) -> u64 {
        self.get(sig).map(|d| d.mask).unwrap_or(0)
    }

    /// What happens when `sig` arrives.
    ///
    /// `SIGKILL` and `SIGSTOP` skip the table entirely: whatever is stored for
    /// them — and `rt_sigaction` will not store anything — they do what they do.
    pub fn action(&self, sig: c_int) -> Action {
        if !valid(sig) {
            return Action::Terminate;
        }
        if !kernel_only(sig) {
            match self.handler(sig) {
                SIG_IGN => return Action::Ignore,
                SIG_DFL => {}
                _ => return Action::Handler,
            }
        }
        match default_action(sig) {
            Default_::Ignore => Action::Ignore,
            Default_::Stop => Action::Stop,
            Default_::Terminate => Action::Terminate,
        }
    }

    /// The two masks `/proc/<pid>/status` prints as `SigIgn` and `SigCgt`.
    ///
    /// Bit `n - 1` is signal `n`, over all 64 of them, which is the convention
    /// every other mask in this tree uses and the one Linux prints. The C this
    /// replaces looped `for (int i = 0; i < 32; i++)` and set `1 << i`, so it
    /// read a signal 0 that does not exist, reported every disposition one bit
    /// too high, and did not look at signals 33..64 at all — a program that
    /// ignores `SIGRTMIN` was reported as ignoring nothing.
    pub fn ignored_and_caught(&self) -> (u64, u64) {
        let (mut ignored, mut caught) = (0u64, 0u64);
        for sig in 1..=MAX_SIG {
            match self.handler(sig) {
                SIG_IGN => ignored |= sig_bit(sig),
                SIG_DFL => {}
                _ => caught |= sig_bit(sig),
            }
        }
        (ignored, caught)
    }

    /// `rt_sigaction`'s rule.
    ///
    /// `installing` is whether an action was supplied. Linux:
    ///
    /// ```c
    /// if (!valid_signal(sig) || sig < 1 || (act && sig_kernel_only(sig)))
    ///         return -EINVAL;
    /// ```
    ///
    /// So `SIGKILL` may be *asked about* and not *set*, which a shell
    /// enumerating dispositions for a child depends on.
    pub fn may_change(sig: c_int, installing: bool) -> bool {
        valid(sig) && !(installing && kernel_only(sig))
    }

    /// What `execve` leaves behind.
    ///
    /// A handler cannot survive: the code it points at is gone. An *ignored*
    /// signal stays ignored, which is how a shell hands `SIGINT` off to a child
    /// it does not want interrupted, and the mask goes. The alternate stack goes
    /// too, and is the calling thread's: [`AltStack::on_exec`].
    pub fn on_exec(&mut self) {
        for sig in 1..=MAX_SIG {
            let d = &mut self.actions[sig as usize];
            if d.handler != SIG_IGN {
                *d = Disposition::default();
            } else {
                // Kept, but its flags and mask are the new program's business.
                *d = Disposition {
                    handler: SIG_IGN,
                    ..Disposition::default()
                };
            }
        }
    }
}

#[path = "altstack.rs"]
mod altstack;
pub use altstack::AltStack;

#[cfg(test)]
mod tests;
