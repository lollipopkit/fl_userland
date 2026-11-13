//! Per-thread alternate signal stack state and rules.

use std::ffi::c_int;

use super::{MINSIGSTKSZ, SA_ONSTACK, SS_DISABLE, SS_ONSTACK};

// ---------------------------------------------------------------------------
// The alternate stack
// ---------------------------------------------------------------------------

/// One **thread's** alternate signal stack, as `sigaltstack(2)` sets it.
///
/// Per thread is Linux's rule (`task_struct.sas_ss_sp`), and it is not a
/// detail: a runtime that runs handlers on a stack of its own gives every
/// thread one, because two threads can be in a handler at the same instant
/// and a stack has room for one frame at a time. Go does exactly that on every
/// `M` it starts.
///
/// What a new thread starts with, what a fork child inherits and what `execve`
/// does are three different answers, and each is a method here so that the
/// caller names which one it wants.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AltStack {
    stack: u64,
    size: u64,
}

impl AltStack {
    /// Where it is and how big, `(0, 0)` for none.
    pub fn bounds(&self) -> (u64, u64) {
        (self.stack, self.size)
    }

    /// Is `sp` inside it?
    ///
    /// Exclusive at the bottom and inclusive at the top, because a stack grows
    /// down and a freshly switched `sp` is one past the end.
    pub fn contains(&self, sp: u64) -> bool {
        self.stack != 0 && sp > self.stack && sp <= self.stack + self.size
    }

    /// Whether a handler with these flags should run on it.
    ///
    /// Both halves matter. `SA_ONSTACK` is the handler asking for it, and
    /// already being on it means not switching again — a nested signal has to
    /// keep the frame it is on. Switching whenever an alternate stack merely
    /// *existed* is a bug this tree has had: JSC installs one for `SIGSEGV` and
    /// registers its other handlers without `SA_ONSTACK`, and running those on
    /// the alternate stack put `sp` outside the bounds its own handler checks.
    pub fn should_switch(&self, flags: u32, sp: u64) -> bool {
        flags & SA_ONSTACK != 0 && self.stack != 0 && !self.contains(sp)
    }

    /// What `sigaltstack` reports: the stack, its size and the `ss_flags`.
    pub fn report(&self, sp: u64) -> (u64, u64, u32) {
        let mut flags = 0;
        if self.stack == 0 {
            flags |= SS_DISABLE;
        }
        if self.contains(sp) {
            flags |= SS_ONSTACK;
        }
        (self.stack, self.size, flags)
    }

    /// `sigaltstack`'s setter. `Err` is a guest errno.
    ///
    /// Changing it while running on it is `EPERM`: the frame under the handler
    /// is on that stack, and moving it out from under itself has nowhere to
    /// return to.
    pub fn set(&mut self, stack: u64, size: u64, flags: u32, sp: u64) -> Result<(), c_int> {
        if self.contains(sp) {
            return Err(-1); // _EPERM
        }
        if flags & SS_DISABLE != 0 {
            *self = AltStack::default();
            return Ok(());
        }
        if size < MINSIGSTKSZ {
            return Err(-12); // _ENOMEM
        }
        self.stack = stack;
        self.size = size;
        Ok(())
    }

    /// A new thread has none. Linux's `copy_process`:
    ///
    /// ```c
    /// /*
    ///  * sigaltstack should be cleared when sharing the same VM
    ///  */
    /// if ((clone_flags & (CLONE_VM|CLONE_VFORK)) == CLONE_VM)
    ///         sas_ss_reset(p);
    /// ```
    ///
    /// A fork child, and a `vfork` child, inherit the calling thread's — that
    /// is a plain copy, and the caller makes it.
    pub fn on_new_thread(&mut self) {
        *self = AltStack::default();
    }

    /// `execve` drops it: the image that allocated it is gone.
    pub fn on_exec(&mut self) {
        *self = AltStack::default();
    }
}
