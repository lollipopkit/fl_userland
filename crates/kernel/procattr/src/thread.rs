//! Per-thread process attributes.

use super::*;

/// The attributes Linux keeps on `task_struct`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct ThreadAttr {
    /// `PR_SET_TIMERSLACK`. Nothing here coalesces a timer; what a program
    /// sets is what it reads back, which is all `PR_GET_TIMERSLACK` promises.
    timer_slack_ns: u64,
    /// What 0 sets it back to: the parent's slack at the moment of the fork,
    /// which is Linux's `copy_process`.
    default_timer_slack_ns: u64,
    comm: [u8; COMM_LEN],
    personality: u32,
    pdeath_signal: i32,
    /// Linux keeps this in `io_context`, which is per task. Sixteen bits,
    /// because that is what `io_context.ioprio` is — a value above that is
    /// truncated rather than refused.
    ioprio: u16,
    no_new_privs: bool,
    /// `PR_SET_IO_FLUSHER`. Nothing here allocates memory on a guest's behalf
    /// in a way the flag could change; it is remembered and reported.
    io_flusher: bool,
    /// `PR_MCE_KILL`: the two `PF_MCE_*` flags.
    mce: u8,
    /// `PR_SET_SPECULATION_CTRL`: the three per-task SSB bits.
    ssb: u8,
    /// `sched_setscheduler`'s policy, for the three this kernel accepts.
    ///
    /// `SCHED_OTHER`, `SCHED_BATCH` and `SCHED_IDLE` are the non-realtime ones:
    /// they need no privilege, their only legal `sched_priority` is 0, and what
    /// they change is how the scheduler *weights* a runnable task, which is not
    /// something a guest can observe directly. So they are remembered and
    /// reported, like `ioprio` and `timer_slack_ns` above.
    ///
    /// The realtime policies are not, and the difference is the point: they
    /// promise preemption, which a guest thread running as an ordinary host
    /// thread cannot be given, and a program told it has `SCHED_FIFO` would
    /// build on a guarantee that is not there. Those stay `EINVAL`.
    ///
    /// Until 2026-09-07 all three were `EINVAL`, which was inconsistent with
    /// `sched_get_priority_min`/`max` in the same crate — those already knew
    /// `SCHED_BATCH` and `SCHED_IDLE` and answered 0 for each. A program that
    /// puts a background worker on `SCHED_IDLE` got an error from a call that
    /// cannot fail on Linux for an unprivileged valid request.
    sched_policy: u8,
    /// `SCHED_FLAG_RESET_ON_FORK` (`sched_setattr`) or `SCHED_RESET_ON_FORK`
    /// (`sched_setscheduler`): a child starts without this thread's negative
    /// nice value, and without the flag.
    sched_reset_on_fork: bool,
}

impl Default for ThreadAttr {
    fn default() -> Self {
        ThreadAttr {
            timer_slack_ns: DEFAULT_TIMER_SLACK_NS,
            default_timer_slack_ns: DEFAULT_TIMER_SLACK_NS,
            comm: [0; COMM_LEN],
            personality: ADDR_NO_RANDOMIZE,
            pdeath_signal: 0,
            ioprio: IOPRIO_NONE,
            no_new_privs: false,
            io_flusher: false,
            mce: 0,
            ssb: 0,
            sched_policy: SCHED_OTHER,
            sched_reset_on_fork: false,
        }
    }
}

impl ThreadAttr {
    pub fn init(&mut self) {
        *self = ThreadAttr::default();
    }

    /// What a `fork` or `clone` leaves the child with, beyond the copy of
    /// the parent. One rule: Linux's `copy_process` sets the child's
    /// *default* timer slack to the parent's *current* one, so a child that
    /// later asks for 0 gets what its parent had at the fork and not 50 µs.
    pub fn on_fork(&mut self) {
        self.default_timer_slack_ns = self.timer_slack_ns;
        // Linux's sched_fork clears it in the child; the nice value it also
        // resets is the group's here, and `crates/kernel/forkcalls` resets it.
        self.sched_reset_on_fork = false;
    }

    /// The thread name, as the sixteen bytes `PR_GET_NAME` writes: NUL-padded,
    /// and always terminated even if nothing was ever set.
    ///
    /// [`Self::name`] is what a reader that wants the *name* should use; this
    /// is the buffer, for the one caller that copies all sixteen bytes out to a
    /// guest.
    pub fn comm(&self) -> &[u8; COMM_LEN] {
        &self.comm
    }

    /// The name, without the padding.
    ///
    /// Four crates built this out of a `*const c_char` until 2026-09-16 —
    /// `std::slice::from_raw_parts(p.cast::<u8>(), 16)`, find the NUL,
    /// `from_utf8_lossy` — and the copies had the same shape because they were
    /// copies. Reaching the buffer as `&[u8; 16]` rather than as a pointer
    /// makes the trim one line, and having it here makes it one line *once*.
    pub fn name(&self) -> &[u8] {
        let end = self.comm.iter().position(|&b| b == 0).unwrap_or(COMM_LEN);
        &self.comm[..end]
    }

    /// The **host** thread name this task should carry: its name, a dash, and
    /// its pid, in the fifteen characters and a terminator Linux allows.
    ///
    /// It is what `sample`, a crash report and a debugger's thread list show,
    /// so it is how a hung thread gets identified — `task_race-5` is a real
    /// line from a stall this tree has chased. The pid is what makes two
    /// threads of one program tellable apart, so it is the part that is
    /// **kept**: the name is truncated to make room for it rather than the
    /// other way round.
    ///
    /// The C did this with a `snprintf` whose return is what it *would* have
    /// written, a subtraction that would underflow for a pid wide enough, and a
    /// bare `sprintf` on the end. It answers the array rather than writing
    /// through an out pointer, which is what its one caller wanted anyway.
    pub fn host_thread_name(&self, pid: i32) -> [u8; COMM_LEN] {
        thread_name(self.name(), pid)
    }

    /// `PR_SET_NAME`. Linux truncates rather than refusing — the copy is
    /// bounded at `COMM_LEN - 1` over a buffer whose last byte it has already
    /// zeroed — so this takes whatever fits and terminates it.
    ///
    /// `name` is the bytes up to the caller's terminator, however many that is.
    pub fn set_comm(&mut self, name: &[u8]) {
        self.comm = [0; COMM_LEN];
        let n = name.iter().position(|b| *b == 0).unwrap_or(name.len());
        let n = n.min(COMM_LEN - 1);
        self.comm[..n].copy_from_slice(&name[..n]);
    }

    /// What an `execve` leaves behind, of the attributes a *thread* has.
    ///
    /// `privileged` is `bprm->secureexec`, which is `AT_SECURE`: the ids or
    /// the capabilities the exec gave. Each rule is silent when it is missing,
    /// which is why they are here with a test each rather than as three lines
    /// in `__do_execve`:
    ///
    /// - **`pdeath_signal` goes on a privileged exec.** Otherwise an
    ///   unprivileged process sets one, execs a setuid binary, and the
    ///   privileged program receives a signal it never asked for at a moment
    ///   the parent chooses by exiting. `prctl(2)`: cleared "when executing a
    ///   set-user-ID or set-group-ID binary".
    ///
    /// Two things Linux does that this deliberately does not:
    ///
    /// - **`no_new_privs` is not reset**, by either kind of exec. It is a
    ///   one-way latch, and a process that set it must not be able to clear it
    ///   by exec'ing.
    /// - **`PER_CLEAR_ON_SETID` is not applied.** Linux clears
    ///   `ADDR_NO_RANDOMIZE` and three neighbours on a privileged exec because
    ///   they weaken the program that is about to gain privilege. This kernel
    ///   has no address-space randomisation at all and reports
    ///   `ADDR_NO_RANDOMIZE` by default, truthfully; clearing it would report
    ///   that randomisation is on. Linux's reason does not hold, so neither
    ///   does the rule.
    ///
    /// One more, Linux's and silent when missing: a speculation mitigation
    /// asked for *until exec* is put back by `arch_setup_new_exec`.
    /// `SECURE_KEEP_CAPS` goes too, with the credentials (`crates/kernel/creds`).
    pub fn on_exec(&mut self, privileged: bool) {
        if privileged {
            self.pdeath_signal = 0;
        }
        if self.ssb & spec::SSB_NOEXEC != 0 {
            self.ssb &= !(spec::SSB_DISABLE | spec::SSB_NOEXEC);
        }
    }

    pub fn personality(&self) -> u32 {
        self.personality
    }

    /// `personality(2)`. Answers the *old* value, which is the whole protocol:
    /// a caller saves what it is given, sets its own, and puts the old one back
    /// on the way out.
    ///
    /// The one refusal is the architecture's. aarch64 does not use the generic
    /// entry point — `arch/arm64/kernel/sys.c` has
    ///
    /// ```c
    /// SYSCALL_DEFINE1(arm64_personality, unsigned int, personality)
    /// {
    ///     if (personality(personality) == PER_LINUX32 &&
    ///         !system_supports_32bit_el0())
    ///         return -EINVAL;
    ///     return ksys_personality(personality);
    /// }
    /// ```
    ///
    /// and `personality(x)` there is `x & PER_MASK`. A CPU with no 32-bit EL0
    /// refuses a request whose *low byte* is `PER_LINUX32`; Apple Silicon is
    /// such a CPU, and so is this emulator, which has no 32-bit guest backend.
    /// The upper bits ride along, so `ADDR_NO_RANDOMIZE | PER_LINUX32` is
    /// refused too — and a low byte of `0x09` is not `PER_LINUX32` and is not.
    pub fn set_personality(&mut self, persona: u32) -> Result<u32, c_int> {
        let old = self.personality;
        if persona == PERSONALITY_QUERY {
            return Ok(old);
        }
        if persona & PER_MASK == PER_LINUX32 {
            return Err(EINVAL);
        }
        self.personality = persona;
        Ok(old)
    }

    pub fn pdeath_signal(&self) -> i32 {
        self.pdeath_signal
    }

    /// `PR_SET_PDEATHSIG`. 0 disarms; anything past the last signal number is
    /// refused. The argument is the full `unsigned long` a guest passed, not a
    /// narrowed one: `0x1_0000_0009` is not `SIGKILL`.
    ///
    /// Refusing it matters beyond conformance. The number is stored and then
    /// handed to `send_signal` when the parent exits, which indexes
    /// `sighand->action[sig]` — so a value past the end was an out-of-bounds
    /// read and a shift of 1 by more than 63 places. That is why the bound is
    /// `MAX_SIG` and not `NUM_SIGS`: the arrays are indexed by the number
    /// itself, so `NUM_SIGS` is their size and `MAX_SIG` is the last index.
    pub fn set_pdeath_signal(&mut self, sig: u64) -> Result<(), c_int> {
        if sig > MAX_SIG {
            return Err(EINVAL);
        }
        self.pdeath_signal = sig as i32;
        Ok(())
    }

    pub fn no_new_privs(&self) -> bool {
        self.no_new_privs
    }

    /// `PR_SET_NO_NEW_PRIVS`. One-way: Linux refuses to clear it, because a
    /// sandbox that could clear it would not be one, and a caller that thought
    /// it had cleared it would be wrong about what it is running under. So 0 is
    /// a refusal rather than a clear.
    ///
    /// `arg3`..`arg5` must be zero. That is in `kernel/sys.c` and in no man
    /// page; a caller that passes junk there gets `EINVAL` on Linux and used to
    /// get success here.
    pub fn set_no_new_privs(&mut self, a2: u64, a3: u64, a4: u64, a5: u64) -> Result<(), c_int> {
        if a2 != 1 || a3 != 0 || a4 != 0 || a5 != 0 {
            return Err(EINVAL);
        }
        self.no_new_privs = true;
        Ok(())
    }

    /// `PR_GET_NO_NEW_PRIVS`, which has the same zero-argument requirement.
    pub fn get_no_new_privs(&self, a2: u64, a3: u64, a4: u64, a5: u64) -> Result<c_int, c_int> {
        if a2 != 0 || a3 != 0 || a4 != 0 || a5 != 0 {
            return Err(EINVAL);
        }
        Ok(self.no_new_privs as c_int)
    }

    pub fn timer_slack(&self) -> u64 {
        self.timer_slack_ns
    }

    /// `PR_SET_TIMERSLACK`. 0 asks for the default, which is the parent's at
    /// the fork; anything else is stored as given. No value is refused.
    pub fn set_timer_slack(&mut self, ns: u64) {
        self.timer_slack_ns = if ns == 0 {
            self.default_timer_slack_ns
        } else {
            ns
        };
    }

    /// `PR_MCE_KILL`: `kernel/sys.c`'s two-level switch, in which `arg4` and
    /// `arg5` are refused for every sub-operation and `arg3` for `CLEAR`.
    pub fn mce_kill(&mut self, a2: u64, a3: u64, a4: u64, a5: u64) -> Result<(), c_int> {
        if a4 | a5 != 0 {
            return Err(EINVAL);
        }
        match a2 {
            mce::KILL_CLEAR => {
                if a3 != 0 {
                    return Err(EINVAL);
                }
                self.mce &= !mce::PROCESS;
            }
            mce::KILL_SET => {
                self.mce |= mce::PROCESS;
                match a3 {
                    mce::KILL_EARLY => self.mce |= mce::EARLY,
                    mce::KILL_LATE => self.mce &= !mce::EARLY,
                    mce::KILL_DEFAULT => self.mce &= !(mce::EARLY | mce::PROCESS),
                    _ => return Err(EINVAL),
                }
            }
            _ => return Err(EINVAL),
        }
        Ok(())
    }

    /// `PR_MCE_KILL_GET`: `EARLY`, `LATE` or `DEFAULT`, with all four arguments
    /// required to be zero.
    pub fn mce_kill_get(&self, a2: u64, a3: u64, a4: u64, a5: u64) -> Result<c_int, c_int> {
        if a2 | a3 | a4 | a5 != 0 {
            return Err(EINVAL);
        }
        Ok(if self.mce & mce::PROCESS == 0 {
            mce::KILL_DEFAULT as c_int
        } else if self.mce & mce::EARLY != 0 {
            mce::KILL_EARLY as c_int
        } else {
            mce::KILL_LATE as c_int
        })
    }

    /// `PR_SET_IO_FLUSHER`. The capability is asked for **before** the
    /// arguments are looked at, and 1 and 0 are the only values.
    pub fn set_io_flusher(
        &mut self,
        a2: u64,
        a3: u64,
        a4: u64,
        a5: u64,
        capable: bool,
    ) -> Result<(), c_int> {
        if !capable {
            return Err(EPERM);
        }
        if a3 | a4 | a5 != 0 {
            return Err(EINVAL);
        }
        match a2 {
            1 => self.io_flusher = true,
            0 => self.io_flusher = false,
            _ => return Err(EINVAL),
        }
        Ok(())
    }

    /// `PR_GET_IO_FLUSHER`, which needs the same capability to *ask*.
    pub fn io_flusher(
        &self,
        a2: u64,
        a3: u64,
        a4: u64,
        a5: u64,
        capable: bool,
    ) -> Result<c_int, c_int> {
        if !capable {
            return Err(EPERM);
        }
        if a2 | a3 | a4 | a5 != 0 {
            return Err(EINVAL);
        }
        Ok(self.io_flusher as c_int)
    }

    /// `PR_GET_SPECULATION_CTRL`. arm64 answers for one misfeature, store
    /// bypass, and `ENODEV` for the other two.
    ///
    /// The answer is `PR_SPEC_ENABLE` with no `PR_SPEC_PRCTL` bit, whatever
    /// the task asked for: `ssbd_prctl_get`'s answer for a CPU in the
    /// `SPECTRE_VULNERABLE` state, which is what the reference kernel reports
    /// in a VM on this hardware. It is also the honest one. No mitigation is
    /// applied on the task's behalf — SSBS is set for the host process by the
    /// host kernel — so telling a sandbox that its `PR_SPEC_DISABLE` took
    /// effect would be telling it that a store cannot bypass, which nothing
    /// here arranges. What the task asked for is still kept, because the
    /// **rules** about asking again are the task's: a forced disable makes a
    /// later enable `EPERM` whether or not the CPU is affected.
    pub fn spec_ctrl_get(&self, which: u64, a3: u64, a4: u64, a5: u64) -> Result<c_int, c_int> {
        if a3 | a4 | a5 != 0 {
            return Err(EINVAL);
        }
        if which != spec::STORE_BYPASS {
            return Err(ENODEV);
        }
        Ok(spec::ENABLE as c_int)
    }

    /// `PR_SET_SPECULATION_CTRL`: `ssbd_prctl_set` under the default dynamic
    /// policy. A forced disable is permanent — `ENABLE` and `DISABLE_NOEXEC`
    /// after it are `EPERM` — and a control that names nothing is `ERANGE`,
    /// not `EINVAL`. The bits are what makes the `EPERM` rule answerable; see
    /// [`ThreadAttr::spec_ctrl_get`] for why they are not reported.
    pub fn spec_ctrl_set(&mut self, which: u64, ctrl: u64, a4: u64, a5: u64) -> Result<(), c_int> {
        if a4 | a5 != 0 {
            return Err(EINVAL);
        }
        if which != spec::STORE_BYPASS {
            return Err(ENODEV);
        }
        let forced = self.ssb & spec::SSB_FORCE_DISABLE != 0;
        match ctrl {
            spec::ENABLE => {
                if forced {
                    return Err(EPERM);
                }
                self.ssb &= !(spec::SSB_DISABLE | spec::SSB_NOEXEC);
            }
            spec::FORCE_DISABLE => {
                self.ssb =
                    (self.ssb & !spec::SSB_NOEXEC) | spec::SSB_DISABLE | spec::SSB_FORCE_DISABLE;
            }
            spec::DISABLE => {
                self.ssb = (self.ssb & !spec::SSB_NOEXEC) | spec::SSB_DISABLE;
            }
            spec::DISABLE_NOEXEC => {
                if forced {
                    return Err(EPERM);
                }
                self.ssb |= spec::SSB_DISABLE | spec::SSB_NOEXEC;
            }
            _ => return Err(ERANGE),
        }
        Ok(())
    }

    pub fn ioprio(&self) -> i32 {
        self.ioprio as i32
    }

    /// The scheduling policy this thread was last given. Always one of
    /// [`SCHED_OTHER`], [`SCHED_BATCH`] or [`SCHED_IDLE`].
    pub fn sched_policy(&self) -> c_int {
        self.sched_policy as c_int
    }

    #[cfg(test)]
    pub(crate) fn ssb_for_test(&self) -> u8 {
        self.ssb
    }

    /// Whether a child is to start with a non-negative nice value and no
    /// flag; see the field.
    pub fn sched_reset_on_fork(&self) -> bool {
        self.sched_reset_on_fork
    }

    pub fn set_sched_reset_on_fork(&mut self, on: bool) {
        self.sched_reset_on_fork = on;
    }

    /// Remember a policy. The caller has already established that
    /// [`sched_policy_supported`] holds and that the priority is 0.
    pub fn set_sched_policy(&mut self, policy: c_int) {
        debug_assert!(sched_policy_supported(policy));
        self.sched_policy = policy as u8;
    }

    /// `ioprio_set`. `privileged` is `CAP_SYS_NICE` or `CAP_SYS_ADMIN`
    /// (`ioprio_check_cap`).
    ///
    /// The rules, all measured:
    ///
    /// - a class above `IOPRIO_CLASS_IDLE` is `EINVAL`;
    /// - `IOPRIO_CLASS_RT` needs privilege, and is `EPERM` without it;
    /// - `IOPRIO_CLASS_NONE` carries no level, so a non-zero *level* — the low
    ///   three bits — is `EINVAL`, and a value like 8 whose low three bits are
    ///   zero is accepted;
    /// - `IOPRIO_CLASS_BE` and `_IDLE` take any level at all, because the check
    ///   Linux does is on the class.
    ///
    /// The value is stored whole and read back whole, in sixteen bits.
    pub fn set_ioprio(&mut self, value: u32, privileged: bool) -> Result<(), c_int> {
        let class = (value >> IOPRIO_CLASS_SHIFT) & IOPRIO_CLASS_MASK;
        let level = value & IOPRIO_LEVEL_MASK;
        match class {
            IOPRIO_CLASS_RT if !privileged => return Err(EPERM),
            IOPRIO_CLASS_RT | IOPRIO_CLASS_BE | IOPRIO_CLASS_IDLE => {}
            IOPRIO_CLASS_NONE if level == 0 => {}
            _ => return Err(EINVAL),
        }
        self.ioprio = value as u16;
        Ok(())
    }

}

/// The naming rule, over any bytes.
///
/// Separate from [`ThreadAttr::host_thread_name`] so its tests can hand it a
/// name longer than a `comm` can hold: the truncation is the part worth
/// testing, and a real `comm` is fifteen characters, so driving it through the
/// type would test the input rather than the rule.
pub(crate) fn thread_name(comm: &[u8], pid: i32) -> [u8; COMM_LEN] {
    let mut out = [0u8; COMM_LEN];
    let suffix = format!("-{pid}");
    let suffix = suffix.as_bytes();
    // The whole sixteen bytes are the pid's if the name cannot fit beside it,
    // which is what "keep the pid" means at the limit.
    let room = out.len() - 1;
    let for_name = room.saturating_sub(suffix.len());

    let comm = &comm[..comm.iter().position(|&b| b == 0).unwrap_or(comm.len())];
    let n = comm.len().min(for_name);
    out[..n].copy_from_slice(&comm[..n]);
    let m = suffix.len().min(room - n);
    out[n..n + m].copy_from_slice(&suffix[..m]);
    out
}
