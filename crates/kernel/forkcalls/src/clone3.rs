//! `clone3` argument decoding, validation, and syscall handling.

use super::*;

// ---------------------------------------------------------------------------
// clone3
// ---------------------------------------------------------------------------

/// Linux's `struct clone_args` (`uapi/linux/sched.h`). Every field is a `u64`.
///
/// Read as bytes rather than cast over guest memory, because the *length* is
/// the caller's and the rule about it is the interesting part.
#[derive(Default, Debug, PartialEq, Eq)]
struct CloneArgs {
    flags: u64,
    /// Where to store a pidfd. Unsupported, so ignored.
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    /// The **lowest** byte of the child stack region.
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

/// How many `u64`s this kernel understands.
const CLONE_ARGS_FIELDS: usize = 11;
const CLONE_ARGS_SIZE: usize = CLONE_ARGS_FIELDS * 8;
/// `CLONE_ARGS_SIZE_VER0`: through `tls`, the struct `clone3` shipped with.
const CLONE_ARGS_SIZE_VER0: usize = 8 * 8;

impl CloneArgs {
    fn decode(bytes: &[u8]) -> CloneArgs {
        let w = |i: usize| {
            bytes
                .get(i * 8..i * 8 + 8)
                .map_or(0, |b| u64::from_le_bytes(b.try_into().unwrap()))
        };
        CloneArgs {
            flags: w(0),
            pidfd: w(1),
            child_tid: w(2),
            parent_tid: w(3),
            exit_signal: w(4),
            stack: w(5),
            stack_size: w(6),
            tls: w(7),
            set_tid: w(8),
            set_tid_size: w(9),
            cgroup: w(10),
        }
    }

    /// Every rule `clone3` applies to its arguments before anything happens.
    ///
    /// Separated from the syscall so that it can be tested without a process
    /// table: it is where the interesting decisions are, and one of them is
    /// about a *length*, which is the combination this tree keeps finding
    /// defects in.
    fn check(&self) -> Result<(), i64> {
        // `exit_signal` is a whole u64 here and every bit of it is checked,
        // where the legacy call could only ever pass the low eight.
        if self.exit_signal & !clone::CSIGNAL != 0 {
            return Err(EINVAL);
        }
        if self.exit_signal > ffi::MAX_SIG as u64 {
            return Err(EINVAL);
        }

        // Both or neither. The array itself is read by [`CloneArgs::set_tid`],
        // after these: Linux copies it in after every static rule.
        if (self.set_tid == 0) != (self.set_tid_size == 0) {
            return Err(EINVAL);
        }
        // MAX_PID_NS_LEVEL, the one bound on this that does not depend on how
        // deep the caller's pid namespace is.
        if self.set_tid_size > 32 {
            return Err(EINVAL);
        }

        // clone3 reclaimed two things the legacy call used: the CSIGNAL bits,
        // which are `exit_signal` now, and CLONE_DETACHED. Either in `flags` is
        // an error rather than a second spelling -- that is what makes the
        // reuse safe.
        if self.flags & !clone::CLONE3_OK != 0 {
            return Err(EINVAL);
        }
        // Sharing the disposition table and clearing it are contradictory.
        // Stated here rather than left to the CLONE_SIGHAND-needs-CLONE_VM
        // rule, which refuses this combination too and for the wrong reason.
        if self.flags & clone::CLEAR_SIGHAND != 0 && self.flags & clone::SIGHAND != 0 {
            return Err(EINVAL);
        }
        Ok(())
    }

    /// `clone3` keeps `exit_signal` separate from `flags`; the legacy path
    /// expects it OR'd into the low byte.
    /// `set_tid`: the pid the child must have, or `None` to let the kernel
    /// choose.
    ///
    /// One entry per pid-namespace level, innermost first, and there is one
    /// level here -- so a longer array is `EINVAL`, which is `alloc_pid`'s
    /// `set_tid_size > ns->level + 1`. Then `alloc_pid`'s own order: a pid
    /// outside `[1, pid_max)` is `EINVAL`, a caller without
    /// `CAP_CHECKPOINT_RESTORE` is `EPERM`, and a pid in use is `EEXIST`,
    /// which the allocation answers. It was `EPERM` for every request until
    /// 2026-11-11, which is what a container without the capability says and
    /// not what this kernel's root should.
    fn set_tid(&self) -> Result<Option<c_int>, Errno> {
        if self.set_tid_size == 0 {
            return Ok(None);
        }
        let mut raw = vec![0u8; self.set_tid_size as usize * 4];
        if usercopy::GuestMem.read(self.set_tid, &mut raw) != 0 {
            return Err(Errno::EFAULT);
        }
        if self.set_tid_size > 1 {
            return Err(Errno::EINVAL);
        }
        let tid = i32::from_le_bytes(raw[..4].try_into().unwrap());
        if tid < 1 || tid >= ffi::MAX_PID as c_int {
            return Err(Errno::EINVAL);
        }
        if !(taskview::capable(taskview::caps::CAP_SYS_ADMIN) || taskview::capable(taskview::caps::CAP_CHECKPOINT_RESTORE)) {
            return Err(Errno::EPERM);
        }
        Ok(Some(tid))
    }

    fn legacy_flags(&self) -> u64 {
        self.flags | (self.exit_signal & clone::CSIGNAL)
    }

    /// `clone3` passes the *base* of the stack region and the child's `sp` is
    /// the top; legacy `clone` passes the top directly. A zero stack means
    /// "share or copy the parent's" and passes through as 0.
    fn child_sp(&self) -> u64 {
        if self.stack == 0 {
            0
        } else {
            self.stack.wrapping_add(self.stack_size)
        }
    }
}

/// `clone3`'s argument struct is **extensible**, and the two directions mean
/// different things.
///
/// A caller older than this kernel sends a short struct and the rest is zero. A
/// caller *newer* than it sends a long one — and the contract is that this
/// kernel may accept it only if every byte it does not understand is zero, and
/// must answer `E2BIG` otherwise. Dropping an unknown field silently is the
/// failure that protocol exists to prevent: a program compiled against a newer
/// kernel would set a flag, have it ignored, and run believing it got what it
/// asked for.
///
/// This clamped `size` to its own struct and read that much, so a longer struct
/// with anything set past the end was accepted and the tail thrown away, and a
/// `size` of a megabyte was accepted rather than refused.
pub fn sys_clone3(args_addr: u64, size: u32) -> Result<i64, Errno> {
    strace!("clone3({args_addr:#x}, {size})");
    // Above a page is E2BIG, answered before the contents are looked at.
    if size as u64 > ffi::PAGE_SIZE as u64 {
        return Err(Errno::E2BIG);
    }
    if (size as usize) < CLONE_ARGS_SIZE_VER0 {
        return Err(Errno::EINVAL);
    }

    let mut bytes = vec![0u8; size as usize];
    if usercopy::GuestMem.read(args_addr, &mut bytes) != 0 {
        return Err(Errno::EFAULT);
    }
    // The tail this kernel has no field for. All of it has to be zero.
    if bytes.len() > CLONE_ARGS_SIZE && bytes[CLONE_ARGS_SIZE..].iter().any(|&b| b != 0) {
        return Err(Errno::E2BIG);
    }

    let args = CloneArgs::decode(&bytes);
    args.check()
        .map_err(|e| Errno::from_negative_or_eio(e as i32))?;
    // The descriptor must fit an `int`, and the field must be inside the
    // caller's struct: a struct that ends before it cannot have meant it.
    if args.flags & clone::INTO_CGROUP != 0
        && (args.cgroup > i32::MAX as u64 || (size as usize) < CLONE_ARGS_SIZE)
    {
        return Err(Errno::EINVAL);
    }
    let set_tid = args.set_tid()?;
    // There is no cgroup2 filesystem here, so no descriptor can be open on a
    // cgroup directory, and Linux's `cgroup_get_from_file` answers `EBADF`
    // for one that is not -- measured with `/dev/null`, `/` and a closed
    // number alike.
    if args.flags & clone::INTO_CGROUP != 0 {
        return Err(Errno::EBADF);
    }
    Errno::split(do_clone(
        args.legacy_flags(),
        args.child_sp(),
        args.parent_tid,
        args.tls,
        args.child_tid,
        args.pidfd,
        set_tid,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(a: &CloneArgs) -> Vec<u8> {
        [
            a.flags,
            a.pidfd,
            a.child_tid,
            a.parent_tid,
            a.exit_signal,
            a.stack,
            a.stack_size,
            a.tls,
            a.set_tid,
            a.set_tid_size,
            a.cgroup,
        ]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect()
    }

    #[test]
    fn a_short_struct_reads_the_rest_as_zero() {
        // A caller older than this kernel sends CLONE_ARGS_SIZE_VER0 and the
        // fields past `tls` are absent, not garbage.
        let mut bytes = encode(&CloneArgs {
            flags: clone::VM,
            tls: 0x1234,
            ..Default::default()
        });
        bytes.truncate(CLONE_ARGS_SIZE_VER0);
        let a = CloneArgs::decode(&bytes);
        assert_eq!(a.tls, 0x1234);
        assert_eq!(a.set_tid, 0);
        assert_eq!(a.cgroup, 0);
    }

    #[test]
    fn the_version_zero_size_is_through_tls() {
        // Getting this bound wrong in the other direction accepts a struct
        // with no tls field and reads one anyway.
        assert_eq!(CLONE_ARGS_SIZE_VER0, 64);
        assert_eq!(CLONE_ARGS_SIZE, 88);
    }

    #[test]
    fn a_stack_region_puts_sp_at_its_top() {
        // clone3 passes the base and the size; the legacy call passes the top.
        // Passing the base through unchanged starts the child at the *bottom*
        // of its own stack, which grows down into nothing.
        let a = CloneArgs {
            stack: 0x1000,
            stack_size: 0x4000,
            ..Default::default()
        };
        assert_eq!(a.child_sp(), 0x5000);
    }

    #[test]
    fn no_stack_stays_no_stack() {
        // Zero means fork-like: share or copy the parent's stack. Adding a
        // size to it would produce an address.
        let a = CloneArgs {
            stack: 0,
            stack_size: 0x4000,
            ..Default::default()
        };
        assert_eq!(a.child_sp(), 0);
    }

    #[test]
    fn the_exit_signal_moved_out_of_the_flags_and_back_in() {
        let a = CloneArgs {
            flags: clone::VM | clone::THREAD,
            exit_signal: 17,
            ..Default::default()
        };
        assert_eq!(a.legacy_flags(), clone::VM | clone::THREAD | 17);
    }

    #[test]
    fn a_flag_the_legacy_call_reclaimed_is_refused() {
        // CLONE_DETACHED and the CSIGNAL bits are `exit_signal` now. Accepting
        // them as a second spelling is what would make the reuse unsafe.
        assert_eq!(
            CloneArgs {
                flags: clone::DETACHED,
                ..Default::default()
            }
            .check(),
            Err(EINVAL)
        );
        assert_eq!(
            CloneArgs {
                flags: 0xff,
                ..Default::default()
            }
            .check(),
            Err(EINVAL)
        );
    }

    #[test]
    fn sharing_the_disposition_table_and_clearing_it_are_contradictory() {
        assert_eq!(
            CloneArgs {
                flags: clone::SIGHAND | clone::CLEAR_SIGHAND | clone::VM,
                ..Default::default()
            }
            .check(),
            Err(EINVAL)
        );
    }

    #[test]
    fn set_tid_needs_both_halves() {
        // One entry is the static rules' business no longer: whether the pid
        // may be had is `set_tid`'s, which reads the array.
        assert_eq!(
            CloneArgs {
                set_tid: 0x1000,
                set_tid_size: 1,
                ..Default::default()
            }
            .check(),
            Ok(())
        );
        assert_eq!(
            CloneArgs {
                set_tid: 0x1000,
                set_tid_size: 33,
                ..Default::default()
            }
            .check(),
            Err(EINVAL)
        );
        // Both or neither.
        assert_eq!(
            CloneArgs {
                set_tid: 0x1000,
                ..Default::default()
            }
            .check(),
            Err(EINVAL)
        );
        assert_eq!(
            CloneArgs {
                set_tid_size: 1,
                ..Default::default()
            }
            .check(),
            Err(EINVAL)
        );
    }

    #[test]
    fn clone3s_flag_set_is_the_legacy_one_minus_what_it_reclaimed() {
        // The two sets are written out separately, so this is the check that
        // they say what the comments claim.
        assert_eq!(clone::CLONE3_OK & clone::DETACHED, 0, "reclaimed");
        assert_eq!(clone::CLONE3_OK & clone::CSIGNAL, 0, "reclaimed");
        assert_ne!(clone::CLONE3_OK & clone::CLEAR_SIGHAND, 0, "clone3-only");
        assert_eq!(
            clone::IMPLEMENTED & clone::CLEAR_SIGHAND,
            clone::CLEAR_SIGHAND,
            "reachable through clone3"
        );
    }
}
