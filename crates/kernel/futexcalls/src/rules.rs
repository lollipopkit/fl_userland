use super::{ENOSYS, guestmem};
// ---------------------------------------------------------------------------
// FUTEX_WAKE_OP
// ---------------------------------------------------------------------------

/// What `val3` says to do, decoded.
///
/// The whole operation is packed into one 32-bit word:
///
/// ```text
///   31..28  op        27  op is a shift  27..24  cmp
///   23..12  oparg, 12 bits signed
///   11..0   cmparg, 12 bits signed
/// ```
///
/// Both arguments are **twelve bits, sign-extended**, which is the part that is
/// easy to get wrong and impossible to notice: a positive `oparg` reads the
/// same either way, and glibc's are positive.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct WakeOp {
    pub(super) op: u32,
    pub(super) cmp: u32,
    pub(super) oparg: i32,
    pub(super) cmparg: i32,
}

pub(super) fn decode_wake_op(val3: u32) -> Result<WakeOp, i64> {
    let mut op = (val3 >> 28) & 0xf;
    let cmp = (val3 >> 24) & 0xf;
    // Bits [23:12] and [11:0], sign-extended from twelve.
    let oparg = ((val3 << 8) as i32) >> 20;
    let cmparg = ((val3 << 20) as i32) >> 20;

    let shift = op & guestmem::op::OPARG_SHIFT != 0;
    op &= !guestmem::op::OPARG_SHIFT;
    let oparg = if shift {
        // **Masked to five bits, not refused.** This answered `EINVAL` above 31
        // on the reasoning that a shift an `int` cannot take is not a shift;
        // Linux masks. Measured by `tests/guest/src/bin/futex_probe.rs`, which
        // sweeps 31, 32, 33, 63 and 4095 and gets 0 from a real kernel for
        // every one of them.
        //
        // Linux arrived there through a security fix rather than a design: the
        // shift used to be undefined behaviour, and the repair was `oparg &=
        // 31` because that is what the hardware was doing anyway. Refusing is
        // arguably better and is not what a guest is written against.
        1 << (oparg & 31)
    } else {
        oparg
    };
    Ok(WakeOp {
        op,
        cmp,
        oparg,
        cmparg,
    })
}

/// Whether the old value satisfies the comparison, or `ENOSYS` for a code
/// Linux does not define.
pub(super) fn wake_op_compare(cmp: u32, old: i32, cmparg: i32) -> Result<bool, i64> {
    Ok(match cmp {
        guestmem::op::CMP_EQ => old == cmparg,
        guestmem::op::CMP_NE => old != cmparg,
        guestmem::op::CMP_LT => old < cmparg,
        guestmem::op::CMP_LE => old <= cmparg,
        guestmem::op::CMP_GT => old > cmparg,
        guestmem::op::CMP_GE => old >= cmparg,
        _ => return Err(ENOSYS),
    })
}

/// Whether `FUTEX_REQUEUE`/`FUTEX_CMP_REQUEUE` will take these two counts.
///
/// Both arrive as 32 bits — `do_futex(..., u32 val, ..., u32 val2, u32 val3)`,
/// which is what the syscall's fourth argument is narrowed to — and
/// `futex_requeue` then reads them as **signed**:
///
/// ```c
/// int futex_requeue(u32 __user *uaddr1, unsigned int flags1,
///                   u32 __user *uaddr2, unsigned int flags2,
///                   int nr_wake, int nr_requeue, u32 *cmpval, int requeue_pi)
/// {
///         ...
///         if (nr_wake < 0 || nr_requeue < 0)
///                 return -EINVAL;
/// ```
///
/// So `0x8000_0000` is a refusal and not a request to move two billion waiters.
/// This kernel counted in `u32` throughout and answered 0, which reads as "no
/// waiter matched" — the one answer a caller will not retry.
///
/// **The check belongs to requeue and not to every operation**, and both halves
/// of that are measured rather than read: `FUTEX_WAKE` with the same count is 0
/// on a real arm64 kernel, and so is `FUTEX_WAKE_OP`. It also comes *before*
/// the `cmpval` comparison — `CMP_REQUEUE` with this count and a value that
/// does not match is `EINVAL` there and not `EAGAIN`.
pub(super) fn requeue_counts_ok(nr_wake: u32, nr_requeue: u32) -> bool {
    (nr_wake as i32) >= 0 && (nr_requeue as i32) >= 0
}

/// An absolute deadline, as a wait from now. Never negative: a deadline that
/// has passed is a wait of zero.
pub(super) fn relative_to(sec: i64, nsec: i64, now_sec: i64, now_nsec: i64) -> libc::timespec {
    let mut s = sec - now_sec;
    let mut ns = nsec - now_nsec;
    if ns < 0 {
        s -= 1;
        ns += 1_000_000_000;
    }
    if s < 0 {
        s = 0;
        ns = 0;
    }
    libc::timespec {
        tv_sec: s as _,
        tv_nsec: ns as _,
    }
}
