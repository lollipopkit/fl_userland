//! What a positioned or vectored read or write may be asked to do.
//!
//! `kernel/fs.c` holds the loops — the descriptor, the bounce buffer, the
//! mount's `->read`. What is here is the arithmetic those loops are only valid
//! for: whether an offset and a count name a range at all, which `RWF_*` flags
//! exist, and what `copy_file_range` refuses.
//!
//! Every rule is a line of `io_probe`'s output from an arm64 container. Where a
//! rule was read from Linux's source as well, the source is quoted — but the
//! measurement is what decides, because reading has been wrong here before:
//! `clock_nanosleep`'s flag check was written from `TIMER_ABSTIME`'s definition
//! and a real kernel disagreed with all five cases.
//!
//! ## What was wrong
//!
//! | The guest did | Linux | This kernel |
//! | --- | --- | --- |
//! | `sendfile(count = ~0)` | `EINVAL` | copied the file |
//! | `preadv(offset = SSIZE_MAX)` | `EINVAL` | 0 |
//! | `preadv2(RWF_DSYNC)` on a read | ignores it | `EOPNOTSUPP` |
//! | `pwritev2(offset = 0, RWF_APPEND)` | appends | `EOPNOTSUPP` |
//! | `pwritev2(RWF_NOSIGNAL)` | writes | `EOPNOTSUPP` |
//! | `pwritev2(RWF_APPEND \| RWF_NOAPPEND)` | `EINVAL` | wrote |
//! | `copy_file_range` of one file onto itself, overlapping | `EINVAL` | copied |
//! | `copy_file_range(offset = -1)` | `EOVERFLOW` | copied |

#![no_std]

use guest_errno::c_int_::{EINVAL, EOPNOTSUPP, EOVERFLOW};

/// The most bytes one read or write may move: Linux's `MAX_RW_COUNT`, which is
/// `INT_MAX` rounded down to a page. A count above it is **shortened**, not
/// refused — but a count that is negative as a signed value is refused, and
/// those are two different things about the same number.
pub const MAX_RW_COUNT: u64 = (i32::MAX as u64) & !0xfff;

/// The largest bounce buffer a syscall allocates on the guest's word.
///
/// Clamping to [`MAX_RW_COUNT`] alone is not enough:
/// `pwrite(fd, buf, 0xFFFFFFFF)` over a 16 KB guest buffer allocated the full
/// two gigabytes and died of `SIGBUS` filling it, before the copy got far
/// enough to answer `EFAULT`. 8 MiB is above any buffer size a guest program
/// actually uses -- stdio picks kilobytes, `cp` and Go pick 32 to 256 KB -- so
/// nothing normal is chunked or shortened.
pub const BOUNCE_CAP: u64 = 8 * 1024 * 1024;

/// What a read or write may actually be given a buffer for.
///
/// `kernel/calls.h` carried a `static inline rw_clamp` that was this function
/// in C, for the syscalls that bounced through a host buffer there; the last
/// of those moved with `kernel/fs.c`, and the C copy went on 2026-09-04.
pub fn bounce_clamp(count: u64) -> usize {
    count.min(MAX_RW_COUNT).min(BOUNCE_CAP) as usize
}

// ------------------------------------------------------- offset and count

/// Whether an offset and a count name a range this file could hold.
///
/// Linux's `rw_verify_area`, for a file without `FMODE_UNSIGNED_OFFSET` — which
/// is every ordinary one:
///
/// ```c
/// if (unlikely((ssize_t) count < 0))
///     return -EINVAL;
/// if (ppos) {
///     loff_t pos = *ppos;
///     if (unlikely(pos < 0)) {
///         if (!unsigned_offsets(file))
///             return -EINVAL;
///         ...
///     } else if (unlikely((loff_t) (pos + count) < 0)) {
///         if (!unsigned_offsets(file))
///             return -EINVAL;
///     }
/// }
/// ```
///
/// The second branch is the one nothing here had: an offset that is positive
/// and a count that pushes it past `LLONG_MAX`. Measured —
/// `preadv(fd, iov, 1, 0x7fff_ffff_ffff_ffff)` is `EINVAL` on a real kernel and
/// returned 0 here, an end-of-file answer for a range that does not exist.
///
/// `pos == -1` is **not** passed here: for `preadv2`/`pwritev2` it means "use
/// the file's own position" and is handled before this is asked.
pub fn verify_area(pos: i64, count: u64) -> Result<(), i32> {
    if (count as i64) < 0 {
        return Err(EINVAL);
    }
    if pos < 0 {
        return Err(EINVAL);
    }
    // The sum, in a type that cannot wrap. `pos` is non-negative here, so the
    // question is only whether it passes i64::MAX.
    if (pos as u64)
        .checked_add(count)
        .is_none_or(|s| s > i64::MAX as u64)
    {
        return Err(EINVAL);
    }
    Ok(())
}

/// What a `sendfile` should actually move, or the errno its count owes.
///
/// The two rules are separate and were applied in the wrong order: a count
/// above `MAX_RW_COUNT` is shortened, and a count that is *negative* as a
/// signed value is `EINVAL`. This kernel only clamped, so `sendfile(out, in,
/// NULL, ~0)` copied the whole file where Linux refuses it.
pub fn sendfile_count(count: u64) -> Result<u64, i32> {
    if (count as i64) < 0 {
        return Err(EINVAL);
    }
    Ok(count.min(MAX_RW_COUNT))
}

/// What a `splice` should actually move, or the errno its length owes.
///
/// The same two rules as [`sendfile_count`], reached by a different route:
/// `do_splice_to` asks `rw_verify_area`, whose first line is
///
/// ```c
/// if (unlikely((ssize_t) count < 0))
///     return -EINVAL;
/// ```
///
/// and the clamp is `SYSCALL_DEFINE6(splice, ..., size_t, len, ...)` meeting a
/// loop that moves a pipeful at a time. Measured rather than inherited from
/// sendfile — `copy_file_range` looks identical to both and is not, which is
/// why [`copy_file_range_len`] is a third function rather than a third caller.
///
/// **The clamp is what makes the transfer loop's 32-bit length safe.** `len`
/// arrives in a 64-bit register and the loop counts in `u32`, so
/// `splice(fd, NULL, pipe, NULL, 1 << 32, 0)` went in as `0` and came out as
/// "nothing left to read" — a caller draining a file in a loop stopped on the
/// first pass with no error. Measured against a real arm64 kernel: 10 bytes
/// there for a ten-byte file, 0 here.
pub fn splice_count(len: u64) -> Result<u64, i32> {
    sendfile_count(len)
}

/// What a `copy_file_range` should actually move.
///
/// **No refusal, unlike the two above**, and that asymmetry is measured rather
/// than reasoned: `copy_file_range(fd, NULL, out, NULL, ~0, 0)` copies a
/// ten-byte file on a real arm64 kernel where `sendfile` with the same count is
/// `EINVAL` and `splice` is `EINVAL`. There is no `rw_verify_area` on this
/// path — `generic_copy_file_checks` shortens the count to the input's size and
/// the only thing it refuses is an offset that *wraps*.
///
/// The clamp is here for the same reason it is in [`splice_count`]: the
/// transfer loop counts in `u32`, and a length of exactly 2^32 truncated to it
/// is zero, which a caller reads as end of file.
pub fn copy_file_range_len(len: u64) -> u64 {
    len.min(MAX_RW_COUNT)
}

// ----------------------------------------------------------------- iovecs

/// Linux's `UIO_MAXIOV`: the most vectors one `readv`/`writev`/`preadv` may
/// name.
///
/// Every vectored call here flattens the guest's vectors into one allocation
/// of the guest's chosen size, so an uncapped count is an allocation the guest
/// picks — `writev(fd, v, -1)` arrived as 0xffffffff vectors and asked for 68
/// gigabytes.
pub const UIO_MAXIOV: u32 = 1024;

/// One vector's length, accumulated into `total`. Returns the length to
/// actually use, which may be **shorter than asked for**.
///
/// This is not the rule [`msghdr::iov_entry`](../msghdr) applies, and the
/// difference is the reason both exist. `sendmsg` hands the protocol the
/// user's pages, so a huge length simply faults; `readv` goes through
/// `rw_verify_area`, which *clamps*:
///
/// ```c
/// for (seg = 0; seg < nr_segs; seg++) {
///     ssize_t len = (ssize_t)iov[seg].iov_len;
///     if (len < 0) { ret = -EINVAL; goto uaccess_end; }
///     if (len > MAX_RW_COUNT - total_len) {
///         len = MAX_RW_COUNT - total_len;
///         iov[seg].iov_len = len;
///     }
///     total_len += len;
/// }
/// ```
///
/// Measured, both: `writev` of two vectors summing past `INT_MAX` writes
/// something on a real kernel and was `EINVAL` here, and a single vector of
/// `INT_MAX` is `EFAULT` there — the clamp leaves it at `INT_MAX`, and then
/// the copy from a buffer that is not that big fails.
///
/// So the errno for an over-large length comes from the *copy*, not from here,
/// and the only thing refused outright is a length that is negative as a
/// signed value.
pub fn iov_entry(len: u64, total: &mut u64) -> Result<u64, i32> {
    if (len as i64) < 0 {
        return Err(EINVAL);
    }
    let room = MAX_RW_COUNT - *total;
    let used = len.min(room);
    *total += used;
    Ok(used)
}

// -------------------------------------------------------------- RWF flags

pub const RWF_HIPRI: u32 = 0x01;
pub const RWF_DSYNC: u32 = 0x02;
pub const RWF_SYNC: u32 = 0x04;
pub const RWF_NOWAIT: u32 = 0x08;
pub const RWF_APPEND: u32 = 0x10;
/// Added in 6.9, and the container has it: `preadv2(flags = 0x20)` succeeds
/// there and was `EOPNOTSUPP` here.
pub const RWF_NOAPPEND: u32 = 0x20;
/// 6.11. A write that is all-or-nothing on power loss, for a file opened
/// `O_DIRECT` on a filesystem and device that can do it.
pub const RWF_ATOMIC: u32 = 0x40;
/// 6.14. Drop the page cache behind the transfer, on a filesystem that says
/// it can (`FOP_DONTCACHE`).
pub const RWF_DONTCACHE: u32 = 0x80;
/// 6.18. A write to a pipe or socket with no reader answers `EPIPE` without
/// raising `SIGPIPE`, as `MSG_NOSIGNAL` does for a send.
pub const RWF_NOSIGNAL: u32 = 0x100;

/// Linux's `RWF_SUPPORTED`. Anything outside it is `EOPNOTSUPP`.
///
/// Lacked the last three until 2026-11-11: `RWF_NOSIGNAL` was `EOPNOTSUPP`
/// here, which made a pipe write that asked not to be signalled fail outright
/// (`rwf_probe`). `crates/kernel/aio` cleared it before asking.
pub const RWF_SUPPORTED: u32 = RWF_HIPRI
    | RWF_DSYNC
    | RWF_SYNC
    | RWF_NOWAIT
    | RWF_APPEND
    | RWF_NOAPPEND
    | RWF_ATOMIC
    | RWF_DONTCACHE
    | RWF_NOSIGNAL;

/// Where a write goes, as the flags word decides it.
///
/// Linux starts the call's `IOCB_APPEND` from the description's `O_APPEND`;
/// `RWF_APPEND` sets it and `RWF_NOAPPEND` clears it, for this call only.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Append {
    /// Whatever the description's `O_APPEND` says.
    #[default]
    AsOpened,
    /// At the end of the file, whatever offset was passed.
    Always,
    /// At the offset, even on an `O_APPEND` description.
    Never,
}

impl Append {
    /// Whether this write goes at the end of a file opened with `o_append`.
    pub fn at_end(self, o_append: bool) -> bool {
        match self {
            Append::AsOpened => o_append,
            Append::Always => true,
            Append::Never => false,
        }
    }
}

/// What a `preadv2`/`pwritev2` flags word asks for.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct RwFlags {
    /// Where a write goes. Only meaningful for a write; `kiocb_set_rw_flags`
    /// sets `IOCB_APPEND` and the write path is what reads it, so a *read*
    /// with either flag simply ignores it. Also ignored for a descriptor with
    /// no end to append at: a pipe takes `RWF_APPEND` and writes.
    pub append: Append,
    /// Do not sleep. Answered here by asking whether the descriptor is
    /// readable; Linux answers `EOPNOTSUPP` for a filesystem without
    /// `FMODE_NOWAIT`, which is a property of the mount rather than a rule.
    pub nowait: bool,
    /// Answer `EPIPE` without `SIGPIPE`. Ignored on a read, as Linux ignores
    /// it there.
    pub nosignal: bool,
}

/// Decodes the flags word for a read or a write. `Err` is the errno.
///
/// The direction matters for exactly one thing, and it is the thing this
/// kernel got wrong in both directions at once. On a **read**, `RWF_DSYNC`,
/// `RWF_SYNC`, `RWF_APPEND` and `RWF_NOAPPEND` are accepted and do nothing —
/// they describe durability and placement, which a read has neither of — and
/// this answered `EOPNOTSUPP` for all four. On a **write**, `RWF_APPEND` with
/// an explicit offset means *ignore the offset*, and this refused it rather
/// than doing it. Measured: `pwritev2(fd, iov, 1, 0, 0, RWF_APPEND)` writes at
/// the end and leaves a ten-byte file thirteen bytes long.
///
/// The rest is `kiocb_set_rw_flags`, in its order, measured by `rwf_probe` on a
/// file, a pipe and a socket alike:
///
/// - `RWF_APPEND | RWF_NOAPPEND` is `EINVAL`, in either direction. This
///   accepted it and let `RWF_NOAPPEND` win.
/// - `RWF_ATOMIC` is `EOPNOTSUPP`: on a read always, and on a write unless
///   the description has `FMODE_CAN_ATOMIC_WRITE`, which only `O_DIRECT` on a
///   block filesystem gets and nothing here is.
/// - `RWF_DONTCACHE` is `EOPNOTSUPP` without `FOP_DONTCACHE`, which pipes,
///   sockets, tmpfs and overlayfs lack, and so does every filesystem here:
///   there is no page cache of this kernel's own to drop.
pub fn rw_flags(flags: u32, writing: bool) -> Result<RwFlags, i32> {
    if flags & !RWF_SUPPORTED != 0 {
        return Err(EOPNOTSUPP);
    }
    if flags & RWF_APPEND != 0 && flags & RWF_NOAPPEND != 0 {
        return Err(EINVAL);
    }
    if flags & (RWF_ATOMIC | RWF_DONTCACHE) != 0 {
        return Err(EOPNOTSUPP);
    }
    let append = match (writing, flags & RWF_APPEND != 0, flags & RWF_NOAPPEND != 0) {
        (false, _, _) | (true, false, false) => Append::AsOpened,
        (true, true, _) => Append::Always,
        (true, false, true) => Append::Never,
    };
    Ok(RwFlags {
        append,
        nowait: (flags & RWF_NOWAIT) != 0,
        nosignal: writing && (flags & RWF_NOSIGNAL) != 0,
    })
}

// -------------------------------------------------------- copy_file_range

/// What `copy_file_range` refuses before it copies anything.
///
/// `same_file` is whether the two descriptors name the same inode, which only
/// the caller can answer. The rest is arithmetic.
///
/// Two of these three had no check at all, and the overlap one can destroy
/// data: copying a range of a file onto an overlapping range of itself reads
/// bytes the same call has already overwritten, so the result is neither the
/// old contents nor the new. Linux refuses it for that reason, and this kernel
/// went ahead — measured, `copy_file_range(fd, &0, fd, &2, 4)` returns `EINVAL`
/// on a real kernel and copied here.
pub fn copy_file_range_checks(
    pos_in: i64,
    pos_out: i64,
    len: u64,
    same_file: bool,
) -> Result<(), i32> {
    // Measured. `generic_copy_file_checks` reads as though a negative offset
    // should be EINVAL, and a real arm64 kernel answers EOVERFLOW; the
    // measurement is what this follows.
    if pos_in < 0 || pos_out < 0 {
        return Err(EOVERFLOW);
    }
    if (pos_in as u64)
        .checked_add(len)
        .is_none_or(|s| s > i64::MAX as u64)
        || (pos_out as u64)
            .checked_add(len)
            .is_none_or(|s| s > i64::MAX as u64)
    {
        return Err(EOVERFLOW);
    }
    if same_file {
        // Half-open ranges. Touching at an endpoint is not an overlap:
        // `[0,4)` and `[4,8)` are two disjoint halves and Linux allows them.
        let a_end = pos_in as u64 + len;
        let b_end = pos_out as u64 + len;
        if (pos_in as u64) < b_end && (pos_out as u64) < a_end {
            return Err(EINVAL);
        }
    }
    Ok(())
}

// ------------------------------------------------------------------ the ABI

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------- offset and count

    #[test]
    fn an_ordinary_range_is_fine() {
        assert_eq!(verify_area(0, 0), Ok(()));
        assert_eq!(verify_area(0, 4096), Ok(()));
        assert_eq!(verify_area(1 << 40, 4096), Ok(()));
    }

    #[test]
    fn a_negative_offset_is_refused() {
        assert_eq!(verify_area(-1, 4), Err(EINVAL));
        assert_eq!(verify_area(i64::MIN, 4), Err(EINVAL));
    }

    #[test]
    fn an_offset_that_the_count_pushes_past_the_end_is_refused() {
        // Measured: EINVAL on a real arm64 kernel, and 0 here -- an
        // end-of-file answer for a range that cannot exist.
        assert_eq!(verify_area(i64::MAX, 4), Err(EINVAL));
        assert_eq!(verify_area(i64::MAX - 3, 4), Err(EINVAL));
        assert_eq!(
            verify_area(i64::MAX - 4, 4),
            Ok(()),
            "exactly reaching the end"
        );
    }

    #[test]
    fn a_count_that_is_negative_as_a_signed_value_is_refused() {
        assert_eq!(verify_area(0, u64::MAX), Err(EINVAL));
        assert_eq!(verify_area(0, 1 << 63), Err(EINVAL));
    }

    // -------------------------------------------------------- sendfile

    #[test]
    fn sendfile_shortens_a_large_count_and_refuses_a_negative_one() {
        assert_eq!(sendfile_count(0), Ok(0));
        assert_eq!(sendfile_count(10), Ok(10));
        assert_eq!(sendfile_count(MAX_RW_COUNT), Ok(MAX_RW_COUNT));
        assert_eq!(sendfile_count(MAX_RW_COUNT + 1), Ok(MAX_RW_COUNT));
        // The one this kernel clamped instead of refusing: it copied the whole
        // file where Linux answers EINVAL.
        assert_eq!(sendfile_count(u64::MAX), Err(EINVAL));
        assert_eq!(sendfile_count(1 << 63), Err(EINVAL));
    }

    // ------------------------------------------- splice and copy_file_range

    /// The value that made these two worth a function: 2^32 is zero in the low
    /// half, and the transfer loop counts in `u32`. Both used to reach it
    /// unclamped, so a guest asking to move four gigabytes was told it had
    /// moved nothing — which is end of file, not a short transfer.
    #[test]
    fn a_length_of_exactly_two_to_the_thirty_second_is_not_zero() {
        assert_eq!(splice_count(1 << 32), Ok(MAX_RW_COUNT));
        assert_eq!(copy_file_range_len(1 << 32), MAX_RW_COUNT);
        assert_ne!(copy_file_range_len(1 << 32), 0);
        // And every clamped answer fits the loop's `u32`, which is what makes
        // the cast at the call site lossless rather than merely large enough
        // today. `MAX_RW_COUNT` is INT_MAX rounded down to a page, so this also
        // says the loop's running total cannot overflow a signed 32-bit count.
        assert!(u32::try_from(MAX_RW_COUNT).is_ok());
        assert!(MAX_RW_COUNT <= i32::MAX as u64);
    }

    #[test]
    fn splice_refuses_a_negative_length_and_copy_file_range_does_not() {
        // Measured on a real arm64 kernel, and they disagree: splice reaches
        // `rw_verify_area` and copy_file_range has no such check. The pair is
        // the point -- writing one rule for both would be wrong either way
        // round.
        assert_eq!(splice_count(u64::MAX), Err(EINVAL));
        assert_eq!(splice_count(1 << 63), Err(EINVAL));
        assert_eq!(copy_file_range_len(u64::MAX), MAX_RW_COUNT);
        assert_eq!(copy_file_range_len(1 << 63), MAX_RW_COUNT);
    }

    #[test]
    fn an_ordinary_transfer_length_is_left_alone() {
        assert_eq!(splice_count(0), Ok(0));
        assert_eq!(splice_count(4096), Ok(4096));
        assert_eq!(copy_file_range_len(0), 0);
        assert_eq!(copy_file_range_len(4096), 4096);
    }

    // ---------------------------------------------------------- iovecs

    #[test]
    fn an_ordinary_vector_is_used_whole() {
        let mut total = 0;
        assert_eq!(iov_entry(0, &mut total), Ok(0));
        assert_eq!(iov_entry(4096, &mut total), Ok(4096));
        assert_eq!(total, 4096);
    }

    #[test]
    fn a_negative_vector_length_is_refused() {
        // The one thing that *is* an error. Measured: writev with iov_len =
        // ~0 or 0x8000_0000_0000_0000 is EINVAL on a real kernel, and so it
        // was here -- this is the case that was already right.
        let mut total = 0;
        assert_eq!(iov_entry(u64::MAX, &mut total), Err(EINVAL));
        assert_eq!(iov_entry(1 << 63, &mut total), Err(EINVAL));
        assert_eq!(total, 0, "nothing accumulates from a refused entry");
    }

    #[test]
    fn an_over_large_vector_is_shortened_not_refused() {
        // This kernel answered EINVAL, and Linux clamps and then lets the copy
        // fail -- which is EFAULT, because a buffer that large is not mapped.
        // Getting the errno right means not deciding it here.
        let mut total = 0;
        assert_eq!(iov_entry(u64::MAX / 2, &mut total), Ok(MAX_RW_COUNT));
        assert_eq!(total, MAX_RW_COUNT);
    }

    #[test]
    fn the_total_is_what_is_clamped() {
        let mut total = 0;
        let half = MAX_RW_COUNT / 2;
        assert_eq!(iov_entry(half, &mut total), Ok(half));
        assert_eq!(iov_entry(half, &mut total), Ok(half));
        // The cap is a multiple of the page size and half of it twice is the
        // whole of it, so the next vector gets nothing rather than one byte.
        assert_eq!(iov_entry(4096, &mut total), Ok(0));
        assert_eq!(total, MAX_RW_COUNT);
    }

    #[test]
    fn a_full_array_of_huge_vectors_does_not_overflow_the_sum() {
        // 1024 vectors of four gigabytes each: the shape that made writev ask
        // for 68 gigabytes of host memory in one syscall.
        let mut total = 0;
        for _ in 0..UIO_MAXIOV {
            assert!(iov_entry(0x1_0000_0000, &mut total).is_ok());
        }
        assert_eq!(total, MAX_RW_COUNT, "clamped at the cap, not wrapped");
    }

    // ------------------------------------------------------- RWF flags

    #[test]
    fn a_flag_outside_the_supported_set_is_eopnotsupp() {
        assert_eq!(rw_flags(0x200, false), Err(EOPNOTSUPP));
        assert_eq!(rw_flags(0x8000_0000, false), Err(EOPNOTSUPP));
        assert_eq!(rw_flags(u32::MAX, true), Err(EOPNOTSUPP));
    }

    #[test]
    fn durability_flags_are_accepted_and_do_nothing() {
        // All four were EOPNOTSUPP here and all four are accepted by a real
        // kernel -- measured on a read, where none of them can mean anything.
        for f in [RWF_HIPRI, RWF_DSYNC, RWF_SYNC, RWF_NOAPPEND, RWF_APPEND, RWF_NOSIGNAL] {
            assert_eq!(rw_flags(f, false), Ok(RwFlags::default()), "flag {f:#x}");
        }
        for f in [RWF_HIPRI, RWF_DSYNC, RWF_SYNC] {
            assert_eq!(rw_flags(f, true), Ok(RwFlags::default()), "flag {f:#x}");
        }
    }

    #[test]
    fn append_and_noappend_decide_where_a_write_goes() {
        assert_eq!(rw_flags(RWF_APPEND, true).unwrap().append, Append::Always);
        assert_eq!(rw_flags(RWF_NOAPPEND, true).unwrap().append, Append::Never);
        assert_eq!(rw_flags(0, true).unwrap().append, Append::AsOpened);
        assert!(Append::AsOpened.at_end(true));
        assert!(!Append::AsOpened.at_end(false));
        assert!(Append::Always.at_end(false));
        assert!(!Append::Never.at_end(true));
    }

    /// `rwf_probe`: EINVAL on a file, a pipe and a socket, read or write. This
    /// accepted the pair and let `RWF_NOAPPEND` win.
    #[test]
    fn append_and_noappend_together_are_einval() {
        assert_eq!(rw_flags(RWF_APPEND | RWF_NOAPPEND, true), Err(EINVAL));
        assert_eq!(rw_flags(RWF_APPEND | RWF_NOAPPEND, false), Err(EINVAL));
        // An unknown bit is looked at first.
        assert_eq!(rw_flags(RWF_APPEND | RWF_NOAPPEND | 0x200, true), Err(EOPNOTSUPP));
    }

    /// `rwf_probe`: neither has a file here that can honour it.
    #[test]
    fn atomic_and_dontcache_are_known_and_refused() {
        for f in [RWF_ATOMIC, RWF_DONTCACHE] {
            assert_eq!(rw_flags(f, false), Err(EOPNOTSUPP), "flag {f:#x}");
            assert_eq!(rw_flags(f, true), Err(EOPNOTSUPP), "flag {f:#x}");
        }
    }

    /// `RWF_NOSIGNAL` was outside the set and so `EOPNOTSUPP`; it is accepted
    /// both ways and means something only on a write.
    #[test]
    fn nosignal_is_a_write_flag() {
        assert!(rw_flags(RWF_NOSIGNAL, true).unwrap().nosignal);
        assert!(!rw_flags(RWF_NOSIGNAL, false).unwrap().nosignal);
    }

    #[test]
    fn nowait_survives_in_both_directions() {
        assert!(rw_flags(RWF_NOWAIT, false).unwrap().nowait);
        assert!(rw_flags(RWF_NOWAIT, true).unwrap().nowait);
    }

    // -------------------------------------------------- copy_file_range

    #[test]
    fn different_files_have_no_overlap_to_check() {
        assert_eq!(copy_file_range_checks(0, 0, 4, false), Ok(()));
        assert_eq!(copy_file_range_checks(0, 2, 4, false), Ok(()));
    }

    #[test]
    fn one_file_copied_onto_an_overlapping_part_of_itself_is_refused() {
        // The one that can destroy data: the read sees bytes the same call has
        // already written. Measured EINVAL; this kernel copied.
        assert_eq!(copy_file_range_checks(0, 2, 4, true), Err(EINVAL));
        assert_eq!(copy_file_range_checks(2, 0, 4, true), Err(EINVAL));
        assert_eq!(copy_file_range_checks(0, 0, 4, true), Err(EINVAL));
    }

    #[test]
    fn ranges_that_only_touch_are_not_an_overlap() {
        assert_eq!(copy_file_range_checks(0, 4, 4, true), Ok(()));
        assert_eq!(copy_file_range_checks(4, 0, 4, true), Ok(()));
        // ...and a zero-length copy overlaps nothing, even at the same place.
        assert_eq!(copy_file_range_checks(8, 8, 0, true), Ok(()));
    }

    #[test]
    fn a_negative_offset_is_eoverflow_here() {
        // Not EINVAL: measured on a real arm64 kernel, which is the whole
        // reason this rule is not shared with verify_area above.
        assert_eq!(copy_file_range_checks(-1, 0, 4, false), Err(EOVERFLOW));
        assert_eq!(copy_file_range_checks(0, -1, 4, false), Err(EOVERFLOW));
    }

    #[test]
    fn an_offset_and_length_that_pass_the_end_are_eoverflow() {
        assert_eq!(
            copy_file_range_checks(i64::MAX, 0, 4, false),
            Err(EOVERFLOW)
        );
        assert_eq!(
            copy_file_range_checks(0, i64::MAX, 4, false),
            Err(EOVERFLOW)
        );
    }
}
