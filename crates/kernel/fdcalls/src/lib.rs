//! The syscalls that take a descriptor **number** and nothing else: `close`,
//! `dup`, `dup2`, `dup3`, `fcntl` and `close_range`.
//!
//! The table these operate on has been `crates/fs/fdtable` since the descriptor
//! layer moved, and the record locks are `crates/fs/locks`, so what was left in
//! `fs/fd.c` around them was the argument rules — and the argument rules are
//! where every defect in this family was. Each one is written down beside the
//! check it produced.
//!
//! What stays in C is the `struct fd` object itself: its allocation, its
//! reference count, its finalizer and the two calls that join it to a task
//! (`f_get`, `f_install`). Those want `struct task` and `struct fd`'s own
//! fields, and go with them.
//!
//! # This family answers a `Result`
//!
//! The first one to, on 2026-09-11. A `sys_*` here returns
//! `Result<T, Errno>` and `crates/kernel/syscalltable`'s `at_res!` turns it
//! into the negative number the guest reads — **the only place in the tree that
//! does**, so nothing in this file can get the sign wrong or return `-EINVAL`
//! where it meant `EINVAL`.
//!
//! It is a re-labelling and not a behaviour change: `Errno::split` hands a
//! number in `[-4095, -1]` back unaltered, and every arm that used to write
//! `return EBADF;` now writes `return Err(Errno::EBADF);` with the same name.
//!
//! What it *does* change is one thing the old shape could not say.
//! `fcntl(F_GETOWN)` answers a **negative** number for a process group, and the
//! comment on `F_GETOWN` used to record that as a limitation — "an errno and a
//! result are not separable there", so an unknown command had to be `EINVAL`
//! and that arm could not report an error at all. `Ok(-1234)` and
//! `Err(Errno::EPERM)` are different values now, even though they are the same
//! 64 bits once the table has converted them.


use std::ffi::{c_int, c_uint};

use guest_errno::Errno;
use strace::strace;
use usercopy::GuestMem;

// The shared Rust types and constants are re-exported by kernel-taskview.
use taskview::ffi;

mod fcntl;
mod ioctl;
pub use fcntl::sys_fcntl;
#[cfg(test)]
use fcntl::*;
pub use ioctl::sys_ioctl;

/// What every `sys_*` in this crate answers.
///
/// `i64` rather than a per-call type because two of them carry a descriptor
/// number, one carries a flag word and one carries a process group — and the
/// dispatcher writes 64 bits to `x0` whatever the call. The syscalls whose
/// success is empty say so: `Result<(), Errno>`.
type Ret = Result<i64, Errno>;

/// The calling task's descriptor table. `kernel/task.c`.
///
/// TODO: goes with `struct task`.
fn table() -> *mut ffi::fdtable {
    taskview::current_fdtable()
}

/// Run `f` on the calling task's descriptor table; `EBADF` for a task that no
/// longer has one.
fn with_table<R>(f: impl FnOnce(&ffi::fdtable) -> Result<R, Errno>) -> Result<R, Errno> {
    taskview::with_current_fdtable(f).unwrap_or(Err(Errno::EBADF))
}

fn nofile_limit() -> u64 {
    kernel_rlimit::current_soft(ffi::RLIMIT_NOFILE_ as c_int as u32)
}

// ---------------------------------------------------------------------------
// close, dup, dup2, dup3
// ---------------------------------------------------------------------------

pub fn sys_close(f: c_int) -> Result<(), Errno> {
    strace!("close({f})");
    Errno::split(fs_fdobj::f_close(f) as i64)?;
    Ok(())
}

pub fn sys_dup(f: c_int) -> Ret {
    strace!("dup({f})");
    let Some(fd) = fs_fdobj::f_get(f) else {
        return Err(Errno::EBADF);
    };
    // `f_install` consumes a reference, and the one `f_get` took belongs to the
    // syscall's drain. This is the table's.
    let fd = fd.retain();
    Errno::split(fs_fdobj::f_install(fd, 0) as i64)
}

pub fn sys_dup3(f: c_int, new_f: c_int, flags: c_int) -> Ret {
    strace!("dup3({f}, {new_f}, {flags})");

    // Three checks, in Linux's order, and all three before the descriptor is
    // looked at -- ksys_dup3 rejects the flags and the same-number case without
    // touching the table, so dup3(bad, bad, 0) is EINVAL rather than EBADF.
    //
    // O_CLOEXEC is the only flag. Every other word used to be accepted and
    // silently ignored, so a caller asking for something this kernel does not
    // do was told it had been done.
    if flags & !(ffi::O_CLOEXEC_ as c_int) != 0 {
        return Err(Errno::EINVAL);
    }
    // The same number twice is refused outright, however good the descriptor
    // is. This is the whole difference between dup3 and dup2: musl's dup2
    // issues dup3, and on EINVAL with the two numbers equal it validates the
    // descriptor and returns the number -- which is what makes dup2(f, f) the
    // no-op it is defined to be.
    //
    // Succeeding here made it *not* a no-op. The sequence below closes what is
    // at new_f before installing over it, and closing a descriptor releases the
    // process's POSIX record locks on that file and clears its close-on-exec
    // bit. dup2(f, f) would have dropped a lock the caller still believed it
    // held, and reported success.
    if f == new_f {
        return Err(Errno::EINVAL);
    }

    let Some(fd) = fs_fdobj::f_get(f) else {
        return Err(Errno::EBADF);
    };
    // The table's own reference, taken before the install and given back by
    // the `Err` arm below if it refuses.
    let owned = fd.retain();

    let cloexec = flags & ffi::O_CLOEXEC_ as c_int != 0;
    let limit = nofile_limit() as usize;
    with_table(move |table| {
        match table.replace(owned, new_f, cloexec, limit) {
            // Released **after** the table's mutex is gone, which is why the
            // displaced reference is handed back rather than dropped inside:
            // a final release reaches the driver's `close`.
            Ok(displaced) => {
                if let Some(displaced) = displaced {
                    fs_fdobj::fd_release_owned(table, displaced);
                }
                Ok(new_f as i64)
            }
            // The table takes the reference only on success, so this is the one
            // taken above coming back rather than a second release of it.
            Err((error, given_back)) => {
                let _ = given_back.close();
                let e = Errno::split(error as i64).err().unwrap_or(Errno::EINVAL);
                // A number above the limit is EBADF here, not EMFILE: dup3
                // names the destination, so "too many open files" would be an
                // answer about a resource rather than about the argument.
                Err(if e == Errno::EMFILE { Errno::EBADF } else { e })
            }
        }
    })
}

// ---------------------------------------------------------------------------
// close_range
// ---------------------------------------------------------------------------

/// Splits a shared descriptor table before closing anything.
const CLOSE_RANGE_UNSHARE: u32 = 0x02;
/// Marks the range close-on-exec instead of closing it.
const CLOSE_RANGE_CLOEXEC: u32 = 0x04;

/// `close_range(unsigned first, unsigned last, unsigned flags)` — Linux 5.9+,
/// syscall 436. Closes every open descriptor in `[first, last]`.
///
/// Both flags are honoured. They were accepted and ignored once, which is the
/// worst of the three possible answers: a caller cannot tell a request that was
/// honoured from one that was dropped.
pub fn sys_close_range(first: u32, last: u32, flags: u32) -> Result<(), Errno> {
    strace!("close_range({first}, {last}, {flags:#x})");
    if first > last {
        return Err(Errno::EINVAL);
    }
    // Linux rejects unknown bits, which is how a caller finds out a request was
    // not honoured. Every flag word was accepted before.
    if flags & !(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC) != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & CLOSE_RANGE_UNSHARE != 0 {
        // Split the table before closing anything, which is the whole point of
        // the flag: `unshare_fd(CLONE_FILES, ...)` is what Linux does here.
        unshare_files()?;
    }
    let cloexec = flags & CLOSE_RANGE_CLOEXEC != 0;
    with_table(|table| Errno::split(table.close_range(first, last, cloexec) as i64))?;
    Ok(())
}

/// Give the calling task a descriptor table of its own if it shares one:
/// `unshare(CLONE_FILES)`, and `close_range(CLOSE_RANGE_UNSHARE)`'s first step.
/// Linux's `unshare_fd`. A table nobody else holds is left alone.
pub fn unshare_files() -> Result<(), Errno> {
    if unsafe { fdtable::is_shared(table()) } {
        // This used to answer EINVAL instead, on the grounds that ignoring the
        // flag would close descriptors out from under whoever else held the
        // table -- true, and refusing was the safe half of the answer rather
        // than the answer. It carried a TODO saying so. Measured: a real arm64
        // kernel returns 0 with a thread sharing the table, and this returned
        // EINVAL; the test that covered it asserted the EINVAL, because it had
        // been written from this implementation.
        //
        // The copy is the same one fork() makes for a child without
        // CLONE_FILES: every open file description gains a reference and the
        // old table loses this task's.
        let old = table();
        let Some(copy) = (unsafe { old.as_ref() }).and_then(fdtable::Table::copy) else {
            return Err(Errno::ENOMEM);
        };
        // The old share is answered by the publication and dropped after it, so
        // that nothing can observe the task with no table at all.
        // SAFETY: no `with_table` borrow is alive here.
        drop(unsafe { taskview::replace_current_fdtable(copy) });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `F_DUPFD`'s minimum is unsigned, so -1 is a very large number and not a
    /// small one.
    ///
    /// This is the check whose absence turned a nonsense argument into
    /// `EMFILE` — "close something and retry", which a caller that passed -1
    /// will do for ever.
    #[test]
    fn a_dupfd_minimum_is_bounded_above_and_unsigned() {
        let limit = 1024;
        assert!(dupfd_start_ok(0, limit));
        assert!(dupfd_start_ok(limit - 1, limit));
        assert!(!dupfd_start_ok(limit, limit));
        // -1 as the guest passed it: the top of the register, not a small
        // negative number.
        assert!(!dupfd_start_ok(u64::MAX, limit));
        assert!(!dupfd_start_ok(-1i32 as u32 as u64, limit));
        // A limit of zero admits nothing at all, rather than wrapping.
        assert!(!dupfd_start_ok(0, 0));
    }

    /// The command numbers, which are Linux's and are the whole interface.
    ///
    /// Written out because there is nothing to generate them from: `fs/fd.c`
    /// spelled them as `#define`s of its own and `<fcntl.h>`'s are the host's,
    /// which differ — macOS `F_GETPATH` is 50 where Linux's 50 is nothing.
    /// `tests/guest/src/bin/fcntl_abi.rs` is what checks them against a guest
    /// libc.
    #[test]
    fn the_command_numbers_are_linuxs() {
        assert_eq!(
            [F_DUPFD, F_GETFD, F_SETFD, F_GETFL, F_SETFL],
            [0, 1, 2, 3, 4]
        );
        assert_eq!([F_GETLK, F_SETLK, F_SETLKW], [5, 6, 7]);
        assert_eq!([F_GETLK64, F_SETLK64, F_SETLKW64], [12, 13, 14]);
        assert_eq!([F_OFD_GETLK, F_OFD_SETLK, F_OFD_SETLKW], [36, 37, 38]);
        assert_eq!(
            [F_DUPFD_CLOEXEC, F_SETPIPE_SZ, F_GETPIPE_SZ],
            [1030, 1031, 1032]
        );
        assert_eq!(
            [F_SETLEASE, F_GETLEASE, F_DUPFD_QUERY, F_CREATED_QUERY],
            [1024, 1025, 1027, 1028]
        );
        assert_eq!([F_GET_RW_HINT, F_SET_RW_HINT], [1035, 1036]);
        assert_eq!([F_RDLCK, F_WRLCK, F_UNLCK], [0, 1, 2]);
    }

    /// `check_fcntl_cmd`: what an O_PATH descriptor may be asked. Every other
    /// command is EBADF on one, which is how a lock, a lease or a status change
    /// is kept off a file the caller cannot read.
    #[test]
    fn an_o_path_descriptor_answers_five_commands() {
        for cmd in [F_DUPFD, F_DUPFD_CLOEXEC, F_GETFD, F_SETFD, F_GETFL] {
            assert!(allowed_on_path_only(cmd), "{cmd}");
        }
        for cmd in [
            F_SETFL,
            F_GETLK,
            F_SETLK,
            F_SETLKW,
            F_OFD_SETLK,
            F_SETLEASE,
            F_GETLEASE,
            F_GETPIPE_SZ,
            F_ADD_SEALS,
            F_GET_SEALS,
            F_DUPFD_QUERY,
            F_CREATED_QUERY,
            F_GET_RW_HINT,
            F_SET_RW_HINT,
            99,
        ] {
            assert!(!allowed_on_path_only(cmd), "{cmd}");
        }
    }

    /// `f_dupfd` takes the minimum as `unsigned int`, so F_DUPFD(1 << 40) is
    /// F_DUPFD(0) and lands on the lowest free number. Measured by fcntl_probe:
    /// a real kernel answered 10 where this answered EINVAL.
    #[test]
    fn the_dupfd_minimum_is_thirty_two_bits() {
        assert_eq!(dupfd_minimum(1 << 40), 0);
        assert_eq!(dupfd_minimum((1 << 32) | 5), 5);
        assert_eq!(dupfd_minimum(u64::MAX), u64::from(u32::MAX));
        assert!(
            !dupfd_start_ok(dupfd_minimum(u64::MAX), 1024),
            "still above the limit"
        );
        assert!(dupfd_start_ok(dupfd_minimum(1 << 40), 1024));
    }

    /// Linux's `rw_hint_valid` is the six RWH_WRITE_LIFE_* values and nothing
    /// else -- not a bitmask, not "anything small".
    #[test]
    fn the_write_hints_are_zero_to_five() {
        for hint in 0..=5 {
            assert!(rw_hint_valid(hint), "{hint}");
        }
        assert!(!rw_hint_valid(6));
        assert!(!rw_hint_valid(99));
        assert!(!rw_hint_valid(1 << 32));
    }

    /// `fcntl32` refuses exactly the three 64-bit lock commands and forwards
    /// everything else.
    ///
    /// Tested as the predicate rather than through the call, which needs a
    /// descriptor table.
    #[test]
    fn fcntl32_refuses_the_64_bit_lock_commands() {
        let refused = |cmd| matches!(cmd, F_GETLK64 | F_SETLK64 | F_SETLKW64);
        assert!(refused(F_GETLK64) && refused(F_SETLK64) && refused(F_SETLKW64));
        assert!(!refused(F_GETLK) && !refused(F_SETLK) && !refused(F_SETLKW));
        assert!(!refused(F_DUPFD) && !refused(F_OFD_SETLK));
    }

    /// A `struct flock` is what a guest hands in and reads back, so the round
    /// trip through bytes has to be the identity.
    #[test]
    fn a_flock_is_thirty_two_bytes_with_start_at_eight() {
        // The offsets fs/inode.h asserts, asserted from the other side: the
        // padding there is explicit because this is a wire format, and a
        // silent change of alignment would be a silent change of ABI.
        assert_eq!(std::mem::size_of::<ffi::flock_>(), 32);
        let f = ffi::flock_ {
            type_: 0,
            whence: 0,
            _pad0: 0,
            start: 0,
            len: 0,
            pid: 0,
            _pad1: 0,
        };
        let base = &f as *const _ as usize;
        assert_eq!(&f.start as *const _ as usize - base, 8);
        assert_eq!(&f.len as *const _ as usize - base, 16);
        assert_eq!(&f.pid as *const _ as usize - base, 24);
    }

    /// The **bytes**, not only the round trip.
    ///
    /// A round trip through one conversion and its inverse is the identity for
    /// any pair of field orders that agree with each other, so the version of
    /// this test that only checked `back.start == -4096` would have passed with
    /// `start` and `len` swapped — which is a change of guest ABI. What a wire
    /// format needs asserted is where each field lands, and that is what this
    /// does; the offsets are the ones `crates/kernel/abi` asserts on the type,
    /// checked here through the conversion the syscall path actually uses.
    #[test]
    fn a_flock_lands_in_the_bytes_a_guest_reads() {
        let flock = ffi::flock_ {
            type_: 1,
            whence: 2,
            _pad0: 0,
            start: -4096,
            len: 8192,
            pid: 1234,
            _pad1: 0,
        };
        let raw: [u8; 32] = *plain::bytes_of(&flock).first_chunk().unwrap();
        // Little-endian, which is the guest's and the host's alike.
        assert_eq!(&raw[0..2], &1u16.to_le_bytes(), "l_type at 0");
        assert_eq!(&raw[2..4], &2u16.to_le_bytes(), "l_whence at 2");
        // Signed, and negative: a lock may start before the current position.
        assert_eq!(&raw[8..16], &(-4096i64).to_le_bytes(), "l_start at 8");
        assert_eq!(&raw[16..24], &8192i64.to_le_bytes(), "l_len at 16");
        assert_eq!(&raw[24..28], &1234i32.to_le_bytes(), "l_pid at 24");

        let mut back = ffi::flock_::default();
        plain::bytes_of_mut(&mut back).copy_from_slice(&raw);
        assert_eq!(back.type_, 1);
        assert_eq!(back.whence, 2);
        assert_eq!(back.start, -4096);
        assert_eq!(back.len, 8192);
        assert_eq!(back.pid, 1234);
    }
}
