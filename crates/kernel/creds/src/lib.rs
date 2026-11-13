//! The rules for changing a task's user and group ids.
//!
//! `setuid`, `setreuid` and `setresuid` differ from each other in ways that are
//! easy to state and easy to get wrong, and each difference is a privilege
//! boundary. This crate is the rules and nothing else: no locks, no `current`,
//! no syscall entry. `kernel/getset.c` reads the ids off the task, calls in,
//! and writes back what comes out.
//!
//! Two defects came out of writing it down. `sys_setreuid` forwarded to
//! `setresuid(ruid, euid, -1)`, which meant
//!
//! - the saved set-user-ID was never updated, so `setreuid(n, n)` left a
//!   privileged saved id behind and `setuid(0)` took root back; and
//! - the **real** id was allowed to be set to the saved id, which
//!   `setresuid` permits and `setreuid` does not.
//!
//! The group calls are the same rules over the group triple. Privilege is
//! `CAP_SETUID` for the one and `CAP_SETGID` for the other, passed in rather
//! than derived, and the capability sets themselves live here too
//! ([`caps`]): they are what a uid change and an `execve` move.

use std::ffi::c_int;

mod access;
mod attribute;
pub mod caps;
mod crosstask;
mod exec;
mod groups;

/* `mod abi` was here until 2026-09-16: twenty-nine `pub unsafe fn` over a
 * `*const Creds` or a `*mut Creds`, each null-checking it and calling the
 * method of the same name. A "C binding" for a C that has not existed since
 * 2026-09-06 -- no `#[no_mangle]` anywhere in this crate, and no header
 * declares one, so every caller was Rust reaching a Rust type through a
 * translation.
 *
 * What it added, and why none of it survived: a null check answering `EINVAL`,
 * `EACCES` or `0` for a pointer no caller could make null (every one is
 * `&raw const (*task).creds`, the address of a field); `Result<(), c_int>`
 * flattened into an errno the caller unflattened; `bool` widened to `c_int`;
 * a `&Groups` handed back as `*const Groups`; and **two out-parameters** whose
 * stated reason -- "a struct small enough to come back in registers leaves its
 * upper half in x0" -- is about a *syscall* return crossing the guest ABI and
 * says nothing about a Rust call. The method it wrapped already answered a
 * `(u32, u32)`.
 *
 * See `docs/changelog/2026-09-16-a-c-binding-for-a-c-that-does-not-exist.md`
 * for the same layer in `crates/kernel/procattr`, removed the same day. */

pub use access::{AC_R, AC_W, AC_X, access, may_link};
use access::in_group;
pub use attribute::{
    Change, mode_after_chown, mode_after_write, setattr,
};
pub use crosstask::PtraceMode;
pub use exec::{Exec, ExecFile};

/// What the guest passes for "leave this one alone". It is `(uid_t) -1`, and
/// the guest's `uid_t` is 32 bits unsigned.
pub const UNCHANGED: u32 = u32::MAX;

/// `NGROUPS_MAX` as this kernel has it. Linux's is 65536; a smaller one is a
/// smaller `setgroups` and nothing else, and it is the array's length here.
pub const MAX_GROUPS: usize = 32;

/// The guest's, from `crates/util/errno`.
use guest_errno::c_int_::{EINVAL, EPERM};

mod types;
pub use types::{Creds, Groups, Ids, Overridden};

// ------------------------------------------------------------------ the set
//
// One object rather than nine fields, because the fields have an invariant
// between them and nine fields do not.
//
// `fsuid` and `fsgid` **follow the effective ids on every change**. That was
// three separate assignments in C -- `uid_ids_set`, `gid_ids_set` and the
// execve transition -- and forgetting one leaves a process making filesystem
// decisions with the id it had before its last `setuid`. Here it is not
// possible to forget: the only way to change the effective ids is through a
// method that carries the fs ones along.

/// `setuid(id)` / `setgid(id)`.
///
/// A privileged caller sets all three. An unprivileged one may name only its
/// real or saved id — **not** its effective one, which would be a no-op — and
/// only the effective id moves.
pub fn set_id(privileged: bool, cur: Ids, id: u32) -> Result<Ids, c_int> {
    if privileged {
        return Ok(Ids {
            real: id,
            eff: id,
            saved: id,
        });
    }
    if id != cur.real && id != cur.saved {
        return Err(EPERM);
    }
    Ok(Ids { eff: id, ..cur })
}

/// `setresuid(r, e, s)` / `setresgid(r, e, s)`.
///
/// Each `UNCHANGED` argument leaves its field alone. An unprivileged caller may
/// set each field to any id it currently holds — the permissive case, and the
/// reason `setreuid` cannot simply forward here.
pub(crate) fn set_resid(privileged: bool, cur: Ids, r: u32, e: u32, s: u32) -> Result<Ids, c_int> {
    if !privileged {
        for id in [r, e, s] {
            if id != UNCHANGED && !cur.holds(id) {
                return Err(EPERM);
            }
        }
    }
    Ok(Ids {
        real: if r == UNCHANGED { cur.real } else { r },
        eff: if e == UNCHANGED { cur.eff } else { e },
        saved: if s == UNCHANGED { cur.saved } else { s },
    })
}

/// `setreuid(r, e)` / `setregid(r, e)`.
///
/// Two things distinguish it from `set_resid`, both from Linux's
/// `__sys_setreuid`:
///
/// - the **real** id may only become the current real or effective id, where
///   `setresuid` also allows the saved one;
/// - the saved id follows the new effective id whenever the real id was set, or
///   the effective id became something other than the *previous real* id. That
///   is what makes `setreuid(n, n)` a permanent drop.
///
/// `setfsuid`/`setfsgid`: the id a filesystem check is made against.
///
/// Linux keeps it separately from the effective id and it follows that one on
/// every credential change, so a program that never asks sees them as the same
/// thing. What it is *for* is a server handling a request on someone else's
/// behalf: the file it opens is checked against the caller's id while
/// everything else it does is still its own.
///
/// **It cannot fail.** There is no error return — `__sys_setfsuid` answers the
/// *previous* value whatever happens, so a caller finds out whether the change
/// took by calling twice and comparing. A request that is not permitted changes
/// nothing and still answers the old value:
///
/// ```c
/// old_fsuid = from_kuid_munged(ns, old->fsuid);
/// if (uid_eq(kuid, old->uid)  || uid_eq(kuid, old->euid)  ||
///     uid_eq(kuid, old->suid) || uid_eq(kuid, old->fsuid) ||
///     ns_capable_setid(old->user_ns, CAP_SETUID)) {
///     new->fsuid = kuid;
/// }
/// return old_fsuid;
/// ```
///
/// Returns what the fsid becomes. The caller answers `fsid` — the value it had
/// — either way.
pub(crate) fn set_fsid(privileged: bool, cur: Ids, fsid: u32, want: u32) -> u32 {
    // `(uid_t) -1` is not a uid. Linux rejects it *before* the permission
    // check, and that ordering is observable: without it a privileged caller
    // would take the `privileged` arm below and really set its fsuid to
    // 0xffffffff, so `setfsuid(-1)` would be a way to read the value for
    // everyone except root, for whom it would destroy it.
    //
    //     kuid = make_kuid(old->user_ns, uid);
    //     if (!uid_valid(kuid))
    //         return old_fsuid;
    //
    // That is exactly the bug the first version of this had, and the guest test
    // found it on its first run.
    if want == UNCHANGED {
        return fsid;
    }
    if want == cur.real || want == cur.eff || want == cur.saved || want == fsid || privileged {
        want
    } else {
        fsid
    }
}

pub(crate) fn set_reid(privileged: bool, cur: Ids, r: u32, e: u32) -> Result<Ids, c_int> {
    if !privileged {
        if r != UNCHANGED && r != cur.real && r != cur.eff {
            return Err(EPERM);
        }
        if e != UNCHANGED && !cur.holds(e) {
            return Err(EPERM);
        }
    }
    let mut out = Ids {
        real: if r == UNCHANGED { cur.real } else { r },
        eff: if e == UNCHANGED { cur.eff } else { e },
        saved: cur.saved,
    };
    if r != UNCHANGED || (e != UNCHANGED && e != cur.real) {
        out.saved = out.eff;
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
