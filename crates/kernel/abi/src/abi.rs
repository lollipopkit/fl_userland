//! The C ABI types and declarations this crate owns.
//!
//! Bindgen generated this until 2026-09-08. It is source now, for the reason
//! `src/task.rs` states: **a definition nothing in C reads is not a C
//! definition; it is a Rust one written in C**, and every crate that imported
//! it paid a bindgen run for the privilege.
//!
//! What that promotion is allowed to change is nothing. The layouts are
//! asserted below exactly as bindgen asserted them, `cpu-offsets.h` comes out
//! byte-identical, and the eight instruction probes do not move.
//!
//! Two things it did change, both of which remove code rather than add it:
//!
//! - **`__IncompleteArrayField<T>` is `[T; 0]`.** Same size, same alignment,
//!   same `as_ptr()`, and it drops a helper with two `unsafe fn` that
//!   `clippy::missing_safety_doc` reported on every build. One field uses it:
//!   `fiber_block::code`, a flexible array member.
//! - **The layout tests are `assert!` rather than an index trick.** Bindgen
//!   writes `["Size of mmu"][size_of::<mmu>() - 32usize];`, which fails with an
//!   out-of-bounds message; `assert!(size_of::<mmu>() == 32, "Size of mmu")`
//!   fails saying which field.

#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

// The four this crate wrote by hand, which the definitions below point at.
// They were `blocklist_type` entries in the generator for the same reason.
use emu_abi::*;

/// The host's pthread objects, `struct timespec`, `ino_t` and `off_t`.
///
/// bindgen rendered all of these a second time, because `lock_t` and `cond_t`
/// embed a `pthread_mutex_t` and a `pthread_cond_t` and the closure from there
/// is wide: 137 lines, including `_opaque_pthread_t`'s 8176-byte body and
/// layout assertions for four structs no line in this tree reads a field of.
///
/// **A second rendering of a type is the defect shape** — two structs the
/// compiler cannot tell apart meeting through a conversion that checks
/// nothing, which `clippy::useless_transmute` found eight of on 2026-09-06.
/// `crates/util/waitfor` had a test asserting bindgen's `pthread_mutex_t` was
/// the same size as `libc`'s, which is what a second rendering costs: a test
/// to check the copy still matches. Naming `libc`'s is the same bytes and
/// there is nothing left to check.
///
/// The **guest's** `struct timespec` is `timespec_`, with the underscore, and
/// is this crate's own. This one is the machine's, and `struct fd` holds it
/// because a host file's timestamps come back in it.
pub use libc::{
    ino_t, off_t, pthread_cond_t, pthread_mutex_t, pthread_t, timespec,
};
pub type pid_t_ = sdword_t;
pub type uid_t_ = dword_t;
pub type mode_t_ = word_t;
pub type off_t_ = sqword_t;
pub type time_t_ = sqword_t;
pub type atomic_int = std::ffi::c_int;
pub type atomic_uint = std::ffi::c_uint;
/* `lock_t`, `lock_t_lock_debug`, `cond_t` and `wrlock_t` were here until
 * 2026-09-09. They are `util/sync.h`'s types, not the kernel's, and keeping
 * them in this crate is what made `crates/util/locks`, `crates/util/waitfor`
 * and `crates/util/guestlock` -- all layer 0 -- depend on a `kernel` crate,
 * which is why `tools/crate-layers.py` exempts this one everywhere.
 *
 * They are `crates/util/synctypes` now and re-exported below, so every
 * consumer still writes `taskview::ffi::lock_t` and `struct task` still
 * embeds three of them. */
#[cfg(iul_lock_debug)]
pub use util_synctypes::lock_t_lock_debug;
pub use util_synctypes::{cond_t, lock_t, wrlock_t};

pub type pollset_callback_t = Option<
    unsafe extern "C" fn(
        context: *mut std::ffi::c_void,
        types: std::ffi::c_int,
        info: u64,
    ) -> std::ffi::c_int,
>;
// `adhoc_kind` and its three constants were here until 2026-09-15 -- a
// `c_uint` with `ADHOC_ANON = 0`, `ADHOC_PIPE = 1`, `ADHOC_SOCKET = 2`, which
// four `match`es read with a `_ =>` arm each. It is `fs_adhoc::Kind` now, an
// enum with the per-kind facts on it, and nothing outside that crate names the
// integers. No header ever did: `iul.h` does not mention it.
/// What the machine's CPUs have been doing, in **ticks of 10ms**.
///
/// `/proc/stat`'s unit, which Linux fixes at `USER_HZ = 100` whatever the
/// kernel's own `HZ` is. `platform/platform.h` said "for some reason a tick is
/// always 10ms" and was deleted on 2026-09-08; `crates/kernel/hoststats` is
/// what fills this, from Mach on Apple and `/proc/stat` elsewhere.
pub type __uint128_t = u128;

#[cfg(test)]
mod tests {
    use crate::constants::*;

    /// Every aggregate here is `#[repr(C)]`.
    ///
    /// This file is 2300 lines that used to be generated, and the promotion
    /// was done by script and then edited by hand — which dropped exactly one
    /// `#[repr(C)]`, from `struct list`. **Nothing else would have said so:**
    /// `list` is two pointers, so Rust's own layout gives it the same size,
    /// the same alignment and the same two offsets, and every assertion beside
    /// it still passed. A struct whose fields differ in type is where it
    /// starts to matter, and by then the reordering is silent in a way a
    /// caller finds at runtime.
    ///
    /// Reading the source is the only way to ask: `size_of` and `offset_of`
    /// answer about the layout Rust chose, not about whether anything pinned
    /// it.
    ///
    /// The guest's `st_mode` bits are **Linux's**, written as literals.
    ///
    /// They came from the host's `sys/stat.h` until 2026-09-08 -- bindgen
    /// followed the include chain and the old shared constant list said `S_I.*`
    /// -- and nothing
    /// compared them with anything. They are right today because Darwin and
    /// Linux use the same historical Unix numbers, which is a coincidence a
    /// test should not rely on: `tools/bindgen-shadowed.py` existed for exactly
    /// this shape, a name a system header and this tree both define, and its
    /// subject went with the last bindgen run over our headers.
    ///
    /// From `include/uapi/linux/stat.h`. Repeating the definition would prove
    /// nothing, so these are the numbers and not the names.
    #[test]
    fn the_mode_bits_are_linuxs() {
        assert_eq!(S_IFMT, 0o170000);
        assert_eq!(S_IFIFO, 0o010000);
        assert_eq!(S_IFCHR, 0o020000);
        assert_eq!(S_IFDIR, 0o040000);
        assert_eq!(S_IFBLK, 0o060000);
        assert_eq!(S_IFREG, 0o100000);
        assert_eq!(S_IFLNK, 0o120000);
        assert_eq!(S_IFSOCK, 0o140000);
        // Every type is inside the mask and no two share a value.
        let types = [
            S_IFIFO, S_IFCHR, S_IFDIR, S_IFBLK, S_IFREG, S_IFLNK, S_IFSOCK,
        ];
        for (i, a) in types.iter().enumerate() {
            assert_eq!(a & S_IFMT, *a, "{a:o} is outside S_IFMT");
            for b in &types[i + 1..] {
                assert_ne!(a, b, "two file types share {a:o}");
            }
        }
        // 0160000 is Darwin's whiteout and Linux has no type there, so a guest
        // mode can never hold it. This is what says it did not come back.
        assert!(!types.contains(&0o160000));

        assert_eq!((S_ISUID, S_ISGID, S_ISVTX), (0o4000, 0o2000, 0o1000));
        assert_eq!(
            (S_IRWXU, S_IRUSR, S_IWUSR, S_IXUSR),
            (0o700, 0o400, 0o200, 0o100)
        );
        assert_eq!(
            (S_IRWXG, S_IRGRP, S_IWGRP, S_IXGRP),
            (0o070, 0o040, 0o020, 0o010)
        );
        assert_eq!(
            (S_IRWXO, S_IROTH, S_IWOTH, S_IXOTH),
            (0o007, 0o004, 0o002, 0o001)
        );
        // The three permission triples and the three special bits together are
        // everything S_IFMT does not cover.
        assert_eq!(
            S_IRWXU | S_IRWXG | S_IRWXO | S_ISUID | S_ISGID | S_ISVTX,
            !S_IFMT & 0o7777
        );
    }

    /// The files this check reads. `src/abi.rs` is not the whole of what this
    /// crate hands out any more: filesystem, I/O, inode, memory, network,
    /// register, signal, stat, system, time and tty layouts, plus
    /// `crates/util/synctypes` and `crates/emu/abi`, are re-exported, and their
    /// layouts are contracts in exactly the same way — `cpu_state`'s with the
    /// gadgets, `lock_t`'s with a `-DLOCK_DEBUG=1` build.
    const SOURCES: [&str; 17] = [
        include_str!("tty_types.rs"),
        include_str!("filesystem_types.rs"),
        // Here since 2026-09-11 because `FsHandle` is what `iul.h`'s four
        // `extern const struct fs_ops` are, so it does cross to C and this is
        // exactly the file the check should be looking at.
        include_str!("fs_ops.rs"),
        include_str!("inode_types.rs"),
        include_str!("io_types.rs"),
        include_str!("memory_types.rs"),
        include_str!("network_types.rs"),
        include_str!("register_types.rs"),
        include_str!("../../siginfo/src/lib.rs"),
        include_str!("abi.rs"),
        include_str!("stat_types.rs"),
        include_str!("system_types.rs"),
        include_str!("time_types.rs"),
        include_str!("../../../util/synctypes/src/lib.rs"),
        include_str!("../../../emu/abi/src/lib.rs"),
        include_str!("../../../emu/abi/src/types.rs"),
        include_str!("../../../emu/abi/src/cpustate.rs"),
    ];

    /// 59 on 2026-09-30, across the fourteen sources. A floor rather than an equality,
    /// so adding a type does not fail the build for a number.
    ///
    /// **It fell from 71 on 2026-09-11 and the floor was lowered with it**,
    /// which is worth stating because lowering a floor is how a gate stops
    /// meaning anything. The two that went are `sighand` and `sigqueue_state`,
    /// field-less placeholders standing in for `kernel_sighand::SigHand` and
    /// `kernel_sigqueue::Signals`; a placeholder has no layout for two crates
    /// to disagree about, so it was never the subject of this test. The
    /// object-model series will take `ptrace_state` and the four `tgroup`
    /// handles the same way and the number will keep falling. What the floor is
    /// for is the *vacuous* case — a rename of the `pub struct ` prefix leaving
    /// the loop iterating over nothing — and 60 is as far below the real types
    /// as that argument needs.
    ///
    /// **And to 50 on 2026-09-30**, when `winsize_` and `termios_` became
    /// re-exports of `fs_tty::tty::Winsize` and `ldisc::Termios`: the same
    /// layouts, each checked where it is owned, so the count here fell to 59
    /// without a layout leaving the tree. A floor that a merge of two
    /// renderings breaks is one that stands in the way of the fix this crate
    /// most often needs.
    const EXPECTED: usize = 50;

    /// Types that deliberately have no `#[repr(C)]`, and why.
    ///
    /// The criterion is **not** "does a C compiler read it" but "does anything
    /// depend on its layout", and the guest, the assembly and the embedder are
    /// three answers the first question does not see. A name goes here only
    /// after all four have been checked.
    const NOT_REPR_C: &[(&str, &str)] = &[
        (
            "Reservation",
            "A value in `mem`'s `Vec`, and nothing else: it was the \
             `malloc`ed node of an intrusive list, `mem_reservation`, until \
             2026-09-29, and its layout was asserted because a `next` pointer \
             threaded through it. No C, assembly or guest reads one.",
        ),
        (
            "statfsbuf",
            "The **internal** shape of a `statfs` answer. What the guest sees \
             is `statfs_arm64_`, which `crates/kernel/fdattr`'s `write_statfs` \
             builds field by field and writes with one `GuestMem::write` -- so \
             this struct's layout is a contract with nobody. It was \
             `#[repr(C)]` with a `spare: [c_long; 4]` and eleven offset \
             assertions until 2026-09-16, which is the shape a C `struct \
             statfs` had; nothing has compiled that since the headers went on \
             2026-09-09. Three of its fields are `Option` now, which is the \
             change that needed the representation gone: `None` is `the \
             filesystem did not answer`, where a zero used to mean it and a \
             filesystem that meant zero could not say so.",
        ),
        (
            "dev_ops",
            "It holds an `Option<&dyn FdOps>`, which has no C layout to \
             declare. Checked 2026-09-11 against `iul.h`, the five `.S` files, \
             `tests/integration/sbm_api_test.c` and every other non-Rust file \
             in the tree: the name appears in none of them, and the one \
             function that takes a `*mut dev_ops` -- `dyn_dev_register` -- is \
             `#[cfg(test)] pub(crate)`, so there is no embedder path either.",
        ),
        (
            "FsHandle",
            "`#[repr(transparent)]` over a `&'static dyn FsOps`, which is \
             stronger than `#[repr(C)]` here rather than weaker: it is what \
             says the exported symbol *is* the trait object. C does cross this \
             one -- `iul.h` declares four `extern const struct fs_ops` and two \
             functions taking `const struct fs_ops *` -- but `struct fs_ops` \
             is an **opaque** forward declaration in the section headed `the \
             objects, all opaque`, so an embedder can only take the address \
             and hand it back. It never reads a field, takes `sizeof` or makes \
             one, so there is no layout to agree about. What does matter is \
             that it is not zero-sized, which \
             `a_handle_is_a_distinct_address_per_filesystem` asserts.",
        ),
        (
            "inode_data",
            "Lost `#[repr(C)]` and its offset assertions on 2026-10-01, when \
             `locks`, `socket_id`, the condition and the `lock_t` became one \
             `GuestLock<InodeState>`. Checked against `iul.h`, the `.S` files \
             and `sbm_api_test.c`: none names it. `crates/fs/inode`'s \
             `#[repr(transparent)]` newtype is the only layout claim on it.",
        ),
        (
            "InodeState",
            "What `inode_data.state` guards; it holds a `Box<dyn Any>`, which \
             has no C layout. Created 2026-10-01.",
        ),
        // `XattrCall` was here until 2026-09-15, when it stopped being a
        // `pub struct` and became an enum -- which the scan above does not look
        // at, so the exemption named nothing and this test said so. What the
        // entry recorded is the measurement rather than the exemption, and it
        // is on the type now: no C crosses it.
    ];

    /// Every aggregate here carries `#[repr(C)]`, except [`NOT_REPR_C`].
    ///
    /// A layout in this crate is a contract with something outside Rust — the
    /// guest, the gadgets, or the embedder — and `#[repr(Rust)]` is free to
    /// reorder. `struct task` is the one type in the tree that gave its up
    /// deliberately, and it is not here.
    ///
    /// The `assert!` on the count is the point of the test as much as the loop
    /// is: **a filter can make an assertion vacuous**, and a rename of the item
    /// prefix would leave this iterating over nothing and reporting success.
    /// It fired for real on 2026-09-09, when the emulator's types moved out and
    /// the count fell through a threshold written for the file before the
    /// split.
    #[test]
    fn every_struct_and_union_is_repr_c() {
        let mut aggregates = 0;
        let mut exempted = 0;
        for src in SOURCES {
            let lines: Vec<&str> = src.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                if !(line.starts_with("pub struct ") || line.starts_with("pub union ")) {
                    continue;
                }
                aggregates += 1;
                let name = line
                    .trim_start_matches("pub struct ")
                    .trim_start_matches("pub union ")
                    .split([' ', '{', '<', '(', ';'])
                    .next()
                    .unwrap_or("");
                if let Some((_, why)) = NOT_REPR_C.iter().find(|(n, _)| *n == name) {
                    exempted += 1;
                    assert!(!why.is_empty());
                    continue;
                }
                // The attributes sit directly above, in any order, possibly
                // with doc comments between them and the item.
                let repr = lines[..i]
                    .iter()
                    .rev()
                    .take_while(|l| l.starts_with("#[") || l.starts_with("///"))
                    .any(|l| l.starts_with("#[repr(C"));
                assert!(repr, "{line} has no #[repr(C)]");
            }
        }
        assert!(
            aggregates >= EXPECTED,
            "only found {aggregates} aggregates to check"
        );
        // An exemption whose type no longer exists is a stale reason, and a
        // reader would take it for a live one. The same rule `crate-layers.py`
        // applies to `ALLOWED`.
        assert_eq!(
            exempted,
            NOT_REPR_C.len(),
            "an entry in NOT_REPR_C names a type this crate no longer defines"
        );
    }
}
