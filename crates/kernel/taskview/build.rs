//! No bindgen. What is left is one `cfg` and one check.
//!
//! **This crate's since 2026-09-09**, from `crates/kernel/abi`. The check is
//! about what a *consumer* gets when it writes `taskview::ffi::…`, and this is
//! the crate that assembles that: `struct task` is here, the guest wire formats
//! are `kernel-abi`'s, the mutex is `util-synctypes`', and the CPU is
//! `emu-abi`'s. Reading the ownership sources from one build script is what the check has
//! to do either way; doing it from the crate that re-exports them is what makes
//! `SOURCES` a statement rather than a list.
//!
//! `crates/kernel/taskview` generated 2706 lines from 44 headers until
//! 2026-09-08 and was the source of the shared C ABI types for the whole
//! workspace, so it was the last bindgen run that mattered: 67 other crates
//! blocklist those names and import them from here. `src/abi.rs` is that
//! output, promoted to source, and this file came with it when the types split
//! out of `taskview` on 2026-09-09.
//!
//! The check below outlived the generator because its subject did. It is about
//! what a **consumer** gets when it blocklists a name and imports it from here,
//! and that is still two different things — a real definition in `src/abi.rs`,
//! or an opaque placeholder from `src/fd.rs`'s macro. Handing out the second
//! where a header defines the first makes `size_of` answer zero in the crate
//! that allocates one; see the `tlb` case it is named for.

use std::collections::HashSet;
use std::path::Path;

/// The names every consumer may import from `taskview::ffi`.
///
/// This list belongs beside the check that validates it. It used to live in
/// A separate build-time crate held this list during the bindgen era; no crate
/// runs bindgen now, so keeping it separate only added a dependency edge
/// without adding an owner.
const SHARED_TYPE_NAMES: &[&str] = &[
    "tlb",
    "fiber_block",
    "fiber_frame",
    "inode_data",
    "asbestos",
    "tlb_entry",
    "page_t",
    "pages_t",
    "rlimit_",
    "rusage_",
    "termios_",
    "winsize_",
    "dev_t_",
    "iul_stat",
    "flock_",
    "tty_driver",
    "tty_driver_ops",
    "tty_external_write_t",
    "timeval_",
    "iovec64_",
    "timer_spec",
    "timer_id_t",
    "pollset_callback_t",
    "stat_arm64",
    "epoll_ready_event",
    "mem_usage",
    "uptime_info",
    "cpu_usage",
    "sockaddr_",
    "sockaddr_max_",
    "ucred_",
    "statfs_arm64_",
    "nsym_ctx",
    "nsym_result",
    "nsym_resume",
    "user_regs_struct_",
    "user_fpsimd_state_",
    "iovec_",
    "timespec_",
    "itimerspec_",
    "sys_info",
    "dev_ops",
    "task",
    "task_cleanup",
    "tgroup",
    "thread_attr",
    "proc_attr",
    "creds",
    "syscall_restart",
    "group_exit",
    "siginfo_",
    "uname",
    "fd",
    // `fd_ops` and `fs_ops` were here until 2026-09-11 and are traits now. The
    // list is about types whose *layout* two crates could disagree about,
    // which is what an opaque placeholder standing in for a real definition
    // would cause; a trait has no layout, so there is nothing for this check
    // to guard. `FsHandle` -- the thing `iul.h`'s four `extern const struct
    // fs_ops` are -- is not here either: it is one `#[repr(transparent)]`
    // wrapper defined once in `crates/kernel/abi`, so there is no second
    // rendering for a consumer to import the wrong one of.
    "mount",
    "dir_entry",
    "statbuf",
    "statfsbuf",
    "Attr",
    "timespec",
    "mm",
    "mem",
    "Reservation",
    "mmu",
    "cpu_state",
    "arm64_vreg",
    "lock_t",
    "cond_t",
    "wrlock_t",
    "group_stop",
    "group_rusage",
    "itimer",
    "ctty",
    // `posix_timers` and `vfork_handoff` were here until 2026-09-11 and neither
    // had a reader: `tgroup.posix_timers` names `taskview`'s own
    // `posix_timers_state` and `task.vfork` names `kernel_vforkhandoff::Handoff`
    // directly. A name in this list that no consumer imports is a contract with
    // nobody, and both were a second rendering of a type the tree already had.
    "fdtable",
    "fs_info",
    "fakedb",
    "pt_node",
    "sigqueue_state",
    "ptrace_state",
    "poll_watchers",
    "tty",
];

/// The files that between them define everything `ffi` re-exports.
/// Every file whose contents this crate hands to a consumer, **including the
/// two crates it re-exports wholesale**.
///
/// `crates/util/synctypes` and `crates/emu/abi` split out on 2026-09-09 and
/// this crate does `pub use` on both, so a name defined there is a name a
/// consumer gets from `taskview::ffi`. The check below is about what the
/// consumer sees, so it has to read them: with only the local files it panicked
/// on `wrlock_t` the minute the first split landed, which is the check working
/// and the list being wrong.
///
/// Paths from the repository root, not from `src/`, for that reason.
const SOURCES: [&str; 23] = [
    "crates/kernel/abi/src/abi.rs",
    "crates/kernel/abi/src/tty_types.rs",
    "crates/kernel/abi/src/filesystem_types.rs",
    "crates/kernel/abi/src/inode_types.rs",
    "crates/kernel/abi/src/io_types.rs",
    "crates/kernel/abi/src/memory_types.rs",
    "crates/kernel/abi/src/network_types.rs",
    "crates/kernel/abi/src/register_types.rs",
    "crates/kernel/siginfo/src/lib.rs",
    "crates/kernel/abi/src/stat_types.rs",
    "crates/kernel/abi/src/system_types.rs",
    "crates/kernel/abi/src/time_types.rs",
    // The `lib.rs` files too: a `pub use X as poll_watchers;` is a definition
    // as far as a consumer is concerned, and six of the shared names are one.
    "crates/kernel/abi/src/lib.rs",
    "crates/kernel/taskview/src/task_types.rs",
    "crates/kernel/abi/src/fd_types.rs",
    "crates/kernel/abi/src/mount_types.rs",
    "crates/kernel/taskview/src/group.rs",
    "crates/kernel/taskview/src/cleanup.rs",
    "crates/kernel/taskview/src/task.rs",
    "crates/util/synctypes/src/lib.rs",
    "crates/emu/abi/src/lib.rs",
    "crates/emu/abi/src/types.rs",
    "crates/emu/abi/src/cpustate.rs",
];

fn main() {
    let root = buildcfg::repo_root();

    // `lock_t` grows a `debug` field under `-DLOCK_DEBUG=1`, which is the one
    // thing in this tree that exercises a second layout. It was an `#if` in
    // `util/sync.h` that bindgen resolved; it is a `cfg` now, and this is where
    // the flag becomes one for the crate that owns the struct.
    buildcfg::emit_cfgs(&["LOCK_DEBUG"]);

    let mut own = String::new();
    for f in SOURCES {
        own.push('\n');
        own.push_str(
            &std::fs::read_to_string(root.join(f))
                .unwrap_or_else(|e| panic!("reading a shared type from {f}: {e}")),
        );
        println!("cargo:rerun-if-changed={}", root.join(f).display());
    }
    check_shared_types_agree(&root, &own);
}

/// A shared type must mean the same thing here as in every crate that imports it.
///
/// Two shapes are safe, for opposite reasons: a type some header *defines*,
/// where this crate writes the same layout out; and a type **no** header
/// defines, where the placeholder is the whole definition — a Rust object
/// behind an opaque pointer.
///
/// The unsafe shape is between them — a type a header defines and this crate
/// only declares as a placeholder. Blocklisting one replaces the owning crate's
/// real definition with the placeholder, and `size_of` answers zero. `tlb` was
/// in the list for one commit; the symptom was a `realloc` abort inside the
/// block cache, four frames from anything to do with tasks.
///
/// So the check is the rule: if the tree defines the struct anywhere, this
/// crate must have written a body for it.
fn check_shared_types_agree(root: &Path, sources: &str) {
    let defined = structs_defined_in_headers(root);
    let mut missing = Vec::new();
    let mut truncated = Vec::new();
    for name in SHARED_TYPE_NAMES {
        let Some(at) = sources
            .find(&format!("\npub struct {name} "))
            .or_else(|| sources.find(&format!("\npub union {name} ")))
            // A Rust `enum`, which a C tag-and-union became: `Attr`, on
            // 2026-09-29. A body like a struct's, so the same search.
            .or_else(|| sources.find(&format!("\npub enum {name} ")))
            // A `typedef` and a C `enum` are an alias, not a struct --
            // `pub type page_t = u64;`, `pub type attr_type = c_uint;`. They
            // are shareable names like any other, and the placeholder check
            // below does not apply: an alias either resolves or does not
            // compile. This search missed them until 2026-09-08, which read as
            // "not generated" for seven names it had.
            .or_else(|| sources.find(&format!("\npub type {name} =")))
            // A host type named from `libc` rather than written out: `pid_t`,
            // `pthread_t`, `timespec`. Same argument as the alias above.
            .or_else(|| {
                // Inside the braces, not merely after them: searching to the
                // end of the file would accept a `pid_t,` in any later list,
                // which is a check that cannot fail.
                let open = sources.find("pub use libc::{")? + "pub use libc::{".len();
                let close = open + sources[open..].find("};")?;
                let block = &sources[open..close];
                [format!("{name},"), name.to_string()]
                    .iter()
                    .find_map(|pat| block.find(pat.as_str()).map(|off| open + off))
            })
            // A type this crate **re-exports from another workspace crate**,
            // written `pub use util_synctypes::{cond_t, lock_t, wrlock_t};`.
            // That is a real definition in the sense this check is about: a
            // consumer that blocklists the name and imports it from here gets
            // the owning crate's type, not a zero-sized stand-in. `util/sync.h`
            // 's four moved out on 2026-09-09 so that the layer-0 crates
            // needing a mutex would stop naming a `kernel` one.
            .or_else(|| {
                sources.lines().find_map(|line| {
                    let line = line.trim();
                    if !line.starts_with("pub use ") || line.contains("libc::") {
                        return None;
                    }
                    let names = line
                        .trim_end_matches(';')
                        .rsplit("::")
                        .next()?
                        .trim_matches(|c| c == '{' || c == '}');
                    names
                        .split(',')
                        .any(|n| n.trim() == *name)
                        .then(|| sources.find(line))?
                })
            })
            // src/fd.rs writes the opaque handles through a macro,
            .or_else(|| sources.find(&format!("\n    {name},")))
            // and src/task.rs re-exports the objects a task holds by value
            // under their C names -- `as creds,` in a braced list, or
            // `as group_exit;` on its own.
            .or_else(|| {
                [
                    format!(" as {name};"),
                    format!(" as {name},"),
                    format!(" as {name}}};"),
                ]
                .iter()
                .find_map(|pat| sources.find(pat.as_str()))
            })
        else {
            missing.push(*name);
            continue;
        };
        // The macro in src/fd.rs spells an opaque handle as a one-line entry in
        // a braced list, so what follows the name is a comma and a newline
        // rather than a `{`.
        let placeholder = sources[at..].starts_with(&format!("\n    {name},"));
        if placeholder && defined.contains(*name) {
            truncated.push(*name);
        }
    }
    assert!(
        missing.is_empty() && truncated.is_empty(),
        "shared type names this crate does not define.\n\
         not defined at all: {missing:?}\n\
         a header defines these, and this crate only declares a placeholder: {truncated:?}\n\
         A consumer blocklists these and imports them from here, so the \
         placeholder would replace the owning crate's real definition and make \
         size_of answer zero. Either write the type out in src/abi.rs, or take \
         the name out of the shared list.",
    );
    // A gate covering nothing is worse than no gate: this one reads a name list
    // and a directory of headers, and either going empty would leave it passing
    // silently. The header count is the half that will go to zero first.
    assert!(
        SHARED_TYPE_NAMES.len() > 50 && !defined.is_empty(),
        "check_shared_types_agree checked {} names against {} structs; both \
         have to be non-empty for a clean run to mean anything",
        SHARED_TYPE_NAMES.len(),
        defined.len(),
    );
}

/// Every `struct <name> {` in the tree's own headers.
///
/// Headers only: a struct defined in a `.c` file is private to it and no crate
/// generates bindings for it. Directories that hold build output are skipped
/// because they contain copies.
fn structs_defined_in_headers(root: &Path) -> HashSet<String> {
    fn walk(dir: &Path, out: &mut HashSet<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                if !name.starts_with('.')
                    && !matches!(&*name, "target" | "node_modules")
                    && !name.starts_with("build")
                {
                    walk(&path, out);
                }
            } else if path.extension().is_some_and(|e| e == "h") {
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                for line in text.lines() {
                    let line = line.trim();
                    if let Some(rest) = line.strip_prefix("struct ")
                        && let Some(ident) = rest.strip_suffix(" {")
                        && ident.chars().all(|c| c.is_alphanumeric() || c == '_')
                    {
                        out.insert(ident.to_string());
                    }
                }
            }
        }
    }
    let mut out = HashSet::new();
    walk(root, &mut out);
    out
}
