//! stat/fstat agreement over a path-translate hook and five bind mounts.
//!
//! `tests/unit/fakefs_stat_test.c` until 2026-09-08, and an **integration**
//! test rather than a `#[cfg(test)] mod` for a reason worth stating: it needs
//! the boot path and the VFS entry points, and those live in crates that
//! `cargo test --lib` would make it link a *second copy* of `fs_fake` beside --
//! once compiled with `cfg(test)` and once as an ordinary dependency. On macOS
//! `ld` warns and picks one, so a call could resolve to either, which is the
//! defect `docs/changelog/2026-09-06-a-test-double-that-replaced-the-real-function-everywhere.md`
//! records in its other form. A `tests/` binary links the plain rlib, and cargo
//! unifies it with the one its dependencies use: one copy, no choice to make.

// The product, so the gadget archive's crypto helpers and the rest of the boot
// path resolve. `_` because nothing here calls it: an `--extern` nothing
// mentions is not loaded, so the dev-dependency alone changes no link.
use iul as _;

use fs_fake::{
    fakefs, fakefs_bind_mount, fakefs_bind_unmount, fakefs_set_path_reverse_hook,
    fakefs_set_path_translate_hook,
};
use std::ffi::{CStr, c_char, c_int};
use taskview::ffi;

// ------------------------------------ stat/fstat over a hook and a bind
//
// `tests/unit/fakefs_stat_test.c` until 2026-09-08. Eleven checks over one
// booted kernel: a fakefs root, a path-translate hook, and five bind
// mounts. One `#[test]`, because they share that state and run in order --
// `become_first_process` is process-wide and cargo runs a crate's tests as
// threads.
//
// A path routed through the translate hook does not go through `meta.db` --
// that is the point of the hook -- so `fakefs_stat` answers it from a host
// `stat()` and fills the guest `statbuf` by hand. It used to fill only
// `st_ino`, leaving `dev`, `nlink` and `blksize` zero, while `fakefs_fstat`
// on the same file went through realfs and got real values for all of them.
// coreutils checks exactly this: `cp` calls `stat()` on the source and
// `fstat()` on the descriptor it opened and compares `st_dev` and `st_ino`,
// so a zero from one and a real one from the other reads as "the file was
// replaced while being copied".

use asbestos_gadgets as _;

/// Guest paths under here are routed to `HOST_DIR`. Everything else falls
/// through to the ordinary `meta.db` lookup, which is what an unhooked path
/// must keep doing.
const HOOK_PREFIX: &str = "/hooked";
const BIND_SAVED_SUFFIX: &str = ".iul-bind-saved";

/// The realpath of the hook's target and of the first bind target.
///
/// `F_GETPATH` answers with the *resolved* path, and on macOS `/tmp` is a
/// symlink to `/private/tmp` -- so the reverse hook has to be told the name
/// the kernel will hand it, not the one the tree was created under.
static HOST_DIR: std::sync::OnceLock<String> = std::sync::OnceLock::new();

unsafe extern "C" fn translate(
    guest: *const c_char,
    _fs_context: u64,
    out: *mut c_char,
    out_size: usize,
) -> bool {
    // SAFETY: the caller passes a NUL-terminated guest path and a buffer.
    let guest = unsafe { CStr::from_ptr(guest) }
        .to_string_lossy()
        .into_owned();
    let Some(rest) = guest.strip_prefix(HOOK_PREFIX) else {
        return false;
    };
    if !rest.is_empty() && !rest.starts_with('/') {
        return false;
    }
    write_c(out, out_size, &format!("{}{rest}", HOST_DIR.get().unwrap()))
}

/// The counterpart, and not optional: `fakefs_fstat`'s hook fallback asks
/// `realfs_getpath` what guest path the descriptor came from, and that
/// answer is a *host* path put back through this. Without it the descriptor
/// looks like an ordinary fakefs one with no `meta.db` row, which is an
/// error rather than a hook-routed file.
unsafe extern "C" fn reverse(host: *const c_char, out: *mut c_char, out_size: usize) -> bool {
    // SAFETY: as above.
    let host = unsafe { CStr::from_ptr(host) }
        .to_string_lossy()
        .into_owned();
    let dir = HOST_DIR.get().unwrap();
    let Some(rest) = host.strip_prefix(dir.as_str()) else {
        return false;
    };
    if !rest.is_empty() && !rest.starts_with('/') {
        return false;
    }
    write_c(out, out_size, &format!("{HOOK_PREFIX}{rest}"))
}

fn write_c(out: *mut c_char, out_size: usize, s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() + 1 > out_size {
        return false;
    }
    // SAFETY: `out` has `out_size` writable bytes and `b.len() + 1` fit.
    unsafe {
        std::ptr::copy_nonoverlapping(b.as_ptr().cast::<c_char>(), out, b.len());
        *out.add(b.len()) = 0;
    }
    true
}

fn statat(path: &str) -> (c_int, ffi::statbuf) {
    let c = std::ffi::CString::new(path).unwrap();
    let mut st = ffi::statbuf::default();
    let err = fs_generic::generic_statat(ffi::At::Pwd, &c, &mut st, true);
    (err, st)
}

fn open_flags(path: &str, flags: c_int) -> Result<fs_fdobj::Owned, c_int> {
    let c = std::ffi::CString::new(path).unwrap();
    fs_generic::generic_openat(ffi::At::Pwd, &c, flags, 0o644).map_err(|e| e.as_c_int())
}

/// 0, or the guest errno the open was refused with.
fn open_for_write(path: &str) -> c_int {
    match open_flags(path, ffi::O_RDWR_ as c_int) {
        Err(e) => e,
        Ok(fd) => {
            fd.close();
            0
        }
    }
}

fn fstat_via_fd(path: &str) -> (c_int, ffi::statbuf) {
    match open_flags(path, ffi::O_RDONLY_ as c_int) {
        Err(e) => (e, ffi::statbuf::default()),
        Ok(fd) => {
            let answer = fs_fdobj::fd_fstat(&fd);
            fd.close();
            match answer {
                Ok(st) => (0, st),
                Err(e) => (e, ffi::statbuf::default()),
            }
        }
    }
}

fn bind(guest: &str, host: &str, read_only: bool) -> c_int {
    let (g, h) = (
        std::ffi::CString::new(guest).unwrap(),
        std::ffi::CString::new(host).unwrap(),
    );
    // SAFETY: two NUL-terminated paths.
    unsafe { fakefs_bind_mount(g.as_ptr(), h.as_ptr(), read_only) }
}

fn unbind(guest: &str) -> c_int {
    let g = std::ffi::CString::new(guest).unwrap();
    // SAFETY: a NUL-terminated path.
    unsafe { fakefs_bind_unmount(g.as_ptr()) }
}

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
use guest_errno::c_int_::{ENOENT, EROFS};

#[test]
fn stat_and_fstat_agree_over_a_hook_and_a_bind_mount() {
    let base = std::env::temp_dir().join(format!("iul-fakefs-stat-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let data = base.join("data");
    std::fs::create_dir_all(&data).unwrap();

    // A fakefs by hand: `crates/tools/fakefsify` would do this from a
    // tarball, but it needs a rootfs. What is needed here is
    // a mountable empty tree -- the root and nothing else, since fakefs
    // stores "/" as the empty blob and every other path is reached through
    // the hook or a bind.
    {
        let db_path = base.join("meta.db");
        let c = std::ffi::CString::new(base.to_str().unwrap()).unwrap();
        assert_eq!(fakedb::db::create_at(&c), Ok(()));
        assert!(db_path.exists());
    }

    // The hook's target and the bind targets, outside the fakefs on
    // purpose: a host directory the guest reaches only because something
    // says so is what a bind mount is.
    let host = base.join("host");
    let bound = base.join("bound");
    // The second target holds a *directory* where the first holds a file,
    // at the same name. That is what makes a stale row visible.
    let bound2 = base.join("bound2");
    let ro = base.join("ro");
    let inner = base.join("inner");
    // Under `data/`, so the symlink's parent is a prefix of the target --
    // the case the relative-path arithmetic used to get wrong. Not the same
    // name as the mount point, or the symlink would point at itself.
    let inside = data.join("realdir");
    for d in [&host, &bound, &bound2, &ro, &inner, &inside] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::create_dir_all(bound2.join("doc.txt")).unwrap();
    std::fs::write(host.join("doc.txt"), b"hello").unwrap();
    std::fs::write(bound.join("doc.txt"), b"bound").unwrap();
    for d in [&inside, &ro, &inner] {
        std::fs::write(d.join("doc.txt"), b"").unwrap();
    }

    let real = |p: &std::path::Path| {
        std::fs::canonicalize(p)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string()
    };
    HOST_DIR.set(real(&host)).unwrap();
    let bound_real = real(&bound);

    fakefs_set_path_translate_hook(Some(translate));
    fakefs_set_path_reverse_hook(Some(reverse));

    let data_c = std::ffi::CString::new(data.to_str().unwrap()).unwrap();
    // SAFETY: `fakefs` is a static table and `data_c` a NUL-terminated path.
    assert_eq!(
        unsafe { kernel_boot::mount_root(&fakefs, data_c.as_ptr()) },
        0
    );
    assert_eq!(kernel_boot::become_first_process(), 0);

    // Registered after the root is mounted, which is when an embedder does
    // it. The read-only one is registered before the writable one nested
    // inside it, which is the order that used to make the nested one
    // read-only as well.
    assert_eq!(bind("/bound", &bound_real, false), 0);
    assert_eq!(bind("/ro", ro.to_str().unwrap(), true), 0);
    assert_eq!(bind("/ro/inner", inner.to_str().unwrap(), false), 0);
    assert_eq!(bind("/inside", inside.to_str().unwrap(), false), 0);

    // -- the pair `cp` compares. This is the whole bug.
    let doc = format!("{HOOK_PREFIX}/doc.txt");
    let (e, by_path) = statat(&doc);
    assert_eq!(e, 0);
    let (e, by_fd) = fstat_via_fd(&doc);
    assert_eq!(e, 0);
    assert_eq!(by_path.dev, by_fd.dev);
    assert_eq!(by_path.inode, by_fd.inode);
    assert_eq!(by_path.nlink, by_fd.nlink);
    assert_eq!(by_path.blksize, by_fd.blksize);

    // Agreement on two zeroes would satisfy that. These are the fields the
    // fix added, and a file that exists has none of them at zero.
    assert_ne!(by_path.dev, 0);
    assert_ne!(by_path.nlink, 0);
    assert_ne!(by_path.blksize, 0);
    assert_eq!(by_path.size, 5);

    // -- a hard link between two hook-routed paths is a host link and
    // nothing else, and a host error comes back as the guest's errno.
    let linkat = |a: &str, b: &str| {
        let (a, b) = (std::ffi::CString::new(a).unwrap(), std::ffi::CString::new(b).unwrap());
        fs_generic::generic_linkat(ffi::At::Pwd, &a, ffi::At::Pwd, &b, false)
    };
    assert_eq!(linkat(&doc, &format!("{HOOK_PREFIX}/doc-link.txt")), 0);
    assert_eq!(std::fs::read(host.join("doc-link.txt")).unwrap(), b"hello");
    assert_eq!(statat(&doc).1.nlink, 2);
    assert_eq!(
        linkat(&format!("{HOOK_PREFIX}/missing.txt"), &format!("{HOOK_PREFIX}/x.txt")),
        -(libc::ENOENT)
    );

    // -- a directory reached through the hook takes the same path, and
    // `cp -r` stats those too.
    let (e, by_path) = statat(HOOK_PREFIX);
    assert_eq!(e, 0);
    let (e, by_fd) = fstat_via_fd(HOOK_PREFIX);
    assert_eq!(e, 0);
    assert_eq!(by_path.dev, by_fd.dev);
    assert_eq!(by_path.inode, by_fd.inode);
    assert_eq!(by_path.mode & S_IFMT, S_IFDIR);

    // -- the other branch of `fakefs_stat` that answers from a host
    // `stat()`: a path in the bind table rather than routed by the hook. It
    // takes inode/mode/owner from `meta.db`, but dev, blksize and blocks
    // are the host's to give.
    //
    // The *first* stat of a bind-mounted path takes a different branch --
    // no row exists yet, so it is created from a full `realfs.stat`. The
    // branch under test is the one every stat after that takes.
    assert_eq!(statat("/bound/doc.txt").0, 0);
    let (e, by_path) = statat("/bound/doc.txt");
    assert_eq!(e, 0);
    let (e, by_fd) = fstat_via_fd("/bound/doc.txt");
    assert_eq!(e, 0);
    assert_eq!(by_path.dev, by_fd.dev);
    assert_eq!(by_path.blksize, by_fd.blksize);
    assert_eq!(by_path.blocks, by_fd.blocks);
    assert_eq!(by_path.nlink, by_fd.nlink);
    assert_ne!(by_path.dev, 0);

    // -- rebinding a guest path must describe the new target.
    //
    // `meta.db` rows are created lazily as paths under a bind mount are
    // stat'd, and they outlive the registration that made them. If they are
    // still there when the same guest path is bound somewhere else, a stat
    // under the new target is answered from the previous target's row --
    // the wrong type, the wrong inode, the wrong mode. `bind_meta_stash`
    // deletes the outgoing bind's rows rather than moving them over the
    // stash.
    //
    // The failure shows on the *second* rebind: the type is refreshed from
    // the host, so after one rebind a stale row still reports the right
    // type by accident.
    let (e, st) = statat("/bound/doc.txt");
    assert_eq!(e, 0);
    assert_eq!(st.mode & S_IFMT, S_IFREG);
    let first_inode = st.inode;

    assert_eq!(bind("/bound", bound2.to_str().unwrap(), false), 0);
    let (e, st) = statat("/bound/doc.txt");
    assert_eq!(e, 0);
    assert_eq!(st.mode & S_IFMT, S_IFDIR);
    assert_ne!(st.inode, first_inode);

    assert_eq!(bind("/bound", &bound_real, false), 0);
    let (e, st) = statat("/bound/doc.txt");
    assert_eq!(e, 0);
    assert_eq!(st.mode & S_IFMT, S_IFREG);

    // -- a bind mount over a directory the guest already had gives it back.
    //
    // The tree at the mount point is moved aside under `.iul-bind-saved`
    // and renamed back at unmount; the alternative -- which this used to do
    // -- is to unlink every child before writing the symlink, and then the
    // guest's files are gone for good.
    let mkdir = |p: &str| {
        let c = std::ffi::CString::new(p).unwrap();
        fs_generic::mkdir_at(ffi::At::Pwd, &c, 0o755)
    };
    assert_eq!(mkdir("/guest-tree"), 0);
    let made = open_flags(
        "/guest-tree/mine.txt",
        (ffi::O_RDWR_ | ffi::O_CREAT_) as c_int,
    )
    .expect("created");
    made.close();
    assert_eq!(statat("/guest-tree/mine.txt").0, 0);

    assert_eq!(bind("/guest-tree", &bound_real, false), 0);
    assert_eq!(statat("/guest-tree/doc.txt").1.mode & S_IFMT, S_IFREG);
    assert_eq!(statat("/guest-tree/mine.txt").0, ENOENT);

    assert_eq!(unbind("/guest-tree"), 0);
    let (e, st) = statat("/guest-tree/mine.txt");
    assert_eq!(e, 0);
    assert_eq!(st.mode & S_IFMT, S_IFREG);
    // And the host tree is not visible through it any more, nor is the
    // stash left lying in the guest's namespace.
    assert_eq!(statat("/guest-tree/doc.txt").0, ENOENT);
    assert_eq!(statat(&format!("/guest-tree{BIND_SAVED_SUFFIX}")).0, ENOENT);

    // -- a mount **replaced** at the same guest path still gives the
    // original tree back when it is finally unmounted. A second
    // registration displaces the *first bind's* rows, and they go rather
    // than overwrite the stash -- deleting the stash first meant an unmount
    // restored the previous target's metadata onto the original tree.
    assert_eq!(mkdir("/twice"), 0);
    let made = open_flags(
        "/twice/original.txt",
        (ffi::O_RDWR_ | ffi::O_CREAT_) as c_int,
    )
    .expect("created");
    made.close();

    assert_eq!(bind("/twice", &bound_real, false), 0);
    assert_eq!(statat("/twice/doc.txt").1.mode & S_IFMT, S_IFREG);
    assert_eq!(bind("/twice", bound2.to_str().unwrap(), false), 0);
    assert_eq!(statat("/twice/doc.txt").1.mode & S_IFMT, S_IFDIR);

    assert_eq!(unbind("/twice"), 0);
    let (e, st) = statat("/twice/original.txt");
    assert_eq!(e, 0);
    assert_eq!(st.mode & S_IFMT, S_IFREG);
    assert_eq!(statat("/twice/doc.txt").0, ENOENT);
    assert_eq!(statat(&format!("/twice{BIND_SAVED_SUFFIX}")).0, ENOENT);

    // -- a read-only bind mount refuses every write under it, because a
    // guest process runs as root and bypasses the `meta.db` mode check.
    assert_eq!(open_for_write("/ro/doc.txt"), EROFS);
    // And a writable mount nested inside it is writable. The rule is "the
    // longest matching mount decides"; read-only used to look for the
    // longest *read-only* match instead, so every write under `/ro/inner`
    // was refused with EROFS and nothing said why.
    assert_eq!(open_for_write("/ro/inner/doc.txt"), 0);

    // -- a bind mount whose host directory is *under* the one the symlink
    // lives in. fakefs writes the mount point as a relative symlink so that
    // moving the whole fakefs does not break it, and the number of `..` is
    // the components of the symlink's parent past the common prefix. The C
    // counted the slashes after the prefix plus one if the parent did not
    // end in a slash -- which agrees only when the prefix ends in the
    // *middle* of the parent. Here it ends at the end of it.
    let (e, st) = statat("/inside/doc.txt");
    assert_eq!(e, 0);
    assert_eq!(st.mode & S_IFMT, S_IFREG);

    // -- the hook is consulted before the `meta.db` table, not instead of
    // it: a path it declines has to keep resolving the ordinary way.
    let (e, st) = statat("/");
    assert_eq!(e, 0);
    assert_eq!(st.mode & S_IFMT, S_IFDIR);

    let _ = std::fs::remove_dir_all(&base);
}
