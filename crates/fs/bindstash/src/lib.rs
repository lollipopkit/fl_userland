//! What happens to the host tree when a bind mount comes and goes.
//!
//! `fakefs_bind_mount(guest_path, host_path)` puts a symlink into the fakefs
//! `data/` tree so that everything below `guest_path` resolves to `host_path`.
//! Whatever the guest already had at that path has to be moved aside first and
//! put back at unmount, or binding over a populated directory destroys it.
//!
//! This crate is that: the stash name, the move, the symlink and the removal.
//! `meta.db` schema and repair statements live in the Rust `fakeschema` and
//! `fakedb` crates.
//!
//! Three things it changes from the C.
//!
//! **`remove_tree_at` recursed once per directory level**, holding an open
//! `DIR *` at each. The tree it walks is the one that was at the mount point,
//! which a guest can make as deep as it likes with `mkdir` — so the depth is
//! guest-chosen, and each level cost a descriptor and a stack frame. It ran out
//! of descriptors long before it ran out of stack, so the failure was a tree it
//! silently did not remove rather than a crash, but neither bound was written
//! down. [`remove_tree`] holds at most [`MAX_DEPTH`] descriptors and restarts
//! from the top when it needs to go deeper, so it finishes at any depth.
//!
//! **The stash name could truncate into the mount point itself.** `snprintf`
//! into `char[PATH_MAX]` of `"%s%s"` with the suffix gives back the mount point
//! for a link within `strlen(suffix)` of the limit — and then
//! `renameat(root, x, root, x)` renames a path onto itself, reports success,
//! and the symlink is written over a guest tree nothing saved. A `String` has
//! no such length, so the case is inexpressible; a name the *host* cannot take
//! fails at the syscall with `ENAMETOOLONG`, which is an error rather than a
//! success.
//!
//! **The relative symlink was computed through three `char[PATH_MAX]`
//! buffers**, each with its own fallback to an absolute link — and an absolute
//! symlink does not work on iOS, so a fallback is a bind mount that resolves to
//! nothing. `bindpath::relative` is Rust already; calling it directly removes
//! the buffers and two of the three fallbacks.

#[cfg(test)]
use std::ffi::CString;
use std::os::raw::c_int;
use std::os::unix::io::BorrowedFd;

use rustix::fs::{AtFlags, FileType};
#[cfg(test)]
use rustix::fs::{Mode, OFlags};

mod tree;

pub use tree::{MAX_DEPTH, remove_tree};

/// What a mount point's previous contents are kept under.
pub const SAVED_SUFFIX: &str = ".iul-bind-saved";

/// A guest errno, negative.
pub type Errno = c_int;

fn map_rustix(e: rustix::io::Errno) -> Errno {
    kernel_errno::map(e.raw_os_error()).guest
}

/// Where the previous contents of `path` are kept.
pub fn saved_name(path: &str) -> String {
    format!("{path}{SAVED_SUFFIX}")
}

/// Move whatever is at `host_link` aside, under `root`.
///
/// A symlink there is one of ours from an earlier registration and carries
/// nothing worth keeping.
pub fn stash(root: BorrowedFd<'_>, host_link: &str) -> Result<(), Errno> {
    let Ok(st) = rustix::fs::statat(root, host_link, AtFlags::SYMLINK_NOFOLLOW) else {
        return Ok(()); // nothing there
    };
    if FileType::from_raw_mode(st.st_mode as _) == FileType::Symlink {
        let _ = rustix::fs::unlinkat(root, host_link, AtFlags::empty());
        return Ok(());
    }

    let saved = saved_name(host_link);
    if rustix::fs::statat(root, saved.as_str(), AtFlags::SYMLINK_NOFOLLOW).is_ok() {
        // A stash from an earlier bind that was never restored. That tree is
        // the guest's original and outranks whatever has appeared at the mount
        // point since, which can only have come from the bind itself.
        remove_tree(root, host_link);
        return Ok(());
    }
    rustix::fs::renameat(root, host_link, root, saved.as_str()).map_err(map_rustix)
}

/// Put back what [`stash`] moved aside.
pub fn restore(root: BorrowedFd<'_>, host_link: &str) {
    if let Ok(st) = rustix::fs::statat(root, host_link, AtFlags::SYMLINK_NOFOLLOW)
        && FileType::from_raw_mode(st.st_mode as _) == FileType::Symlink
    {
        let _ = rustix::fs::unlinkat(root, host_link, AtFlags::empty());
    }
    let saved = saved_name(host_link);
    if rustix::fs::statat(root, saved.as_str(), AtFlags::SYMLINK_NOFOLLOW).is_ok() {
        let _ = rustix::fs::renameat(root, saved.as_str(), root, host_link);
    }
}

/// The symlink that makes the bind work: `root/host_link` -> `host_path`.
///
/// Relative where a relative form exists, because an absolute symlink does not
/// resolve on iOS — the app's container is not at the path it was written with.
/// So a fallback to the absolute form is a bind mount that points at nothing,
/// and the C had three of them, one per fixed buffer it could overflow.
pub fn symlink(root: BorrowedFd<'_>, host_link: &str, host_path: &str) -> Result<(), Errno> {
    let target = match relative_target(root, host_link, host_path) {
        Some(rel) => rel,
        // Absolute is what is left when the two have no common prefix at all —
        // different volumes, which iOS does have. Not a truncation any more.
        None => host_path.to_string(),
    };
    rustix::fs::symlinkat(target.as_str(), root, host_link).map_err(map_rustix)
}

/// The relative form of `host_path` as seen from the symlink's own directory.
fn relative_target(root: BorrowedFd<'_>, host_link: &str, host_path: &str) -> Option<String> {
    // F_GETPATH resolves symlinks, so /var comes back as /private/var. The
    // target has to be resolved the same way or the two have no common prefix
    // and the arithmetic answers about a directory that is not there.
    let root_abs = fd_path(root)?;
    let host_real = real_path(host_path)?;

    let mut link_abs = format!("{root_abs}/{host_link}");
    // The symlink's parent, which is what a relative target is relative to.
    let slash = link_abs.rfind('/')?;
    link_abs.truncate(slash);

    // No `out_len`: the length rule belongs to the C buffer this replaced, and
    // a target the host will not take fails at symlinkat with ENAMETOOLONG.
    bindpath::relative(&link_abs, &host_real, usize::MAX)
}

fn fd_path(fd: BorrowedFd<'_>) -> Option<String> {
    rustix::fs::getpath(fd).ok()?.into_string().ok()
}

fn real_path(path: &str) -> Option<String> {
    std::fs::canonicalize(path).ok()?.into_os_string().into_string().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::io::AsFd;
    use std::path::{Path, PathBuf};

    use crate::tree::{open_dir, open_dir_c};

    /// A directory of our own, removed on drop. The repository builds its own
    /// rather than taking `tempfile`, so this follows
    /// `crates/tools/fakefsify/tests/roundtrip.rs`.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> TempDir {
            let mut path = std::env::temp_dir();
            path.push(format!(
                "bindstash-{tag}-{}-{:p}",
                std::process::id(),
                &tag as *const _
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("a temp directory");
            TempDir(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
        fn open(&self) -> std::fs::File {
            std::fs::File::open(&self.0).expect("the temp directory opens")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A tree `levels` deep, built by descending with `openat`.
    ///
    /// Not with absolute paths: past about 250 levels the path itself exceeds
    /// the host's `PATH_MAX` and `fs::write` fails with `ENAMETOOLONG`. That is
    /// the case this exists to test — a tree deeper than any path that names it,
    /// which is reachable because every level is one relative `mkdir` — and it
    /// is also why the removal has to descend by descriptor.
    fn deep(root: BorrowedFd<'_>, top: &str, levels: usize) {
        rustix::fs::mkdirat(root, top, Mode::from_raw_mode(0o755)).expect("the top");
        let mut here = open_dir(root, top).expect("the top opens");
        for i in 0..levels {
            let name = format!("d{i}");
            rustix::fs::mkdirat(&here, name.as_str(), Mode::from_raw_mode(0o755)).expect("a level");
            let f = rustix::fs::openat(
                &here,
                "file",
                OFlags::CREATE | OFlags::WRONLY,
                Mode::from_raw_mode(0o644),
            )
            .expect("a file at each level");
            drop(f);
            here = open_dir_c(&here, &CString::new(name).expect("no NUL")).expect("descend");
        }
    }

    #[test]
    fn the_stash_name_never_equals_the_thing_it_saves() {
        // The whole reason this is a String. At PATH_MAX - 4 the C's snprintf
        // truncated back to the mount point, and renameat(fd, x, fd, x)
        // reported success while destroying the tree.
        for len in [1usize, 100, 1000, 1020, 1023, 1024, 4096] {
            let name = "a".repeat(len);
            let saved = saved_name(&name);
            assert_ne!(saved, name, "at length {len}");
            assert!(saved.starts_with(&name));
            assert_eq!(saved.len(), len + SAVED_SUFFIX.len());
        }
    }

    #[test]
    fn a_tree_deeper_than_the_descriptor_bound_is_still_removed() {
        // The one the recursion could not do. MAX_DEPTH is 64 and this is four
        // times that, so it takes several passes.
        let t = TempDir::new("deep");
        let root = t.open();
        deep(root.as_fd(), "deep", MAX_DEPTH * 4);
        assert!(t.path().join("deep").exists());
        assert!(remove_tree(root.as_fd(), "deep"));
        assert!(!t.path().join("deep").exists());
    }

    #[test]
    fn a_tree_twenty_times_the_bound_is_removed_in_a_bounded_number_of_passes() {
        // The lift is what makes this finish. Without it the walk stops at
        // MAX_DEPTH and reports that it could not remove the tree; with the
        // descriptor-per-level recursion it replaced, this is 1280 open
        // directories at once.
        let t = TempDir::new("verydeep");
        let root = t.open();
        deep(root.as_fd(), "vd", MAX_DEPTH * 20);
        assert!(remove_tree(root.as_fd(), "vd"));
        assert!(!t.path().join("vd").exists());
    }

    #[test]
    fn a_lift_does_not_take_a_name_the_guest_is_using() {
        // The lifted subtree needs a name inside the tree being removed, and
        // the guest chose every other name in there.
        let t = TempDir::new("collide");
        let root = t.open();
        deep(root.as_fd(), "c", MAX_DEPTH * 3);
        // Occupy the names a lift would reach for first, with files rather
        // than directories so a mistaken rename over one would be visible.
        for i in 0..4 {
            fs::write(t.path().join("c").join(format!(".iul-deep-{i}")), b"guest")
                .expect("a name in the way");
        }
        assert!(remove_tree(root.as_fd(), "c"));
        assert!(!t.path().join("c").exists());
    }

    #[test]
    fn a_wide_tree_goes_too() {
        let t = TempDir::new("wide");
        let root = t.open();
        fs::create_dir(t.path().join("w")).expect("the top");
        for i in 0..200 {
            let d = t.path().join("w").join(format!("s{i}"));
            fs::create_dir(&d).expect("a subdirectory");
            fs::write(d.join("f"), b"x").expect("a file");
        }
        assert!(remove_tree(root.as_fd(), "w"));
        assert!(!t.path().join("w").exists());
    }

    #[test]
    fn a_symlink_inside_the_tree_is_removed_and_not_followed() {
        let t = TempDir::new("link");
        let root = t.open();
        fs::create_dir(t.path().join("keep")).expect("the target");
        fs::write(t.path().join("keep/precious"), b"x").expect("something to lose");
        fs::create_dir(t.path().join("tree")).expect("the tree");
        std::os::unix::fs::symlink("../keep", t.path().join("tree/into-keep")).expect("a symlink");

        assert!(remove_tree(root.as_fd(), "tree"));
        assert!(!t.path().join("tree").exists());
        assert!(
            t.path().join("keep/precious").exists(),
            "the symlink was unlinked, not walked"
        );
    }

    #[test]
    fn removing_something_that_is_not_a_directory_unlinks_it() {
        let t = TempDir::new("file");
        let root = t.open();
        fs::write(t.path().join("f"), b"x").expect("a file");
        assert!(remove_tree(root.as_fd(), "f"));
        assert!(!t.path().join("f").exists());
        // And something that is not there at all is not an error worth having.
        assert!(!remove_tree(root.as_fd(), "nothing"));
    }

    #[test]
    fn stash_moves_a_directory_aside_and_restore_brings_it_back() {
        let t = TempDir::new("roundtrip");
        let root = t.open();
        fs::create_dir(t.path().join("mnt")).expect("the mount point");
        fs::write(t.path().join("mnt/guest-file"), b"guest data").expect("guest data");

        stash(root.as_fd(), "mnt").expect("stashed");
        assert!(!t.path().join("mnt").exists(), "moved aside");
        assert!(t.path().join(saved_name("mnt")).exists());
        assert_eq!(
            fs::read(t.path().join(saved_name("mnt")).join("guest-file")).expect("still there"),
            b"guest data"
        );

        restore(root.as_fd(), "mnt");
        assert!(!t.path().join(saved_name("mnt")).exists());
        assert_eq!(
            fs::read(t.path().join("mnt/guest-file")).expect("back"),
            b"guest data"
        );
    }

    #[test]
    fn stash_over_a_previous_bind_keeps_the_original_tree() {
        // The stash is the guest's original and outranks whatever appeared at
        // the mount point since, which can only have come from the bind.
        let t = TempDir::new("twice");
        let root = t.open();
        fs::create_dir(t.path().join("mnt")).expect("the mount point");
        fs::write(t.path().join("mnt/original"), b"first").expect("the original");
        stash(root.as_fd(), "mnt").expect("first stash");

        // A second registration, with something at the mount point again.
        fs::create_dir(t.path().join("mnt")).expect("the second one");
        fs::write(t.path().join("mnt/from-the-bind"), b"second").expect("the bind's");
        stash(root.as_fd(), "mnt").expect("second stash");

        restore(root.as_fd(), "mnt");
        assert!(
            t.path().join("mnt/original").exists(),
            "the guest's own tree came back"
        );
        assert!(!t.path().join("mnt/from-the-bind").exists());
    }

    #[test]
    fn stashing_a_symlink_of_ours_keeps_nothing() {
        let t = TempDir::new("oursymlink");
        let root = t.open();
        std::os::unix::fs::symlink("/somewhere", t.path().join("mnt")).expect("an old bind");
        stash(root.as_fd(), "mnt").expect("stashed");
        assert!(!t.path().join("mnt").exists());
        assert!(
            !t.path().join(saved_name("mnt")).exists(),
            "a symlink of ours carries nothing worth keeping"
        );
    }

    #[test]
    fn stashing_nothing_is_not_an_error() {
        let t = TempDir::new("empty");
        let root = t.open();
        stash(root.as_fd(), "not-there").expect("nothing to move");
        restore(root.as_fd(), "not-there");
    }

    #[test]
    fn the_symlink_is_relative_and_resolves() {
        // Absolute symlinks do not resolve on iOS, so a relative target is not
        // an optimisation: it is the only form that works.
        let t = TempDir::new("symlink");
        let root = t.open();
        fs::create_dir_all(t.path().join("target/inner")).expect("the target");
        fs::write(t.path().join("target/inner/f"), b"reached").expect("something to reach");
        fs::create_dir(t.path().join("mnt-parent")).expect("a parent for the link");

        let target = t.path().join("target/inner");
        symlink(
            root.as_fd(),
            "mnt-parent/here",
            target.to_str().expect("utf8"),
        )
        .expect("linked");

        let written = fs::read_link(t.path().join("mnt-parent/here")).expect("a symlink");
        assert!(
            written.is_relative(),
            "the target is relative, got {written:?}"
        );
        assert_eq!(
            fs::read(t.path().join("mnt-parent/here/f")).expect("it resolves"),
            b"reached"
        );
    }

    #[test]
    fn a_symlink_over_something_that_exists_fails_rather_than_replacing_it() {
        // stash() is what moves the old thing away; symlink() must not do it by
        // accident, or a caller that skipped the stash would destroy the tree.
        let t = TempDir::new("occupied");
        let root = t.open();
        fs::create_dir(t.path().join("mnt")).expect("something in the way");
        let target = t.path().join("mnt");
        let err =
            symlink(root.as_fd(), "mnt", target.to_str().expect("utf8")).expect_err("refused");
        assert_eq!(err, kernel_errno::guest::EEXIST);
        assert!(t.path().join("mnt").is_dir(), "and it is still a directory");
    }
}
