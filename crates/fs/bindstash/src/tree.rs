//! Descriptor-bounded removal of arbitrary directory trees.

use std::ffi::{CStr, CString};
use std::os::unix::io::{BorrowedFd, OwnedFd};

use rustix::fs::{AtFlags, FileType, Mode, OFlags};

/// How many directories deep [`remove_tree`] descends before restarting.
///
/// It bounds open descriptors, not the tree: a deeper tree costs another pass,
/// not a failure. Chosen well under any plausible `RLIMIT_NOFILE` because this
/// runs while a guest holds descriptors of its own.
pub const MAX_DEPTH: usize = 64;

/// Delete `path` and everything under it, relative to `root`.
///
/// Bounded in descriptors and in stack. Returns whether the tree is gone; a
/// `false` means something under it could not be removed, which the C had no
/// way to say.
pub fn remove_tree(root: BorrowedFd<'_>, path: &str) -> bool {
    // Not a directory, or not there: one unlink settles it either way.
    let Ok(dir) = open_dir(root, path) else {
        return rustix::fs::unlinkat(root, path, AtFlags::empty()).is_ok();
    };
    drop(dir);

    // Each pass descends as far as MAX_DEPTH lets it and empties what it
    // reaches. A tree deeper than that needs another pass, and every pass that
    // reaches the bottom removes at least one directory — so the number of
    // passes is bounded by the depth and the loop terminates. The alternative,
    // one open descriptor per level, is bounded by RLIMIT_NOFILE and by nothing
    // this code chose.
    loop {
        match empty_below(root, path) {
            Progress::Done => break,
            // Something is left and this pass removed nothing, so another pass
            // would do nothing either: a permission, a mount, an open
            // directory the host will not unlink.
            Progress::Stuck => return false,
            Progress::Again => continue,
        }
    }
    rustix::fs::unlinkat(root, path, AtFlags::REMOVEDIR).is_ok()
}

enum Progress {
    /// Everything below the root of this walk is gone.
    Done,
    /// Something was removed and something is left.
    Again,
    /// Something is left and nothing was removed.
    Stuck,
}

pub(crate) fn open_dir(at: BorrowedFd<'_>, path: &str) -> rustix::io::Result<OwnedFd> {
    rustix::fs::openat(
        at,
        path,
        // NOFOLLOW: the thing at the mount point may be a symlink of ours, and
        // following it would walk the host tree the bind points at.
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// One pass: empty `path`, holding at most [`MAX_DEPTH`] descriptors.
///
/// A depth-first walk with an explicit stack. The interesting case is what
/// happens when the tree is deeper than the stack, because a guest can make it
/// as deep as it likes: the deep subdirectory is **renamed up to the top of the
/// walk**, which is one operation whatever is under it and leaves the tree
/// shallower by [`MAX_DEPTH`] levels. So a pass always makes progress and the
/// number of passes is the depth divided by the bound, rather than the walk
/// failing or the descriptors running out.
///
/// The recursion this replaces held an open `DIR *` per level and had neither
/// bound written down. It ran out of descriptors first, so a tree deep enough
/// was silently not removed.
fn empty_below(root: BorrowedFd<'_>, path: &str) -> Progress {
    let Ok(top) = open_dir(root, path) else {
        return Progress::Done;
    };
    struct Level {
        dir: OwnedFd,
        /// The name this level has in its parent, for the parent's `tried`.
        name: Option<CString>,
        /// Children this level has already tried and could not empty. Without
        /// it, a parent re-reads its directory on the way up, finds the child
        /// still there, and descends into it again for ever.
        tried: Vec<CString>,
        /// Something here is staying, so the parent cannot remove this level.
        stuck: bool,
    }
    let mut stack = vec![Level {
        dir: top,
        name: None,
        tried: Vec::new(),
        stuck: false,
    }];
    let mut removed = false;
    let mut left = false;
    let mut lifted = 0u32;

    loop {
        let i = stack.len() - 1;
        let swept = sweep(&stack[i].dir, &stack[i].tried);
        removed |= swept.removed;
        if swept.stuck {
            stack[i].stuck = true;
        }

        if let Some(name) = swept.remaining {
            if stack.len() < MAX_DEPTH {
                match open_dir_c(&stack[i].dir, &name) {
                    Ok(fd) => {
                        stack.push(Level {
                            dir: fd,
                            name: Some(name),
                            tried: Vec::new(),
                            stuck: false,
                        });
                    }
                    Err(_) => {
                        // Cannot be opened and cannot be removed.
                        stack[i].tried.push(name);
                        stack[i].stuck = true;
                    }
                }
            } else if i == 0 {
                // Nowhere to lift to. Unreachable while MAX_DEPTH is above 1,
                // and stated rather than left to that constant.
                stack[0].tried.push(name);
                stack[0].stuck = true;
            } else {
                // As deep as the descriptors go. Move the whole subtree to the
                // top of this walk, where the next sweep of the top will find
                // it MAX_DEPTH - 1 levels shallower than it was.
                let (top_rest, here) = stack.split_at_mut(i);
                let lifted_name = lift(&top_rest[0].dir, &here[0].dir, &name, &mut lifted);
                match lifted_name {
                    Some(()) => removed = true, // the tree changed; another pass will see it
                    None => {
                        here[0].tried.push(name);
                        here[0].stuck = true;
                    }
                }
            }
            continue;
        }

        // Nothing more here this pass.
        let done = stack.pop().expect("the stack is never empty here");
        if done.stuck {
            left = true;
            if let (Some(parent), Some(name)) = (stack.last_mut(), done.name) {
                parent.tried.push(name);
                parent.stuck = true;
            }
        }
        if stack.is_empty() {
            break;
        }
        // The parent's next sweep is what removes the directory just emptied.
    }

    if !left {
        Progress::Done
    } else if removed {
        Progress::Again
    } else {
        Progress::Stuck
    }
}

/// Move `name` out of `from` and into `to`, under a name nothing is using.
///
/// One `renameat` moves a subtree of any size and any depth, which is what
/// makes a bounded walk able to finish: the levels below the bound become
/// levels below the top instead.
fn lift(to: &OwnedFd, from: &OwnedFd, name: &CStr, counter: &mut u32) -> Option<()> {
    for _ in 0..1024 {
        let candidate = format!(".iul-deep-{counter}");
        *counter += 1;
        if rustix::fs::statat(to, candidate.as_str(), AtFlags::SYMLINK_NOFOLLOW).is_ok() {
            continue; // taken, by a previous lift or by the guest
        }
        if rustix::fs::renameat(from, name, to, candidate.as_str()).is_ok() {
            return Some(());
        }
        return None;
    }
    None
}

struct Swept {
    /// Something was unlinked.
    removed: bool,
    /// A subdirectory that is not empty and is not in `skip`.
    remaining: Option<CString>,
    /// Something is left that is not a subdirectory to descend into.
    stuck: bool,
}

/// Unlink everything in `dir` that can go, and name one subdirectory that
/// cannot. `skip` holds the ones already tried.
fn sweep(dir: &OwnedFd, skip: &[CString]) -> Swept {
    let mut out = Swept {
        removed: false,
        remaining: None,
        stuck: false,
    };
    let Ok(entries) = rustix::fs::Dir::read_from(dir) else {
        out.stuck = true;
        return out;
    };
    for entry in entries {
        let Ok(entry) = entry else {
            out.stuck = true;
            continue;
        };
        let name = entry.file_name();
        if name == c"." || name == c".." {
            continue;
        }
        if skip.iter().any(|s| s.as_c_str() == name) {
            continue;
        }
        let is_dir = match entry.file_type() {
            FileType::Directory => true,
            // Some filesystems do not fill d_type. Ask.
            FileType::Unknown => rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)
                .map(|st| FileType::from_raw_mode(st.st_mode as _) == FileType::Directory)
                .unwrap_or(false),
            _ => false,
        };
        if is_dir {
            if rustix::fs::unlinkat(dir, name, AtFlags::REMOVEDIR).is_ok() {
                out.removed = true;
            } else if out.remaining.is_none() {
                out.remaining = Some(name.to_owned());
            }
            // A second non-empty subdirectory is not recorded: this level is
            // swept again as soon as the first one is dealt with, and it will
            // be found then.
        } else if rustix::fs::unlinkat(dir, name, AtFlags::empty()).is_ok() {
            out.removed = true;
        } else {
            out.stuck = true;
        }
    }
    out
}

pub(crate) fn open_dir_c(at: &OwnedFd, name: &CStr) -> rustix::io::Result<OwnedFd> {
    rustix::fs::openat(
        at,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}
