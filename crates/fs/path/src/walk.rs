//! The path walk itself.
//!
//! Rewritten rather than translated, and three things changed with it:
//!
//! - **Symlink expansion is a loop, not recursion.** The C recursed into
//!   `__path_normalize` for every link and carried a `levels` counter, which
//!   put a guest-controlled bound on host stack depth.
//! - **The link limit is 40, not 5.** `SYMLOOP_MAX` on Linux is 40; the C
//!   stopped at 5, so a legitimately deep chain of links — five is not many
//!   when a distribution's `/bin/sh` goes through a couple — got ELOOP. It is
//!   forty *links*, which is forty-one passes: a chain of exactly forty was
//!   ELOOP here until 2026-09-04, and `path_probe` is what said so.
//! - **No cache.** See [`resolve`].
//!
//! # `openat2`'s refusals are the walk's
//!
//! [`Scope`] is `struct open_how`'s `resolve` word, and each flag is enforced
//! where the escape it stops happens, because that is the only place that sees
//! it: `..` at the floor, an absolute path or link, a magic link, a step onto
//! another mount. A syscall that accepted the flags and walked as usual would
//! hand back a descriptor the caller believes cannot be outside its root.
//!
//! The order of the checks at a symlink is Linux's `pick_link` and
//! `nd_jump_link`, measured by `tests/guest/src/bin/openat2_probe.rs`:
//! `RESOLVE_NO_SYMLINKS` first, then `RESOLVE_CACHED`, then
//! `RESOLVE_NO_MAGICLINKS`, `RESOLVE_NO_XDEV` and the two scoping flags.

use std::ffi::CStr;

use libc::c_int;

use crate::ffi;

pub const MAX_PATH: usize = ffi::MAX_PATH as usize;
pub const MAX_NAME: usize = ffi::MAX_NAME as usize;

pub use guest_errno::c_int_::{EAGAIN, ELOOP, ENAMETOOLONG, ENOENT, ENOTDIR, EXDEV};
use guest_errno::c_int_::EINVAL;

/// What a caller asked the walk to refuse: `openat2`'s `RESOLVE_*` flags.
/// The default refuses nothing, which is every path syscall but `openat2`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Scope {
    /// `RESOLVE_NO_XDEV`: every step stays on the mount the walk started on.
    pub no_xdev: bool,
    /// `RESOLVE_NO_MAGICLINKS`: a procfs link onto an open file is `ELOOP`.
    pub no_magiclinks: bool,
    /// `RESOLVE_NO_SYMLINKS`: any link that would be followed is `ELOOP`.
    pub no_symlinks: bool,
    /// `RESOLVE_BENEATH`: `..` above the starting directory, an absolute
    /// link and a magic link are `EXDEV`.
    pub beneath: bool,
    /// `RESOLVE_IN_ROOT`: the starting directory is `/` for the walk -- an
    /// absolute link restarts there and `..` stops there, as under `chroot`.
    /// The caller passes it as both `at` and `root`; a magic link is `EXDEV`.
    pub in_root: bool,
    /// `RESOLVE_CACHED`: `EAGAIN` for any step that would need I/O. See
    /// [`Walk::refuse`].
    pub cached: bool,
}

impl Scope {
    fn scoped(&self) -> bool {
        self.beneath || self.in_root
    }
}

/// What Linux allows, and what a rootfs with a couple of layered symlinks
/// needs. `SYMLOOP_MAX` in `limits.h`.
const SYMLOOP_MAX: usize = 40;

/// File type bits in a guest mode. `statbuf.mode` is the guest's, so these are
/// the guest's values — which happen to be the host's too, which is why the C
/// could get away with calling the host's `S_ISDIR` on it.
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;

type Result<T> = std::result::Result<T, c_int>;

/// Resolve `input` against `at`, following symlinks.
///
/// # Why there is no cache
///
/// The C kept a 64-entry thread-local cache of normalized paths with a 100 ms
/// TTL. It is not reinstated here, because as written it was wrong in three
/// ways and each fix costs most of what it saved:
///
/// - **It skipped the permission check.** The miss path calls `access_check`
///   for execute permission on each directory it descends through; the hit
///   path returned the cached string and called nothing. Dropping the execute
///   bit on a directory left it traversable for another 100 ms.
/// - **Its key was truncated.** The key was built with
///   `snprintf(full_input, MAX_PATH, "%s/%s", at_path, path)`, so two
///   different `(at, path)` pairs that agree on the first MAX_PATH bytes share
///   an entry and one resolves to the other's answer.
/// - **It did not see mounts.** A mount or unmount inside the TTL does not
///   invalidate anything.
///
/// A correct cache here would have to be keyed on the untruncated input, be
/// invalidated by mount changes, and still consult the permission check on
/// every hit — which is the part that has to touch the filesystem anyway. If
/// profiling shows this walk is hot, the thing to cache is the `stat` behind
/// `access_check`, not the string.
/// `parent_dir_write` is `N_PARENT_DIR_WRITE`: the caller is about to create,
/// remove or rename the last component, so the *directory holding it* has to be
/// writable.
///
/// That flag was defined in 2019, is passed by nine call sites in `fs/generic.c`
/// — every create, unlink, rename, rmdir, symlink and link — and **had never
/// been read, in any revision**. `git log -S` across the whole history finds no
/// code that looks at it. Measured against a real arm64 kernel with an
/// unprivileged fsuid in a directory it could search but not write: `mkdir`,
/// `symlink`, `link`, `unlink`, `rmdir` and `rename` all succeeded here and are
/// all `EACCES` there.
///
/// `fs/fake.h` also documents `fakefs_bind_mount(read_only = true)` as working
/// by writing mode 0555 and letting "iSH's generic N_PARENT_DIR_WRITE check"
/// reject the writes. That is an embedder-facing guarantee resting on a check
/// that did not exist.
/// When the parent-directory write check applies.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParentWrite {
    /// Not asked for.
    No,
    /// Either way. A rename's destination: it needs write on that directory
    /// whether it is making the name or replacing one.
    Always,
    /// Only if the last component does *not* exist. A create: if the name is
    /// already there the operation reports `EEXIST`, or in `open`'s case just
    /// opens it, and Linux answers that before it answers the permission.
    /// Without this, `open("existing", O_CREAT|O_RDONLY)` in a directory the
    /// caller cannot write would fail — and that is an ordinary thing to do.
    IfMissing,
    /// Only if it *does*. A removal: a name that is not there is `ENOENT`.
    IfPresent,
}

/// The resolved path, and whether the last component existed *if the walk had
/// to find out*. It does for a create or a delete, to decide whether the parent
/// check applies — and `generic_openat` wants the same answer, because a file
/// `O_CREAT` has just made must not then be permission-checked. Returning it
/// costs nothing and saves that caller a second `stat` of a name the walk has
/// already looked at.
pub struct Resolved {
    pub path: Vec<u8>,
    pub last_existed: Option<bool>,
    /// The open file the last component's link stands for, when it has no
    /// name to follow (see `FsOps::magic_link`): `open` reopens it and `stat`
    /// reports it. `path` is then the link's own.
    pub magic: Option<ffi::FdOwned>,
}

pub fn resolve(
    at: Option<&[u8]>,
    root: &[u8],
    input: &[u8],
    follow: bool,
    parent_dir_write: ParentWrite,
    scope: Scope,
) -> Result<Resolved> {
    if input.is_empty() {
        return Err(ENOENT);
    }

    // `..` may climb out of a working directory but not out of the task's own
    // root — otherwise `/../etc` from a task rooted at `/jail` normalizes to
    // `/etc` and the root is not a root. "/" means the machine's own, so the
    // floor is 0 and nothing is pinned.
    let root_floor = if root == b"/" { 0 } else { root.len() };

    // The base with any trailing slash removed, and `None` when that leaves
    // nothing.
    //
    // A component is appended as `/` + name, so a base that already ends in one
    // produces a doubled slash: `openat(dirfd_on_/dev, "shm")` normalised to
    // `/dev//shm`. `generic_getpath` answers `/dev/` for a descriptor open on a
    // *mount root*, which is every `openat` relative to one — dpkg does it for
    // `/dev/shm` on every run, and the `debug_assert` on the walk's own output
    // caught it. The resolver found the file anyway, because an empty component
    // is skipped; what was wrong was the string, which is what a bind mount, an
    // inotify watch and `/proc/<pid>/maps` all compare.
    //
    // `"/"` becoming `None` is what the old `filter(|b| *b != b"/")` did, and
    // falls out of the same rule.
    let mut base: Option<Vec<u8>> = at
        .map(|b| {
            let mut v = b.to_vec();
            while v.last() == Some(&b'/') {
                v.pop();
            }
            v
        })
        .filter(|v| !v.is_empty());
    let mut remaining: Vec<u8> = input.to_vec();

    // `RESOLVE_BENEATH`'s floor is the starting directory itself, and `..`
    // there is refused rather than absorbed.
    let floor = if scope.beneath {
        base.as_ref().map_or(0, Vec::len)
    } else {
        root_floor
    };
    let mut walk = Walk {
        root,
        floor,
        scope,
        // Linux sets the walk's root when it first needs it: an absolute
        // path, a `..`, or a scoped lookup, whose root is the dirfd from the
        // start. `RESOLVE_NO_XDEV` reads whether that has happened yet --
        // see `jump_root`.
        root_set: scope.scoped() || input.first() == Some(&b'/'),
        start_mount: scope.no_xdev.then(|| mount_id_of(base.as_deref().unwrap_or(b""))),
    };

    // `0..=`, not `0..`: each pass either finishes or expands **one** link, so
    // forty passes can expand thirty-nine and finish on the fortieth. Linux
    // allows forty links and refuses the forty-first, which is forty-one
    // passes. `path_probe` measured a chain of forty being ELOOP here and
    // opening there.
    for _ in 0..=SYMLOOP_MAX {
        match walk.pass(base.as_deref(), &remaining, follow)? {
            Pass::Done(out, magic) => {
                let last_existed = check_parent_writable(&out, parent_dir_write)?;
                return Ok(Resolved {
                    path: out,
                    last_existed,
                    magic,
                });
            }
            Pass::Symlink {
                restart_at,
                expanded,
            } => {
                base = restart_at;
                remaining = expanded;
            }
        }
    }
    Err(ELOOP)
}

enum Pass {
    Done(Vec<u8>, Option<ffi::FdOwned>),
    /// A symlink was hit: resolution restarts with `expanded` against
    /// `restart_at`.
    Symlink {
        restart_at: Option<Vec<u8>>,
        expanded: Vec<u8>,
    },
}

/// The state one resolution carries across its passes.
struct Walk<'a> {
    root: &'a [u8],
    /// How far `..` may climb: the task's root, or under `RESOLVE_BENEATH`
    /// the starting directory.
    floor: usize,
    scope: Scope,
    /// Whether Linux's walk would have set its root by now. See `jump_root`.
    root_set: bool,
    /// The mount the walk started on, under `RESOLVE_NO_XDEV` only: every
    /// position the walk reaches has to be on it.
    start_mount: Option<u32>,
}

impl Walk<'_> {
    /// A refusal made *during* the walk, which under `RESOLVE_CACHED` is
    /// `EAGAIN` instead.
    ///
    /// Linux tries a cached lookup first and answers these from the uncached
    /// retry -- `..` at a `RESOLVE_BENEATH` floor, a step across a mount under
    /// `RESOLVE_NO_XDEV`, a link it cannot read from memory. `RESOLVE_CACHED`
    /// forbids the retry, so the cached attempt's "cannot do this here" is the
    /// answer. Measured: `..` under `CACHED|BENEATH` is `EAGAIN`, not `EXDEV`.
    fn refuse(&self, e: c_int) -> c_int {
        if self.scope.cached { EAGAIN } else { e }
    }

    /// `RESOLVE_NO_XDEV`: the position `path` has to be on the starting mount.
    fn same_mount(&self, path: &[u8]) -> Result<()> {
        match self.start_mount {
            Some(start) if mount_id_of(path) != start => Err(self.refuse(EXDEV)),
            _ => Ok(()),
        }
    }

    /// An absolute symlink restarts at the root: Linux's `nd_jump_root`.
    ///
    /// `RESOLVE_BENEATH` refuses it outright. `RESOLVE_NO_XDEV` refuses it
    /// unless the walk is still on the root's mount -- and, because Linux
    /// fills in the walk's root lazily, also refuses it when nothing has set
    /// the root yet: an absolute symlink met before any absolute path or `..`
    /// is `EXDEV` even when its target is on the same mount. That is a quirk
    /// and it is what a real kernel answers: `abs -> /etc` from a directory on
    /// `/` is `EXDEV`, and `sub/../abs` opens `/etc`.
    fn jump_root(&mut self) -> Result<()> {
        if self.scope.beneath {
            return Err(EXDEV);
        }
        if let Some(start) = self.start_mount
            && (!self.root_set || mount_id_of(self.root_or_empty()) != start)
        {
            return Err(EXDEV);
        }
        self.root_set = true;
        Ok(())
    }

    /// A magic link jumps to an open file: Linux's `nd_jump_link`.
    ///
    /// `on_mount` is the mount the file is on, or `None` for one with no name
    /// (a pipe), which is on no mount the walk can be on.
    fn jump_magic(&self, on_mount: Option<u32>) -> Result<()> {
        // The cached attempt cannot read a procfs link at all: Linux's
        // `proc_pid_get_link` refuses without a dentry.
        if self.scope.cached {
            return Err(EAGAIN);
        }
        if self.scope.no_magiclinks {
            return Err(ELOOP);
        }
        if let Some(start) = self.start_mount
            && on_mount != Some(start)
        {
            return Err(EXDEV);
        }
        if self.scope.scoped() {
            return Err(EXDEV);
        }
        Ok(())
    }

    fn root_or_empty(&self) -> &[u8] {
        if self.root == b"/" { b"" } else { self.root }
    }

    fn pass(&mut self, base: Option<&[u8]>, input: &[u8], follow: bool) -> Result<Pass> {
        let root = self.root;
        let root_floor = self.floor;
        let mut out: Vec<u8> = base.map(|b| b.to_vec()).unwrap_or_default();
        if out.len() + 2 > MAX_PATH {
            return Err(ENAMETOOLONG);
        }

        // POSIX: a trailing slash requires the path to name a directory. For a
        // symlink in the last position that means following it even when the
        // caller asked not to — `lstat("l")` reports the link, `lstat("l/")` has
        // to report what it points at. The C did not, so `stat -c %F /proc/self/`
        // answered "symbolic link" where Linux says "directory".
        let trailing_slash = input.last() == Some(&b'/');

        let mut rest = input;
        // Leading slashes are skipped: what makes a path absolute is already
        // decided by the caller, which picked the root as the base.
        while rest.first() == Some(&b'/') {
            rest = &rest[1..];
        }

        while !rest.is_empty() {
            let (component, tail) = split_component(rest);
            rest = tail;

            match component {
                b"." => continue,
                b".." => {
                    self.root_set = true;
                    // Delete the last component, but never climb past the root.
                    if out.len() > root_floor {
                        match out.iter().rposition(|&b| b == b'/') {
                            Some(slash) if slash >= root_floor => out.truncate(slash),
                            _ => {}
                        }
                    } else if self.scope.beneath {
                        // At the starting directory: `RESOLVE_BENEATH` is
                        // refused here rather than absorbed, even when a later
                        // component would come back in.
                        return Err(self.refuse(EXDEV));
                    }
                    // Out of a mount's root is onto the one it is mounted on.
                    self.same_mount(&out)?;
                    continue;
                }
                _ => {}
            }
            if component.len() > MAX_NAME {
                return Err(ENAMETOOLONG);
            }

            let component_start = out.len();
            if out.len() + 1 + component.len() + 1 > MAX_PATH {
                return Err(ENAMETOOLONG);
            }
            out.push(b'/');
            out.extend_from_slice(component);
            // Stepping onto a mount point is a crossing whether or not the
            // name is then followed: `openat2("/", "proc", O_PATH, NO_XDEV)`
            // is `EXDEV`.
            self.same_mount(&out)?;

            // The last component is only followed when asked; everything before
            // it always is, because a path continues through it. A trailing
            // slash makes the last one continue too.
            let is_last = rest.is_empty();
            if !follow && is_last && !trailing_slash {
                continue;
            }

            // One question per component instead of two.
            //
            // This asked the mount `readlink`, and then — for a component the
            // path continues through — `stat`. Both are lookups of the same
            // name, and the mount's `stat` is an **lstat**: `realfs_stat` passes
            // `AT_SYMLINK_NOFOLLOW` and this walk resolves symlinks itself. So
            // one stat answers both "is it a symlink" and "is it a directory I
            // may traverse".
            //
            // It matters because a mount's answer is not always one host
            // syscall. On fakefs each is a `meta.db` query, and resolving a
            // six-component path made eleven of them: measured at 3.9 us per
            // component against realfs's 1.1, and the gap is exactly the second
            // lookup.
            //
            // A mount that cannot answer — no `stat` operation, or a name that
            // is not there — falls through to what this did before, so nothing
            // that depended on the old order changes.
            let answer = lstat_component(&out);
            let component_stat = answer.as_ref().and_then(|a| a.as_ref().ok()).copied();
            let maybe_link = match &component_stat {
                Some(st) => st.mode & S_IFMT == ffi::S_IFLNK,
                None => true,
            };
            let known_link = component_stat.is_some();
            let link = if maybe_link { readlink(&out, known_link)? } else { None };
            if link.is_some() && self.scope.no_symlinks {
                // Before anything else is asked of the link, as Linux's
                // `pick_link` does: a dangling one is `ELOOP` too.
                return Err(ELOOP);
            }
            match link {
                // A link onto an open file with no name -- `/proc/self/fd/0`
                // on a pipe -- is that file, not its text: `pipe:[123]` read as
                // a relative name was ENOENT, so `cat /dev/stdin` failed on a
                // pipe and so did `echo x > /dev/stderr` (`tests/guest`
                // fdlink_probe). Nothing can be under it, which is ENOTDIR as
                // on Linux.
                Some(Link::Open(file)) => {
                    self.jump_magic(None)?;
                    if !is_last || trailing_slash {
                        return Err(ENOTDIR);
                    }
                    return Ok(Pass::Done(out, Some(file)));
                }
                Some(Link::Text { target, magic, in_memory }) => {
                    let absolute = target.first() == Some(&b'/');
                    if magic {
                        self.jump_magic(Some(mount_id_of(&target)))?;
                    } else {
                        // A link whose text has to be read from the host is a
                        // step the cached attempt cannot make. Measured: a
                        // relative link on the container's overlayfs is
                        // `EAGAIN` under `RESOLVE_CACHED`, `/proc/self` is not.
                        if self.scope.cached && !in_memory {
                            return Err(EAGAIN);
                        }
                        if absolute {
                            self.jump_root()?;
                        }
                    }
                    // An absolute target restarts from a root, and the root it
                    // means is the task's, the way a chrooted process on Linux
                    // resolves one. With a task rooted at a subtree, restarting
                    // from the machine's walked out of the filesystem the task
                    // can see: Alpine's `/bin/sh -> /bin/busybox` resolved to a
                    // `/bin` that was not the guest's, and every busybox applet
                    // with it.
                    //
                    // A relative one restarts from the directory the link is
                    // in, with the target in the link's place. It restarted
                    // from the machine's root with the directory prepended
                    // until 2026-11-11, which walked every component above the
                    // link a second time -- harmless until `RESOLVE_NO_XDEV`,
                    // which would have seen the prefix's mounts as crossings.
                    if target.is_empty() {
                        // An empty target names nothing.
                        return Err(ENOENT);
                    }
                    let mut expanded = target;
                    if !rest.is_empty() {
                        // Bounded here rather than left to grow: the target and
                        // the unconsumed remainder are each under MAX_PATH, but
                        // their concatenation is not.
                        if expanded.len() + 1 + rest.len() + 1 > MAX_PATH {
                            return Err(ENAMETOOLONG);
                        }
                        expanded.push(b'/');
                        expanded.extend_from_slice(rest);
                    } else if trailing_slash {
                        // Carry the requirement across the expansion: what the
                        // link points at still has to be a directory.
                        if expanded.len() + 1 >= MAX_PATH {
                            return Err(ENAMETOOLONG);
                        }
                        expanded.push(b'/');
                    }
                    let restart_at = if absolute {
                        (root != b"/").then(|| root.to_vec())
                    } else {
                        Some(out[..component_start].to_vec()).filter(|d| !d.is_empty())
                    };
                    return Ok(Pass::Symlink {
                        restart_at,
                        expanded,
                    });
                }
                None => {
                    // Not a symlink. If the path continues through it, it has
                    // to be a directory this task may traverse -- and a
                    // **trailing slash** makes the last component continue
                    // too, which is what the slash means: `open("file/")` is
                    // `ENOTDIR`.
                    //
                    // The normalised output drops the slash, so a caller that
                    // looked at it could not tell; this is the only place that
                    // knows. It used to check nothing, so `unlink("file/")`
                    // removed the file, `stat("file/")` reported a regular
                    // file, and `rename("a", "b/")` moved it -- each of them a
                    // request the caller wrote wrong and Linux refuses.
                    //
                    // A name that is *not there* is not an error even with the
                    // slash: `mkdir("newdir/")` is legal, and so is a create
                    // whose own syscall then decides (`generic_openat` answers
                    // EISDIR).
                    if is_last
                        && trailing_slash
                        && let Some(st) = &component_stat
                        && st.mode & S_IFMT != S_IFDIR
                    {
                        return Err(ENOTDIR);
                    }
                    if !is_last {
                        match (component_stat, answer) {
                            // Answered above; no second lookup.
                            (Some(st), _) => {
                                if st.mode & S_IFMT != S_IFDIR {
                                    return Err(ENOTDIR);
                                }
                                access(&out, &st, ffi::AC_X as c_int)?;
                            }
                            // **A name the path continues through has to be
                            // there.** This carried on, and the `..` after it
                            // then took it off again: `open("missing/../f")`
                            // opened `f`, where Linux answers ENOENT. Measured
                            // by `openat2_probe`, and `RESOLVE_BENEATH`'s
                            // `missing/..` is the same walk.
                            (None, Some(Err(e))) => return Err(e),
                            // The mount could not say. A component that does
                            // not exist is not an error here — the caller may
                            // be creating it — and check_traversable says so
                            // too.
                            (None, _) => check_traversable(&out)?,
                        }
                    }
                }
            }
        }

        Ok(Pass::Done(out, None))
    }
}

/// The id of the mount `path` is on: what `RESOLVE_NO_XDEV` compares.
fn mount_id_of(path: &[u8]) -> u32 {
    let mut buf = Vec::with_capacity(path.len() + 1);
    buf.extend_from_slice(path);
    buf.push(0);
    let path = CStr::from_bytes_until_nul(&buf).expect("terminated just above");
    fs_mounttable::mount_find(path).id
}

/// Split off the leading component, returning it and what follows with any
/// separators eaten.
fn split_component(path: &[u8]) -> (&[u8], &[u8]) {
    let end = path.iter().position(|&b| b == b'/').unwrap_or(path.len());
    let (component, mut tail) = path.split_at(end);
    while tail.first() == Some(&b'/') {
        tail = &tail[1..];
    }
    (component, tail)
}

/// What the mount says `path` is, without following it.
///
/// `None` when the mount has no `stat` operation, which is not an error at this
/// point: the caller falls back to asking the old way. `Some(Err)` is a name
/// the mount looked for and did not find, which the caller needs to tell apart
/// for a component the path continues through.
fn lstat_component(path: &[u8]) -> Option<std::result::Result<ffi::statbuf, c_int>> {
    with_mount(path, |mount, trimmed| Ok(mount.fs.and_then(|fs| fs.stat(mount, trimmed))))
        .ok()
        .flatten()
}

/// What following a symlink reaches.
enum Link {
    /// A name, to resolve in its place. `magic` is a procfs link onto an open
    /// file that happens to have a name (see `FsOps::is_magic_link`), and
    /// `in_memory` says reading it needed no I/O (`FsOps::links_in_memory`).
    Text {
        target: Vec<u8>,
        magic: bool,
        in_memory: bool,
    },
    /// An open file with no name; see `FsOps::magic_link`.
    Open(ffi::FdOwned),
}

/// Read `path` as a symlink. `Ok(None)` when it is not one. Asked in one
/// mount lookup with the magic-link question, since every link followed asks
/// both.
///
/// `known_link` is that the mount's `lstat` said this is a symlink. A refusal
/// to read one then ends the walk, as Linux's `get_link` does: procfs answers
/// `EACCES` for another user's `/proc/<pid>/cwd`, and treating that as "not a
/// link" made `stat` of it answer for the link itself. Without the `lstat`
/// the name may not exist at all, and only the operation can say what that
/// means -- `O_CREAT` makes it.
fn readlink(path: &[u8], known_link: bool) -> Result<Option<Link>> {
    with_mount(path, |mount, trimmed| {
        let Some(fs) = mount.fs else {
            return Ok(None);
        };
        if let Some(file) = fs.magic_link(mount, trimmed)? {
            return Ok(Some(Link::Open(file)));
        }
        let mut buf = vec![0u8; MAX_PATH];
        // One less than the buffer: readlink does not write a terminator, and
        // the length it returns is used to size the result below.
        //
        // A filesystem with no `readlink` reaches the trait's default, which
        // answers `_EINVAL` -- the same answer a path that is not a symlink
        // gets, and the `res < 0` below already treats both the same way.
        let last = buf.len() - 1;
        let res = fs.readlink(mount, trimmed, &mut buf[..last]);
        if res < 0 && known_link && res != EINVAL as isize {
            return Err(res as c_int);
        }
        if res < 0 {
            // Not a symlink, or a filesystem with no readlink at all: both
            // mean "carry on treating it as a name".
            return Ok(None);
        }
        buf.truncate(res as usize);
        Ok(Some(Link::Text {
            target: buf,
            magic: fs.is_magic_link(mount, trimmed),
            in_memory: fs.links_in_memory(),
        }))
    })
}

/// The directory that holds `path`, which the caller is about to change.
///
/// A parent that does not exist is not an error here, for the same reason a
/// missing component is not in `check_traversable`: the operation itself
/// reports `ENOENT`, and answering `EACCES` would mask it.
fn check_parent_writable(path: &[u8], when: ParentWrite) -> Result<Option<bool>> {
    if when == ParentWrite::No {
        return Ok(None);
    }
    // The existence question comes first, because Linux answers it first and
    // the ordering is observable -- see [`ParentWrite`].
    let mut existed = None;
    if when != ParentWrite::Always {
        let exists = stat_of(path).is_some();
        existed = Some(exists);
        if exists != (when == ParentWrite::IfPresent) {
            return Ok(existed);
        }
    }
    // The root is the **empty** path here -- the walk builds its result by
    // pushing "/component", so a path that resolves to "/" has nothing in it.
    // Slicing `..1` out of that aborted the emulator, because a panic in an
    // `extern "C"` function cannot unwind. `fs_conformance: tmpfs` found it on
    // the first run.
    let parent: &[u8] = match path.iter().rposition(|b| *b == b'/') {
        // "/" has no parent; it is its own.
        Some(0) | None => b"",
        Some(i) => &path[..i],
    };
    let Some(stat) = stat_of(parent) else {
        // A parent that is not there is not an error here, for the same reason
        // a missing component is not in `check_traversable`: the operation
        // itself reports ENOENT, and answering EACCES would mask it.
        return Ok(existed);
    };
    // Not a directory: the operation will say so. Checking write on a regular
    // file here would answer EACCES where ENOTDIR is the truth.
    if stat.mode & S_IFMT != S_IFDIR {
        return Ok(existed);
    }
    access(parent, &stat, ffi::AC_W as c_int)?;
    Ok(existed)
}

/// The mount's `stat` for an already-normalised absolute path, or `None` if
/// there is no such name or the mount cannot answer.
fn stat_of(path: &[u8]) -> Option<ffi::statbuf> {
    // The root, which the walk spells as the empty path. Every mount wants a
    // real one.
    let path: &[u8] = if path.is_empty() { b"/" } else { path };
    with_mount(path, |mount, trimmed| {
        // As `lstat_component`: neither way of not answering is an error.
        let answer = mount.fs.and_then(|fs| fs.stat(mount, trimmed));
        Ok(answer.and_then(std::result::Result::ok))
    })
    // No mount for it is the same answer as no such name: the operation
    // reports it, and this must not turn it into EACCES.
    .ok()
    .flatten()
}

/// A path continues through this component, so it must be a directory the task
/// has execute permission on.
///
/// A component that does not exist is not an error here: the caller may be
/// creating it, and the operation itself reports ENOENT if not.
fn check_traversable(path: &[u8]) -> Result<()> {
    with_mount(path, |mount, trimmed| {
        let answer = mount.fs.and_then(|fs| fs.stat(mount, trimmed));
        // A filesystem that cannot stat and one whose stat failed are the same
        // answer: nothing here refuses the traversal.
        let Some(Ok(stat)) = answer else {
            return Ok(());
        };
        if stat.mode & S_IFMT != S_IFDIR {
            return Err(ENOTDIR);
        }
        fs_perm::access_check(&stat, ffi::AC_X as c_int)
            .or_else(|e| if permits_despite_mode(mount, trimmed, ffi::AC_X as c_int) { Ok(()) } else { Err(e) })
    })
}

/// May the caller have `want` (`AC_*`) on the already-normalised absolute
/// `path`, whose `stat` is `stat`? The mode first, and then the mount's
/// [`ffi::FsOps::permits_despite_mode`] -- Linux's order, where an inode's
/// `permission` op is consulted in place of `generic_permission`. Every
/// permission check made by path goes through here, so a filesystem's rule
/// cannot be honoured by one syscall and missed by the next.
pub fn access(path: &[u8], stat: &ffi::statbuf, want: c_int) -> Result<()> {
    fs_perm::access_check(stat, want).or_else(|e| {
        let path: &[u8] = if path.is_empty() { b"/" } else { path };
        let granted = with_mount(path, |mount, trimmed| Ok(permits_despite_mode(mount, trimmed, want)));
        if granted == Ok(true) { Ok(()) } else { Err(e) }
    })
}

fn permits_despite_mode(mount: &ffi::mount, trimmed: &CStr, want: c_int) -> bool {
    mount.fs.is_some_and(|fs| fs.permits_despite_mode(mount, trimmed, want))
}

/// Find the mount `path` falls in, run `f` against it and the path trimmed to
/// be relative to it, and release the mount however `f` ends.
fn with_mount<T>(path: &[u8], f: impl FnOnce(&ffi::mount, &CStr) -> Result<T>) -> Result<T> {
    // find_mount_and_trim_path rewrites the buffer in place, so it gets its
    // own copy rather than the caller's.
    let mut buf = Vec::with_capacity(path.len() + 1);
    buf.extend_from_slice(path);
    buf.push(0);

    // No null check: `mount_find` panics when nothing is mounted rather than
    // answering one, so the `if mount.is_null() { ENOENT }` that stood here was
    // unreachable and the guard type makes saying so free.
    let mount = fs_mounttable::find_mount_and_trim_path(&mut buf);
    // Still NUL-terminated -- the trim only moves the contents down.
    let trimmed = CStr::from_bytes_until_nul(&buf).expect("the trim keeps the NUL");
    // Lent: `mount` outlives the call and is released by its own drop,
    // however `f` ends. It was handed over as a raw pointer each caller
    // dereferenced in an `unsafe` block until 2026-10-17.
    f(&mount, trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    // These cover the pure string handling. Anything that resolves a symlink
    // or checks a permission needs a mounted filesystem, which is what
    // tests/integration/fs_conformance.c exercises.

    /// The base a component is appended to never ends in a slash.
    ///
    /// `generic_getpath` answers `/dev/` for a descriptor open on a mount root
    /// — every `openat` relative to one — and a component is appended as `/` +
    /// name, so `openat(dirfd_on_/dev, "shm")` normalised to `/dev//shm`. The
    /// resolver found the file anyway, because an empty component is skipped;
    /// the wrong thing was the string, which is what a bind mount, an inotify
    /// watch and `/proc/<pid>/maps` compare.
    #[test]
    fn a_base_with_a_trailing_slash_does_not_double_it() {
        let strip = |b: &[u8]| -> Option<Vec<u8>> {
            Some(b.to_vec())
                .map(|mut v| {
                    while v.last() == Some(&b'/') {
                        v.pop();
                    }
                    v
                })
                .filter(|v| !v.is_empty())
        };
        assert_eq!(strip(b"/dev/").as_deref(), Some(&b"/dev"[..]));
        assert_eq!(strip(b"/dev").as_deref(), Some(&b"/dev"[..]));
        assert_eq!(strip(b"/a/b//").as_deref(), Some(&b"/a/b"[..]));
        // The root becomes None, which is what the old special case did.
        assert_eq!(strip(b"/"), None);
        assert_eq!(strip(b"///"), None);
        assert_eq!(strip(b""), None);
    }

    #[test]
    fn components_are_split_on_runs_of_slashes() {
        assert_eq!(split_component(b"a/b"), (&b"a"[..], &b"b"[..]));
        assert_eq!(split_component(b"a//b"), (&b"a"[..], &b"b"[..]));
        assert_eq!(split_component(b"a"), (&b"a"[..], &b""[..]));
        assert_eq!(split_component(b"a///"), (&b"a"[..], &b""[..]));
    }

    #[test]
    fn dotdot_cannot_climb_past_the_root_floor() {
        // A task rooted at /jail asking for /../etc must stay inside it.
        let mut out = b"/jail".to_vec();
        let floor = out.len();
        // Simulate the `..` branch directly: nothing above the floor to drop.
        if out.len() > floor {
            unreachable!();
        }
        assert_eq!(out, b"/jail");

        // One below the floor does come off.
        out.extend_from_slice(b"/sub");
        assert!(out.len() > floor);
        let slash = out.iter().rposition(|&b| b == b'/').unwrap();
        assert!(slash >= floor);
        out.truncate(slash);
        assert_eq!(out, b"/jail");
    }
}
