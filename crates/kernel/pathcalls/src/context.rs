//! Working-directory, chroot, and umask operations.

use super::*;

// ---------------------------------------------------------------------------
// Where the task is
// ---------------------------------------------------------------------------

/// The working directory, reported relative to the task's own root.
///
/// `generic_getpath` answers in the *machine's* terms, and a task rooted at a
/// subtree would otherwise be told its working directory is a path it cannot
/// name — `/jail` for what is its own `/`. That is what Linux does for a
/// chrooted process.
///
/// Two things this must not do. `generic_getpath` answers `"/"` for a task
/// rooted at the machine's own — it repairs an empty result to that — so
/// stripping unconditionally would take the leading slash off every path a
/// normal task reports and turn `/tmp` into `tmp`. And the prefix has to end on
/// a component boundary, or a cwd of `/jail-old` under a root of `/jail` would
/// be reported as `-old`.
///
/// A cwd outside the root is left as it is: it cannot be spelled from inside,
/// but a machine-absolute path is at least true, and there is no reachable way
/// to produce one — `fs_chdir` only stores what this task resolved.
fn relative_to_root(pwd: &[u8], root: &[u8]) -> Vec<u8> {
    if root.len() > 1 && pwd.starts_with(root) && matches!(pwd.get(root.len()), None | Some(b'/')) {
        let rest = &pwd[root.len()..];
        return if rest.is_empty() {
            b"/".to_vec()
        } else {
            rest.to_vec()
        };
    }
    pwd.to_vec()
}

pub fn sys_getcwd(buf_addr: u64, size: u64) -> Result<i64, Errno> {
    strace!("getcwd({buf_addr:#x}, {size:#x})");
    // Both with a reference taken, and the lock released before generic_getpath
    // is called: that dispatches into a filesystem's own getpath, and holding
    // fs->lock across a call into an arbitrary mount is how lock-order
    // inversions get made.
    let (wd, root_fd) = with_context(fsinfo::FsInfo::pwd_and_root);

    let mut pwd = [0u8; MAX_PATH + 1];
    let mut root = [0u8; MAX_PATH + 1];
    // **Both sides ask the same question now.** These were
    // `generic_getpath(as_ptr_or_null(&..))`, and the second was guarded by
    // `root_fd.is_some()` while the first was not -- but `generic_getpath`
    // dereferences its argument on the first line and always did, so a task
    // with no working directory would have read through a null. It takes a
    // borrow, so the `Option` has to be opened, and the asymmetry could not
    // survive being written down.
    //
    // A task with no working directory is not something this kernel makes --
    // `become_first_process` sets one and `chdir` replaces it -- so `ENOENT`
    // here is Linux's answer for a cwd that no longer resolves rather than a
    // case anything reaches.
    let Some(wd_fd) = wd.as_deref() else {
        return Err(Errno::ENOENT);
    };
    let mut err = fs_generic::generic_getpath(wd_fd, &mut pwd);
    if err >= 0
        && let Some(root_dir) = root_fd.as_deref()
    {
        err = fs_generic::generic_getpath(root_dir, &mut root);
    }
    // Both released here, by going out of scope, on this path and the `?` below.
    drop((wd, root_fd));
    done(err)?;

    let out = relative_to_root(ffi::path_bytes(&pwd), ffi::path_bytes(&root));
    // The terminator counts, as it does on Linux: getcwd answers the length of
    // the string *including* the NUL, and ERANGE when the buffer cannot hold
    // that much.
    let needed = out.len() + 1;
    if needed > size as usize {
        return Err(Errno::ERANGE);
    }
    let mut with_nul = out;
    with_nul.push(0);
    strace!(" {:?}", String::from_utf8_lossy(&with_nul[..needed - 1]));
    if GuestMem.write(buf_addr, &with_nul) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(needed as i64)
}

/// A directory to become the working directory or the root.
///
/// Refused unless it *is* a directory: `chdir` to a regular file is `ENOTDIR`,
/// and the open below would otherwise succeed and leave the task resolving
/// relative paths against a file.
fn open_dir(path: &Path) -> Result<fs_fdobj::Owned, Errno> {
    let mut st = ffi::statbuf::default();
    done(fs_generic::generic_statat(ffi::At::Pwd, path.as_cstr(), &mut st, true))?;
    if st.mode & ffi::S_IFDIR == 0 {
        return Err(Errno::ENOTDIR);
    }
    // `generic_openat`, not the `iul.h` entry point beside it: this is a Rust
    // caller and the layer below answers a `Result`.
    fs_generic::generic_openat(ffi::At::Pwd, path.as_cstr(), ffi::O_RDONLY_ as c_int, 0)
}

pub fn sys_chdir(path_addr: u64) -> Result<(), Errno> {
    let path = Path::read(path_addr)?;
    strace!("chdir({:?})", path.as_str());
    let dir = open_dir(&path)?;
    with_context(|fs| fs.chdir(dir));
    Ok(())
}

pub fn sys_fchdir(f: c_int) -> Result<(), Errno> {
    strace!("fchdir({f})");
    let dir = fs_fdobj::f_get(f).ok_or(Errno::EBADF)?;
    // It has to *be* a directory. This took any descriptor and answered 0, so
    // `fchdir` on `/dev/null` or on a regular file reported success and left the
    // working directory pointing at a file -- after which every relative path
    // resolved against something that cannot be walked. `chdir` could not do
    // this, because it resolves a path and the walk refuses; `fchdir` skips the
    // walk, which is the whole point of it.
    if dir.type_ as u32 & ffi::S_IFMT != ffi::S_IFDIR {
        return Err(Errno::ENOTDIR);
    }
    // f_get's reference belongs to the syscall and is released when it returns,
    // so the context needs one of its own.
    with_context(|fs| fs.chdir(dir.retain()));
    Ok(())
}

pub fn sys_chroot(path_addr: u64) -> Result<(), Errno> {
    // CAP_SYS_CHROOT on Linux. Unchecked, this was not only a missing rule: an
    // unprivileged process being able to chroot is the classic way *out* of a
    // chroot -- make a subdirectory, chroot into it, and `..` walks past the
    // old root. A confinement this kernel can be asked to apply could be undone
    // by the process it was applied to.
    if !taskview::capable(taskview::caps::CAP_SYS_CHROOT) {
        return Err(Errno::EPERM);
    }
    let path = Path::read(path_addr)?;
    strace!("chroot({:?})", path.as_str());
    let dir = open_dir(&path)?;
    with_context(|fs| fs.chroot(dir));
    Ok(())
}

/// The **previous** umask, and it cannot fail: every mode word is a legal
/// answer, which is why Linux gives this no error return either.
pub fn sys_umask(mask: c_uint) -> u32 {
    strace!("umask({mask:#o})");
    with_context(|fs| fs.set_umask(mask))
}

#[cfg(test)]
mod tests {
    use super::relative_to_root;

    #[test]
    fn root_path_becomes_guest_root() {
        assert_eq!(relative_to_root(b"/jail", b"/jail"), b"/");
    }

    #[test]
    fn descendant_loses_only_the_root_prefix() {
        assert_eq!(relative_to_root(b"/jail/tmp", b"/jail"), b"/tmp");
    }

    #[test]
    fn component_prefix_is_not_stripped() {
        assert_eq!(
            relative_to_root(b"/jail-old/tmp", b"/jail"),
            b"/jail-old/tmp"
        );
    }

    #[test]
    fn outside_root_is_preserved() {
        assert_eq!(relative_to_root(b"/other", b"/jail"), b"/other");
    }
}
