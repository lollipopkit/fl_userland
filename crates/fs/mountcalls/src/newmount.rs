//! `pivot_root(2)` and Linux 5.2+ new mount API (`fsopen`/`fsconfig`/`fsmount`/
//! `fspick`/`open_tree`/`open_tree_attr`/`move_mount`/`mount_setattr`).

use std::ffi::{CStr, c_int};
use std::sync::Mutex;

use guest_errno::Errno;
use strace::strace;
use usercopy::GuestMem;

use crate::{as_str, cstr, ffi, fs_by_name, read_path};

const AT_FDCWD: c_int = -100;
const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
const AT_EMPTY_PATH: u32 = 0x1000;
const AT_RECURSIVE: u32 = 0x8000;

const FSOPEN_CLOEXEC: u32 = 0x0000_0001;
const FSMOUNT_CLOEXEC: u32 = 0x0000_0001;
const FSPICK_CLOEXEC: u32 = 0x0000_0008;
const FSPICK_SYMLINK_NOFOLLOW: u32 = 0x0000_0001;
const FSPICK_NO_AUTOMOUNT: u32 = 0x0000_0002;
const FSPICK_EMPTY_PATH: u32 = 0x0000_0004;

const OPEN_TREE_CLONE: u32 = 1;
const OPEN_TREE_CLOEXEC: u32 = ffi::O_CLOEXEC_ as u32;

const MOVE_MOUNT_F_SYMLINKS: u32 = 0x0000_0001;
const MOVE_MOUNT_F_AUTOMOUNTS: u32 = 0x0000_0002;
const MOVE_MOUNT_F_EMPTY_PATH: u32 = 0x0000_0004;
const MOVE_MOUNT_T_SYMLINKS: u32 = 0x0000_0010;
const MOVE_MOUNT_T_AUTOMOUNTS: u32 = 0x0000_0020;
const MOVE_MOUNT_T_EMPTY_PATH: u32 = 0x0000_0040;
const MOVE_MOUNT_SET_GROUP: u32 = 0x0000_0100;
const MOVE_MOUNT_BENEATH: u32 = 0x0000_0200;
const MOVE_MOUNT_ALL_FLAGS: u32 = MOVE_MOUNT_F_SYMLINKS
    | MOVE_MOUNT_F_AUTOMOUNTS
    | MOVE_MOUNT_F_EMPTY_PATH
    | MOVE_MOUNT_T_SYMLINKS
    | MOVE_MOUNT_T_AUTOMOUNTS
    | MOVE_MOUNT_T_EMPTY_PATH
    | MOVE_MOUNT_SET_GROUP
    | MOVE_MOUNT_BENEATH;

const FSCONFIG_SET_FLAG: u32 = 0;
const FSCONFIG_SET_STRING: u32 = 1;
const FSCONFIG_SET_BINARY: u32 = 2;
const FSCONFIG_SET_PATH: u32 = 3;
const FSCONFIG_SET_PATH_EMPTY: u32 = 4;
const FSCONFIG_SET_FD: u32 = 5;
const FSCONFIG_CMD_CREATE: u32 = 6;
const FSCONFIG_CMD_RECONFIGURE: u32 = 7;
const FSCONFIG_CMD_CREATE_EXCL: u32 = 8;

const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
const MOUNT_ATTR_NOSUID: u64 = 0x0000_0002;
const MOUNT_ATTR_NODEV: u64 = 0x0000_0004;
const MOUNT_ATTR_NOEXEC: u64 = 0x0000_0008;
const MOUNT_ATTR_SUPPORTED: u64 =
    MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC;
const MOUNT_ATTR_ALL: u64 = MOUNT_ATTR_SUPPORTED
    | 0x0000_0070 // atime bits
    | 0x0000_0080 // nodiratime
    | 0x0010_0000 // idmap
    | 0x0020_0000; // nosymfollow

const MOUNT_ATTR_SIZE_VER0: usize = 32;

#[derive(Clone, Debug)]
struct FsContextInner {
    fs_name: String,
    source: String,
    options: Vec<String>,
    created: bool,
    reconfiguring: bool,
}

struct FsContextState {
    inner: Mutex<FsContextInner>,
}

struct FsContextOps;

impl ffi::FdOps for FsContextOps {
    fn caps(&self) -> ffi::Caps {
        ffi::Caps::default()
    }
    fn close(&self, fd: &mut ffi::fd) -> c_int {
        drop(fd.take_driver_state::<FsContextState>());
        0
    }
}

static FSCONTEXT_OPS: FsContextOps = FsContextOps;

#[derive(Clone, Debug)]
struct MountTreeInner {
    fs_name: String,
    source: String,
    target: String,
    options: Vec<String>,
    mount_flags: c_int,
    attached: bool,
}

struct MountTreeState {
    inner: Mutex<MountTreeInner>,
}

struct MountTreeOps;

impl ffi::FdOps for MountTreeOps {
    fn caps(&self) -> ffi::Caps {
        ffi::Caps::default()
    }
    fn show_fdinfo(&self, fd: &ffi::fd, out: &mut String) {
        if let Some(state) = fd.driver_state::<MountTreeState>() {
            let target = state.inner.lock().unwrap_or_else(|e| e.into_inner()).target.clone();
            out.push_str(&format!("mnt_target:\t{target}\n"));
        }
    }
    fn close(&self, fd: &mut ffi::fd) -> c_int {
        drop(fd.take_driver_state::<MountTreeState>());
        0
    }
}

static MOUNTTREE_OPS: MountTreeOps = MountTreeOps;

fn require_cap_sys_admin() -> Result<(), Errno> {
    if !taskview::capable(taskview::caps::CAP_SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    Ok(())
}

fn read_short_cstr(addr: u64, max: usize) -> Result<String, Errno> {
    if addr == 0 {
        return Err(Errno::EFAULT);
    }
    let mut buf = vec![0u8; max];
    let err = mmapcalls::usermem::read_current_string(addr, &mut buf);
    if err < 0 {
        return Err(Errno::from_negative_or_eio(err));
    }
    Ok(String::from_utf8_lossy(as_str(&buf)).into_owned())
}

fn resolve_dirfd_path(
    dfd: c_int,
    path_addr: u64,
    follow: bool,
    allow_empty: bool,
) -> Result<(Vec<u8>, bool), Errno> {
    if path_addr == 0 {
        return Err(Errno::EFAULT);
    }
    let raw = read_path(path_addr)?;
    let raw_bytes = cstr(&raw).to_bytes();

    if raw_bytes.is_empty() {
        if !allow_empty {
            return Err(Errno::ENOENT);
        }
        if dfd == AT_FDCWD {
            let mut pwd_buf = vec![0u8; ffi::MAX_PATH as usize + 1];
            let Some(pwd) = taskview::with_current_fs(|fs| fs.pwd_and_root().0).flatten() else {
                return Err(Errno::ENOENT);
            };
            if pwd.unnamed.is_some() {
                return Err(Errno::EINVAL);
            }
            let err = fs_generic::generic_getpath(&pwd, &mut pwd_buf);
            if err < 0 {
                return Err(Errno::from_negative_or_eio(err));
            }
            let len = pwd_buf.iter().position(|&b| b == 0).unwrap_or(pwd_buf.len());
            if !pwd_buf.starts_with(b"/") {
                return Err(Errno::EINVAL);
            }
            pwd_buf.truncate(len + 1);
            let is_dir = (u32::from(pwd.type_) & ffi::S_IFMT) == ffi::S_IFDIR;
            return Ok((pwd_buf, is_dir));
        }
        let dir_fd = fs_fdobj::f_get(dfd).ok_or(Errno::EBADF)?;
        if dir_fd.unnamed.is_some() {
            return Err(Errno::EINVAL);
        }
        let mut path_buf = vec![0u8; ffi::MAX_PATH as usize + 1];
        let err = fs_generic::generic_getpath(&dir_fd, &mut path_buf);
        if err < 0 {
            return Err(Errno::from_negative_or_eio(err));
        }
        let len = path_buf.iter().position(|&b| b == 0).unwrap_or(path_buf.len());
        if !path_buf.starts_with(b"/") {
            return Err(Errno::EINVAL);
        }
        path_buf.truncate(len + 1);
        let is_dir = (u32::from(dir_fd.type_) & ffi::S_IFMT) == ffi::S_IFDIR;
        return Ok((path_buf, is_dir));
    }

    let dir_owned = if dfd == AT_FDCWD || raw_bytes.starts_with(b"/") {
        None
    } else {
        Some(fs_fdobj::f_get(dfd).ok_or(Errno::EBADF)?)
    };
    let at = match dir_owned.as_deref() {
        Some(fd) => ffi::At::Fd(fd),
        None => ffi::At::Pwd,
    };
    let flags = if follow {
        ffi::N_SYMLINK_FOLLOW
    } else {
        ffi::N_SYMLINK_NOFOLLOW
    };
    let mut stat = ffi::statbuf::default();
    let err = fs_generic::generic_statat(at, cstr(&raw), &mut stat, follow);
    if err < 0 {
        return Err(Errno::from_negative_or_eio(err));
    }
    let is_dir = (stat.mode & ffi::S_IFMT) == ffi::S_IFDIR;
    let mut path = fs_generic::normalize::resolve(at, raw_bytes, flags as c_int)
        .map_err(Errno::from_negative_or_eio)?
        .path;
    path.push(0);
    Ok((path, is_dir))
}

fn path_is_within(child: &[u8], parent: &[u8]) -> bool {
    let child = cstr(child).to_bytes();
    let parent = cstr(parent).to_bytes();
    if parent == b"/" {
        return child.starts_with(b"/");
    }
    child == parent || (child.starts_with(parent) && child.get(parent.len()) == Some(&b'/'))
}

fn install_anon(
    ops: &'static dyn ffi::FdOps,
    name: &'static CStr,
    cloexec: bool,
    state: impl std::any::Any + Send + Sync + 'static,
) -> Result<i64, Errno> {
    let mut fd = fs_adhoc::adhoc_anon(Some(ops), Some(name));
    fd.set_driver_state(Box::new(state));
    let flags = if cloexec { ffi::O_CLOEXEC_ as c_int } else { 0 };
    Errno::split(fs_fdobj::f_install(fd.into_owned(), flags) as i64)
}

fn mount_point_cstr(resolved: &[u8]) -> &CStr {
    let cs = cstr(resolved);
    if cs.to_bytes() == b"/" {
        c""
    } else {
        cs
    }
}

fn resolve_mount_spec(
    fs_name: Option<String>,
    point: &[u8],
    source_bytes: &[u8],
    lookup_bytes: &[u8],
    want_clone: bool,
) -> Result<(String, String), Errno> {
    let fs_name = fs_name.ok_or(Errno::EINVAL)?;
    let rel = lookup_bytes.strip_prefix(point).unwrap_or(b"");
    if want_clone {
        if fs_name == "tmpfs" {
            return Err(Errno::EOPNOTSUPP);
        }
        if !rel.is_empty() && fs_name != "realfs" {
            return Err(Errno::EINVAL);
        }
    }
    let base_source = String::from_utf8_lossy(source_bytes).into_owned();
    let source = if !rel.is_empty() && fs_name == "realfs" {
        format!(
            "{}{}",
            base_source.trim_end_matches('/'),
            String::from_utf8_lossy(rel)
        )
    } else {
        base_source
    };
    Ok((fs_name, source))
}

fn resolve_existing_mount(resolved: &[u8], want_clone: bool) -> Result<(String, String), Errno> {
    let lookup = mount_point_cstr(resolved);
    let mnt = fs_mounttable::mount_find(lookup);
    resolve_mount_spec(
        mnt.fs
            .and_then(|fs| fs.name())
            .map(|n| String::from_utf8_lossy(n.to_bytes()).into_owned()),
        mnt.point.to_bytes(),
        mnt.source.to_bytes(),
        lookup.to_bytes(),
        want_clone,
    )
}

fn apply_mount_attr_flags(cur: c_int, set_ms: c_int, clr_ms: c_int) -> c_int {
    (cur & !clr_ms) | set_ms
}

fn mount_attrs_to_ms_flags(attr_set: u64) -> c_int {
    let mut flags: u32 = 0;
    if attr_set & MOUNT_ATTR_RDONLY != 0 {
        flags |= ffi::MS_READONLY_;
    }
    if attr_set & MOUNT_ATTR_NOSUID != 0 {
        flags |= ffi::MS_NOSUID_;
    }
    if attr_set & MOUNT_ATTR_NODEV != 0 {
        flags |= ffi::MS_NODEV_;
    }
    if attr_set & MOUNT_ATTR_NOEXEC != 0 {
        flags |= ffi::MS_NOEXEC_;
    }
    flags as c_int
}

fn validate_mount_attr_bits(attr_set: u64, attr_clr: u64) -> Result<(c_int, c_int), Errno> {
    let combined = attr_set | attr_clr;
    if combined & !MOUNT_ATTR_ALL != 0 {
        return Err(Errno::EINVAL);
    }
    if combined & !MOUNT_ATTR_SUPPORTED != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    Ok((
        mount_attrs_to_ms_flags(attr_set),
        mount_attrs_to_ms_flags(attr_clr),
    ))
}

fn validate_move_mount_flags(flags: u32) -> Result<(), Errno> {
    if flags & !MOVE_MOUNT_ALL_FLAGS != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & (MOVE_MOUNT_SET_GROUP | MOVE_MOUNT_BENEATH) != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    Ok(())
}

pub fn sys_pivot_root(new_root_addr: u64, put_old_addr: u64) -> Result<(), Errno> {
    require_cap_sys_admin()?;
    let new_root_raw = read_path(new_root_addr)?;
    let put_old_raw = read_path(put_old_addr)?;
    strace!(
        "pivot_root({:?}, {:?})",
        String::from_utf8_lossy(as_str(&new_root_raw)),
        String::from_utf8_lossy(as_str(&put_old_raw))
    );

    let (new_root_resolved, new_is_dir) = resolve_dirfd_path(AT_FDCWD, new_root_addr, true, false)?;
    let (put_old_resolved, old_is_dir) = resolve_dirfd_path(AT_FDCWD, put_old_addr, true, false)?;
    if !new_is_dir || !old_is_dir {
        return Err(Errno::ENOTDIR);
    }
    if !path_is_within(&put_old_resolved, &new_root_resolved) {
        return Err(Errno::EINVAL);
    }

    let dir = fs_generic::generic_openat(
        ffi::At::Pwd,
        cstr(&new_root_raw),
        ffi::O_RDONLY_ as c_int,
        0,
    )?;
    let pwd_dir = fs_generic::generic_openat(
        ffi::At::Pwd,
        cstr(&new_root_raw),
        ffi::O_RDONLY_ as c_int,
        0,
    )?;
    taskview::with_current_fs(|fs| {
        fs.chroot(dir);
        fs.chdir(pwd_dir);
    });
    Ok(())
}

pub fn sys_fsopen(fs_name_addr: u64, flags: u32) -> Result<i64, Errno> {
    require_cap_sys_admin()?;
    if flags & !FSOPEN_CLOEXEC != 0 {
        return Err(Errno::EINVAL);
    }
    let fs_name = read_short_cstr(fs_name_addr, 128)?;
    strace!("fsopen({fs_name:?}, {flags:#x})");
    if fs_by_name(fs_name.as_bytes()).is_none() {
        return Err(Errno::ENODEV);
    }
    install_anon(
        &FSCONTEXT_OPS,
        c"[fscontext]",
        flags & FSOPEN_CLOEXEC != 0,
        FsContextState {
            inner: Mutex::new(FsContextInner {
                fs_name,
                source: String::new(),
                options: Vec::new(),
                created: false,
                reconfiguring: false,
            }),
        },
    )
}

pub fn sys_fspick(dfd: c_int, path_addr: u64, flags: u32) -> Result<i64, Errno> {
    require_cap_sys_admin()?;
    let allowed = FSPICK_CLOEXEC | FSPICK_SYMLINK_NOFOLLOW | FSPICK_NO_AUTOMOUNT | FSPICK_EMPTY_PATH;
    if flags & !allowed != 0 {
        return Err(Errno::EINVAL);
    }
    let (resolved, _) = resolve_dirfd_path(
        dfd,
        path_addr,
        flags & FSPICK_SYMLINK_NOFOLLOW == 0,
        flags & FSPICK_EMPTY_PATH != 0,
    )?;
    let target = String::from_utf8_lossy(cstr(&resolved).to_bytes()).into_owned();
    let (fs_name, source) = resolve_existing_mount(&resolved, false)?;
    strace!("fspick({dfd}, {target:?}, {flags:#x})");
    install_anon(
        &FSCONTEXT_OPS,
        c"[fscontext]",
        flags & FSPICK_CLOEXEC != 0,
        FsContextState {
            inner: Mutex::new(FsContextInner {
                fs_name,
                source,
                options: Vec::new(),
                created: false,
                reconfiguring: true,
            }),
        },
    )
}

pub fn sys_fsconfig(
    fs_fd: c_int,
    cmd: u32,
    key_addr: u64,
    value_addr: u64,
    aux: c_int,
) -> Result<(), Errno> {
    require_cap_sys_admin()?;
    let fd = fs_fdobj::f_get(fs_fd).ok_or(Errno::EBADF)?;
    let state = fd
        .driver_state::<FsContextState>()
        .ok_or(Errno::EINVAL)?;
    let mut inner = state.inner.lock().unwrap_or_else(|e| e.into_inner());

    match cmd {
        FSCONFIG_SET_FLAG => {
            if inner.created {
                return Err(Errno::EBUSY);
            }
            if value_addr != 0 || aux != 0 {
                return Err(Errno::EINVAL);
            }
            let key = read_short_cstr(key_addr, 256)?;
            if !key.is_empty() {
                inner.options.push(key);
            }
            Ok(())
        }
        FSCONFIG_SET_STRING => {
            if inner.created {
                return Err(Errno::EBUSY);
            }
            if aux != 0 {
                return Err(Errno::EINVAL);
            }
            let key = read_short_cstr(key_addr, 256)?;
            let val = read_short_cstr(value_addr, 1024)?;
            if key == "source" {
                inner.source = val;
            } else {
                inner.options.push(format!("{key}={val}"));
            }
            Ok(())
        }
        FSCONFIG_SET_BINARY => {
            if inner.created {
                return Err(Errno::EBUSY);
            }
            if aux <= 0 || aux > 4096 {
                return Err(Errno::EINVAL);
            }
            let key = read_short_cstr(key_addr, 256)?;
            let mut raw = vec![0u8; aux as usize];
            if GuestMem::current().read(value_addr, &mut raw) < 0 {
                return Err(Errno::EFAULT);
            }
            inner
                .options
                .push(format!("{key}=<binary:{}>", raw.len()));
            Ok(())
        }
        FSCONFIG_SET_PATH | FSCONFIG_SET_PATH_EMPTY => {
            if inner.created {
                return Err(Errno::EBUSY);
            }
            let key = read_short_cstr(key_addr, 256)?;
            let (resolved, _) = resolve_dirfd_path(
                aux,
                value_addr,
                true,
                cmd == FSCONFIG_SET_PATH_EMPTY,
            )?;
            let path = String::from_utf8_lossy(cstr(&resolved).to_bytes()).into_owned();
            if key == "source" {
                inner.source = path;
            } else {
                inner.options.push(format!("{key}={path}"));
            }
            Ok(())
        }
        FSCONFIG_SET_FD => {
            if inner.created {
                return Err(Errno::EBUSY);
            }
            if value_addr != 0 {
                return Err(Errno::EINVAL);
            }
            let _ = fs_fdobj::f_get(aux).ok_or(Errno::EBADF)?;
            let key = read_short_cstr(key_addr, 256)?;
            inner.options.push(format!("{key}=fd:{aux}"));
            Ok(())
        }
        FSCONFIG_CMD_CREATE | FSCONFIG_CMD_CREATE_EXCL => {
            if key_addr != 0 || value_addr != 0 || aux != 0 {
                return Err(Errno::EINVAL);
            }
            if inner.created || inner.reconfiguring {
                return Err(Errno::EBUSY);
            }
            inner.created = true;
            Ok(())
        }
        FSCONFIG_CMD_RECONFIGURE => {
            if key_addr != 0 || value_addr != 0 || aux != 0 {
                return Err(Errno::EINVAL);
            }
            if !inner.created && !inner.reconfiguring {
                return Err(Errno::EINVAL);
            }
            Err(Errno::EOPNOTSUPP)
        }
        _ => Err(Errno::EINVAL),
    }
}

pub fn sys_fsmount(fs_fd: c_int, flags: u32, attr_flags: u32) -> Result<i64, Errno> {
    require_cap_sys_admin()?;
    if flags & !FSMOUNT_CLOEXEC != 0 {
        return Err(Errno::EINVAL);
    }
    let (mount_flags, _) = validate_mount_attr_bits(attr_flags as u64, 0)?;
    let fd = fs_fdobj::f_get(fs_fd).ok_or(Errno::EBADF)?;
    let state = fd
        .driver_state::<FsContextState>()
        .ok_or(Errno::EINVAL)?;
    let snapshot = {
        let inner = state.inner.lock().unwrap_or_else(|e| e.into_inner());
        if !inner.created {
            return Err(Errno::EINVAL);
        }
        inner.clone()
    };
    let source = if snapshot.source.is_empty() {
        snapshot.fs_name.clone()
    } else {
        snapshot.source
    };
    install_anon(
        &MOUNTTREE_OPS,
        c"[mnt]",
        flags & FSMOUNT_CLOEXEC != 0,
        MountTreeState {
            inner: Mutex::new(MountTreeInner {
                fs_name: snapshot.fs_name,
                source,
                target: String::from("/"),
                options: snapshot.options,
                mount_flags,
                attached: false,
            }),
        },
    )
}

pub fn sys_open_tree(dfd: c_int, filename_addr: u64, flags: u32) -> Result<i64, Errno> {
    sys_open_tree_attr(dfd, filename_addr, flags, 0, 0)
}

pub fn sys_open_tree_attr(
    dfd: c_int,
    filename_addr: u64,
    flags: u32,
    uattr_addr: u64,
    usize_: usize,
) -> Result<i64, Errno> {
    let allowed = OPEN_TREE_CLONE
        | OPEN_TREE_CLOEXEC
        | AT_EMPTY_PATH
        | AT_SYMLINK_NOFOLLOW
        | AT_RECURSIVE;
    if flags & !allowed != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & OPEN_TREE_CLONE != 0 {
        require_cap_sys_admin()?;
    }
    let attr_flags = if uattr_addr != 0 || usize_ != 0 {
        let (set_ms, clr_ms) = read_mount_attr(uattr_addr, usize_)?;
        set_ms & !clr_ms
    } else {
        0
    };
    let (resolved, _) = resolve_dirfd_path(
        dfd,
        filename_addr,
        flags & AT_SYMLINK_NOFOLLOW == 0,
        flags & AT_EMPTY_PATH != 0,
    )?;
    let target = String::from_utf8_lossy(cstr(&resolved).to_bytes()).into_owned();
    let (fs_name, source) = resolve_existing_mount(&resolved, flags & OPEN_TREE_CLONE != 0)?;
    strace!("open_tree_attr({dfd}, {target:?}, {flags:#x})");

    install_anon(
        &MOUNTTREE_OPS,
        c"[mnt]",
        flags & OPEN_TREE_CLOEXEC != 0,
        MountTreeState {
            inner: Mutex::new(MountTreeInner {
                fs_name,
                source,
                target,
                options: Vec::new(),
                mount_flags: attr_flags,
                attached: flags & OPEN_TREE_CLONE == 0,
            }),
        },
    )
}

pub fn sys_move_mount(
    from_dfd: c_int,
    from_pathname_addr: u64,
    to_dfd: c_int,
    to_pathname_addr: u64,
    flags: u32,
) -> Result<(), Errno> {
    require_cap_sys_admin()?;
    validate_move_mount_flags(flags)?;

    let (to_resolved, to_is_dir) = resolve_dirfd_path(
        to_dfd,
        to_pathname_addr,
        flags & MOVE_MOUNT_T_SYMLINKS != 0,
        flags & MOVE_MOUNT_T_EMPTY_PATH != 0,
    )?;
    if !to_is_dir {
        return Err(Errno::ENOTDIR);
    }

    if flags & MOVE_MOUNT_F_EMPTY_PATH != 0
        && from_dfd >= 0
        && cstr(&read_path(from_pathname_addr)?).to_bytes().is_empty()
    {
        if let Some(fd) = fs_fdobj::f_get(from_dfd) {
            if let Some(tree) = fd.driver_state::<MountTreeState>() {
                let mut inner = tree.inner.lock().unwrap_or_else(|e| e.into_inner());
                if inner.attached {
                    return Err(Errno::EOPNOTSUPP);
                }
                let fs = fs_by_name(inner.fs_name.as_bytes()).ok_or(Errno::ENODEV)?;
                let mut src = inner.source.as_bytes().to_vec();
                src.push(0);
                let data_str = inner.options.join(",");
                let mut data = data_str.into_bytes();
                data.push(0);
                let mount_res = fs_mount::mount(
                    fs.0,
                    cstr(&src),
                    mount_point_cstr(&to_resolved),
                    cstr(&data),
                    inner.mount_flags,
                );
                if let Err(err) = mount_res {
                    return Err(Errno::from_negative_or_eio(err));
                }
                inner.target =
                    String::from_utf8_lossy(cstr(&to_resolved).to_bytes()).into_owned();
                inner.attached = true;
                return Ok(());
            }
        }
    }

    let (from_resolved, _) = resolve_dirfd_path(
        from_dfd,
        from_pathname_addr,
        flags & MOVE_MOUNT_F_SYMLINKS != 0,
        flags & MOVE_MOUNT_F_EMPTY_PATH != 0,
    )?;
    let lookup = mount_point_cstr(&from_resolved);
    let mnt = fs_mounttable::mount_find(lookup);
    if mnt.point.to_bytes() != lookup.to_bytes() {
        return Err(Errno::EINVAL);
    }
    Err(Errno::EOPNOTSUPP)
}

fn read_mount_attr(uattr_addr: u64, usize_: usize) -> Result<(c_int, c_int), Errno> {
    if usize_ < MOUNT_ATTR_SIZE_VER0 || usize_ > 4096 {
        return Err(Errno::EINVAL);
    }
    if uattr_addr == 0 {
        return Err(Errno::EFAULT);
    }
    let mut buf = vec![0u8; usize_];
    if GuestMem::current().read(uattr_addr, &mut buf) < 0 {
        return Err(Errno::EFAULT);
    }
    if buf[MOUNT_ATTR_SIZE_VER0..].iter().any(|&b| b != 0) {
        return Err(Errno::E2BIG);
    }
    let attr_set = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let attr_clr = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    validate_mount_attr_bits(attr_set, attr_clr)
}

pub fn sys_mount_setattr(
    dfd: c_int,
    path_addr: u64,
    flags: u32,
    uattr_addr: u64,
    usize_: usize,
) -> Result<(), Errno> {
    require_cap_sys_admin()?;
    let allowed = AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW | AT_RECURSIVE | 0x0800; // AT_NO_AUTOMOUNT
    if flags & !allowed != 0 {
        return Err(Errno::EINVAL);
    }
    let (set_ms, clr_ms) = read_mount_attr(uattr_addr, usize_)?;
    let raw_path = read_path(path_addr)?;
    if flags & AT_EMPTY_PATH != 0 && dfd >= 0 && cstr(&raw_path).to_bytes().is_empty() {
        if let Some(fd) = fs_fdobj::f_get(dfd) {
            if let Some(tree) = fd.driver_state::<MountTreeState>() {
                let mut inner = tree.inner.lock().unwrap_or_else(|e| e.into_inner());
                if inner.attached {
                    if (set_ms | clr_ms) != 0 {
                        return Err(Errno::EOPNOTSUPP);
                    }
                    return Ok(());
                }
                inner.mount_flags = apply_mount_attr_flags(inner.mount_flags, set_ms, clr_ms);
                return Ok(());
            }
        }
    }
    let (_, _) = resolve_dirfd_path(
        dfd,
        path_addr,
        flags & AT_SYMLINK_NOFOLLOW == 0,
        flags & AT_EMPTY_PATH != 0,
    )?;
    if (set_ms | clr_ms) != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_containment_checks_component_boundary() {
        assert!(path_is_within(b"/new/old\0", b"/new\0"));
        assert!(path_is_within(b"/new\0", b"/new\0"));
        assert!(path_is_within(b"/anything\0", b"/\0"));
        assert!(!path_is_within(b"/new2/old\0", b"/new\0"));
        assert!(!path_is_within(b"/old\0", b"/new\0"));
    }

    #[test]
    fn mount_attr_conversion_maps_expected_ms_bits() {
        let flags = mount_attrs_to_ms_flags(MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOEXEC);
        assert_ne!(flags & ffi::MS_READONLY_ as c_int, 0);
        assert_ne!(flags & ffi::MS_NOEXEC_ as c_int, 0);
        assert_eq!(flags & ffi::MS_NOSUID_ as c_int, 0);

        let updated = apply_mount_attr_flags(
            flags,
            mount_attrs_to_ms_flags(MOUNT_ATTR_NOSUID),
            mount_attrs_to_ms_flags(MOUNT_ATTR_NOEXEC),
        );
        assert_ne!(updated & ffi::MS_READONLY_ as c_int, 0);
        assert_ne!(updated & ffi::MS_NOSUID_ as c_int, 0);
        assert_eq!(updated & ffi::MS_NOEXEC_ as c_int, 0);
    }

    #[test]
    fn mount_resolution_handles_realfs_subdirs_and_special_fs() {
        assert_eq!(
            resolve_mount_spec(
                Some("realfs".into()),
                b"",
                b"/host/root/",
                b"/var/lib",
                true,
            ),
            Ok(("realfs".into(), "/host/root/var/lib".into()))
        );
        assert_eq!(
            resolve_mount_spec(
                Some("proc".into()),
                b"/proc",
                b"proc",
                b"/proc",
                false,
            ),
            Ok(("proc".into(), "proc".into()))
        );
        assert_eq!(
            resolve_mount_spec(
                Some("proc".into()),
                b"/proc",
                b"proc",
                b"/proc/self",
                true,
            ),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            resolve_mount_spec(
                Some("tmpfs".into()),
                b"/tmp",
                b"tmpfs",
                b"/tmp",
                true,
            ),
            Err(Errno::EOPNOTSUPP)
        );
    }

    #[test]
    fn mount_attr_validation_rejects_unknown_and_unsupported_bits() {
        assert_eq!(validate_mount_attr_bits(1u64 << 60, 0), Err(Errno::EINVAL));
        for unsupported in [0x80u64, 0x0010_0000, 0x0020_0000, 0x10] {
            assert_eq!(validate_mount_attr_bits(unsupported, 0), Err(Errno::EOPNOTSUPP));
            assert_eq!(validate_mount_attr_bits(0, unsupported), Err(Errno::EOPNOTSUPP));
        }
        assert_eq!(
            validate_mount_attr_bits(MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOEXEC, MOUNT_ATTR_NOSUID),
            Ok((
                (ffi::MS_READONLY_ | ffi::MS_NOEXEC_) as c_int,
                ffi::MS_NOSUID_ as c_int,
            ))
        );
        assert_eq!(validate_move_mount_flags(1 << 30), Err(Errno::EINVAL));
        assert_eq!(validate_move_mount_flags(MOVE_MOUNT_BENEATH), Err(Errno::EOPNOTSUPP));
        assert_eq!(validate_move_mount_flags(MOVE_MOUNT_SET_GROUP), Err(Errno::EOPNOTSUPP));
        assert_eq!(validate_move_mount_flags(MOVE_MOUNT_F_EMPTY_PATH), Ok(()));
    }
}
