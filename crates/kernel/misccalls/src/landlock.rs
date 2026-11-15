//! Landlock LSM syscalls (`landlock_create_ruleset`, `landlock_add_rule`,
//! `landlock_restrict_self`) implementing ABI v3 path-access enforcement on `open*`.

use std::any::Any;
use std::cell::RefCell;
use std::ffi::c_int;
use std::sync::{Arc, Mutex};

use guest_errno::Errno;
use strace::strace;
use taskview::ffi;
use usercopy::GuestMem;

const LANDLOCK_ABI_VERSION: i64 = 3;
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
const LANDLOCK_CREATE_RULESET_ERRATA: u32 = 1 << 1;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
const LANDLOCK_ACCESS_FS_FILE_MASK: u64 = LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_TRUNCATE;
const LANDLOCK_ACCESS_FS_SUPPORTED: u64 = (1 << 15) - 1;
const MAX_LANDLOCK_LAYERS: usize = 16;

#[derive(Clone, Debug)]
struct PathRule {
    prefix: Vec<u8>,
    allowed_access: u64,
}

#[derive(Clone, Debug)]
struct RulesetInner {
    handled_access_fs: u64,
    rules: Vec<PathRule>,
}

struct RulesetState {
    inner: Mutex<RulesetInner>,
}

struct RulesetOps;

impl ffi::FdOps for RulesetOps {
    fn caps(&self) -> ffi::Caps {
        ffi::Caps::default()
    }
    fn close(&self, fd: &mut ffi::fd) -> c_int {
        drop(fd.take_driver_state::<RulesetState>());
        0
    }
}

static RULESET_OPS: RulesetOps = RulesetOps;

thread_local! {
    static TEST_DOMAINS: RefCell<Option<Arc<Vec<RulesetInner>>>> = const { RefCell::new(None) };
}

fn current_domains() -> Option<Arc<Vec<RulesetInner>>> {
    match taskview::with_current_task(|t| t.landlock_domains()) {
        Some(maybe_any) => maybe_any.and_then(|any| any.downcast::<Vec<RulesetInner>>().ok()),
        None => TEST_DOMAINS.with(|cell| cell.borrow().clone()),
    }
}

fn push_domain_layer(layer: RulesetInner) -> Result<(), Errno> {
    if let Some(res) = taskview::with_current_task(|t| {
        let mut layers = t
            .landlock_domains()
            .and_then(|any| any.downcast::<Vec<RulesetInner>>().ok())
            .map(|arc| (*arc).clone())
            .unwrap_or_default();
        if layers.len() >= MAX_LANDLOCK_LAYERS {
            return Err(Errno::E2BIG);
        }
        layers.push(layer.clone());
        let next: Arc<dyn Any + Send + Sync> = Arc::new(layers);
        t.replace_landlock_domains(Some(next));
        Ok(())
    }) {
        return res;
    }

    TEST_DOMAINS.with(|cell| {
        let mut slot = cell.borrow_mut();
        let mut layers = slot.as_ref().map(|arc| (**arc).clone()).unwrap_or_default();
        if layers.len() >= MAX_LANDLOCK_LAYERS {
            return Err(Errno::E2BIG);
        }
        layers.push(layer);
        *slot = Some(Arc::new(layers));
        Ok(())
    })
}

fn path_matches_prefix(path: &[u8], prefix: &[u8]) -> bool {
    if prefix == b"/" {
        return path.starts_with(b"/");
    }
    path == prefix || (path.starts_with(prefix) && path.get(prefix.len()) == Some(&b'/'))
}

fn required_access_for_open(flags: c_int, is_dir: bool, creating: bool, exec: bool) -> (u64, u64) {
    if flags as u32 & ffi::O_PATH_ != 0 {
        return (0, 0);
    }
    let acc = flags as u32 & ffi::O_ACCMODE_;
    let is_tmpfile = (flags as u32 & ffi::O_TMPFILE_) == ffi::O_TMPFILE_;
    let mut need = 0u64;
    if exec {
        need |= LANDLOCK_ACCESS_FS_EXECUTE;
    } else {
        if acc == ffi::O_RDONLY_ || acc == ffi::O_RDWR_ {
            if is_dir {
                need |= LANDLOCK_ACCESS_FS_READ_DIR;
            } else {
                need |= LANDLOCK_ACCESS_FS_READ_FILE;
            }
        }
        if acc == ffi::O_WRONLY_ || acc == ffi::O_RDWR_ {
            need |= LANDLOCK_ACCESS_FS_WRITE_FILE;
        }
        if flags as u32 & ffi::O_TRUNC_ != 0 {
            need |= LANDLOCK_ACCESS_FS_TRUNCATE;
        }
    }
    let parent_need = if creating || is_tmpfile {
        LANDLOCK_ACCESS_FS_MAKE_REG
    } else {
        0
    };
    (need, parent_need)
}

fn parent_dir_for_create(path: &[u8], flags: c_int) -> &[u8] {
    if (flags as u32 & ffi::O_TMPFILE_) == ffi::O_TMPFILE_ {
        return path;
    }
    match path.iter().rposition(|&b| b == b'/') {
        Some(0) | None => b"/",
        Some(pos) => &path[..pos],
    }
}

fn check_domain_layer(layer: &RulesetInner, path: &[u8], needed: u64) -> bool {
    let handled = needed & layer.handled_access_fs;
    if handled == 0 {
        return true;
    }
    let mut granted = 0u64;
    for rule in &layer.rules {
        if path_matches_prefix(path, &rule.prefix) {
            granted |= rule.allowed_access;
        }
    }
    (handled & !granted) == 0
}

fn landlock_open_check(
    path: &[u8],
    flags: c_int,
    is_dir: bool,
    creating: bool,
    exec: bool,
) -> Result<(), Errno> {
    let Some(layers) = current_domains() else {
        return Ok(());
    };
    let (needed, parent_needed) = required_access_for_open(flags, is_dir, creating, exec);
    let parent = (parent_needed != 0).then(|| parent_dir_for_create(path, flags));
    for layer in layers.iter() {
        if !check_domain_layer(layer, path, needed) {
            return Err(Errno::EACCES);
        }
        if let Some(parent_path) = parent
            && !check_domain_layer(layer, parent_path, parent_needed)
        {
            return Err(Errno::EACCES);
        }
    }
    Ok(())
}

pub fn sys_landlock_create_ruleset(
    attr_addr: u64,
    size: usize,
    flags: u32,
) -> Result<i64, Errno> {
    strace!("landlock_create_ruleset({attr_addr:#x}, {size}, {flags:#x})");
    if flags == LANDLOCK_CREATE_RULESET_VERSION {
        if attr_addr != 0 || size != 0 {
            return Err(Errno::EINVAL);
        }
        return Ok(LANDLOCK_ABI_VERSION);
    }
    if flags == LANDLOCK_CREATE_RULESET_ERRATA {
        if attr_addr != 0 || size != 0 {
            return Err(Errno::EINVAL);
        }
        return Ok(0);
    }
    if flags != 0 {
        return Err(Errno::EINVAL);
    }
    if size < 8 {
        return Err(Errno::EINVAL);
    }
    if size > 4096 {
        return Err(Errno::E2BIG);
    }
    if attr_addr == 0 {
        return Err(Errno::EFAULT);
    }
    let mut raw = vec![0u8; size];
    if GuestMem.read(attr_addr, &mut raw) != 0 {
        return Err(Errno::EFAULT);
    }
    if size > 8 && raw[8..].iter().any(|&b| b != 0) {
        return Err(Errno::E2BIG);
    }
    let handled_access_fs = u64::from_le_bytes(raw[0..8].try_into().unwrap());
    if handled_access_fs == 0 || (handled_access_fs & !LANDLOCK_ACCESS_FS_SUPPORTED) != 0 {
        return Err(Errno::EINVAL);
    }

    let mut fd = fs_adhoc::adhoc_anon(Some(&RULESET_OPS), Some(c"[landlock-ruleset]"));
    fd.set_driver_state(Box::new(RulesetState {
        inner: Mutex::new(RulesetInner {
            handled_access_fs,
            rules: Vec::new(),
        }),
    }));
    Errno::split(fs_fdobj::f_install(fd.into_owned(), ffi::O_CLOEXEC_ as c_int) as i64)
}

pub fn sys_landlock_add_rule(
    ruleset_fd: c_int,
    rule_type: u32,
    rule_attr_addr: u64,
    flags: u32,
) -> Result<(), Errno> {
    strace!("landlock_add_rule({ruleset_fd}, {rule_type}, {rule_attr_addr:#x}, {flags:#x})");
    if flags != 0 {
        return Err(Errno::EINVAL);
    }
    let fd = fs_fdobj::f_get(ruleset_fd).ok_or(Errno::EBADF)?;
    let state = fd.driver_state::<RulesetState>().ok_or(Errno::EBADF)?;

    if rule_type != LANDLOCK_RULE_PATH_BENEATH {
        return Err(Errno::EINVAL);
    }

    let mut raw = [0u8; 12];
    if GuestMem.read(rule_attr_addr, &mut raw) != 0 {
        return Err(Errno::EFAULT);
    }
    let allowed_access = u64::from_le_bytes(raw[0..8].try_into().unwrap());
    let parent_fd = i32::from_le_bytes(raw[8..12].try_into().unwrap());
    let pfd = fs_fdobj::f_get(parent_fd).ok_or(Errno::EBADF)?;
    if pfd.unnamed.is_some() {
        return Err(Errno::EBADFD);
    }
    let mut path_buf = vec![0u8; ffi::MAX_PATH as usize + 1];
    let err = fs_generic::generic_getpath(&pfd, &mut path_buf);
    if err < 0 {
        return Err(Errno::EBADFD);
    }
    let len = path_buf.iter().position(|&b| b == 0).unwrap_or(path_buf.len());
    path_buf.truncate(len);
    if !path_buf.starts_with(b"/") {
        return Err(Errno::EBADFD);
    }
    let pfd_mode = if pfd.type_ != 0 {
        u32::from(pfd.type_)
    } else {
        fs_fdobj::fd_fstat(&pfd).map(|st| st.mode).unwrap_or(0)
    };
    let pfd_is_dir = (pfd_mode & ffi::S_IFMT) == ffi::S_IFDIR;

    let mut inner = state.inner.lock().unwrap_or_else(|e| e.into_inner());
    if allowed_access == 0 || (allowed_access & !inner.handled_access_fs) != 0 {
        return Err(Errno::EINVAL);
    }
    if !pfd_is_dir && (allowed_access & !LANDLOCK_ACCESS_FS_FILE_MASK) != 0 {
        return Err(Errno::EINVAL);
    }
    inner.rules.push(PathRule {
        prefix: path_buf,
        allowed_access,
    });
    Ok(())
}

pub fn sys_landlock_restrict_self(ruleset_fd: c_int, flags: u32) -> Result<(), Errno> {
    strace!("landlock_restrict_self({ruleset_fd}, {flags:#x})");
    if flags != 0 {
        return Err(Errno::EINVAL);
    }
    let no_new_privs = kernel_pids::PidsGuard::take()
        .me()
        .is_some_and(|m| m.attr().no_new_privs());
    if !no_new_privs && !taskview::capable(taskview::caps::CAP_SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    let fd = fs_fdobj::f_get(ruleset_fd).ok_or(Errno::EBADF)?;
    let state = fd.driver_state::<RulesetState>().ok_or(Errno::EBADF)?;
    let snapshot = state.inner.lock().unwrap_or_else(|e| e.into_inner()).clone();

    fs_generic::set_landlock_open_hook(landlock_open_check);
    push_domain_layer(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn landlock_layer_enforces_path_beneath_access() {
        let layer = RulesetInner {
            handled_access_fs: LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE,
            rules: vec![PathRule {
                prefix: b"/tmp".to_vec(),
                allowed_access: LANDLOCK_ACCESS_FS_READ_FILE,
            }],
        };
        assert!(check_domain_layer(&layer, b"/tmp/a.txt", LANDLOCK_ACCESS_FS_READ_FILE));
        assert!(!check_domain_layer(&layer, b"/tmp/a.txt", LANDLOCK_ACCESS_FS_WRITE_FILE));
        assert!(!check_domain_layer(&layer, b"/etc/passwd", LANDLOCK_ACCESS_FS_READ_FILE));
        assert!(!check_domain_layer(&layer, b"/tmp2/a.txt", LANDLOCK_ACCESS_FS_READ_FILE));
    }

    #[test]
    fn landlock_version_errata_and_bounds() {
        assert_eq!(sys_landlock_create_ruleset(0, 0, LANDLOCK_CREATE_RULESET_VERSION), Ok(3));
        assert_eq!(sys_landlock_create_ruleset(0, 0, LANDLOCK_CREATE_RULESET_ERRATA), Ok(0));
        assert_eq!(sys_landlock_create_ruleset(1, 0, LANDLOCK_CREATE_RULESET_VERSION), Err(Errno::EINVAL));
        assert_eq!(sys_landlock_create_ruleset(0, 8, LANDLOCK_CREATE_RULESET_ERRATA), Err(Errno::EINVAL));
        assert_eq!(sys_landlock_create_ruleset(0, 4, 0), Err(Errno::EINVAL));
        assert_eq!(sys_landlock_create_ruleset(0, 4097, 0), Err(Errno::E2BIG));
    }

    #[test]
    fn landlock_domain_stacks_up_to_limit() {
        TEST_DOMAINS.with(|cell| *cell.borrow_mut() = None);
        let layer = RulesetInner {
            handled_access_fs: LANDLOCK_ACCESS_FS_READ_FILE,
            rules: vec![PathRule {
                prefix: b"/tmp".to_vec(),
                allowed_access: LANDLOCK_ACCESS_FS_READ_FILE,
            }],
        };
        for _ in 0..MAX_LANDLOCK_LAYERS {
            assert_eq!(push_domain_layer(layer.clone()), Ok(()));
        }
        assert_eq!(push_domain_layer(layer), Err(Errno::E2BIG));
        assert_eq!(
            landlock_open_check(b"/tmp/ok", ffi::O_RDONLY_ as c_int, false, false, false),
            Ok(())
        );
        assert_eq!(
            landlock_open_check(b"/etc/shadow", ffi::O_RDONLY_ as c_int, false, false, false),
            Err(Errno::EACCES)
        );
        TEST_DOMAINS.with(|cell| *cell.borrow_mut() = None);
    }

    #[test]
    fn landlock_checks_dirs_creation_and_exec() {
        TEST_DOMAINS.with(|cell| *cell.borrow_mut() = None);
        let layer = RulesetInner {
            handled_access_fs: LANDLOCK_ACCESS_FS_EXECUTE
                | LANDLOCK_ACCESS_FS_READ_FILE
                | LANDLOCK_ACCESS_FS_WRITE_FILE
                | LANDLOCK_ACCESS_FS_READ_DIR
                | LANDLOCK_ACCESS_FS_MAKE_REG,
            rules: vec![PathRule {
                prefix: b"/work".to_vec(),
                allowed_access: LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE,
            }],
        };
        assert_eq!(push_domain_layer(layer), Ok(()));
        assert_eq!(
            landlock_open_check(b"/work", ffi::O_RDONLY_ as c_int, true, false, false),
            Err(Errno::EACCES)
        );
        assert_eq!(
            landlock_open_check(
                b"/work/new.txt",
                (ffi::O_CREAT_ | ffi::O_WRONLY_) as c_int,
                false,
                true,
                false,
            ),
            Err(Errno::EACCES)
        );
        assert_eq!(
            landlock_open_check(b"/work/tool", ffi::O_RDONLY_ as c_int, false, false, true),
            Err(Errno::EACCES)
        );

        let allow_layer = RulesetInner {
            handled_access_fs: LANDLOCK_ACCESS_FS_EXECUTE
                | LANDLOCK_ACCESS_FS_READ_DIR
                | LANDLOCK_ACCESS_FS_MAKE_REG
                | LANDLOCK_ACCESS_FS_WRITE_FILE,
            rules: vec![PathRule {
                prefix: b"/allow".to_vec(),
                allowed_access: LANDLOCK_ACCESS_FS_EXECUTE
                    | LANDLOCK_ACCESS_FS_READ_DIR
                    | LANDLOCK_ACCESS_FS_MAKE_REG
                    | LANDLOCK_ACCESS_FS_WRITE_FILE,
            }],
        };
        TEST_DOMAINS.with(|cell| *cell.borrow_mut() = None);
        assert_eq!(push_domain_layer(allow_layer), Ok(()));
        assert_eq!(
            landlock_open_check(b"/allow", ffi::O_RDONLY_ as c_int, true, false, false),
            Ok(())
        );
        assert_eq!(
            landlock_open_check(
                b"/allow/new.txt",
                (ffi::O_CREAT_ | ffi::O_WRONLY_) as c_int,
                false,
                true,
                false,
            ),
            Ok(())
        );
        assert_eq!(
            landlock_open_check(b"/allow/tool", ffi::O_RDONLY_ as c_int, false, false, true),
            Ok(())
        );
        assert_eq!(parent_dir_for_create(b"/top", ffi::O_CREAT_ as c_int), b"/");
        TEST_DOMAINS.with(|cell| *cell.borrow_mut() = None);
    }
}
