//! Guest-side ownership and set-id metadata persisted in host extended attributes.
//!
//! On macOS and iOS sandboxes, `realfs` runs as the app's unprivileged host user,
//! so `chown` and `chmod` with `S_ISUID`/`S_ISGID` fail with `EPERM` at the host
//! kernel -- and iOS 27 refuses `S_ISVTX` too. Storing the guest's `uid`, `gid`,
//! and those special mode bits in `com.flul.meta`
//! lets `stat`, `fstat`, and VFS DAC checks (`fs_perm`) enforce multi-user
//! isolation without a separate database.

use std::ffi::{CStr, CString};
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::OnceLock;

use rustix::fs::{self, AtFlags, Mode, OFlags, XattrFlags};

use crate::errno::{Result, rx};
use crate::{at_path, ffi};

const META_XATTR: &CStr = c"com.flul.meta";
pub(crate) const META_PREFIX: &[u8] = b"com.flul.";
pub const UNSET: u32 = u32::MAX;
const SETID_MASK: u32 = 0o6000;
/// The mode bits a host may refuse and `com.flul.meta` records: set-id and sticky.
pub const SPECIAL_MASK: u32 = 0o7000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestMeta {
    pub uid: u32,
    pub gid: u32,
    pub special_bits: u32,
}

impl Default for GuestMeta {
    fn default() -> Self {
        Self {
            uid: UNSET,
            gid: UNSET,
            special_bits: UNSET,
        }
    }
}

impl GuestMeta {
    fn is_empty(self) -> bool {
        self.uid == UNSET && self.gid == UNSET && self.special_bits == UNSET
    }

    fn encode(self) -> [u8; 12] {
        let mut buf = [0u8; 12];
        buf[0..4].copy_from_slice(&self.uid.to_le_bytes());
        buf[4..8].copy_from_slice(&self.gid.to_le_bytes());
        buf[8..12].copy_from_slice(&self.special_bits.to_le_bytes());
        buf
    }

    fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() != 12 {
            return None;
        }
        Some(Self {
            uid: u32::from_le_bytes(buf[0..4].try_into().ok()?),
            gid: u32::from_le_bytes(buf[4..8].try_into().ok()?),
            special_bits: u32::from_le_bytes(buf[8..12].try_into().ok()?),
        })
    }
}

fn host_process_uid() -> u32 {
    static UID: OnceLock<u32> = OnceLock::new();
    *UID.get_or_init(|| rustix::process::geteuid().as_raw())
}

fn host_process_gid() -> u32 {
    static GID: OnceLock<u32> = OnceLock::new();
    *GID.get_or_init(|| rustix::process::getegid().as_raw())
}

fn open_no_follow(root: BorrowedFd<'_>, path: &CStr, write: bool) -> Result<rustix::fd::OwnedFd> {
    let base = if write {
        OFlags::WRONLY
    } else {
        OFlags::RDONLY
    };
    let flags = base
        | OFlags::NONBLOCK
        | OFlags::NOCTTY
        | OFlags::from_bits_retain(libc::O_SYMLINK as _);
    rx(fs::openat(root, at_path(path), flags, Mode::empty()))
}

fn retry_fd_with_mode<T>(
    fd: BorrowedFd<'_>,
    needed_bits: libc::mode_t,
    mut op: impl FnMut() -> rustix::io::Result<T>,
) -> rustix::io::Result<T> {
    match op() {
        Err(rustix::io::Errno::ACCESS) => {
            let st = fs::fstat(fd)?;
            let raw_mode = st.st_mode as libc::mode_t;
            if (raw_mode & libc::S_IFMT) == libc::S_IFLNK || (raw_mode & needed_bits) == needed_bits {
                return Err(rustix::io::Errno::ACCESS);
            }
            let orig_mode = Mode::from_raw_mode(raw_mode);
            let temp_mode = Mode::from_raw_mode(raw_mode | needed_bits);
            fs::fchmod(fd, temp_mode)?;
            let res = op();
            let _ = fs::fchmod(fd, orig_mode);
            res
        }
        other => other,
    }
}

pub fn read_fd(fd: BorrowedFd<'_>) -> Option<GuestMeta> {
    let mut buf = [0u8; 12];
    match retry_fd_with_mode(fd, 0o400, || fs::fgetxattr(fd, META_XATTR, &mut buf)) {
        Ok(12) => GuestMeta::decode(&buf),
        _ => None,
    }
}

fn resolve_at_path(root: BorrowedFd<'_>, rel: &CStr) -> Option<CString> {
    let rel_bytes = rel.to_bytes();
    if rel_bytes.starts_with(b"/") {
        return CString::new(rel_bytes).ok();
    }
    let root_c = fs::getpath(root).ok()?;
    let root_bytes = root_c.as_bytes();
    if rel_bytes.is_empty() || rel_bytes == b"." {
        return Some(root_c);
    }
    let mut full = Vec::with_capacity(root_bytes.len() + 1 + rel_bytes.len());
    full.extend_from_slice(root_bytes);
    if !root_bytes.ends_with(b"/") {
        full.push(b'/');
    }
    full.extend_from_slice(rel_bytes);
    CString::new(full).ok()
}

pub fn read_path(root: BorrowedFd<'_>, path: &CStr) -> Option<GuestMeta> {
    if let Ok(fd) = open_no_follow(root, path, false) {
        return read_fd(fd.as_fd());
    }
    let rel = at_path(path);
    let abs = resolve_at_path(root, rel)?;
    let mut buf = [0u8; 12];
    match fs::lgetxattr(abs.as_c_str(), META_XATTR, &mut buf) {
        Ok(12) => return GuestMeta::decode(&buf),
        Ok(_) => return None,
        Err(rustix::io::Errno::ACCESS) => {}
        Err(_) => return None,
    }

    // Mode 0000 files owned by the host user can deny xattr reads with EACCES
    // until read permission is temporarily restored.
    let st = fs::statat(root, rel, AtFlags::SYMLINK_NOFOLLOW).ok()?;
    if (st.st_mode as libc::mode_t & libc::S_IFMT) == libc::S_IFLNK {
        return None;
    }
    let orig_mode = Mode::from_raw_mode(st.st_mode as libc::mode_t);
    let temp_mode = Mode::from_raw_mode((st.st_mode as libc::mode_t) | 0o400);
    fs::chmodat(root, rel, temp_mode, AtFlags::SYMLINK_NOFOLLOW).ok()?;
    let res = fs::lgetxattr(abs.as_c_str(), META_XATTR, &mut buf);
    let _ = fs::chmodat(root, rel, orig_mode, AtFlags::SYMLINK_NOFOLLOW);
    match res {
        Ok(12) => GuestMeta::decode(&buf),
        _ => None,
    }
}

pub fn write_fd(fd: BorrowedFd<'_>, meta: GuestMeta) -> Result<()> {
    if meta.is_empty() {
        return match retry_fd_with_mode(fd, 0o600, || fs::fremovexattr(fd, META_XATTR)) {
            Ok(()) => Ok(()),
            Err(e) if e == rustix::io::Errno::NODATA || e.raw_os_error() == libc::ENOATTR => {
                Ok(())
            }
            Err(e) => rx(Err(e)),
        };
    }
    rx(retry_fd_with_mode(fd, 0o600, || {
        fs::fsetxattr(fd, META_XATTR, &meta.encode(), XattrFlags::empty())
    }))
}

pub fn write_path(root: BorrowedFd<'_>, path: &CStr, meta: GuestMeta) -> Result<()> {
    if let Ok(fd) = open_no_follow(root, path, false)
        .or_else(|_| open_no_follow(root, path, true))
    {
        match write_fd(fd.as_fd(), meta) {
            Ok(()) => return Ok(()),
            // Read-only files (e.g. 0444/0555) can open O_RDONLY yet fail
            // fsetxattr with EACCES on Darwin; fall through to temporary chmod.
            Err(e) if e == kernel_errno::raised(libc::EACCES) => {}
            Err(e) => return Err(e),
        }
    }

    let rel = at_path(path);
    let abs = resolve_at_path(root, rel).ok_or_else(|| kernel_errno::raised(libc::ENOENT))?;

    let retry_path_with_mode = |mut op: Box<dyn FnMut() -> rustix::io::Result<()>>| -> Result<()> {
        match op() {
            Ok(()) => Ok(()),
            Err(rustix::io::Errno::ACCESS) => {
                let st = rx(fs::statat(root, rel, AtFlags::SYMLINK_NOFOLLOW))?;
                if (st.st_mode as libc::mode_t & libc::S_IFMT) == libc::S_IFLNK {
                    return Err(kernel_errno::raised(libc::EACCES));
                }
                let orig_mode = Mode::from_raw_mode(st.st_mode as libc::mode_t);
                let temp_mode = Mode::from_raw_mode((st.st_mode as libc::mode_t) | 0o600);
                rx(fs::chmodat(root, rel, temp_mode, AtFlags::SYMLINK_NOFOLLOW))?;
                let res = rx(op());
                let _ = fs::chmodat(root, rel, orig_mode, AtFlags::SYMLINK_NOFOLLOW);
                res
            }
            Err(err) => rx(Err(err)),
        }
    };

    if meta.is_empty() {
        return retry_path_with_mode(Box::new(|| match fs::lremovexattr(abs.as_c_str(), META_XATTR) {
            Ok(()) => Ok(()),
            Err(e) if e == rustix::io::Errno::NODATA || e.raw_os_error() == libc::ENOATTR => {
                Ok(())
            }
            Err(e) => Err(e),
        }));
    }

    let raw = meta.encode();
    retry_path_with_mode(Box::new(|| {
        fs::lsetxattr(abs.as_c_str(), META_XATTR, &raw, XattrFlags::empty())
    }))
}

pub fn apply_stat(host: &libc::stat, meta: Option<GuestMeta>, out: &mut ffi::statbuf) {
    if host.st_uid == host_process_uid() {
        out.uid = 0;
    }
    if host.st_gid == host_process_gid() {
        out.gid = 0;
    }
    if let Some(m) = meta {
        if m.uid != UNSET {
            out.uid = m.uid;
        }
        if m.gid != UNSET {
            out.gid = m.gid;
        }
        if m.special_bits != UNSET {
            // The host keeps a sticky bit it accepted; the record adds one it refused.
            out.mode = (out.mode & !SETID_MASK) | (m.special_bits & SPECIAL_MASK);
        }
    }
}

pub fn stamp_new_fd(fd: BorrowedFd<'_>) {
    let (uid, gid) = taskview::current_fsids();
    if uid == 0 && gid == 0 {
        return;
    }
    let _ = write_fd(
        fd,
        GuestMeta {
            uid,
            gid,
            special_bits: UNSET,
        },
    );
}

pub fn stamp_new_path(root: BorrowedFd<'_>, path: &CStr) {
    stamp_new_path_with_special(root, path, None);
}

pub fn stamp_new_path_with_special(root: BorrowedFd<'_>, path: &CStr, special: Option<u32>) {
    let (uid, gid) = taskview::current_fsids();
    let special_bits = special.unwrap_or(UNSET);
    if uid == 0 && gid == 0 && special.is_none() {
        return;
    }
    let (meta_uid, meta_gid) = if uid == 0 && gid == 0 {
        (UNSET, UNSET)
    } else {
        (uid, gid)
    };
    let _ = write_path(
        root,
        path,
        GuestMeta {
            uid: meta_uid,
            gid: meta_gid,
            special_bits,
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn encode_decode_round_trips() {
        let m = GuestMeta {
            uid: 104,
            gid: 65534,
            special_bits: 0o4000,
        };
        assert_eq!(GuestMeta::decode(&m.encode()), Some(m));
        assert_eq!(GuestMeta::decode(&[0u8; 8]), None);
    }

    #[test]
    fn a_refused_sticky_bit_comes_back_from_the_record() {
        let mut host: libc::stat = unsafe { std::mem::zeroed() };
        host.st_mode = (libc::S_IFDIR | 0o777) as libc::mode_t;
        let mut out = crate::stat::convert(&host);
        apply_stat(&host, Some(GuestMeta { special_bits: 0o1000, ..GuestMeta::default() }), &mut out);
        assert_eq!(out.mode & 0o7777, 0o1777);

        // A sticky bit the host accepted survives a record written for set-id.
        host.st_mode = (libc::S_IFDIR | 0o1777) as libc::mode_t;
        let mut out = crate::stat::convert(&host);
        apply_stat(&host, Some(GuestMeta { special_bits: 0, ..GuestMeta::default() }), &mut out);
        assert_eq!(out.mode & 0o7777, 0o1777);
    }

    #[test]
    fn apply_stat_maps_host_owner_to_root_and_respects_overrides() {
        let mut host: libc::stat = unsafe { std::mem::zeroed() };
        host.st_uid = host_process_uid();
        host.st_gid = host_process_gid();
        host.st_mode = (libc::S_IFREG | 0o755) as libc::mode_t;

        let mut out = crate::stat::convert(&host);
        apply_stat(&host, None, &mut out);
        assert_eq!(out.uid, 0);
        assert_eq!(out.gid, 0);
        assert_eq!(out.mode & 0o7777, 0o755);

        let mut out2 = crate::stat::convert(&host);
        apply_stat(
            &host,
            Some(GuestMeta {
                uid: 104,
                gid: 42,
                special_bits: 0o6000,
            }),
            &mut out2,
        );
        assert_eq!(out2.uid, 104);
        assert_eq!(out2.gid, 42);
        assert_eq!(out2.mode & 0o7777, 0o6755);
    }

    #[test]
    fn write_and_read_path_xattr_works_on_0000_file_and_symlink() {
        let dir = std::env::temp_dir().join(format!("realfs-meta-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let dir_fd = fs::open(&dir, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).unwrap();
        let file = dir.join("secret");
        std::fs::write(&file, b"hi").unwrap();
        fs::chmodat(dir_fd.as_fd(), c"secret", Mode::empty(), AtFlags::empty()).unwrap();

        let meta = GuestMeta {
            uid: 104,
            gid: 104,
            special_bits: 0o4000,
        };
        write_path(dir_fd.as_fd(), c"secret", meta).unwrap();
        assert_eq!(read_path(dir_fd.as_fd(), c"secret"), Some(meta));
        write_path(dir_fd.as_fd(), c"secret", GuestMeta::default()).unwrap();
        assert_eq!(read_path(dir_fd.as_fd(), c"secret"), None);

        let link_name = CString::new("sym").unwrap();
        fs::symlinkat(c"secret", dir_fd.as_fd(), &link_name).unwrap();
        let link_meta = GuestMeta {
            uid: 1000,
            gid: 1000,
            special_bits: UNSET,
        };
        write_path(dir_fd.as_fd(), &link_name, link_meta).unwrap();
        assert_eq!(read_path(dir_fd.as_fd(), &link_name), Some(link_meta));

        let ro = dir.join("readonly");
        std::fs::write(&ro, b"ro").unwrap();
        fs::chmodat(dir_fd.as_fd(), c"readonly", Mode::from_raw_mode(0o444), AtFlags::empty()).unwrap();
        write_path(dir_fd.as_fd(), c"readonly", meta).unwrap();
        assert_eq!(read_path(dir_fd.as_fd(), c"readonly"), Some(meta));

        let wronly_zero = fs::openat(
            dir_fd.as_fd(),
            c"dpkg-new",
            OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC,
            Mode::empty(),
        )
        .unwrap();
        write_fd(wronly_zero.as_fd(), GuestMeta::default()).unwrap();
        assert_eq!(read_fd(wronly_zero.as_fd()), None);
        write_fd(wronly_zero.as_fd(), meta).unwrap();
        assert_eq!(read_fd(wronly_zero.as_fd()), Some(meta));
        let st = fs::fstat(wronly_zero.as_fd()).unwrap();
        assert_eq!(st.st_mode as libc::mode_t & 0o777, 0);

        fs::chmodat(
            dir_fd.as_fd(),
            c"secret",
            Mode::from_raw_mode(0o644),
            AtFlags::empty(),
        )
        .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stamp_new_path_with_special_preserves_sticky_and_setgid() {
        let dir = std::env::temp_dir().join(format!("realfs-meta-special-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dir_fd = fs::open(&dir, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).unwrap();

        fs::mkdirat(dir_fd.as_fd(), c"tmp", Mode::from_raw_mode(0o777)).unwrap();
        stamp_new_path_with_special(dir_fd.as_fd(), c"tmp", Some(0o1000));

        let st = fs::statat(dir_fd.as_fd(), c"tmp", AtFlags::SYMLINK_NOFOLLOW).unwrap();
        let mut raw_stat: libc::stat = unsafe { std::mem::zeroed() };
        raw_stat.st_mode = st.st_mode as libc::mode_t;
        raw_stat.st_uid = host_process_uid();
        raw_stat.st_gid = host_process_gid();
        let mut out = crate::stat::convert(&raw_stat);
        apply_stat(&raw_stat, read_path(dir_fd.as_fd(), c"tmp"), &mut out);
        assert_eq!(out.mode & 0o7000, 0o1000);
        assert_eq!(out.mode & 0o777, (st.st_mode as u32) & 0o777);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
