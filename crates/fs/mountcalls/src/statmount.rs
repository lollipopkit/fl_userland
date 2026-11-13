//! `statmount(2)` and `listmount(2)`, Linux 6.8: the mount table by unique id,
//! as a struct and as a list, instead of `/proc/self/mountinfo` text.
//!
//! systemd and libmount ask these before they parse `mountinfo`, so what they
//! report has to be the same table: the same mounts, the same parent rule
//! (the longest proper prefix, which is how `crates/fs/mounttable` decides
//! which mount owns a path), the same device. The unique id is
//! `ffi::unique_mount_id`, which is also what `STATX_MNT_ID_UNIQUE` answers.
//!
//! What this table cannot hold reads as what Linux reports for a mount that
//! has none of it: there is one mount namespace, every mount is private
//! (`MS_PRIVATE`, no peer group, no master), no mount is idmapped, and no
//! filesystem has a subtype or security options. A string with nothing in it
//! is left out of the answer and its mask bit clear, as Linux leaves it.
//!
//! The argument protocol and the string table were measured with
//! `tests/guest/src/bin/fsat_probe.rs` against an arm64 7.2 kernel.

use std::ffi::c_int;

use guest_errno::Errno;
use strace::strace;
use usercopy::GuestMem;

use crate::ffi;

/// `struct mnt_id_req`: `{ u32 size; u32 mnt_ns_fd or mnt_fd; u64 mnt_id;
/// u64 param; u64 mnt_ns_id; }`. VER0 stops before `mnt_ns_id`.
const MNT_ID_REQ_SIZE_VER0: usize = 24;
const MNT_ID_REQ_SIZE_VER1: usize = 32;

/// `struct statmount` without its strings.
const STATMOUNT_SIZE: usize = 512;

/// `LSMT_ROOT`: list from the caller's root.
const LSMT_ROOT: u64 = u64::MAX;
const LISTMOUNT_REVERSE: u32 = 1;
/// `statmount`'s one flag, Linux 7.x: `mnt_fd` names the mount by a
/// descriptor on it.
const STATMOUNT_BY_FD: u32 = 1;

/// The one mount namespace's id. There is no `nsfs` here to hand out another,
/// so a request naming any other answers ENOENT, as one naming a namespace
/// that has gone does.
const MNT_NS_ID: u64 = 1;

const SB_BASIC: u64 = 0x1;
const MNT_BASIC: u64 = 0x2;
const PROPAGATE_FROM: u64 = 0x4;
const MNT_ROOT: u64 = 0x8;
const MNT_POINT: u64 = 0x10;
const FS_TYPE: u64 = 0x20;
const MNT_NS_ID_BIT: u64 = 0x40;
const MNT_OPTS: u64 = 0x80;
const FS_SUBTYPE: u64 = 0x100;
const SB_SOURCE: u64 = 0x200;
const OPT_ARRAY: u64 = 0x400;
const OPT_SEC_ARRAY: u64 = 0x800;
const SUPPORTED_MASK: u64 = 0x1000;
const MNT_UIDMAP: u64 = 0x2000;
const MNT_GIDMAP: u64 = 0x4000;
/// Every bit above, each of which is answered -- some with "there is none".
const STATMOUNT_SUPPORTED: u64 = 0x7fff;

/// `MS_PRIVATE`, the only propagation a mount here has.
const MS_PRIVATE: u64 = 1 << 18;

/// The request, decoded. `fd` is the union of `mnt_ns_fd` and `mnt_fd`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Request {
    fd: u32,
    mnt_id: u64,
    param: u64,
    mnt_ns_id: u64,
}

/// Linux's `copy_mnt_id_req`: the size is read first and on its own, so a
/// NULL request is EFAULT before anything else is said about it.
fn read_request(addr: u64) -> Result<Request, Errno> {
    let mut size = [0u8; 4];
    if GuestMem.read(addr, &mut size) != 0 {
        return Err(Errno::EFAULT);
    }
    let size = u32::from_le_bytes(size) as usize;
    if size > ffi::PAGE_SIZE as usize {
        return Err(Errno::E2BIG);
    }
    if size < MNT_ID_REQ_SIZE_VER0 {
        return Err(Errno::EINVAL);
    }
    let mut raw = [0u8; MNT_ID_REQ_SIZE_VER1];
    usercopy::read_extensible(&GuestMem, addr, size, &mut raw)?;
    let u64_at = |i: usize| u64::from_le_bytes(raw[i..i + 8].try_into().expect("eight bytes"));
    Ok(Request {
        fd: u32::from_le_bytes(raw[4..8].try_into().expect("four bytes")),
        mnt_id: u64_at(8),
        param: u64_at(16),
        mnt_ns_id: u64_at(24),
    })
}

/// The checks both calls make of a request that names a mount by id.
fn check_request(req: &Request) -> Result<(), Errno> {
    // A namespace descriptor. There are none here, so any nonzero one is not
    // one, which Linux answers EINVAL for.
    if req.fd != 0 {
        return Err(Errno::EINVAL);
    }
    if req.mnt_id <= ffi::MNT_UNIQUE_ID_OFFSET {
        return Err(Errno::EINVAL);
    }
    namespace(req)
}

fn namespace(req: &Request) -> Result<(), Errno> {
    if req.mnt_ns_id != 0 && req.mnt_ns_id != MNT_NS_ID {
        return Err(Errno::ENOENT);
    }
    Ok(())
}

/// One mount, read out of the table while its lock is held.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Row {
    id: u32,
    /// The machine path, `""` for the root as the table spells it.
    point: Vec<u8>,
    source: Vec<u8>,
    options: Vec<u8>,
    flags: u32,
    fstype: Vec<u8>,
    magic: u32,
    dev: u32,
}

impl Row {
    fn unique(&self) -> u64 {
        ffi::unique_mount_id(self.id)
    }
}

fn snapshot() -> Vec<Row> {
    let mut rows: Vec<Row> = fs_mounttable::with_mounts(|mounts| {
        mounts
            .iter()
            .map(|m| Row {
                id: m.id,
                point: m.point.to_bytes().to_vec(),
                source: m.source.to_bytes().to_vec(),
                options: m.info.to_bytes().to_vec(),
                flags: m.flags as u32,
                fstype: m.fs.and_then(|fs| fs.name()).map_or(Vec::new(), |n| n.to_bytes().to_vec()),
                magic: m.fs.map_or(0, |fs| fs.magic()),
                dev: m.dev() as u32,
            })
            .collect()
    });
    rows.sort_by_key(|r| r.id);
    rows
}

/// Is `path` at or under `dir`, on a component boundary? `""` is the root.
fn under(dir: &[u8], path: &[u8]) -> bool {
    path.starts_with(dir) && (dir.is_empty() || matches!(path.get(dir.len()), None | Some(b'/')))
}

/// The mount `row` is mounted on: the longest proper prefix of its point.
/// The root is its own parent, as the root of a mount namespace is.
fn parent<'a>(row: &'a Row, rows: &'a [Row]) -> &'a Row {
    rows.iter()
        .filter(|o| o.point.len() < row.point.len() && under(&o.point, &row.point))
        .max_by_key(|o| o.point.len())
        .unwrap_or(row)
}

/// The calling task's root as the table spells paths: `""` for the machine's.
fn task_root() -> Vec<u8> {
    let Some(Some(root)) = taskview::with_current_fs(|fs| fs.root()) else {
        return Vec::new();
    };
    let mut buf = vec![0u8; ffi::MAX_PATH as usize + 1];
    if fs_generic::generic_getpath(&root, &mut buf) < 0 {
        return Vec::new();
    }
    let mut path = ffi::path_bytes(&buf).to_vec();
    while path.last() == Some(&b'/') {
        path.pop();
    }
    path
}

/// Whether the caller can see `row` from its root, which is what lets it ask
/// without `CAP_SYS_ADMIN`: a mount under the root, or the one the root is on.
fn visible(row: &Row, rows: &[Row], root: &[u8]) -> bool {
    under(root, &row.point) || rows.iter().filter(|o| under(&o.point, root)).max_by_key(|o| o.point.len()) == Some(row)
}

fn permitted(row: &Row, rows: &[Row], root: &[u8]) -> Result<(), Errno> {
    if visible(row, rows, root) || taskview::capable(taskview::caps::CAP_SYS_ADMIN) {
        Ok(())
    } else {
        Err(Errno::EPERM)
    }
}

/// `MOUNT_ATTR_*` from the four `MS_*` flags a mount here keeps. The atime
/// mode is `relatime`, which is attribute 0.
fn mount_attr(flags: u32) -> u64 {
    [
        (ffi::MS_READONLY_, 0x1),
        (ffi::MS_NOSUID_, 0x2),
        (ffi::MS_NODEV_, 0x4),
        (ffi::MS_NOEXEC_, 0x8),
    ]
    .iter()
    .filter(|(ms, _)| flags & ms != 0)
    .fold(0, |acc, (_, attr)| acc | attr)
}

/// `struct statmount` and the string table after it.
struct Answer {
    sm: [u8; STATMOUNT_SIZE],
    mask: u64,
    strings: Vec<u8>,
    /// The caller's buffer size, which a string must leave room in.
    bufsize: usize,
}

impl Answer {
    fn put_u32(&mut self, at: usize, v: u32) {
        self.sm[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u64(&mut self, at: usize, v: u64) {
        self.sm[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// Linux's `statmount_string`: offset 0 is a reserved empty string, so an
    /// unset offset reads as `""`; nothing emitted leaves the bit clear; and a
    /// string that would not leave room for itself in the caller's buffer is
    /// EOVERFLOW.
    fn string(&mut self, bit: u64, offset_field: usize, bytes: &[u8]) -> Result<(), Errno> {
        if self.strings.is_empty() {
            self.strings.push(0);
        }
        if bytes.is_empty() {
            return Ok(());
        }
        let start = self.strings.len();
        if STATMOUNT_SIZE + start + bytes.len() >= self.bufsize {
            return Err(Errno::EOVERFLOW);
        }
        self.strings.extend_from_slice(bytes);
        self.strings.push(0);
        self.put_u32(offset_field, start as u32);
        self.mask |= bit;
        Ok(())
    }
}

/// The mount point as the caller's root sees it, or nothing for one it
/// cannot name.
fn point_from(root: &[u8], point: &[u8]) -> Vec<u8> {
    if !under(root, point) {
        return Vec::new();
    }
    let rest = &point[root.len()..];
    if rest.is_empty() { b"/".to_vec() } else { rest.to_vec() }
}

fn describe(row: &Row, rows: &[Row], root: &[u8], want: u64, bufsize: usize) -> Result<Answer, Errno> {
    let mut a = Answer { sm: [0; STATMOUNT_SIZE], mask: 0, strings: Vec::new(), bufsize };
    if want & SB_BASIC != 0 {
        a.put_u32(16, fs_devices::dev_major(row.dev));
        a.put_u32(20, fs_devices::dev_minor(row.dev));
        a.put_u64(24, u64::from(row.magic));
        // `SB_RDONLY` is `MS_RDONLY`'s bit; the other three `SB_*` this
        // reports are flags no mount here keeps.
        a.put_u32(32, row.flags & ffi::MS_READONLY_);
        a.mask |= SB_BASIC;
    }
    if want & MNT_BASIC != 0 {
        let p = parent(row, rows);
        a.put_u64(40, row.unique());
        a.put_u64(48, p.unique());
        a.put_u32(56, row.id);
        a.put_u32(60, p.id);
        a.put_u64(64, mount_attr(row.flags));
        a.put_u64(72, MS_PRIVATE);
        a.mask |= MNT_BASIC;
    }
    if want & PROPAGATE_FROM != 0 {
        a.mask |= PROPAGATE_FROM;
    }
    if want & FS_TYPE != 0 {
        a.string(FS_TYPE, 36, &row.fstype)?;
    }
    if want & MNT_ROOT != 0 {
        // No bind mount of a subtree exists at this level, so every mount is
        // of its filesystem's root.
        a.string(MNT_ROOT, 104, b"/")?;
    }
    if want & MNT_POINT != 0 {
        a.string(MNT_POINT, 108, &point_from(root, &row.point))?;
    }
    if want & MNT_OPTS != 0 {
        a.string(MNT_OPTS, 4, &row.options)?;
    }
    if want & OPT_ARRAY != 0 {
        let opts: Vec<&[u8]> = row.options.split(|b| *b == b',').filter(|o| !o.is_empty()).collect();
        // The options, each terminated; `string` terminates the last.
        let joined = opts.join(&0u8);
        a.string(OPT_ARRAY, 132, &joined)?;
        if a.mask & OPT_ARRAY != 0 {
            a.put_u32(128, opts.len() as u32);
        }
    }
    // `OPT_SEC_ARRAY`, `FS_SUBTYPE`, `MNT_UIDMAP` and `MNT_GIDMAP` have
    // nothing to say here and say nothing, as Linux does for a mount without
    // them.
    if want & SB_SOURCE != 0 {
        a.string(SB_SOURCE, 124, &row.source)?;
    }
    if want & MNT_NS_ID_BIT != 0 {
        a.put_u64(112, MNT_NS_ID);
        a.mask |= MNT_NS_ID_BIT;
    }
    if want & SUPPORTED_MASK != 0 {
        a.put_u64(144, STATMOUNT_SUPPORTED);
        a.mask |= SUPPORTED_MASK;
    }
    let _ = (OPT_SEC_ARRAY, FS_SUBTYPE, MNT_UIDMAP, MNT_GIDMAP);
    Ok(a)
}

pub fn sys_statmount(req_addr: u64, buf_addr: u64, bufsize: u64, flags: u32) -> Result<(), Errno> {
    strace!("statmount({req_addr:#x}, {buf_addr:#x}, {bufsize}, {flags:#x})");
    if flags & !STATMOUNT_BY_FD != 0 {
        return Err(Errno::EINVAL);
    }
    let req = read_request(req_addr)?;
    let rows = snapshot();
    let row = if flags & STATMOUNT_BY_FD != 0 {
        namespace(&req)?;
        let fd = fs_fdobj::f_get(req.fd as c_int).ok_or(Errno::EBADF)?;
        let id = fd.mount().map(|m| m.id).ok_or(Errno::EINVAL)?;
        rows.iter().find(|r| r.id == id).ok_or(Errno::ENOENT)?
    } else {
        check_request(&req)?;
        rows.iter().find(|r| r.unique() == req.mnt_id).ok_or(Errno::ENOENT)?
    };
    let root = task_root();
    permitted(row, &rows, &root)?;
    let bufsize = bufsize as usize;
    let a = describe(row, &rows, &root, req.param, bufsize)?;
    let mut sm = a.sm;
    let copysize = bufsize.min(STATMOUNT_SIZE);
    sm[0..4].copy_from_slice(&((copysize + a.strings.len()) as u32).to_le_bytes());
    sm[8..16].copy_from_slice(&a.mask.to_le_bytes());
    if !a.strings.is_empty() && GuestMem.write(buf_addr + STATMOUNT_SIZE as u64, &a.strings) != 0 {
        return Err(Errno::EFAULT);
    }
    if GuestMem.write(buf_addr, &sm[..copysize]) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(())
}

/// The most ids one call may ask for: Linux's `MAX_RW_COUNT` in bytes.
const LISTMOUNT_MAX: u64 = ((i32::MAX as u64) & !0xfff) / 8;

pub fn sys_listmount(req_addr: u64, ids_addr: u64, nr: u64, flags: u32) -> Result<i64, Errno> {
    strace!("listmount({req_addr:#x}, {ids_addr:#x}, {nr}, {flags:#x})");
    if flags & !LISTMOUNT_REVERSE != 0 {
        return Err(Errno::EINVAL);
    }
    if nr > LISTMOUNT_MAX {
        return Err(Errno::EOVERFLOW);
    }
    let req = read_request(req_addr)?;
    check_request(&req)?;
    let last = req.param;
    if last != 0 && last <= ffi::MNT_UNIQUE_ID_OFFSET {
        return Err(Errno::EINVAL);
    }
    let rows = snapshot();
    let root = task_root();
    let listed = listed(&rows, &root, req.mnt_id)?;
    let ids = page(listed, last, flags & LISTMOUNT_REVERSE != 0, nr as usize);
    for (i, id) in ids.iter().enumerate() {
        if GuestMem.write_u64(ids_addr + 8 * i as u64, *id) != 0 {
            return Err(Errno::EFAULT);
        }
    }
    Ok(ids.len() as i64)
}

/// Every mount under `parent` -- or, for `LSMT_ROOT`, under the caller's
/// root, the root's own mount included -- in ascending id order. Linux's rule
/// is reachability from the parent's root, which in a table with no bind
/// mounts is a point below the parent's.
fn listed(rows: &[Row], root: &[u8], parent: u64) -> Result<Vec<u64>, Errno> {
    if parent == LSMT_ROOT {
        return Ok(rows.iter().filter(|r| under(root, &r.point)).map(Row::unique).collect());
    }
    let p = rows.iter().find(|r| r.unique() == parent).ok_or(Errno::ENOENT)?;
    permitted(p, rows, root)?;
    Ok(rows.iter().filter(|r| r.id != p.id && under(&p.point, &r.point)).map(Row::unique).collect())
}

/// The ids after `last` in the order asked for, at most `nr` of them.
fn page(mut ids: Vec<u64>, last: u64, reverse: bool, nr: usize) -> Vec<u64> {
    if reverse {
        ids.reverse();
        ids.retain(|id| last == 0 || *id < last);
    } else {
        ids.retain(|id| *id > last);
    }
    ids.truncate(nr);
    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: u32, point: &str) -> Row {
        Row { id, point: point.as_bytes().to_vec(), ..Default::default() }
    }

    fn table() -> Vec<Row> {
        vec![row(1, ""), row(2, "/proc"), row(3, "/dev"), row(4, "/dev/pts"), row(5, "/devices")]
    }

    #[test]
    fn a_parent_is_the_longest_proper_prefix_and_the_root_its_own() {
        let t = table();
        assert_eq!(parent(&t[3], &t).id, 3, "/dev/pts is under /dev");
        assert_eq!(parent(&t[4], &t).id, 1, "/devices is not under /dev");
        assert_eq!(parent(&t[1], &t).id, 1);
        assert_eq!(parent(&t[0], &t).id, 1, "the root is its own parent");
    }

    #[test]
    fn listmount_lists_descendants_and_not_the_mount_itself() {
        let t = table();
        let u = |id: u32| ffi::unique_mount_id(id);
        assert_eq!(listed(&t, b"", LSMT_ROOT).unwrap(), vec![u(1), u(2), u(3), u(4), u(5)]);
        assert_eq!(listed(&t, b"", u(1)).unwrap(), vec![u(2), u(3), u(4), u(5)]);
        assert_eq!(listed(&t, b"", u(3)).unwrap(), vec![u(4)]);
        assert_eq!(listed(&t, b"", u(99)), Err(Errno::ENOENT));
        // A task rooted at /dev sees /dev's mount and what is under it.
        assert_eq!(listed(&t, b"/dev", LSMT_ROOT).unwrap(), vec![u(3), u(4)]);
    }

    #[test]
    fn listmount_pages_from_the_last_id_either_way() {
        let ids = vec![10, 20, 30, 40];
        assert_eq!(page(ids.clone(), 0, false, 2), vec![10, 20]);
        assert_eq!(page(ids.clone(), 20, false, 9), vec![30, 40]);
        assert_eq!(page(ids.clone(), 0, true, 2), vec![40, 30]);
        assert_eq!(page(ids.clone(), 30, true, 9), vec![20, 10]);
        assert_eq!(page(ids, 0, false, 0), Vec::<u64>::new());
    }

    /// Offset 0 is the reserved empty string; an empty string is not
    /// reported; a string that does not fit is EOVERFLOW, measured with a
    /// 520-byte buffer (fits "/proc") and a 64-byte one (does not).
    #[test]
    fn the_string_table_is_linuxs() {
        let r = Row { point: b"/proc".to_vec(), fstype: b"proc".to_vec(), ..row(2, "/proc") };
        let a = describe(&r, std::slice::from_ref(&r), b"", FS_TYPE | MNT_POINT | SB_SOURCE, 4096).unwrap();
        assert_eq!(a.strings, b"\0proc\0/proc\0");
        assert_eq!(a.mask, FS_TYPE | MNT_POINT, "an empty source is left out");
        assert_eq!(u32::from_le_bytes(a.sm[36..40].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(a.sm[108..112].try_into().unwrap()), 6);
        assert!(describe(&r, std::slice::from_ref(&r), b"", MNT_POINT, 520).is_ok());
        assert_eq!(describe(&r, std::slice::from_ref(&r), b"", MNT_POINT, 64).err(), Some(Errno::EOVERFLOW));
        assert!(describe(&r, std::slice::from_ref(&r), b"", MNT_BASIC, 64).is_ok());
    }

    #[test]
    fn the_mount_point_is_the_callers_roots() {
        assert_eq!(point_from(b"", b""), b"/");
        assert_eq!(point_from(b"", b"/proc"), b"/proc");
        assert_eq!(point_from(b"/jail", b"/jail/proc"), b"/proc");
        assert_eq!(point_from(b"/jail", b"/jail"), b"/");
        assert_eq!(point_from(b"/jail", b"/proc"), b"");
        assert_eq!(point_from(b"/jail", b"/jailed"), b"");
    }
}
