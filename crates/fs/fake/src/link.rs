//! Hard link and fake symlink readback operations.

use std::ffi::{CStr, c_int};

use crate::{io_err, root, rx_err};
use crate::{
    EINVAL, ENOENT, EROFS, EXDEV, ffi, fix_path,
    is_under_readonly_bind_mount, mount_db, record_write, translate,
};

// --------------------------------------------------------- link and readlink

pub fn fakefs_rs_link(mount: &ffi::mount,
    src: &CStr,
    dst: &CStr,
) -> c_int {
    let (src_c, dst_c) = (src, dst);
    if is_under_readonly_bind_mount(dst_c) {
        return EROFS;
    }

    // A hook-routed path cannot share a meta.db row -- there is none -- so a
    // hard link between two of them is a host link and nothing else. Mixing a
    // hook-routed side with an ordinary one is EXDEV, which is what a link
    // across two filesystems is and which is the closest true statement: the
    // two sides genuinely cannot share metadata.
    let (src_t, dst_t) = (translate(src_c), translate(dst_c));
    let src_hook = matches!(src_t, Some((_, true)));
    let dst_hook = matches!(dst_t, Some((_, true)));
    if src_hook != dst_hook {
        return EXDEV;
    }
    if src_hook {
        let (a, b) = (src_t.expect("hook").0, dst_t.expect("hook").0);
        if let Err(e) = rustix::fs::link(a.as_slice(), b.as_slice()) {
            return rx_err(e);
        }
        record_write(dst_c);
        return 0;
    }

    let db = mount_db(mount);
    let mut tx = db.write();
    let err = realfs::realfs_link(mount, src, dst);
    if err < 0 {
        tx.rollback();
        return err;
    }
    if !tx.link(src_c.to_bytes(), dst_c.to_bytes()) {
        // The host link is already made and the metadata is not, so `dst`
        // would be a file with no row -- which stat answers ENOENT for while
        // the host still holds a reference to the contents. Undone rather than
        // left, and the transaction goes back with it.
        realfs::realfs_unlink(mount, dst);
        tx.rollback();
        return ENOENT;
    }
    tx.commit();
    0
}

/// A symlink whose target is the contents of a regular file.
///
/// That is fakefs's whole symlink model: the host holds a file with the target
/// in it and `meta.db` holds the `S_IFLNK` bit, because an iOS app cannot
/// always create a real symlink — a broken one cannot be shipped inside an app
/// bundle at all, Xcode refuses the build.
///
/// # Safety
///
/// `mount` is live.
fn file_readlink(mount: &ffi::mount,
    path: &CStr,
    buf: &mut [u8],
) -> isize {
    use rustix::fs::{Mode, OFlags, openat};
    use std::io::{ErrorKind, Read};

    let mut read = || -> Result<usize, c_int> {
        let fd = openat(root(mount)?, fix_path(path), OFlags::RDONLY, Mode::empty())
            .map_err(rx_err)?;
        let mut file = std::fs::File::from(fd);
        // The same loop as the write in symlink, for the same reason: a short
        // read is not an error and the thing being read is a path. One read(2)
        // returning less than the file holds gave the guest a prefix of the
        // target, which usually names something and is not it.
        let mut done = 0usize;
        while done < buf.len() {
            match file.read(&mut buf[done..]) {
                // the whole target, which is shorter than the buffer
                Ok(0) => break,
                Ok(n) => done += n,
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(io_err(e)),
            }
        }
        Ok(done)
    };
    match read() {
        Ok(n) => n as isize,
        Err(e) => e as isize,
    }
}

/// # Safety
///
/// `mount` is live with a `fakefs` database.
pub fn fakefs_rs_readlink(mount: &ffi::mount,
    path: &CStr,
    buf: &mut [u8],
) -> isize {
    let (db, path_c) = (mount_db(mount), path);
    // The row, and then it is done with. It used to be held across
    // realfs.readlink *and* the file read below, which opens a host file -- so
    // every readlink in the process serialised behind whichever one was in the
    // host. Nothing needs the row and the target together: the row only says
    // whether this is a link at all.
    let Some((iul, _)) = db.lookup_path(path_c.to_bytes()) else {
        return ENOENT as isize;
    };
    if iul.mode & libc::S_IFMT as u32 != libc::S_IFLNK as u32 {
        return EINVAL as isize;
    }
    let err = realfs::realfs_readlink(mount, path, buf);
    if err == EINVAL as isize {
        // Not a host symlink, so it is one of fakefs's own: a regular file
        // holding the target.
        return file_readlink(mount, path_c, buf);
    }
    err
}
