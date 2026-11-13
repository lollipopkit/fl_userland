//! Per-descriptor and per-mount state for tmpfs.

use std::sync::{Arc, Mutex};

use libc::c_ulong;

use taskview::ffi;

use crate::tree::Dirent;

/// State kept in a tmpfs file descriptor's opaque filesystem slot.
pub(crate) struct FdState {
    pub(crate) dirent: Arc<Dirent>,
    pub(crate) dir_pos: Mutex<DirPos>,
}

/// Whether a descriptor was opened for reading.
pub(crate) fn readable(fd: &ffi::fd) -> bool {
    let mode = (fd.flags()) & ffi::O_ACCMODE_;
    mode == ffi::O_RDONLY_ || mode == ffi::O_RDWR_
}

/// Whether a descriptor was opened for writing.
pub(crate) fn writable(fd: &ffi::fd) -> bool {
    let mode = (fd.flags()) & ffi::O_ACCMODE_;
    mode == ffi::O_WRONLY_ || mode == ffi::O_RDWR_
}

/// Cursor used by directory reads. It is stored separately from `fd.offset`
/// because directory cookies identify children rather than byte positions.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirPos {
    Dot,
    DotDot,
    Child(u64),
    End,
}

impl DirPos {
    pub(crate) fn to_cookie(self) -> c_ulong {
        match self {
            DirPos::Dot => 0,
            DirPos::DotDot => 1,
            DirPos::Child(i) => (i as c_ulong).wrapping_add(2),
            DirPos::End => c_ulong::MAX,
        }
    }

    pub(crate) fn from_cookie(cookie: c_ulong) -> DirPos {
        match cookie {
            0 => DirPos::Dot,
            1 => DirPos::DotDot,
            c_ulong::MAX => DirPos::End,
            n => DirPos::Child(n - 2),
        }
    }
}

/// # Safety
/// `fd` must be a live `struct fd` this filesystem opened.
pub(crate) fn fd_state(fd: &ffi::fd) -> Option<&FdState> {
    fd.fs_data::<FdState>()
}

/// The mount's root directory; `None` for a mount that is not a tmpfs, which
/// the type check says rather than a contract.
pub(crate) fn mount_root(mount: &ffi::mount) -> Option<&Arc<Dirent>> {
    mount.state.data::<Arc<Dirent>>()
}
