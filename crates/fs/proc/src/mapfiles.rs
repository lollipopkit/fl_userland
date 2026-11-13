//! `/proc/<pid>/map_files`: one link per file mapping, named
//! `<start>-<end>` in unpadded hex and reading as the mapped file's path.
//!
//! Linux's rules, measured by `procstate_probe` and `procaccess_probe`:
//!
//! - the directory is `dr-x------`, owned as the process's other entries are,
//!   and its own thread group may list it whoever owns it
//!   (`proc_fd_permission`);
//! - listing it, looking a name up and reading a link ask
//!   `PTRACE_MODE_READ_FSCREDS` (`EACCES`), the rows' `guard`;
//! - **following** a link asks `CAP_SYS_ADMIN` as well (`EPERM`), because the
//!   file it reaches is the mapping's and not a fresh lookup of its name:
//!   without the capability a process could open a file it mapped through a
//!   directory it can no longer search;
//! - a link's mode is `r` and `w` for the user by how the mapped file was
//!   opened.

use std::ffi::{CString, c_int, c_ulong};

use crate::ffi;
use crate::pidentry::ptrace_guard;
use crate::root::blank;

use guest_errno::c_int_::{ENOENT, EPERM};

fn name_of(start: u64, end: u64) -> String {
    format!("{start:x}-{end:x}")
}

fn map_getname(entry: &mut ffi::proc_entry, buf: &mut [u8]) {
    let name = entry.name.as_ref().map_or(&b""[..], |n| n.to_bytes());
    crate::entry::put_name(buf, name);
}

/// The file mapped at the region this entry names, if it is still mapped
/// exactly there.
fn mapped(entry: &mut ffi::proc_entry) -> Option<fs_fdobj::Owned> {
    let want = entry.name.as_ref()?.to_str().ok()?.to_owned();
    crate::pidmem::file_regions(entry).into_iter().find(|(s, e, _)| name_of(*s, *e) == want).map(|(_, _, fd)| fd)
}

fn map_readlink(entry: &mut ffi::proc_entry, buf: &mut [u8]) -> c_int {
    match mapped(entry) {
        Some(fd) => fs_generic::generic_getpath(&fd, buf),
        None => ENOENT,
    }
}

/// `proc_map_files_get_link`. A file with a path is followed by it, as
/// `fd/<n>` is; one without (a `memfd`) is the mapping's own.
fn map_magic(entry: &mut ffi::proc_entry) -> Result<Option<ffi::FdOwned>, c_int> {
    if !(taskview::capable(taskview::caps::CAP_SYS_ADMIN) || taskview::capable(taskview::caps::CAP_CHECKPOINT_RESTORE)) {
        return Err(EPERM);
    }
    let Some(fd) = mapped(entry) else {
        return Ok(None);
    };
    let mut buf = vec![0u8; ffi::MAX_PATH as usize];
    Ok((fs_generic::generic_getpath(&fd, &mut buf) >= 0 && buf[0] != b'/').then_some(fd))
}

const fn link(mode: u32) -> ffi::proc_dir_entry {
    ffi::proc_dir_entry {
        mode: libc::S_IFLNK | mode as u16,
        getname: Some(map_getname),
        readlink: Some(map_readlink),
        magic: Some(map_magic),
        jumps: true,
        guard: Some(ptrace_guard),
        ..blank()
    }
}

/// By the open file's access mode: `O_RDONLY`, `O_WRONLY`, `O_RDWR`, and the
/// fourth, which opens for neither.
static LINKS: [ffi::proc_dir_entry; 4] = [link(0o400), link(0o200), link(0o600), link(0)];

pub(crate) fn map_files_readdir(entry: &mut ffi::proc_entry, index: &mut c_ulong) -> Option<ffi::proc_entry> {
    let i = *index as usize;
    let (start, end, fd) = crate::pidmem::file_regions(entry).into_iter().nth(i)?;
    let access = (fd.flags() & ffi::O_ACCMODE_) as usize;
    *index += 1;
    Some(ffi::proc_entry {
        meta: Some(&LINKS[access]),
        name: CString::new(name_of(start, end)).ok(),
        pid: entry.pid,
        fd: i as i32,
        ..ffi::proc_entry::default()
    })
}
