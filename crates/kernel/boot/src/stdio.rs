//! Initialize the guest's standard descriptors.

use std::os::fd::FromRawFd;
use std::ffi::{c_char, c_int};

use crate::ffi;

use guest_errno::c_int_::EBADF;

// ------------------------------------------------------------------- stdio

pub fn set_console_device(major: c_int, minor: c_int) {
    // `crates/fs/ttydev`'s, which an embedder may point elsewhere. A safe Rust
    // call since 2026-09-06: it was two `extern "C" { static mut }`
    // declarations and a pair of raw writes -- a dependency edge cargo cannot
    // see, and an `unsafe` block for what is now an atomic store.
    fs_ttydev::set_console_device(major, minor);
}

/// One definition, in `crates/fs/devices`.
fn dev_make(major: c_int, minor: c_int) -> u32 {
    fs_devices::dev_make(major as u32, minor as u32)
}

/// `dev_fake_from_real` in `fs/dev.h`: a host `dev_t` repacked as a guest one.
fn dev_fake_from_real(dev: libc::dev_t) -> u32 {
    fs_devices::dev_make(libc::major(dev) as u32, libc::minor(dev) as u32)
}

/// Descriptors 0, 1 and 2 pointing at one device.
///
/// # Safety
/// `iul.h`'s contract: `file` is a NUL-terminated guest path, and this runs on
/// the thread of the task being set up.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn create_stdio(file: *const c_char, major: c_int, minor: c_int) -> c_int {
    // SAFETY: the caller's contract, as declared in `iul.h`.
    open_stdio(unsafe { std::ffi::CStr::from_ptr(file) }, major, minor)
}

/// [`create_stdio`] for a Rust caller.
pub fn open_stdio(file: &std::ffi::CStr, major: c_int, minor: c_int) -> c_int {
    // `generic_openat`, not `generic_open`: the second is the `iul.h` entry
    // point and answers an `ERR_PTR`, and this is a Rust caller that can have
    // the `Result` the layer below already produces.
    // A regular file rather than a char device -- realfs cannot make device
    // nodes -- is dropped here, which closes it, and the fallback is used.
    //
    // By `type_`, which every open sets. It asked `fd.stat` until 2026-09-30,
    // which is the cache a *fakefs* descriptor answers `fstat` from and is
    // zero on this one -- so every console that opened was dropped, and the
    // guest's stdio was always the fallback below: a descriptor with no path,
    // `anon_inode:[unknown]` at `/proc/self/fd/0`, which `ttyname` cannot
    // name and `tty` calls "not a tty".
    let opened = fs_generic::generic_openat(ffi::At::Pwd, file, ffi::O_RDWR_ as c_int, 0)
        .ok()
        .filter(|fd| u32::from(fd.type_) & ffi::S_IFMT == ffi::S_IFCHR);
    let fd = match opened {
        Some(fd) => fd,
        None => {
            let mut fd = fs_adhoc::adhoc_anon(None, None);
            fd.stat.rdev = u64::from(dev_make(major, minor));
            fd.stat.mode = (libc::S_IFCHR | libc::S_IRUSR) as u32;
            fd.set_flags(ffi::O_RDWR_);
            // Unpublished through the device's open, as `generic_openat` does;
            // a refusal drops it.
            let err = fs_devices::open_device(major, minor, ffi::DEV_CHAR as c_int, &mut fd);
            if err < 0 {
                return err;
            }
            fd.into_owned()
        }
    };

    // The three slots publish as one table transaction: Rust takes the extra
    // references while holding its mutex, and every displaced owner is released
    // after that mutex is gone.
    let mut displaced = Vec::new();
    let limit = kernel_rlimit::current_soft(ffi::RLIMIT_NOFILE_ as c_int as u32) as usize;
    let fd = fd;
    match taskview::with_current_fdtable(|table| table.replace_range(fd, 0, 3, false, limit, &mut displaced)) {
        Some(Ok(())) => {}
        // The table takes the reference only on success, so this is the one
        // handed in coming back -- the same close the raw-pointer version did,
        // said by the type.
        Some(Err((error, given_back))) => {
            let _ = given_back.close();
            return error;
        }
        // No table: `fd` went with the closure, which is its release.
        None => return EBADF,
    }
    // After the table's mutex is gone; see `fdtable::replace_range`.
    drop(displaced);
    0
}

/// A guest descriptor onto a host one this process already has.
///
/// The stat matters: node's libuv calls `fstat` on stdout and stderr to decide
/// whether they are a tty, a pipe or a file, and an all-zero one makes
/// `console.log` silently do nothing.
///
/// **The description owns the host descriptor**, as it always did: its close is
/// `realfs_close`, which closed `fd_no` by number. `OwnedFd` says so since
/// 2026-09-29, and it is why this is not a `dup`: the guest closing its last
/// reference to stdout closes the process's, which is what a program at the
/// end of a pipe is waiting for.
///
/// A host pipe is a pipe here too, so `/proc/self/fd/1` reads `pipe:[ino]` and
/// `fstatfs` names pipefs, as on Linux. Every host descriptor was an anonymous
/// inode until 2026-10-18, which read back as `anon_inode:[unknown]`.
fn from_host_fd(fd_no: c_int) -> fs_fdobj::Owned {
    // SAFETY: one of 0, 1 and 2, which this process holds and hands to the
    // guest here, once each.
    let host = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd_no) };
    let st = rustix::fs::fstat(&host).ok();
    let mut fresh = if st.is_some_and(|st| st.st_mode & libc::S_IFMT == libc::S_IFIFO) {
        fs_adhoc::adhoc_new(Some(&realfs::REALFS_FDOPS), fs_adhoc::Kind::Pipe)
    } else {
        fs_adhoc::adhoc_anon(Some(&realfs::REALFS_FDOPS), None)
    };
    if let Some(st) = st {
        fresh.stat.mode = st.st_mode as u32;
        fresh.stat.rdev = u64::from(dev_fake_from_real(st.st_rdev));
        fresh.stat.inode = st.st_ino;
        fresh.stat.size = st.st_size as u64;
        // On macOS a piped or redirected descriptor can appear as a socket,
        // and guest programs -- node and libuv especially -- do not recognise
        // one as a valid stdio type and fail to set stdout up at all. Linux
        // shows a character device for a tty, so that is what a socket or a
        // real terminal is reported as, which lets uv_guess_handle see
        // something it knows.
        if st.st_mode & libc::S_IFMT == libc::S_IFSOCK || rustix::termios::isatty(&host) {
            fresh.stat.mode = (libc::S_IFCHR | 0o620) as u32;
            fresh.stat.rdev = u64::from(dev_make(ffi::TTY_PSEUDO_SLAVE_MAJOR as c_int, 0));
        }
    }
    fresh.real_fd = Some(host);
    fresh.into_owned()
}

/// Descriptors 0, 1 and 2 onto the host's, for a guest sharing this process's
/// terminal or pipes.
pub fn create_piped_stdio() -> c_int {
    for slot in 0..3 {
        let fd = from_host_fd(slot);
        let limit = kernel_rlimit::current_soft(ffi::RLIMIT_NOFILE_ as c_int as u32) as usize;
        // Whatever comes back -- the displaced descriptor, or this one refused
        // -- is dropped after the table's mutex is gone.
        drop(taskview::with_current_fdtable(|table| table.replace(fd, slot, false, limit)));
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_make_packs_the_way_fs_dev_h_packs_one() {
        assert_eq!(dev_make(4, 1), 0x401);
        assert_eq!(dev_make(136, 3), (136 << 8) | 3);
    }
}
