//! A guest's descriptor limit is the guest's, not the host's.
//!
//! Every guest descriptor is backed by at least one host descriptor. macOS and
//! iOS default the soft `RLIMIT_NOFILE` to 256, and this kernel's own default
//! for a guest is 1024 soft / 4096 hard — so an embedder that never raised the
//! host's limit gave its guests a quarter of what `getrlimit` told them they
//! had, and the failure arrived as `EMFILE` at a number the guest could not
//! account for.

use guest_tests::{Harness, check};

fn main() {
    let mut h = Harness::new();
    h.group("open-up-to-the-guests-own-limit");

    let mut lim: libc::rlimit = unsafe { std::mem::zeroed() };
    unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) };
    let soft = lim.rlim_cur as usize;
    check!(h, soft >= 1024, "the guest is told it has at least 1024: {soft}");

    // Leave headroom for what the process already has open and for anything the
    // harness needs; the point is to get close to the limit, not to hit it
    // exactly.
    let want = soft.min(4096) - 32;
    let mut fds = Vec::with_capacity(want);
    let mut err = 0;
    let path = std::ffi::CString::new("/dev/null").unwrap();
    while fds.len() < want {
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
        if fd < 0 {
            err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            break;
        }
        fds.push(fd);
    }
    let got = fds.len();
    for fd in &fds {
        unsafe { libc::close(*fd) };
    }
    check!(h, got == want,
        "opened {want} descriptors under a limit of {soft}: got {got}, errno {err}");

    std::process::exit(h.finish());
}
