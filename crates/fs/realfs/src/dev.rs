//! Device numbers, and the `/dev` entries a passthrough mount fakes.
//!
//! A host directory used as a guest root has no device nodes in it — iOS gives
//! an app no way to make one, and on a Mac they would need root. What is there
//! instead is an ordinary empty file per device, and `stat` rewrites its mode
//! and rdev so the guest sees a character device.
//!
//! The encoding is Linux's legacy `dev_t`, which is what the guest expects and
//! is unrelated to the host's. It is duplicated from the inline functions in
//! `fs/dev.h` rather than called through them because they are `static inline`
//! and bindgen emits nothing for those; the test below pins the two together
//! by checking the round trip and the documented layout.

use crate::ffi;

/// `mmmMMMmm` in hex, where M is major and m is minor.
pub fn make(major: u32, minor: u32) -> ffi::dev_t_ {
    ((minor & 0xfff00) << 12) | (major << 8) | (minor & 0xff)
}

/// A host `dev_t` re-encoded the way the guest reads them.
pub(crate) fn fake_from_real(dev: libc::dev_t) -> ffi::dev_t_ {
    make(libc::major(dev) as u32, libc::minor(dev) as u32)
}

/// The device a well-known `/dev` path stands for, if it is one.
///
/// Matched on the guest path, before `fix_path` strips the leading slash.
pub(crate) fn for_path(path: &[u8]) -> Option<ffi::dev_t_> {
    let name = path.strip_prefix(b"/dev/")?;
    let (major, minor) = match name {
        b"null" => (ffi::MEM_MAJOR, ffi::DEV_NULL_MINOR),
        b"zero" => (ffi::MEM_MAJOR, ffi::DEV_ZERO_MINOR),
        b"full" => (ffi::MEM_MAJOR, ffi::DEV_FULL_MINOR),
        b"random" => (ffi::MEM_MAJOR, ffi::DEV_RANDOM_MINOR),
        b"urandom" => (ffi::MEM_MAJOR, ffi::DEV_URANDOM_MINOR),
        b"tty" => (ffi::TTY_ALTERNATE_MAJOR, ffi::DEV_TTY_MINOR),
        b"console" => (ffi::TTY_ALTERNATE_MAJOR, ffi::DEV_CONSOLE_MINOR),
        b"ptmx" => (ffi::TTY_ALTERNATE_MAJOR, ffi::DEV_PTMX_MINOR),
        _ => return None,
    };
    Some(make(major, minor))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The inverses, only needed to check that `make` is one.
    fn major(dev: ffi::dev_t_) -> u32 {
        (dev & 0xfff00) >> 8
    }
    fn minor(dev: ffi::dev_t_) -> u32 {
        ((dev & 0xfff00000) >> 12) | (dev & 0xff)
    }

    #[test]
    fn the_encoding_is_the_one_fs_dev_h_documents() {
        // mmmMMMmm: major 0x123 with minor 0x45678 packs to 0x45612378 —
        // the minor's high bits, the major, then the minor's low byte.
        #[allow(clippy::unusual_byte_groupings)]
        let packed = 0x456_123_78;
        assert_eq!(make(0x123, 0x45678), packed);
    }

    #[test]
    fn make_round_trips_through_both_halves_of_the_minor() {
        for &(maj, min) in &[(1u32, 3u32), (5, 0), (136, 0), (0xfff, 0xfffff), (4, 255)] {
            let dev = make(maj, min);
            assert_eq!(major(dev), maj, "major of {maj}:{min}");
            assert_eq!(minor(dev), min, "minor of {maj}:{min}");
        }
    }

    #[test]
    fn a_host_dev_t_survives_the_trip() {
        let host = libc::makedev(14, 200);
        let guest = fake_from_real(host);
        assert_eq!((major(guest), minor(guest)), (14, 200));
    }

    #[test]
    fn dev_paths_are_matched_whole() {
        assert_eq!(for_path(b"/dev/null"), Some(make(1, 3)));
        assert_eq!(for_path(b"/dev/ptmx"), Some(make(5, 2)));
        // Not a prefix match: these are ordinary files that happen to start
        // with the name of a device.
        assert_eq!(for_path(b"/dev/nullx"), None);
        assert_eq!(for_path(b"/dev/null/x"), None);
        assert_eq!(for_path(b"/dev/subdir/null"), None);
        assert_eq!(for_path(b"/devnull"), None);
        assert_eq!(for_path(b"/tmp/null"), None);
        assert_eq!(for_path(b"/dev/"), None);
        assert_eq!(for_path(b""), None);
    }
}
