//! A temporary change of the **host process's** working directory.
//!
//! One host process runs every guest thread, so its working directory is shared
//! by all of them and by whatever else the embedder is doing. Some host calls
//! have no `*at` form that this kernel can use — `mknod` of a FIFO is the one
//! that needed this — so the directory is changed, the call is made, and it is
//! changed back, under a lock that makes the three one operation.
//!
//! # Nothing used to change it back
//!
//! One `realfs_mknod` of a FIFO moved the host process's working directory to a
//! mount's root **permanently**, and every later relative host syscall — in any
//! thread, in any mount, including the host integrations outside this kernel —
//! resolved against it.
//!
//! # Refusing is the only safe failure
//!
//! Without somewhere to come back to, the change is not temporary, and the
//! caller does relative host operations on the strength of it being so. So a
//! failure to open `.` is a refusal rather than a change made anyway.

use std::fs::File;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::{Mutex, MutexGuard};

/// Held for as long as the directory is changed.
static LOCK: Mutex<()> = Mutex::new(());

/// The directory is changed while this lives, and goes back when it drops --
/// including on an early return.
///
/// There were two calls, `lock_fchdir` and `unlock_fchdir`, until 2026-09-29,
/// because the C that called them could not hold a guard: the `MutexGuard` was
/// leaked into a `Box` and its address parked in a second static for the
/// unlock to find. Every caller is Rust now, so the guard is simply a field.
pub struct Chdir {
    /// Where to come back to. Dropped after the change back, because the
    /// fields drop after `Drop::drop` runs.
    here: OwnedFd,
    _held: MutexGuard<'static, ()>,
}

impl Chdir {
    /// Change to `dir`, remembering where we were. On an error nothing has
    /// changed and nothing is held.
    pub fn to(dir: impl AsFd) -> io::Result<Chdir> {
        let held = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let here = File::open(".")?.into();
        rustix::process::fchdir(dir)?;
        Ok(Chdir { here, _held: held })
    }
}

impl Drop for Chdir {
    fn drop(&mut self) {
        // Nothing to report to: a failure here means `.` was removed while we
        // were away, and the lock is released either way.
        let _ = rustix::process::fchdir(&self.here);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// These change the *process's* working directory, and cargo runs a
    /// crate's tests on several threads of one process. `Chdir` serialises the
    /// changes but not the `current_dir` either side of them, so a test reading
    /// where it started while another has the directory moved would read the
    /// other one's. One lock over each whole case.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn serial() -> MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn cwd() -> PathBuf {
        std::env::current_dir().unwrap()
    }

    fn root() -> File {
        File::open("/").unwrap()
    }

    /// The whole point: where we were is where we end up.
    #[test]
    fn the_directory_comes_back() {
        let _serial = serial();
        let before = cwd();
        {
            let _at = Chdir::to(root()).expect("changed");
            assert_eq!(cwd(), PathBuf::from("/"));
        }
        assert_eq!(cwd(), before);
    }

    /// A descriptor that is not a directory changes nothing and holds nothing --
    /// which the next successful change proves, because it could not take the
    /// lock otherwise.
    ///
    /// An invalid descriptor is not a case any more: `-1` was, when this took a
    /// `c_int`, and `BorrowedFd` cannot hold it.
    #[test]
    fn a_failed_change_leaves_the_lock_free() {
        let _serial = serial();
        let before = cwd();
        let not_a_dir = File::open("/etc/hosts").unwrap();
        let err = Chdir::to(&not_a_dir).err().expect("refused");
        assert_eq!(err.raw_os_error(), Some(libc::ENOTDIR));
        assert_eq!(cwd(), before);

        drop(Chdir::to(root()).expect("the lock was free"));
        assert_eq!(cwd(), before);
    }

    /// An early return still goes back.
    #[test]
    fn an_early_return_still_comes_back() {
        let _serial = serial();
        let before = cwd();
        fn body(dir: File) -> Option<()> {
            let _at = Chdir::to(dir).ok()?;
            None // the "error" path, taken with the directory changed
        }
        assert!(body(root()).is_none());
        assert_eq!(cwd(), before);
    }

    /// Repeated use does not accumulate descriptors: the saved cwd is opened on
    /// every change and has to be closed on every return.
    ///
    /// A probe descriptor's *number* stands in for how many are open: the
    /// lowest free number does not climb if nothing is being kept. One round
    /// first, so any one-off allocation is already made.
    #[test]
    fn repeated_use_does_not_leak() {
        let _serial = serial();
        let dir = root();
        drop(Chdir::to(&dir).unwrap());
        let probe = || {
            use std::os::fd::AsRawFd;
            File::open("/dev/null").unwrap().as_raw_fd()
        };
        let before = probe();
        for i in 0..64 {
            drop(Chdir::to(&dir).unwrap_or_else(|e| panic!("iteration {i}: {e}")));
        }
        assert_eq!(probe(), before, "a descriptor was kept");
    }
}
