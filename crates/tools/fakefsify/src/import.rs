//! Tarball -> fakefs.

use std::io::Write;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use rustix::fs::{AtFlags, Mode, OFlags, Timespec, Timestamps};

use crate::archive::{self, FileType};
use crate::db::{self, IulStat};
use crate::error::{Error, IoContext, Result};
use crate::path as guest_path;

/// `utimensat` reads this in `tv_nsec` to mean "leave this timestamp alone".
const UTIME_OMIT: i64 = 1_073_741_822;

pub fn import(archive_path: &Path, fs: &Path) -> Result<()> {
    // Refuse to import over an existing directory, as the C version did by
    // letting this mkdir fail.
    std::fs::create_dir(fs).doing(|| format!("creating {}", fs.display()))?;

    let data = fs.join("data");
    match std::fs::create_dir(&data) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => {
            return Err(Error::Io {
                doing: format!("creating {}", data.display()),
                source: e,
            });
        }
    }
    let root = rustix::fs::open(&data, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
        .doing(|| format!("opening {}", data.display()))?;

    let mut conn = db::create(&fs.join("meta.db"))?;

    // One transaction for the whole import, matching the C version: a
    // half-imported fakefs is not something the kernel should ever open.
    let tx = conn.transaction()?;
    let mut archive_has_root = false;
    {
        let mut insert_stat = tx.prepare("insert into stats (stat) values (?)")?;
        let mut insert_path = tx.prepare("insert or replace into paths values (?, ?)")?;
        let mut insert_hardlink = tx.prepare(
            "insert or replace into paths values (?, (select inode from paths where path = ? limit 1))",
        )?;

        archive::read(archive_path, |entry, body| {
            let Some(path) = guest_path::normalize(&entry.pathname) else {
                eprintln!(
                    "warning: skipped possible path traversal {}",
                    guest_path::display(&entry.pathname)
                );
                return Ok(());
            };
            if path.is_empty() {
                archive_has_root = true;
            }

            if let Some(hardlink) = &entry.hardlink {
                let Some(target) = guest_path::normalize(hardlink) else {
                    eprintln!(
                        "warning: skipped hardlink to a path outside the root: {}",
                        guest_path::display(hardlink)
                    );
                    return Ok(());
                };
                rustix::fs::linkat(
                    root.as_fd(),
                    guest_path::fix(&target),
                    root.as_fd(),
                    guest_path::fix(&path),
                    AtFlags::empty(),
                )
                .doing(|| {
                    format!(
                        "linking {} to {}",
                        guest_path::display(&path),
                        guest_path::display(&target)
                    )
                })?;
                insert_hardlink.execute(rusqlite::params![&path[..], &target[..]])?;
                return Ok(());
            }

            create_parent_dirs(root.as_fd(), &path)?;

            // First create the node. A symlink is stored as a regular file
            // whose contents are the target: the mode in meta.db is what makes
            // it a symlink to the guest.
            let mut fd: Option<OwnedFd> = None;
            match entry.filetype {
                FileType::Regular
                | FileType::Symlink
                | FileType::Block
                | FileType::Char
                | FileType::Socket => {
                    match rustix::fs::openat(
                        root.as_fd(),
                        guest_path::fix(&path),
                        OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::CLOEXEC,
                        Mode::from_bits_truncate(0o666),
                    ) {
                        Ok(f) => fd = Some(f),
                        // Assume a case-insensitive host filesystem already
                        // has this name as a directory.
                        Err(rustix::io::Errno::ISDIR) => return Ok(()),
                        Err(e) => {
                            return Err(Error::Io {
                                doing: format!("creating {}", guest_path::display(&path)),
                                source: e.into(),
                            });
                        }
                    }
                }
                FileType::Directory => {
                    match rustix::fs::mkdirat(
                        root.as_fd(),
                        guest_path::fix(&path),
                        Mode::from_bits_truncate(0o777),
                    ) {
                        Ok(()) => {}
                        Err(rustix::io::Errno::EXIST) => {}
                        Err(e) => {
                            return Err(Error::Io {
                                doing: format!("creating directory {}", guest_path::display(&path)),
                                source: e.into(),
                            });
                        }
                    }
                }
                FileType::Fifo => mkfifo_at(root.as_fd(), &path)?,
                FileType::Other => {
                    eprintln!(
                        "warning: {} has a file type fakefs does not handle; recording metadata only",
                        guest_path::display(&path)
                    );
                }
            }

            // Then fill in contents, for the two types that have any.
            match entry.filetype {
                FileType::Regular => {
                    let fd = fd.take().expect("a regular file was just opened");
                    std::io::copy(body, &mut std::fs::File::from(fd))
                        .doing(|| format!("writing {}", guest_path::display(&path)))?;
                }
                FileType::Symlink => {
                    let target = entry.symlink.as_deref().unwrap_or_default();
                    let fd = fd.as_ref().expect("a symlink was just opened");
                    let mut file =
                        std::fs::File::from(fd.try_clone().doing(|| {
                            format!("duplicating fd for {}", guest_path::display(&path))
                        })?);
                    file.write_all(target).doing(|| {
                        format!("writing symlink target for {}", guest_path::display(&path))
                    })?;
                }
                _ => {}
            }
            drop(fd);

            set_times(root.as_fd(), &path, &entry.atime, &entry.mtime)?;

            let stat = IulStat {
                mode: entry.mode,
                uid: entry.uid,
                gid: entry.gid,
                rdev: entry.rdev,
            };
            insert_stat.execute(rusqlite::params![&stat.to_blob()[..]])?;
            insert_path.execute(rusqlite::params![&path[..], tx.last_insert_rowid()])?;
            Ok(())
        })?;

        // The kernel resolves the root by looking up the empty blob, so a
        // tarball that carries no entry for "." still needs the row.
        if !archive_has_root {
            let stat = IulStat {
                mode: libc::S_IFDIR as u32 | 0o755,
                ..IulStat::default()
            };
            insert_stat.execute(rusqlite::params![&stat.to_blob()[..]])?;
            insert_path.execute(rusqlite::params![&b""[..], tx.last_insert_rowid()])?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// `mkdir -p` for everything above the last component of `path`.
///
/// Tarballs do not reliably carry an entry for every parent directory.
fn create_parent_dirs(root: BorrowedFd<'_>, path: &[u8]) -> Result<()> {
    for (i, _) in path.iter().enumerate().filter(|&(_, &b)| b == b'/') {
        if i == 0 {
            // The leading slash: the prefix would be the empty root, which
            // already exists.
            continue;
        }
        let prefix = &path[..i];
        match rustix::fs::mkdirat(
            root,
            guest_path::fix(prefix),
            Mode::from_bits_truncate(0o777),
        ) {
            Ok(()) => {}
            Err(rustix::io::Errno::EXIST) => {}
            Err(e) => {
                return Err(Error::Io {
                    doing: format!("creating directory {}", guest_path::display(prefix)),
                    source: e.into(),
                });
            }
        }
    }
    Ok(())
}

fn set_times(
    root: BorrowedFd<'_>,
    path: &[u8],
    atime: &Option<(i64, i64)>,
    mtime: &Option<(i64, i64)>,
) -> Result<()> {
    // An unset timestamp becomes UTIME_OMIT rather than the epoch. ctime
    // cannot be set through utimensat at all.
    let to_spec = |t: &Option<(i64, i64)>| match t {
        Some((sec, nsec)) => Timespec {
            tv_sec: *sec,
            tv_nsec: *nsec as _,
        },
        None => Timespec {
            tv_sec: 0,
            tv_nsec: UTIME_OMIT as _,
        },
    };
    let times = Timestamps {
        last_access: to_spec(atime),
        last_modification: to_spec(mtime),
    };
    rustix::fs::utimensat(root, guest_path::fix(path), &times, AtFlags::empty())
        .doing(|| format!("setting timestamps on {}", guest_path::display(path)))
}

/// Create a FIFO relative to `root`.
///
/// `mkfifoat`, which both Darwin and Linux have. This used to change directory
/// and change back, on the stated grounds that there is no `mkfifoat` — and the
/// current directory is **process-wide**, so two threads importing at once each
/// created their FIFO in whichever directory the other had just moved to. It
/// showed up as `crates/tools/fakefsify`'s own tests failing about one workspace
/// run in three, one with `EEXIST` creating a fifo and the other with `ENOENT`
/// stamping the one it thought it had made.
///
/// The C this was rewritten from held a lock (`lock_fchdir`) for exactly that
/// reason. The rewrite replaced the restore with a `Drop` guard, which is
/// better, and dropped the mutual exclusion, which was the other half of what
/// the lock was for. Not changing directory at all needs neither.
fn mkfifo_at(root: BorrowedFd<'_>, path: &[u8]) -> Result<()> {
    let name = std::ffi::CString::new(guest_path::fix(path))
        .map_err(|_| Error::Corrupt("fifo path contains an interior NUL".into()))?;
    // SAFETY: `name` is a valid NUL-terminated string for the duration of the
    // call and `root` is an open directory.
    let rc = unsafe { libc::mkfifoat(rustix::fd::AsRawFd::as_raw_fd(&root), name.as_ptr(), 0o666) };
    if rc < 0 {
        return Err(Error::Io {
            doing: format!("creating fifo {}", guest_path::display(path)),
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(())
}
