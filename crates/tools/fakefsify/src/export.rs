//! fakefs -> tarball.

use std::io::Read;
use std::os::fd::AsFd;
use std::path::Path;

use rustix::fs::{AtFlags, Mode, OFlags};

use crate::archive::{FileType, LinkResolver, OwnedEntry, Writer};
use crate::db::{self, IulStat};
use crate::error::{Error, IoContext, Result};
use crate::path as guest_path;

/// Stands in for st_dev in exported entries. A fakefs is one "device"; the
/// value is arbitrary but must be non-zero and the same for every entry, so
/// that (dev, ino) identifies an inode within the archive.
const FAKEFS_DEV: u64 = 1;

pub fn export(fs: &Path, archive_path: &Path) -> Result<()> {
    let mut writer = Writer::create(archive_path)?;

    let data = fs.join("data");
    let root = rustix::fs::open(&data, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
        .doing(|| format!("opening {}", data.display()))?;

    let conn = db::open_for_export(&fs.join("meta.db"))?;
    let mut resolver = LinkResolver::new_tar();

    // nlink comes along because the link resolver needs it to spot a file with
    // more than one name; see OwnedEntry::set_nlink.
    let mut stmt = conn.prepare(
        "select path, inode, stat, count(*) over (partition by inode) \
         from paths, stats using (inode)",
    )?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let db_path: Vec<u8> = row.get(0)?;
        let inode: i64 = row.get(1)?;
        let stat_blob: Vec<u8> = row.get(2)?;
        let nlink: i64 = row.get(3)?;
        let stat = IulStat::from_blob(&stat_blob)?;

        // Archive members are relative: the root, stored as the empty blob,
        // becomes ".". This doubles as the path for the *at() calls below.
        let mut path = Vec::with_capacity(db_path.len() + 1);
        path.push(b'.');
        path.extend_from_slice(&db_path);

        let real = match rustix::fs::statat(root.as_fd(), &path[..], AtFlags::empty()) {
            Ok(s) => s,
            Err(rustix::io::Errno::NOENT) => {
                // meta.db knows a path that data/ does not have.
                println!("skipping {}", guest_path::display(&path));
                continue;
            }
            Err(e) => {
                return Err(Error::Io {
                    doing: format!("stat {}", guest_path::display(&path)),
                    source: e.into(),
                });
            }
        };

        let mut entry = OwnedEntry::new();
        entry.set_pathname(&path)?;
        // Inode numbers are meta.db rowids and the "device" is the fakefs
        // itself, so a constant stands in for it. Both are needed: the link
        // resolver keys on the pair.
        entry.set_dev(FAKEFS_DEV);
        entry.set_ino64(inode);
        entry.set_nlink(nlink.max(1) as u32);
        // Mode, ownership and device numbers come from meta.db, not from the
        // host file — carrying them is the entire point of a fakefs.
        entry.set_filetype(FileType::of_mode(stat.mode));
        entry.set_mode(stat.mode);
        entry.set_uid(stat.uid);
        entry.set_gid(stat.gid);
        entry.set_rdev(stat.rdev);
        entry.set_size(real.st_size as i64);
        entry.set_atime(real.st_atime as i64, real.st_atime_nsec as i64);
        entry.set_mtime(real.st_mtime as i64, real.st_mtime_nsec as i64);
        entry.set_ctime(real.st_ctime as i64, real.st_ctime_nsec as i64);

        // Regular files and symlinks have contents in data/; everything else
        // is metadata only. The C version called openat() for both without
        // checking the result and passed -1 straight to read().
        let mut file = if stat.is_regular() || stat.is_symlink() {
            let fd = rustix::fs::openat(
                root.as_fd(),
                &path[..],
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .doing(|| format!("opening {}", guest_path::display(&path)))?;
            Some(std::fs::File::from(fd))
        } else {
            None
        };

        if stat.is_symlink() {
            // A symlink's target is the file's contents.
            let mut target = Vec::new();
            file.as_mut()
                .expect("a symlink was just opened")
                .read_to_end(&mut target)
                .doing(|| format!("reading symlink target of {}", guest_path::display(&path)))?;
            entry.set_symlink(&target)?;
        }

        // Filter through the hardlink cache: the second and later names of an
        // inode come back as hardlinks with no body.
        let entry = resolver.linkify(entry);
        match file.as_mut().filter(|_| stat.is_regular()) {
            Some(file) => writer.write_entry(&entry, file)?,
            None => writer.write_entry(&entry, std::io::empty())?,
        }
    }

    drop(rows);
    drop(stmt);
    writer.finish()
}
