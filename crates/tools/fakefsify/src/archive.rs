//! Reading and writing the gzipped tarballs fakefsify converts.
//!
//! The `tar` and `flate2` crates since 2026-10-17. It was a wrapper over
//! libarchive -- forty-six `unsafe` blocks, a `Drop` per handle, a linker
//! search for Homebrew's keg-only copy, and a locale dependency: libarchive
//! converts a stored name to the process's narrow charset, so in the `"C"`
//! locale a non-ASCII symlink target came back NULL and aborted the import
//! (`a_symlink_target_that_is_not_ascii`). Names are bytes here, end to end.
//!
//! What is kept from that wrapper: an entry's fields are copied out before its
//! body is handed over, and archives are written in pax form -- a name or link
//! target too long for the ustar header goes in a pax record, raw, so the
//! archive carries exactly the bytes it was given, `..` and `//` included.
//! Import is what decides what a name means.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;

use crate::error::{Error, IoContext, Result};

/// What kind of node an archive entry describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FileType {
    Regular,
    Symlink,
    Directory,
    Fifo,
    Block,
    Char,
    Socket,
    /// A type fakefs has no handling for. Kept visible instead of silent.
    #[default]
    Other,
}

impl FileType {
    /// The `S_IFMT` bits for this type; 0 for [`FileType::Other`].
    fn mode_bits(self) -> u32 {
        (match self {
            FileType::Regular => libc::S_IFREG,
            FileType::Symlink => libc::S_IFLNK,
            FileType::Directory => libc::S_IFDIR,
            FileType::Fifo => libc::S_IFIFO,
            FileType::Block => libc::S_IFBLK,
            FileType::Char => libc::S_IFCHR,
            FileType::Socket => libc::S_IFSOCK,
            FileType::Other => 0,
        }) as u32
    }

    /// The type an `st_mode` names.
    pub fn of_mode(mode: u32) -> FileType {
        match mode & libc::S_IFMT as u32 {
            m if m == libc::S_IFREG as u32 => FileType::Regular,
            m if m == libc::S_IFLNK as u32 => FileType::Symlink,
            m if m == libc::S_IFDIR as u32 => FileType::Directory,
            m if m == libc::S_IFIFO as u32 => FileType::Fifo,
            m if m == libc::S_IFBLK as u32 => FileType::Block,
            m if m == libc::S_IFCHR as u32 => FileType::Char,
            m if m == libc::S_IFSOCK as u32 => FileType::Socket,
            _ => FileType::Other,
        }
    }

    fn from_entry_type(t: tar::EntryType) -> FileType {
        match t {
            tar::EntryType::Regular | tar::EntryType::Continuous | tar::EntryType::Link => {
                FileType::Regular
            }
            tar::EntryType::Symlink => FileType::Symlink,
            tar::EntryType::Directory => FileType::Directory,
            tar::EntryType::Fifo => FileType::Fifo,
            tar::EntryType::Block => FileType::Block,
            tar::EntryType::Char => FileType::Char,
            _ => FileType::Other,
        }
    }
}

/// Everything import needs from one archive entry.
#[derive(Debug)]
pub struct EntryInfo {
    pub pathname: Vec<u8>,
    pub hardlink: Option<Vec<u8>>,
    pub symlink: Option<Vec<u8>>,
    pub filetype: FileType,
    /// Permission bits **and** the `S_IFMT` type bits, as `st_mode` has them.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    /// `(seconds, nanoseconds)`, or `None` when the archive does not set it --
    /// which becomes `UTIME_OMIT` rather than a timestamp of zero.
    pub atime: Option<(i64, i64)>,
    pub mtime: Option<(i64, i64)>,
}

fn archive_error(doing: &str, e: std::io::Error) -> Error {
    Error::Archive {
        code: e.raw_os_error().unwrap_or(0),
        message: format!("{doing}: {e}"),
    }
}

/// A pax time, `seconds[.fraction]`, as `(seconds, nanoseconds)`.
fn parse_pax_time(v: &[u8]) -> Option<(i64, i64)> {
    let s = std::str::from_utf8(v).ok()?;
    let (sec, frac) = s.split_once('.').unwrap_or((s, ""));
    let sec: i64 = sec.parse().ok()?;
    let digits: String = frac.chars().take(9).collect();
    let nsec = if digits.is_empty() {
        0
    } else {
        format!("{digits:0<9}").parse().ok()?
    };
    Some((sec, nsec))
}

/// Call `f` with every entry of the gzipped -- or plain -- tar archive at
/// `path`, in order, and the entry's body.
///
/// A visitor rather than an iterator: an entry borrows the archive, and a
/// visitor is what lets the body be a plain `Read` without a self-referential
/// reader.
pub fn read(path: &Path, mut f: impl FnMut(EntryInfo, &mut dyn Read) -> Result<()>) -> Result<()> {
    let file = File::open(path).doing(|| format!("opening {}", path.display()))?;
    let mut buffered = BufReader::new(file);
    let gzipped = buffered
        .fill_buf()
        .doing(|| format!("reading {}", path.display()))?
        .starts_with(&[0x1f, 0x8b]);
    let input: Box<dyn Read> = if gzipped {
        Box::new(flate2::read::MultiGzDecoder::new(buffered))
    } else {
        Box::new(buffered)
    };
    let mut archive = tar::Archive::new(input);
    let entries = archive.entries().map_err(|e| archive_error("reading the archive", e))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| archive_error("reading a header", e))?;
        let info = entry_info(&mut entry)?;
        f(info, &mut entry)?;
    }
    Ok(())
}

fn entry_info(entry: &mut tar::Entry<'_, impl Read>) -> Result<EntryInfo> {
    let corrupt = |what: &str, e: std::io::Error| archive_error(what, e);
    let header = entry.header();
    let kind = header.entry_type();
    let filetype = FileType::from_entry_type(kind);
    let mode = header.mode().map_err(|e| corrupt("reading a mode", e))? & 0o7777;
    let uid = header.uid().map_err(|e| corrupt("reading a uid", e))? as u32;
    let gid = header.gid().map_err(|e| corrupt("reading a gid", e))? as u32;
    let major = header.device_major().ok().flatten().unwrap_or(0);
    let minor = header.device_minor().ok().flatten().unwrap_or(0);
    let header_mtime = header.mtime().map_err(|e| corrupt("reading an mtime", e))?;
    let gnu_atime = header.as_gnu().and_then(|g| g.atime().ok()).filter(|&t| t != 0);

    let pathname = entry.path_bytes().into_owned();
    let link = entry.link_name_bytes().map(|l| l.into_owned());
    let (hardlink, symlink) = match kind {
        tar::EntryType::Link => (link, None),
        tar::EntryType::Symlink => (None, link),
        _ => (None, None),
    };

    let mut mtime = Some((header_mtime as i64, 0));
    let mut atime = gnu_atime.map(|t| (t as i64, 0));
    if let Some(pax) = entry.pax_extensions().map_err(|e| corrupt("reading pax records", e))? {
        for ext in pax {
            let ext = ext.map_err(|e| corrupt("reading a pax record", e))?;
            match ext.key_bytes() {
                b"mtime" => mtime = parse_pax_time(ext.value_bytes()).or(mtime),
                b"atime" => atime = parse_pax_time(ext.value_bytes()).or(atime),
                _ => {}
            }
        }
    }

    Ok(EntryInfo {
        pathname,
        hardlink,
        symlink,
        filetype,
        mode: mode | filetype.mode_bits(),
        uid,
        gid,
        rdev: libc::makedev(major as _, minor as _) as u32,
        atime,
        mtime,
    })
}

/// An entry the caller fills in, for writing.
#[derive(Debug, Clone, Default)]
pub struct OwnedEntry {
    path: Vec<u8>,
    symlink: Option<Vec<u8>>,
    hardlink: Option<Vec<u8>>,
    filetype: FileType,
    mode: u32,
    uid: u32,
    gid: u32,
    rdev: u32,
    size: u64,
    /// `(dev, ino)`, which is what [`LinkResolver`] keys on.
    dev: u64,
    ino: i64,
    nlink: u32,
    atime: Option<(i64, i64)>,
    mtime: Option<(i64, i64)>,
    ctime: Option<(i64, i64)>,
}

/// An archive member's name may not contain a NUL: the ustar header is a C
/// string and a pax record is read up to its length, so the two would
/// disagree.
fn no_nul(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.contains(&0) {
        return Err(Error::Corrupt(format!(
            "path contains an interior NUL: {:?}",
            String::from_utf8_lossy(bytes)
        )));
    }
    Ok(bytes.to_vec())
}

impl OwnedEntry {
    pub fn new() -> OwnedEntry {
        OwnedEntry::default()
    }

    pub fn set_pathname(&mut self, path: &[u8]) -> Result<()> {
        self.path = no_nul(path)?;
        Ok(())
    }

    pub fn set_symlink(&mut self, target: &[u8]) -> Result<()> {
        self.symlink = Some(no_nul(target)?);
        Ok(())
    }

    pub fn set_hardlink(&mut self, target: &[u8]) -> Result<()> {
        self.hardlink = Some(no_nul(target)?);
        Ok(())
    }

    /// The type. [`OwnedEntry::set_mode`] keeps only the permission bits, so
    /// the two can be set in either order.
    pub fn set_filetype(&mut self, filetype: FileType) {
        self.filetype = filetype;
    }

    pub fn set_ino64(&mut self, ino: i64) {
        self.ino = ino;
    }

    /// How many paths point at this inode. [`LinkResolver`] needs it to spot
    /// a file with more than one name; the C version never set it, so
    /// exporting a rootfs turned each of busybox's several hundred hardlinks
    /// into a separate copy of the binary.
    pub fn set_nlink(&mut self, nlink: u32) {
        self.nlink = nlink;
    }

    /// The device the inode belongs to; with the inode, what
    /// [`LinkResolver`] keys on.
    pub fn set_dev(&mut self, dev: u64) {
        self.dev = dev;
    }

    /// The permission bits. Type bits in `mode` are ignored: the type is
    /// [`OwnedEntry::set_filetype`]'s.
    pub fn set_mode(&mut self, mode: u32) {
        self.mode = mode & 0o7777;
    }

    pub fn set_uid(&mut self, uid: u32) {
        self.uid = uid;
    }

    pub fn set_gid(&mut self, gid: u32) {
        self.gid = gid;
    }

    pub fn set_rdev(&mut self, rdev: u32) {
        self.rdev = rdev;
    }

    pub fn set_size(&mut self, size: i64) {
        self.size = size.max(0) as u64;
    }

    pub fn size(&self) -> i64 {
        self.size as i64
    }

    pub fn set_atime(&mut self, sec: i64, nsec: i64) {
        self.atime = Some((sec, nsec));
    }

    pub fn set_mtime(&mut self, sec: i64, nsec: i64) {
        self.mtime = Some((sec, nsec));
    }

    pub fn set_ctime(&mut self, sec: i64, nsec: i64) {
        self.ctime = Some((sec, nsec));
    }
}

/// A pax time record's value.
fn pax_time((sec, nsec): (i64, i64)) -> Vec<u8> {
    if nsec == 0 {
        sec.to_string().into_bytes()
    } else {
        format!("{sec}.{nsec:09}").into_bytes()
    }
}

/// The largest value a ustar numeric field of `width` octal digits holds.
const fn octal_max(width: u32) -> u64 {
    (1 << (3 * width)) - 1
}

/// Writer for a gzipped pax-format tar archive.
pub struct Writer {
    builder: tar::Builder<flate2::write::GzEncoder<File>>,
}

impl Writer {
    pub fn create(path: &Path) -> Result<Writer> {
        let file = File::create(path).doing(|| format!("creating {}", path.display()))?;
        let gz = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut builder = tar::Builder::new(gz);
        // An entry's header says what it is; following a host symlink would
        // be reading a file the caller did not hand over.
        builder.follow_symlinks(false);
        Ok(Writer { builder })
    }

    /// Write `entry`, and `body` as its contents: exactly `entry.size()` bytes
    /// of it for a regular file, none for anything else.
    pub fn write_entry(&mut self, entry: &OwnedEntry, body: impl Read) -> Result<()> {
        let mut header = tar::Header::new_ustar();
        let mut pax: Vec<(&str, Vec<u8>)> = Vec::new();

        let (kind, size) = match (&entry.hardlink, entry.filetype) {
            (Some(_), _) => (tar::EntryType::Link, 0),
            (None, FileType::Regular) => (tar::EntryType::Regular, entry.size),
            (None, FileType::Symlink) => (tar::EntryType::Symlink, 0),
            (None, FileType::Directory) => (tar::EntryType::Directory, 0),
            (None, FileType::Fifo) => (tar::EntryType::Fifo, 0),
            (None, FileType::Block) => (tar::EntryType::Block, 0),
            (None, FileType::Char) => (tar::EntryType::Char, 0),
            (None, FileType::Socket | FileType::Other) => {
                return Err(Error::Archive {
                    code: 0,
                    message: format!(
                        "tar format cannot archive {}",
                        String::from_utf8_lossy(&entry.path)
                    ),
                });
            }
        };
        header.set_entry_type(kind);
        header.set_size(size);
        header.set_mode(entry.mode);

        // The name and the link target go in the header raw, truncated, and in
        // a pax record when they do not fit -- never through `set_path`, which
        // would normalise them.
        let old = header.as_old_mut();
        put_raw(&mut old.name, &entry.path, "path", &mut pax);
        if let Some(link) = entry.hardlink.as_ref().or(entry.symlink.as_ref()) {
            put_raw(&mut old.linkname, link, "linkpath", &mut pax);
        }

        for (key, id, field) in [("uid", entry.uid, 0), ("gid", entry.gid, 1)] {
            let id = u64::from(id);
            if id > octal_max(7) {
                pax.push((key, id.to_string().into_bytes()));
            } else if field == 0 {
                header.set_uid(id);
            } else {
                header.set_gid(id);
            }
        }

        let mtime = entry.mtime.unwrap_or((0, 0));
        header.set_mtime(mtime.0.clamp(0, octal_max(11) as i64) as u64);
        if mtime.1 != 0 || mtime.0 < 0 || mtime.0 as u64 > octal_max(11) {
            pax.push(("mtime", pax_time(mtime)));
        }
        if let Some(t) = entry.atime {
            pax.push(("atime", pax_time(t)));
        }
        if let Some(t) = entry.ctime {
            pax.push(("ctime", pax_time(t)));
        }

        if matches!(kind, tar::EntryType::Block | tar::EntryType::Char) {
            let dev = entry.rdev as libc::dev_t;
            header
                .set_device_major(libc::major(dev) as u32)
                .and_then(|()| header.set_device_minor(libc::minor(dev) as u32))
                .map_err(|e| archive_error("writing a device number", e))?;
        }
        header.set_cksum();

        if !pax.is_empty() {
            self.builder
                .append_pax_extensions(pax.iter().map(|(k, v)| (*k, &v[..])))
                .map_err(|e| archive_error("writing pax records", e))?;
        }
        self.builder
            .append(&header, body.take(size))
            .map_err(|e| archive_error("writing an entry", e))
    }

    /// Flush and close. Where a full disk surfaces, for a compressed archive.
    pub fn finish(self) -> Result<()> {
        let gz = self.builder.into_inner().map_err(|e| archive_error("closing the archive", e))?;
        let mut file = gz.finish().map_err(|e| archive_error("closing the archive", e))?;
        file.flush().map_err(|e| archive_error("closing the archive", e))
    }
}

/// `bytes` into a fixed header field, and into a pax record under `key` when
/// it does not fit -- the ustar field is then a truncated copy, as every pax
/// writer leaves it.
fn put_raw<'k>(field: &mut [u8], bytes: &[u8], key: &'k str, pax: &mut Vec<(&'k str, Vec<u8>)>) {
    let n = bytes.len().min(field.len());
    field[..n].copy_from_slice(&bytes[..n]);
    if bytes.len() > field.len() {
        pax.push((key, bytes.to_vec()));
    }
}

/// Rewrites the second and later names of an inode into bodyless hardlinks
/// to the first -- the tar strategy libarchive's resolver had.
#[derive(Default)]
pub struct LinkResolver {
    first: HashMap<(u64, i64), Vec<u8>>,
}

impl LinkResolver {
    pub fn new_tar() -> LinkResolver {
        LinkResolver::default()
    }

    /// The entry to write: `entry` itself, or a hardlink to the first name
    /// already written for its inode. Keyed on `(dev, ino)`, and only for an
    /// entry with more than one link and a device set.
    pub fn linkify(&mut self, mut entry: OwnedEntry) -> OwnedEntry {
        let linkable = entry.nlink > 1
            && entry.dev != 0
            && entry.hardlink.is_none()
            && entry.filetype != FileType::Directory;
        if linkable {
            match self.first.get(&(entry.dev, entry.ino)) {
                Some(first) => {
                    entry.hardlink = Some(first.clone());
                    entry.size = 0;
                }
                None => {
                    self.first.insert((entry.dev, entry.ino), entry.path.clone());
                }
            }
        }
        entry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pax_time_keeps_its_nanoseconds() {
        assert_eq!(parse_pax_time(b"1700000000"), Some((1_700_000_000, 0)));
        assert_eq!(parse_pax_time(b"1700000000.5"), Some((1_700_000_000, 500_000_000)));
        assert_eq!(parse_pax_time(b"1.000000001"), Some((1, 1)));
        assert_eq!(pax_time((1, 1)), b"1.000000001");
        assert_eq!(parse_pax_time(&pax_time((7, 123_456_789))), Some((7, 123_456_789)));
    }

    #[test]
    fn the_second_name_of_an_inode_becomes_a_hardlink() {
        let mut r = LinkResolver::new_tar();
        let mut a = OwnedEntry::new();
        a.set_pathname(b"./a").unwrap();
        a.set_filetype(FileType::Regular);
        a.set_dev(1);
        a.set_ino64(9);
        a.set_nlink(2);
        a.set_size(5);
        let mut b = a.clone();
        b.set_pathname(b"./b").unwrap();

        let a = r.linkify(a);
        assert!(a.hardlink.is_none() && a.size() == 5, "the first name keeps its body");
        let b = r.linkify(b);
        assert_eq!(b.hardlink.as_deref(), Some(&b"./a"[..]));
        assert_eq!(b.size(), 0, "and the second has none");
    }
}
