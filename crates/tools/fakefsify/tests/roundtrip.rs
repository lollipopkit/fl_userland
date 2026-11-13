//! End-to-end tests: tarball -> fakefs -> tarball.
//!
//! The archives are built with the crate's own writer rather than by shelling
//! out to `tar`, so the cases that matter — an overlong pathname, a name that
//! only looks like `..` — can be constructed exactly.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use std::os::unix::fs::FileTypeExt;

use fakefsify::archive::{FileType, OwnedEntry, Writer};
use fakefsify::db::IulStat;

/// A scratch directory that removes itself.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "fakefsify-test-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("creating scratch directory");
        TempDir(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Member {
    path: Vec<u8>,
    filetype: FileType,
    mode: u32,
    uid: u32,
    gid: u32,
    rdev: u32,
    data: Vec<u8>,
    symlink: Option<Vec<u8>>,
    hardlink: Option<Vec<u8>>,
}

impl Member {
    fn new(path: &[u8], filetype: FileType, mode: u32) -> Member {
        Member {
            path: path.to_vec(),
            filetype,
            mode,
            uid: 0,
            gid: 0,
            rdev: 0,
            data: Vec::new(),
            symlink: None,
            hardlink: None,
        }
    }

    fn file(path: &[u8], data: &[u8]) -> Member {
        let mut m = Member::new(path, FileType::Regular, 0o644);
        m.data = data.to_vec();
        m
    }

    fn dir(path: &[u8]) -> Member {
        Member::new(path, FileType::Directory, 0o755)
    }
}

fn write_archive(out: &Path, members: &[Member]) {
    let mut writer = Writer::create(out).expect("creating archive");
    for m in members {
        let mut entry = OwnedEntry::new();
        entry.set_pathname(&m.path).unwrap();
        entry.set_filetype(m.filetype);
        entry.set_mode(m.mode);
        entry.set_uid(m.uid);
        entry.set_gid(m.gid);
        entry.set_rdev(m.rdev);
        entry.set_mtime(1_700_000_000, 0);
        if let Some(target) = &m.symlink {
            entry.set_symlink(target).unwrap();
        }
        if let Some(target) = &m.hardlink {
            entry.set_hardlink(target).unwrap();
        }
        entry.set_size(m.data.len() as i64);
        writer.write_entry(&entry, &m.data[..]).expect("writing entry");
    }
    writer.finish().expect("closing archive");
}

/// `path -> (inode, stat)` for every row in a fakefs, keyed so two fakefs can
/// be compared regardless of row order.
fn read_fakefs(fs: &Path) -> BTreeMap<Vec<u8>, (i64, IulStat)> {
    let conn = rusqlite::Connection::open(fs.join("meta.db")).expect("opening meta.db");
    let mut stmt = conn
        .prepare("select path, inode, stat from paths, stats using (inode)")
        .unwrap();
    let rows = stmt
        .query_map([], |row| {
            let path: Vec<u8> = row.get(0)?;
            let inode: i64 = row.get(1)?;
            let blob: Vec<u8> = row.get(2)?;
            Ok((path, inode, blob))
        })
        .unwrap();
    rows.map(|r| {
        let (path, inode, blob) = r.unwrap();
        (path, (inode, IulStat::from_blob(&blob).unwrap()))
    })
    .collect()
}

fn sample_members() -> Vec<Member> {
    let mut members = vec![
        Member::dir(b"./"),
        Member::file(b"./file", b"hello world\n"),
        Member::dir(b"./dir/"),
        // No entry for ./dir/nested or ./dir/nested/deep: tarballs do not
        // reliably carry every parent, so import has to create them.
        Member::file(b"./dir/nested/deep/leaf", b"deep\n"),
        // Redundant separators must collapse to one path.
        Member::file(b"./sub//double///slash", b"collapse\n"),
        // A name that starts with two dots but is not "..".
        Member::file(b"./..foo", b"not dotdot\n"),
    ];

    let mut link = Member::new(b"./link", FileType::Symlink, 0o777);
    link.symlink = Some(b"/file".to_vec());
    members.push(link);

    let mut hard = Member::new(b"./hardlink", FileType::Regular, 0o644);
    hard.hardlink = Some(b"./file".to_vec());
    members.push(hard);

    members.push(Member::new(b"./fifo", FileType::Fifo, 0o666));

    let mut chardev = Member::new(b"./chardev", FileType::Char, 0o600);
    chardev.rdev = libc::makedev(1, 3) as u32;
    members.push(chardev);

    // Ownership and setuid are the whole reason meta.db exists.
    let mut owned = Member::file(b"./owned", b"y");
    owned.uid = 1000;
    owned.gid = 1000;
    owned.mode = 0o600;
    members.push(owned);

    let mut setuid = Member::file(b"./setuid", b"x");
    setuid.mode = 0o4755;
    members.push(setuid);

    members
}

/// Two imports at once, each with a FIFO, into roots of their own.
///
/// `mkfifo` has no directory descriptor, so creating one relative to the fakefs
/// `data/` used to mean `fchdir` in and `fchdir` back — and the current
/// directory is **process-wide**. Two threads doing that at the same time each
/// created their FIFO in whichever directory the other had just moved to, which
/// showed up as this file's own tests failing about one workspace run in three:
/// one with `EEXIST` creating a fifo, the other with `ENOENT` stamping the one
/// it thought it had made.
///
/// `mkfifoat` exists on Darwin and on Linux, so there is no directory change
/// and nothing to serialise. Backing that out makes this fail every run.
///
/// Many FIFOs per archive, not one: with one, each thread passes through the
/// window once and eight threads staggered by their own startup mostly miss
/// each other. `FIFOS` of them keeps every thread inside it for long enough
/// that the collision is certain rather than likely.
#[test]
fn concurrent_imports_do_not_create_each_others_fifos() {
    const THREADS: usize = 8;
    const FIFOS: usize = 200;
    let dirs: Vec<TempDir> = (0..THREADS)
        .map(|i| TempDir::new(&format!("concurrent-{i}")))
        .collect();

    std::thread::scope(|scope| {
        for (i, tmp) in dirs.iter().enumerate() {
            scope.spawn(move || {
                let tar = tmp.join("in.tar.gz");
                let mut members = vec![Member::file(b"./file", b"x")];
                for f in 0..FIFOS {
                    members.push(Member::new(
                        format!("./fifo{f}").as_bytes(),
                        FileType::Fifo,
                        0o666,
                    ));
                }
                write_archive(&tar, &members);
                let fs = tmp.join("fs");
                fakefsify::import(&tar, &fs).unwrap_or_else(|e| panic!("thread {i} import: {e:?}"));
            });
        }
    });

    // Every root has every one of its own fifos, and no more.
    for tmp in &dirs {
        for f in 0..FIFOS {
            let fifo = tmp.join(&format!("fs/data/fifo{f}"));
            let meta = std::fs::symlink_metadata(&fifo).unwrap_or_else(|e| panic!("{fifo:?}: {e}"));
            assert!(
                meta.file_type().is_fifo(),
                "{fifo:?} is not a fifo: {:?}",
                meta.file_type()
            );
        }
    }
}

#[test]
fn import_records_every_path_and_creates_missing_parents() {
    let tmp = TempDir::new("import");
    let tar = tmp.join("in.tar.gz");
    write_archive(&tar, &sample_members());

    let fs = tmp.join("fs");
    fakefsify::import(&tar, &fs).expect("import");

    let rows = read_fakefs(&fs);
    let paths: Vec<&[u8]> = rows.keys().map(|k| k.as_slice()).collect();

    // The root is stored as the empty blob, not "/".
    assert!(paths.contains(&&b""[..]), "root row missing: {paths:?}");
    assert!(paths.contains(&&b"/file"[..]));
    assert!(paths.contains(&&b"/dir/nested/deep/leaf"[..]));
    // Separators collapsed.
    assert!(paths.contains(&&b"/sub/double/slash"[..]));
    assert!(!paths.iter().any(|p| p.windows(2).any(|w| w == b"//")));
    // "..foo" is an ordinary name, not a traversal attempt.
    assert!(paths.contains(&&b"/..foo"[..]));

    // Parents the archive never mentioned were created on disk.
    assert!(fs.join("data/dir/nested/deep").is_dir());

    // Modes, ownership and device numbers survive.
    assert_eq!(rows[&b"/owned"[..]].1.uid, 1000);
    assert_eq!(rows[&b"/owned"[..]].1.gid, 1000);
    assert_eq!(rows[&b"/setuid"[..]].1.mode & 0o7777, 0o4755);
    assert_eq!(rows[&b"/chardev"[..]].1.rdev, libc::makedev(1, 3) as u32);
    assert!(rows[&b"/link"[..]].1.is_symlink());

    // A hardlink is a second path onto the same inode.
    assert_eq!(rows[&b"/hardlink"[..]].0, rows[&b"/file"[..]].0);

    assert_eq!(
        std::fs::read(fs.join("data/file")).unwrap(),
        b"hello world\n"
    );
}

#[test]
fn roundtrip_through_export_preserves_everything() {
    let tmp = TempDir::new("roundtrip");
    let tar = tmp.join("in.tar.gz");
    write_archive(&tar, &sample_members());

    let first = tmp.join("first");
    fakefsify::import(&tar, &first).expect("first import");

    let exported = tmp.join("out.tar.gz");
    fakefsify::export(&first, &exported).expect("export");

    let second = tmp.join("second");
    fakefsify::import(&exported, &second).expect("second import");

    assert_eq!(
        read_fakefs(&first),
        read_fakefs(&second),
        "a fakefs exported and reimported should be identical"
    );
}

#[test]
fn export_works_without_a_wal_index_beside_the_database() {
    // meta.db is created with journal_mode=wal, and that lives in the header.
    // A read-only connection cannot create the -shm WAL index, so the C
    // version's export failed with SQLITE_CANTOPEN on any fakefs whose -shm
    // had been cleaned up — which is what a clean close does.
    let tmp = TempDir::new("nowal");
    let tar = tmp.join("in.tar.gz");
    write_archive(&tar, &sample_members());

    let fs = tmp.join("fs");
    fakefsify::import(&tar, &fs).expect("import");

    // Checkpoint and drop the sidecars, as closing the last connection does.
    {
        let conn = rusqlite::Connection::open(fs.join("meta.db")).unwrap();
        conn.pragma_update(None, "wal_checkpoint", "truncate").ok();
    }
    let _ = std::fs::remove_file(fs.join("meta.db-shm"));
    let _ = std::fs::remove_file(fs.join("meta.db-wal"));
    assert!(!fs.join("meta.db-shm").exists());

    fakefsify::export(&fs, &tmp.join("out.tar.gz")).expect("export without -shm");
}

#[test]
fn an_overlong_pathname_is_skipped_and_the_rest_imports() {
    // The C version normalized into a 4096-byte stack buffer with no bounds
    // check, and pax extended headers impose no limit on pathname length. An
    // 8 KiB name aborted it on the stack guard; 200 KiB segfaulted it.
    let tmp = TempDir::new("overlong");
    let tar = tmp.join("in.tar.gz");

    let mut members = vec![Member::dir(b"./")];
    let mut long_name = b"./".to_vec();
    long_name.extend(std::iter::repeat_n(b'A', 200_000));
    members.push(Member::file(&long_name, b"overflow\n"));
    members.push(Member::file(b"./sentinel", b"ok\n"));
    write_archive(&tar, &members);

    let fs = tmp.join("fs");
    fakefsify::import(&tar, &fs).expect("import should skip the entry, not die");

    let rows = read_fakefs(&fs);
    assert!(
        rows.contains_key(&b"/sentinel"[..]),
        "entries after the overlong one should still be imported"
    );
    assert!(
        rows.keys().all(|p| p.len() <= fakefsify::path::MAX_PATH),
        "no overlong path should have been recorded"
    );
}

#[test]
fn a_traversing_pathname_is_skipped_and_the_rest_imports() {
    let tmp = TempDir::new("traversal");
    let tar = tmp.join("in.tar.gz");
    write_archive(
        &tar,
        &[
            Member::dir(b"./"),
            Member::file(b"../escaped", b"pwned\n"),
            Member::file(b"./dir/../../also-escaped", b"pwned\n"),
            Member::file(b"./sentinel", b"ok\n"),
        ],
    );

    let fs = tmp.join("fs");
    fakefsify::import(&tar, &fs).expect("import");

    let rows = read_fakefs(&fs);
    assert!(rows.contains_key(&b"/sentinel"[..]));
    assert_eq!(rows.len(), 2, "only the root and the sentinel: {rows:?}");
    // Nothing was written next to the fakefs.
    assert!(!tmp.join("escaped").exists());
    assert!(!tmp.join("also-escaped").exists());
}

#[test]
fn importing_over_an_existing_directory_is_refused() {
    let tmp = TempDir::new("exists");
    let tar = tmp.join("in.tar.gz");
    write_archive(&tar, &[Member::dir(b"./")]);

    let fs = tmp.join("fs");
    std::fs::create_dir(&fs).unwrap();
    assert!(
        fakefsify::import(&tar, &fs).is_err(),
        "importing into an existing directory should fail, not merge"
    );
}

/// A symlink whose target is not ASCII.
///
/// Alpine's own `ca-certificates` ships one — `/etc/ssl/certs/…` points at
/// `NetLock_Arany_=Class_Gold=_Főtanúsítvány.crt` — so this is not a corner
/// case, it is every rootfs with certificates in it.
///
/// libarchive converted a stored pathname to the process's narrow charset, and
/// a program that never calls `setlocale` is in the `"C"` locale, where `ő` has
/// no representation: `archive_entry_symlink()` returned NULL and the whole
/// import aborted. The reader has been the `tar` crate since 2026-10-17, which
/// keeps names as bytes, so this runs in the `"C"` locale on purpose.
///
/// The fixture is 571 bytes and built by `tar`, on purpose: the crate's own
/// `Writer` is what the tests above use, and a reader bug needs an archive the
/// crate did not write.
#[test]
fn a_symlink_target_that_is_not_ascii() {
    let dir = TempDir::new("nonascii");
    let out = dir.join("fs");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/nonascii-symlink.tar.gz");

    fakefsify::import::import(&fixture, &out).expect("a non-ASCII symlink target imports");

    let entries = read_fakefs(&out);
    let names: Vec<&[u8]> = entries.keys().map(|k| k.as_slice()).collect();
    assert!(
        names.iter().any(|n| n.ends_with(b"link")),
        "the symlink is in the database: {names:?}"
    );
    // Any byte above 0x7f: that is the whole property under test, and asserting
    // a particular code point would be asserting the fixture rather than the
    // behaviour. macOS normalises a filename to NFD when it is created, so the
    // `ő` in this archive is `o` + U+030B and a check for `[0xc5, 0x91]` fails
    // against a working import.
    assert!(
        names.iter().any(|n| n.iter().any(|b| *b > 0x7f)),
        "and so is the file it points at, with its bytes intact: {names:?}"
    );
}
