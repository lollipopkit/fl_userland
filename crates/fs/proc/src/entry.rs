//! The generic procfs entry layer: what an entry's mode is, what it is called,
//! what `stat` says about it, and how a directory is walked.
//!
//! These six functions were `fs/proc/entry.c`. They keep their C names for the
//! shared `proc_dir_entry` ABI; the content files and directory tables that
//! call them are Rust now.

use std::os::raw::c_int;

use crate::ffi;
use crate::inode;

/// A mode with the parts the tables leave out filled in.
///
/// A table entry names a type only when it is not a regular file, and names
/// permissions only when the default will not do.
pub(crate) fn proc_entry_mode(entry: &mut ffi::proc_entry) -> u16 {
    // An entry with no row is the default-constructed one, which no lookup
    // answers; 0 becomes a regular file below, as a nameless table row does.
    let mut mode = entry.meta.map_or(0, |m| m.mode) as u32;
    if mode & libc::S_IFMT as u32 == 0 {
        mode |= libc::S_IFREG as u32;
    }
    if mode & 0o777 == 0 {
        mode |= match mode & libc::S_IFMT as u32 {
            x if x == libc::S_IFREG as u32 => 0o444,
            x if x == libc::S_IFDIR as u32 => 0o555,
            x if x == libc::S_IFLNK as u32 => 0o777,
            _ => 0,
        };
    }
    mode as u16
}

pub(crate) fn proc_entry_stat(entry: &mut ffi::proc_entry, stat: &mut ffi::statbuf) -> c_int {
    *stat = ffi::statbuf::default();
    stat.mode = proc_entry_mode(entry) as u32;

    // The owner is the task's, when there is one. When there is not, the
    // default buffer already says root, which is what /proc's own files
    // are owned by.
    if let Some((uid, gid)) = crate::pidsnap::dump_owner(entry.pid, stat.mode) {
        stat.uid = uid;
        stat.gid = gid;
    }

    stat.inode = inode::for_entry(entry.meta, entry.pid, entry.fd);
    stat.nlink = nlink(entry, stat.mode);
    0
}

/// The link count, which was 0 -- "deleted" -- for everything until
/// 2026-10-18 (`tests/guest` procfs_probe).
///
/// A file or a symlink is 1; a directory is what its row's [`ffi::Links`]
/// says. Every path walk through a directory stats it, so this must not list
/// it: counting `/proc` by listing walked the pid space on every open below.
fn nlink(entry: &ffi::proc_entry, mode: u32) -> u32 {
    let is_dir = |mode: u32| mode & libc::S_IFMT as u32 == libc::S_IFDIR as u32;
    let Some(meta) = entry.meta.filter(|_| is_dir(mode)) else {
        return 1;
    };
    match meta.links {
        ffi::Links::One => 1,
        ffi::Links::Threads => 2 + crate::pidsnap::threads(entry.pid).unwrap_or(0) as u32,
        ffi::Links::Subdirs => {
            let children = meta.children.unwrap_or_default();
            2 + children.iter().filter(|c| is_dir(c.mode as u32)).count() as u32
        }
    }
}

/// The entry's name, into the caller's buffer.
pub(crate) fn proc_entry_getname(entry: &mut ffi::proc_entry, buf: &mut [u8]) {
    let Some(meta) = entry.meta else {
        put_name(buf, b"");
        return;
    };
    if let Some(getname) = meta.getname {
        getname(entry, buf);
    } else if let Some(name) = meta.name {
        // strcpy in the C, into a buffer whose size it was not told. The
        // names in the tables are string literals and fit, but that is a
        // property of the tables rather than of this function, and the one
        // that does not fit would be found by a reader of a corrupted
        // stack rather than by this returning something.
        put_name(buf, name.to_bytes());
    } else {
        // A table entry with neither a name nor a getname. The C asserted,
        // which takes the emulator down for a malformed static table; an empty
        // name is visible in a directory listing and survivable.
        put_name(buf, b"");
    }
}

/// A name into a caller's buffer, **truncated** rather than refused.
///
/// The other half of [`ffi::fill_path`]'s rule, and it is a different rule
/// because `getname` has no way to answer: the table's entry returns `()`, so
/// a name that does not fit has to become a shorter name. `MAX_NAME` is what
/// every caller's buffer is and a listing shows what fits.
///
/// **Every implementation of `getname` was writing this itself and one of them
/// was not bounded at all.** `crates/fs/proc`'s `defaults_getname` copied the
/// whole of an embedder-provided key, terminator included, into a caller's
/// `MAX_NAME + 1` bytes — so a key of 257 bytes overran a stack buffer in
/// `descriptor::find_child`, whose comment said "getname writes at most
/// MAX_NAME bytes plus a terminator" and was true of the other four.
pub(crate) fn put_name(buf: &mut [u8], name: &[u8]) {
    let Some((last, head)) = buf.split_last_mut() else {
        return; // no room even for the terminator
    };
    let n = name.len().min(head.len());
    head[..n].copy_from_slice(&name[..n]);
    if n < head.len() {
        head[n] = 0;
    } else {
        *last = 0;
    }
}

/// Step a directory: the entry at `*index`, having advanced it.
///
/// A `bool` and a `*mut proc_entry` out-parameter until 2026-09-16, with the
/// contract "fills `next` or returns false" written in a comment at each of its
/// two call sites. The `Option` is that contract, and both callers built their
/// out-parameter fresh each time round the loop anyway.
pub(crate) fn proc_dir_read(
    entry: &mut ffi::proc_entry,
    index: &mut u64,
) -> Option<ffi::proc_entry> {
    let meta = entry.meta?;
    if let Some(readdir) = meta.readdir {
        return readdir(entry, index);
    }
    if let Some(children) = meta.children {
        // `get`, not `as_ptr().add(i)` against a separate `count`: the
        // length is the slice's and the bound is the compiler's.
        let child = children.get(*index as usize)?;
        *index += 1;
        return Some(ffi::proc_entry {
            meta: Some(child),
            pid: entry.pid,
            ..ffi::proc_entry::default()
        });
    }
    // Neither: a directory with no way to list it. The C asserted here
    // too. An empty directory is what a reader sees instead.
    None
}

// `free_string_array` and `proc_entry_cleanup` were here until 2026-09-14.
// The first freed a `libc::malloc`'d `char **` by walking it to its NULL; the
// second freed that and `entry.name` and then zeroed the struct, and fourteen
// call sites had to remember it on every path. Both fields are Rust's now, so
// `Drop` is the whole of it -- the same trade `crates/fs/mounttable`'s
// `MountRef` and `fs_fd::Owned` made for mounts and descriptors.

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(mode: u16) -> ffi::proc_dir_entry {
        ffi::proc_dir_entry {
            mode,
            ..Default::default()
        }
    }

    /// A table row an entry can point at. The rows are `static` in the
    /// product, so the lifetime is `'static`; a test leaks one rather than
    /// asking the type to accept a shorter one, which would be a lifetime
    /// parameter on `proc_entry` bought for the tests alone.
    fn entry_for(m: ffi::proc_dir_entry) -> ffi::proc_entry {
        ffi::proc_entry {
            meta: Some(Box::leak(Box::new(m))),
            ..Default::default()
        }
    }

    #[test]
    fn a_mode_with_no_type_is_a_regular_file() {
        let mut e = entry_for(meta(0));
        let mode = proc_entry_mode(&mut e) as u32;
        assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFREG as u32);
        assert_eq!(mode & 0o777, 0o444);
    }

    #[test]
    fn the_default_permissions_depend_on_the_type() {
        for (ty, want) in [
            (libc::S_IFREG, 0o444),
            (libc::S_IFDIR, 0o555),
            (libc::S_IFLNK, 0o777),
        ] {
            let mut e = entry_for(meta(ty));
            assert_eq!(proc_entry_mode(&mut e) as u32 & 0o777, want);
        }
    }

    #[test]
    fn permissions_already_named_are_left_alone() {
        let mut e = entry_for(meta(libc::S_IFREG | 0o640));
        assert_eq!(proc_entry_mode(&mut e) as u32 & 0o777, 0o640);
    }

    #[test]
    fn a_name_longer_than_the_buffer_is_truncated_not_written_past() {
        // The C strcpy'd into a buffer whose size it did not know. Nothing in
        // the tables is this long, which is the point: the check belongs here
        // rather than in the tables.
        let long: &'static std::ffi::CStr = Box::leak(
            std::ffi::CString::new("x".repeat(ffi::MAX_NAME as usize + 50))
                .unwrap()
                .into_boxed_c_str(),
        );
        let mut m = meta(0);
        m.name = Some(long);
        let mut e = entry_for(m);

        // One byte of slack past MAX_NAME + 1, poisoned, to catch an overrun.
        let mut buf = vec![0xAAu8; ffi::MAX_NAME as usize + 2];
        let len = ffi::MAX_NAME as usize + 1;
        proc_entry_getname(&mut e, &mut buf[..len]);
        assert_eq!(
            buf[ffi::MAX_NAME as usize + 1],
            0xAA,
            "wrote past the buffer"
        );
        assert_eq!(buf[ffi::MAX_NAME as usize], 0, "not terminated");
        assert!(buf[..ffi::MAX_NAME as usize].iter().all(|&b| b == b'x'));
    }

    /// The bound is the *buffer's*, which is what a sentence in a doc comment
    /// could not say. Backed out — `put_name` copying `name.len()` — this is
    /// the case that goes red rather than the one above, because the one above
    /// happens to be handed exactly the length the old constant named.
    #[test]
    fn the_truncation_is_against_the_buffer_and_not_against_max_name() {
        let mut buf = [0xAAu8; 8];
        put_name(&mut buf[..4], b"abcdefghij");
        assert_eq!(&buf[..4], b"abc\0");
        assert_eq!(&buf[4..], [0xAA; 4], "wrote past the buffer");

        // Exactly filling it, which is where the terminator has to displace a
        // byte of the name rather than follow it.
        put_name(&mut buf[..4], b"abc");
        assert_eq!(&buf[..4], b"abc\0");
        put_name(&mut buf[..4], b"ab");
        assert_eq!(&buf[..3], b"ab\0");

        // Nowhere to put even a terminator: nothing is written.
        put_name(&mut [], b"abc");
    }

    #[test]
    fn an_entry_with_no_name_at_all_is_empty_rather_than_fatal() {
        let mut e = entry_for(meta(0));
        let mut buf = [0xAAu8; 8];
        proc_entry_getname(&mut e, &mut buf);
        assert_eq!(buf[0], 0);
    }

    #[test]
    fn a_directory_with_neither_children_nor_readdir_is_empty() {
        let mut e = entry_for(meta(libc::S_IFDIR));
        let mut index = 0u64;
        assert!(proc_dir_read(&mut e, &mut index).is_none());
    }

    /// A fresh entry owns nothing, which is what makes dropping one free.
    ///
    /// `cleanup_of_an_empty_entry_is_a_no_op` and
    /// `free_string_array_accepts_null` were the two tests here until
    /// 2026-09-14, and both were about the hand-written destructor's tolerance
    /// of null. There is no destructor to be tolerant.
    #[test]
    fn a_fresh_entry_owns_nothing() {
        let e = ffi::proc_entry::default();
        assert!(e.name.is_none());
        assert!(e.child_names.is_empty());
    }
}
