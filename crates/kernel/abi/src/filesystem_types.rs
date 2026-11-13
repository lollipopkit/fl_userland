//! Guest filesystem descriptors, callbacks, and attribute layouts.

#![allow(non_upper_case_globals)]

use crate::{byte_t, fd, mode_t_, off_t_, qword_t, uid_t_};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct dir_entry {
    pub inode: qword_t,
    pub type_: byte_t,
    pub name: [std::ffi::c_char; 256usize],
}
impl dir_entry {
    /// The name, up to its terminator — or the whole array if there is none.
    ///
    /// `name` is a fixed `[c_char; 256]` because that is the shape `readdir`
    /// fills, and every reader wrote its own `CStr::from_ptr` or its own
    /// `position(|&b| b == 0)`. This is the one definition; the array is a
    /// buffer and not a string, so a mount that forgets the terminator gets a
    /// truncated name rather than a walk off the end.
    pub fn name(&self) -> &[u8] {
        // SAFETY: `c_char` and `u8` have the same layout, and the length is
        // the array's own.
        let bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(self.name.as_ptr().cast::<u8>(), self.name.len()) };
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        &bytes[..end]
    }

    /// Fill it, terminator included. `false` for a name that does not fit,
    /// which is the answer `readdir` turns into "skip this entry".
    pub fn set_name(&mut self, name: &[u8]) -> bool {
        if name.len() >= self.name.len() {
            return false;
        }
        for (slot, b) in self.name.iter_mut().zip(name) {
            *slot = *b as std::ffi::c_char;
        }
        self.name[name.len()] = 0;
        true
    }
}

impl Default for dir_entry {
    fn default() -> Self {
        Self {
            inode: 0,
            type_: 0,
            name: [0; 256],
        }
    }
}
const _: () = {
    assert!(std::mem::size_of::<dir_entry>() == 272, "Size of dir_entry");
    assert!(
        std::mem::align_of::<dir_entry>() == 8,
        "Alignment of dir_entry"
    );
    assert!(
        std::mem::offset_of!(dir_entry, inode) == 0,
        "Offset of field: dir_entry::inode"
    );
    assert!(
        std::mem::offset_of!(dir_entry, type_) == 8,
        "Offset of field: dir_entry::type_"
    );
    assert!(
        std::mem::offset_of!(dir_entry, name) == 9,
        "Offset of field: dir_entry::name"
    );
};
pub type dev_t_ = u32;

/// A character or block device: what opening its node does, and the driver the
/// descriptor gets.
///
/// No longer `#[repr(C)]` and no longer carrying an `fd_ops` **by value**:
/// nothing outside this workspace names it — it is absent from `iul.h`, from
/// the gadgets and from the embedder example — and the operations it used to
/// embed are a [`crate::FdOps`] implementation now.
#[derive(Default, Copy, Clone)]
pub struct dev_ops {
    /// A **safe Rust** function pointer, for the reason the type comment
    /// gives: nothing outside this workspace names `dev_ops`, so nothing
    /// outside it can install one. It was `unsafe extern "C" fn` until
    /// 2026-09-11 and all five implementors were already safe `fn`, so the
    /// `unsafe` was an obligation at the one call site that nobody owed.
    ///
    /// **`&mut fd`, not `*mut fd`**, since 2026-09-16. This runs on the
    /// construction path -- a descriptor `generic_open` has just made and
    /// nothing else can see yet -- so exclusive access is what the caller
    /// actually has, and two of the five implementors write a field through
    /// it. The `unsafe` each of them needed to do that is gone with the
    /// pointer.
    pub open: Option<
        fn(major: std::ffi::c_int, minor: std::ffi::c_int, fd: &mut fd) -> std::ffi::c_int,
    >,
    /// The driver a descriptor opened on this device is answered by. `None`
    /// for a device that answers nothing, which is what `Default` is.
    pub fd: Option<&'static dyn crate::FdOps>,
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct iul_stat {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
}
const _: () = {
    assert!(std::mem::size_of::<iul_stat>() == 16, "Size of iul_stat");
    assert!(
        std::mem::align_of::<iul_stat>() == 4,
        "Alignment of iul_stat"
    );
    assert!(
        std::mem::offset_of!(iul_stat, mode) == 0,
        "Offset of field: iul_stat::mode"
    );
    assert!(
        std::mem::offset_of!(iul_stat, uid) == 4,
        "Offset of field: iul_stat::uid"
    );
    assert!(
        std::mem::offset_of!(iul_stat, gid) == 8,
        "Offset of field: iul_stat::gid"
    );
    assert!(
        std::mem::offset_of!(iul_stat, rdev) == 12,
        "Offset of field: iul_stat::rdev"
    );
};
/* `fs_info` was a placeholder here until 2026-09-11 and is `fsinfo::FsInfo`,
 * re-exported under that name by `crates/kernel/taskview`. It cannot be
 * re-exported here: `kernel-fsinfo` reads `struct fd`'s `owner` field, so it
 * depends on *this* crate. Same constraint, and same one-commit rule, as
 * `sighand` and `sigqueue_state` -- `taskview::ffi` globs both crates and a
 * name defined in each is ambiguous rather than shadowed. */
/// One attribute a `setattr` changes: `chown`'s owner or its group, `chmod`'s
/// mode, `truncate`'s size.
///
/// A `#[repr(C)]` tag beside a union until 2026-09-29 -- the C's
/// `struct attr`, rendered by bindgen and then kept by hand. No C read it by
/// then, so the layout was a contract with nobody, and what it cost was that
/// every reader matched the tag and then read the arm the tag named inside an
/// `unsafe` block: thirty-one of them, across twelve crates, each asserting
/// the pairing the compiler now checks. One writer built a mode through the
/// `size` arm, which was right only because both arms start at offset 0 on a
/// little-endian machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attr {
    Uid(uid_t_),
    Gid(uid_t_),
    Mode(mode_t_),
    Size(off_t_),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filesystem_defaults_preserve_zero_value_semantics() {
        let entry = dir_entry::default();
        assert_eq!(entry.inode, 0);
        assert_eq!(entry.type_, 0);
        assert!(entry.name.iter().all(|&byte| byte == 0));

        // `fs_ops::default()` was asserted here too -- a null name, a zero
        // magic and two `None` operations. It is a trait since 2026-09-11 and
        // has no default value; what a filesystem that implements nothing
        // answers is `crates/kernel/abi/src/fs_ops.rs`'s
        // `a_filesystem_that_implements_nothing_refuses_the_right_way`, which
        // asks about behaviour rather than about a zeroed struct.
        let dev = dev_ops::default();
        assert!(dev.open.is_none());
        assert!(dev.fd.is_none());
    }

    /// The name stops at the terminator, not at the end of the array. The
    /// array is `NAME_MAX + 1` bytes and almost every name is shorter, so
    /// reading the whole thing would put 255 bytes of zeroes in every record.
    #[test]
    fn a_name_is_read_up_to_its_terminator() {
        let mut e = dir_entry::default();
        assert!(e.set_name(b"hello"));
        assert_eq!(e.name(), b"hello");
        assert!(e.set_name(b""));
        assert_eq!(e.name(), b"");
        let long = vec![b'x'; 255];
        assert!(e.set_name(&long));
        assert_eq!(e.name(), &long[..]);
    }

    /// A name that fills the array with no terminator stops at its end rather
    /// than running past it. A mount is trusted to terminate, but "trusted" is
    /// what the C's `assert` said too — and `set_name` cannot produce this, so
    /// the array is filled by hand.
    #[test]
    fn an_unterminated_name_stops_at_the_array() {
        let mut e = dir_entry::default();
        for slot in e.name.iter_mut() {
            *slot = b'z' as std::ffi::c_char;
        }
        assert_eq!(e.name().len(), e.name.len());
    }

    /// One byte too long is refused rather than truncated: 256 characters
    /// leaves no room for the terminator.
    #[test]
    fn a_name_that_does_not_fit_with_its_terminator_is_refused() {
        let mut e = dir_entry::default();
        assert!(e.set_name(&vec![b'x'; 255]));
        assert!(!e.set_name(&vec![b'x'; 256]));
        // And the refusal leaves what was there, which is what makes
        // "skip this entry" the caller's only correct response.
        assert_eq!(e.name().len(), 255);
    }
}
