//! What a unix socket is called, and the id that stands for it.
//!
//! An `AF_UNIX` socket is named either by a path in the filesystem or by a name
//! in the *abstract namespace* — a byte string that exists only in this table.
//! Either way the name is turned into a small integer, and the integer is what
//! goes into the host socket's path: two guest sockets that agree on a name end
//! up on the same `/tmp/iulsock<pid>.<id>`.
//!
//! Only the abstract namespace lives here. The filesystem side is the VFS's —
//! a `stat`, a `mknod`, an inode — and stays in `fs/sock.c`; it takes its ids
//! from [`next_id`] so that the two namespaces cannot collide.
//!
//! # An abstract name is bytes
//!
//! Not a C string. Linux takes exactly `addrlen - offsetof(sun_path)` bytes
//! after the leading NUL, and they may contain NULs of their own. The C this
//! replaces got that wrong twice, and each time the symptom was two different
//! sockets behaving as one:
//!
//! - keyed with `strlen`/`strcmp`, `"\0log\0v1"` and `"\0log\0v2"` were the
//!   same name, so a bind of the second was refused as already taken and a
//!   connect to it reached the first;
//! - keyed by the hash alone, two names that collided in a 1024-bucket table
//!   were the same name, with the same result for whichever pair collided.
//!
//! A `HashMap<Vec<u8>, u32>` cannot express either. The C was a fixed array of
//! 1024 intrusive list heads, a Bernstein hash, a `refcount` nothing ever
//! incremented, and a `malloc` with a flexible array member.
//!
//! # The handle
//!
//! A bind hands back an opaque handle, which the socket keeps and gives up when
//! it closes. It is the name — nothing else is needed to find the entry again,
//! and giving the caller a pointer *into* the table is what would make the
//! table's own storage part of the interface.

use std::collections::HashMap;
use std::ffi::c_int;
use std::sync::Mutex;

/// Linux's `unix_bind_abstract` answers this for a name that is already
/// bound, the same as the filesystem path does for a socket file that exists.
/// The C answered `EEXIST`, which says something different to a caller: an
/// `EEXIST` from `bind` reads as "a stale socket file is in the way, unlink it
/// and retry", and an abstract name is not a file and cannot be unlinked.
use guest_errno::c_int_::EADDRINUSE;
/// A *lookup* miss, which only a connect or a send can ask for.
///
/// Not `ENOENT`. The filesystem namespace answers `ENOENT` because a path
/// lookup did, and the C carried that over to the abstract namespace, where
/// there is no directory and nothing was looked up. Linux's
/// `unix_find_abstract` answers `ECONNREFUSED`, which is also the only one of
/// the two a caller can act on: an abstract name that is not bound is not a
/// missing file to be created, it is nobody listening.
use guest_errno::c_int_::ECONNREFUSED;
use guest_errno::c_int_::{ENOMEM, ENOSPC};

#[derive(Default)]
pub struct Names {
    /// The name's bytes to the id that stands for it.
    bound: HashMap<Vec<u8>, u32>,
    /// Shared with the filesystem namespace, so the two cannot collide. It
    /// starts at 1 because 0 means "no id yet" in the inode that caches one.
    next_id: u32,
    /// Where the next autobind starts looking. Linux starts from a random
    /// point and scans the whole space; a cursor does the same work without
    /// randomness, and these names are not a secret.
    next_auto: u32,
}

/// The autobound name space: five hex digits, so 2^20 of them.
const AUTOBIND_SPACE: u32 = 1 << 20;

impl Names {
    pub fn next_id(&mut self) -> u32 {
        self.next_id += 1;
        self.next_id
    }

    /// Claim a name. `Err(EADDRINUSE)` if it is already bound.
    pub fn bind(&mut self, name: &[u8]) -> Result<u32, c_int> {
        if self.bound.contains_key(name) {
            return Err(EADDRINUSE);
        }
        let id = self.next_id();
        let mut owned = Vec::new();
        if owned.try_reserve_exact(name.len()).is_err() {
            return Err(ENOMEM);
        }
        owned.extend_from_slice(name);
        if self.bound.try_reserve(1).is_err() {
            return Err(ENOMEM);
        }
        self.bound.insert(owned, id);
        Ok(id)
    }

    /// Pick an unused name for a socket that bound the family and nothing
    /// else, as Linux's `unix_autobind` does: a leading NUL and five hex
    /// digits, so the whole address is eight bytes.
    ///
    /// The C had no autobind at all. `bind(fd, {AF_UNIX}, 2)` computed a name
    /// of zero length and returned `ENOENT`, so a socket that wanted an
    /// address it did not have to choose could not get one -- and `ENOENT`
    /// from `bind` names no remedy, since there is nothing to create.
    pub fn autobind(&mut self) -> Result<(Vec<u8>, u32), c_int> {
        let start = self.next_auto;
        for step in 0..AUTOBIND_SPACE {
            let n = start.wrapping_add(step) % AUTOBIND_SPACE;
            let name = format!("\0{n:05x}").into_bytes();
            if !self.bound.contains_key(&name) {
                self.next_auto = (n + 1) % AUTOBIND_SPACE;
                let id = self.bind(&name)?;
                return Ok((name, id));
            }
        }
        // A million names all taken. Linux says ENOSPC too.
        Err(ENOSPC)
    }

    /// The id a name already stands for. `Err(ECONNREFUSED)` if nothing bound
    /// it: see the constant.
    ///
    /// A lookup takes no reference. It reads the id and is done, and the C
    /// that incremented a refcount here leaked the name for ever: only the
    /// bind case had anywhere to put the pointer that release is called with.
    pub fn lookup(&self, name: &[u8]) -> Result<u32, c_int> {
        self.bound.get(name).copied().ok_or(ECONNREFUSED)
    }

    /// The socket that bound this name has closed.
    pub fn release(&mut self, name: &[u8]) -> bool {
        self.bound.remove(name).is_some()
    }

    pub fn len(&self) -> usize {
        self.bound.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bound.is_empty()
    }
}

static NAMES: Mutex<Option<Names>> = Mutex::new(None);

/// A claim on an abstract name. **Dropping it is the release.**
///
/// There is no way to hold a claim without one and no way to hold one without
/// a claim: [`bind`] and [`autobind`] are the only constructors and each makes
/// it from a `Names::bind` that has just succeeded.
///
/// It was `Handle(Vec<u8>)` with a `Handle::new` and a `release_handle`, and
/// the comment above it said it "stays a thin pointer when boxed, which lets
/// the socket keep it in the ABI-shaped integer slot". That slot is
/// `crates/fs/sock`'s own Rust struct and has been since 2026-09-05, so what
/// the shape was for had gone; what was left was a `Box::into_raw(…) as usize`
/// on one side and a `Box::from_raw` on the other, with the release written
/// out on three paths.
///
/// # The lock
///
/// `Drop` takes the table's lock, so a `Handle` must not be dropped while it
/// is held. Nothing can: the two constructors below build it *after* their
/// `with_names` returns, and `Names` itself never makes one.
pub struct Handle(Vec<u8>);

impl Drop for Handle {
    fn drop(&mut self) {
        with_names(|names| names.release(&self.0));
    }
}

/// Claim an abstract name, or say why not.
pub fn bind(name: &[u8]) -> Result<(Handle, u32), c_int> {
    let id = with_names(|t| t.bind(name))?;
    Ok((Handle(name.to_vec()), id))
}

/// Pick an unused name and claim it, as Linux's `unix_autobind` does.
///
/// The name comes back as well as the claim because `getsockname` reports it —
/// and it is the table's *key*, which for an autobind includes the leading NUL
/// where an explicit bind's does not. Handing the caller a `Handle` it cannot
/// look inside is what stops the two being confused: the version before this
/// stored the wrong one once, and the address stayed taken for the life of the
/// process.
pub fn autobind() -> Result<(Handle, Vec<u8>, u32), c_int> {
    let (name, id) = with_names(Names::autobind)?;
    Ok((Handle(name.clone()), name, id))
}

/// The id a name already stands for, for a connect or a send. Takes no claim.
pub fn lookup(name: &[u8]) -> Result<u32, c_int> {
    with_names(|t| t.lookup(name))
}

/// The one table, for a Rust caller.
///
/// The C ABI below is the same call with its arguments flattened; a Rust caller
/// takes this instead, so that `crates/fs/sock` reaches the namespace without
/// going out through C and back.
pub fn with_table<T>(f: impl FnOnce(&mut Names) -> T) -> T {
    with_names(f)
}

fn with_names<T>(f: impl FnOnce(&mut Names) -> T) -> T {
    let mut guard = NAMES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    f(guard.get_or_insert_with(Names::default))
}

/// The next socket id, for the filesystem namespace. Never 0.
pub fn unixname_next_id() -> u32 {
    with_names(Names::next_id)
}

// `release_handle(Handle)` was here until 2026-09-14. `Handle` has a `Drop`
// now, so the release is what happens when the claim goes out of scope and
// there is nothing for a caller to forget.

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    #[test]
    fn a_bound_name_is_found_and_a_second_bind_is_addrinuse() {
        let mut names = Names::default();
        let id = names.bind(b"log").expect("free");
        assert_eq!(names.lookup(b"log"), Ok(id));
        assert_eq!(names.bind(b"log"), Err(EADDRINUSE));
        assert_eq!(names.lookup(b"nothing"), Err(ECONNREFUSED));
    }

    /// The first of the two defects the C had: keyed with `strlen`/`strcmp`,
    /// `"log\0v1"` and `"log\0v2"` were one name, so a bind of the second
    /// answered `EEXIST` and a connect to it reached the first.
    #[test]
    fn a_name_is_bytes_and_may_contain_nuls() {
        let mut names = Names::default();
        let v1 = names.bind(b"log\0v1").expect("free");
        let v2 = names.bind(b"log\0v2").expect("also free");
        assert_ne!(v1, v2);
        assert_eq!(names.lookup(b"log\0v1"), Ok(v1));
        assert_eq!(names.lookup(b"log\0v2"), Ok(v2));
        // And the prefix they share is a third name, bound by neither.
        assert_eq!(names.lookup(b"log"), Err(ECONNREFUSED));
    }

    /// The second: keyed by a 32-bit hash alone, two names that collided were
    /// one name. Nothing here hashes for identity, so the property to check is
    /// that a large set of names stays a large set.
    #[test]
    fn distinct_names_stay_distinct_in_bulk() {
        let mut names = Names::default();
        let mut ids = std::collections::HashSet::new();
        for i in 0..4096u32 {
            let name = format!("sock-{i}").into_bytes();
            let id = names.bind(&name).expect("free");
            assert!(ids.insert(id), "id {id} handed out twice");
        }
        assert_eq!(names.len(), 4096);
        for i in 0..4096u32 {
            assert!(names.lookup(format!("sock-{i}").as_bytes()).is_ok());
        }
    }

    /// An empty name is a name. `bind(fd, "\0", 3)` — the family and one NUL —
    /// names the empty abstract string, and it is not the same as no name.
    #[test]
    fn the_empty_name_is_a_name() {
        let mut names = Names::default();
        let id = names.bind(b"").expect("free");
        assert_eq!(names.lookup(b""), Ok(id));
        assert_eq!(names.bind(b""), Err(EADDRINUSE));
        assert!(names.release(b""));
        assert_eq!(names.lookup(b""), Err(ECONNREFUSED));
    }

    #[test]
    fn releasing_frees_the_name_for_the_next_binder() {
        let mut names = Names::default();
        let first = names.bind(b"log").expect("free");
        assert!(names.release(b"log"));
        assert!(!names.release(b"log"), "releasing twice does nothing");
        let second = names.bind(b"log").expect("free again");
        // A rebind is a new socket, so it gets a new id: the old one may still
        // be named by a host path a stale peer is holding.
        assert_ne!(first, second);
    }

    /// Ids are shared with the filesystem namespace, so an abstract bind and a
    /// filesystem socket can never be handed the same one. And never 0, which
    /// is what an inode with no id yet holds.
    #[test]
    fn ids_are_unique_across_both_namespaces_and_never_zero() {
        let mut names = Names::default();
        let mut seen = std::collections::HashSet::new();
        for i in 0..64u32 {
            let id = if i % 2 == 0 {
                names.next_id()
            } else {
                names.bind(format!("n{i}").as_bytes()).expect("free")
            };
            assert_ne!(id, 0);
            assert!(seen.insert(id), "id {id} handed out twice");
        }
    }

    /// Autobind picks a name of Linux's shape: a leading NUL and five hex
    /// digits, so `getsockname` reports eight bytes in all.
    #[test]
    fn autobind_picks_a_name_of_linuxs_shape() {
        let mut names = Names::default();
        let (name, id) = names.autobind().expect("space");
        assert_eq!(name.len(), 6, "a NUL and five digits: {name:?}");
        assert_eq!(name[0], 0);
        assert!(
            name[1..]
                .iter()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "lowercase hex: {name:?}"
        );
        assert_eq!(names.lookup(&name), Ok(id));
        // And it is bound, so binding it again is refused like any other.
        assert_eq!(names.bind(&name), Err(EADDRINUSE));
    }

    /// Two autobinds never pick the same name, and one never picks a name
    /// something else already holds.
    #[test]
    fn autobind_skips_what_is_taken() {
        let mut names = Names::default();
        // Take the name the cursor is about to reach, twice over.
        assert!(names.bind(b"\x0000000").is_ok());
        assert!(names.bind(b"\x0000001").is_ok());
        let (first, _) = names.autobind().expect("space");
        let (second, _) = names.autobind().expect("space");
        assert_ne!(first, second);
        for name in [&first, &second] {
            assert_ne!(name.as_slice(), b"\x0000000");
            assert_ne!(name.as_slice(), b"\x0000001");
        }
    }

    /// The whole round trip through the process-wide table: claim, find, and
    /// give the claim up by dropping it.
    ///
    /// This was `the_c_api_binds_looks_up_and_releases` and drove a
    /// `#[cfg(test)]` `unixname_bind(*const c_char, usize, *mut u32,
    /// *mut *mut Handle) -> c_int` with a `unixname_lookup` beside it — a
    /// second implementation of these three lines, with a pointer and a length
    /// where the real one takes a slice, two out-parameters, and an integer
    /// error code. Its doc comment said it was "what `fs/sock.c` actually
    /// calls", and there has been no `fs/sock.c` since 2026-09-06: what it
    /// tested was itself.
    ///
    /// A name with a NUL in the middle is the case worth keeping, and it is
    /// the real API's now.
    #[test]
    fn a_claim_is_given_up_by_dropping_it() {
        let name = b"ffi-test-name\0with-a-nul";
        let (claim, id) = bind(name).expect("free");
        assert_ne!(id, 0);
        assert_eq!(lookup(name), Ok(id));

        drop(claim);
        assert_eq!(lookup(name), Err(ECONNREFUSED));
    }
}

// `unixname_bind`, `unixname_lookup` and their `borrow` helper were here,
// behind `#[cfg(test)]`, until 2026-09-14: a C ABI over this table -- pointer
// and length, two out-parameters, an integer errno, and a `Box::into_raw`d
// `Handle` -- kept alive by the one test that called it. No C has called it
// since `fs/sock.c` went on 2026-09-06.
