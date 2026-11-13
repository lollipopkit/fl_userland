//! Inotify watch state, event queueing and guest wire encoding.

use std::collections::HashMap;
use std::ffi::c_int;

/// Bytes before the name.
const HDR: usize = 16;

// The events a watch may ask for.
pub const IN_ACCESS: u32 = 0x0000_0001;
pub const IN_MODIFY: u32 = 0x0000_0002;
pub const IN_ATTRIB: u32 = 0x0000_0004;
pub const IN_CLOSE_WRITE: u32 = 0x0000_0008;
pub const IN_CLOSE_NOWRITE: u32 = 0x0000_0010;
pub const IN_OPEN: u32 = 0x0000_0020;
pub const IN_MOVED_FROM: u32 = 0x0000_0040;
pub const IN_MOVED_TO: u32 = 0x0000_0080;
pub const IN_CREATE: u32 = 0x0000_0100;
pub const IN_DELETE: u32 = 0x0000_0200;
pub const IN_DELETE_SELF: u32 = 0x0000_0400;
pub const IN_MOVE_SELF: u32 = 0x0000_0800;
/// Everything a watch may name.
pub const IN_ALL_EVENTS: u32 = 0x0000_0fff;

// Bits the kernel sets on an event, which a watch does not ask for.
pub const IN_UNMOUNT: u32 = 0x0000_2000;
pub const IN_Q_OVERFLOW: u32 = 0x0000_4000;
pub const IN_IGNORED: u32 = 0x0000_8000;
pub const IN_ISDIR: u32 = 0x4000_0000;

// Modifiers a watch may pass alongside the events.
pub const IN_ONLYDIR: u32 = 0x0100_0000;
pub const IN_DONT_FOLLOW: u32 = 0x0200_0000;
pub const IN_EXCL_UNLINK: u32 = 0x0400_0000;
pub const IN_MASK_CREATE: u32 = 0x1000_0000;
pub const IN_MASK_ADD: u32 = 0x2000_0000;
pub const IN_ONESHOT: u32 = 0x8000_0000;
pub const IN_MODIFIERS: u32 =
    IN_ONLYDIR | IN_DONT_FOLLOW | IN_EXCL_UNLINK | IN_MASK_CREATE | IN_MASK_ADD | IN_ONESHOT;

use guest_errno::c_int_::{EEXIST, EINVAL};

/// How many events one instance will hold before it starts dropping them.
/// Linux's default `max_queued_events` is 16384 and it reports the loss with a
/// single `IN_Q_OVERFLOW` rather than growing without bound, which a guest that
/// stops reading could otherwise make it do.
pub const MAX_QUEUED: usize = 16384;

/// The name a record carries, and the bytes it occupies.
///
/// `len` is the name field's length — the NUL and the padding included — not
/// the record's. A reader adds `sizeof(struct inotify_event)` to it to find the
/// next event.
fn name_field_len(name: &[u8]) -> usize {
    if name.is_empty() {
        // An event about the watched thing itself carries no name at all, and
        // `len` is 0 rather than a lone padded NUL.
        0
    } else {
        (name.len() + 1).next_multiple_of(HDR)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub wd: i32,
    pub mask: u32,
    pub cookie: u32,
    pub name: Vec<u8>,
}

impl Event {
    /// The bytes this record occupies.
    pub fn size(&self) -> usize {
        HDR + name_field_len(&self.name)
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        let field = name_field_len(&self.name);
        out.extend_from_slice(&self.wd.to_le_bytes());
        out.extend_from_slice(&self.mask.to_le_bytes());
        out.extend_from_slice(&self.cookie.to_le_bytes());
        out.extend_from_slice(&(field as u32).to_le_bytes());
        let start = out.len();
        out.extend_from_slice(&self.name);
        // NUL and padding, all zero.
        out.resize(start + field, 0);
    }
}

#[derive(Debug)]
struct Watch {
    path: Vec<u8>,
    mask: u32,
    inode: Inode,
}

/// The file a watch was placed on, as `stat` named it when it was: Linux's
/// mark is on the inode, so this is what `/proc/<pid>/fdinfo` reports even
/// after the path has moved on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Inode {
    pub ino: u64,
    /// `st_dev`, in `stat`'s encoding.
    pub dev: u64,
}

/// One watch as `/proc/<pid>/fdinfo` lists it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Listed {
    pub wd: i32,
    /// `inotify_mark_user_mask`: the events, and of the modifiers only the two
    /// a mark keeps, `IN_ONESHOT` and `IN_EXCL_UNLINK`.
    pub mask: u32,
    pub inode: Inode,
}

/// One inotify descriptor.
#[derive(Debug, Default)]
pub struct Instance {
    watches: HashMap<i32, Watch>,
    /// Reverse index, so adding a watch for a path already watched updates it
    /// rather than handing out a second descriptor — which is what Linux does
    /// and what the caller relies on to avoid duplicate events.
    by_path: HashMap<Vec<u8>, i32>,
    next_wd: i32,
    queue: Vec<Event>,
    overflowed: bool,
}

/// Whether a mask names something to watch for, and nothing this kernel does
/// not have.
///
/// It is a function rather than the first four lines of `add_watch` because the
/// **syscall** has to apply it before it does anything else: Linux validates the
/// mask ahead of the descriptor and the path, so
/// `inotify_add_watch(-1, "/tmp", 0)` is `EINVAL` and not `EBADF`. Two copies of
/// the rule would be two chances to disagree about which bits exist.
pub fn check_mask(mask: u32) -> Result<(), c_int> {
    // Linux's test is `!(mask & ALL_INOTIFY_BITS)`, and `ALL_INOTIFY_BITS`
    // includes the **modifiers** — so `IN_ONLYDIR` on its own is accepted and
    // makes a watch that can never fire. This asked for an *event* bit, which is
    // the rule somebody would write down, and refused it.
    //
    // Measured rather than read: `tests/guest/src/bin/inotify_probe.rs` sweeps
    // eight masks against a real kernel, and this was the one that differed. The
    // caller that reaches it is one building a mask at run time whose event bits
    // all turned out to be zero — refusing tells it the arguments are wrong when
    // Linux tells it nothing is being watched for, which is a different bug to
    // go looking for.
    if mask & (IN_ALL_EVENTS | IN_MODIFIERS) == 0 || mask & !(IN_ALL_EVENTS | IN_MODIFIERS) != 0 {
        return Err(EINVAL);
    }
    if mask & IN_MASK_ADD != 0 && mask & IN_MASK_CREATE != 0 {
        // Contradictory: one says update the existing watch, the other says
        // fail if there is one.
        return Err(EINVAL);
    }
    Ok(())
}

impl Instance {
    pub fn new() -> Self {
        Instance {
            next_wd: 1,
            ..Default::default()
        }
    }

    /// Adds or updates a watch on `inode`, found at `path`. Answers the watch
    /// descriptor, or a negative errno. An update keeps the watch's inode, as
    /// Linux's mark stays on the one it was placed on.
    pub fn add_watch(&mut self, path: &[u8], mask: u32, inode: Inode) -> c_int {
        if let Err(e) = check_mask(mask) {
            return e;
        }
        if let Some(&wd) = self.by_path.get(path) {
            if mask & IN_MASK_CREATE != 0 {
                return EEXIST;
            }
            let watch = self
                .watches
                .get_mut(&wd)
                .expect("by_path names a live watch");
            watch.mask = if mask & IN_MASK_ADD != 0 {
                watch.mask | (mask & !IN_MASK_ADD)
            } else {
                mask
            };
            return wd;
        }
        let wd = self.next_wd;
        // Never reused, so a stale descriptor is refused rather than silently
        // naming whatever was watched next.
        self.next_wd += 1;
        self.watches.insert(
            wd,
            Watch {
                path: path.to_vec(),
                mask,
                inode,
            },
        );
        self.by_path.insert(path.to_vec(), wd);
        wd
    }

    pub fn rm_watch(&mut self, wd: i32) -> c_int {
        match self.watches.remove(&wd) {
            Some(watch) => {
                self.by_path.remove(&watch.path);
                // Linux reports the removal to the reader.
                self.push_raw(Event {
                    wd,
                    mask: IN_IGNORED,
                    cookie: 0,
                    name: Vec::new(),
                });
                0
            }
            None => EINVAL,
        }
    }

    fn push_raw(&mut self, event: Event) {
        if self.queue.len() >= MAX_QUEUED {
            // One overflow marker, not one per dropped event.
            if !self.overflowed {
                self.overflowed = true;
                self.queue.push(Event {
                    wd: -1,
                    mask: IN_Q_OVERFLOW,
                    cookie: 0,
                    name: Vec::new(),
                });
            }
            return;
        }
        // Linux coalesces an event that is identical to the one already at the
        // tail, which is what stops a program writing in a loop from filling
        // the queue with IN_MODIFY.
        if self.queue.last() == Some(&event) {
            return;
        }
        self.queue.push(event);
    }

    /// Reports `mask` happening to `name` inside `dir`, and to `dir` itself if
    /// it is being watched. Answers how many watches were interested, so the
    /// caller can tell whether anything was recorded.
    pub fn notify(&mut self, dir: &[u8], name: &[u8], mask: u32, cookie: u32) -> usize {
        let mut hits = 0;
        // A watch on the containing directory hears about the child, by name.
        if let Some(&wd) = self.by_path.get(dir) {
            let watch = &self.watches[&wd];
            if watch.mask & mask & IN_ALL_EVENTS != 0 {
                let oneshot = watch.mask & IN_ONESHOT != 0;
                self.push_raw(Event {
                    wd,
                    mask,
                    cookie,
                    name: name.to_vec(),
                });
                hits += 1;
                if oneshot {
                    self.rm_watch(wd);
                }
            }
        }
        // A watch on the thing itself hears about it without a name.
        let mut full = dir.to_vec();
        if !name.is_empty() {
            if full.last() != Some(&b'/') {
                full.push(b'/');
            }
            full.extend_from_slice(name);
        }
        if let Some(&wd) = self.by_path.get(&full) {
            let watch = &self.watches[&wd];
            // A watch on a file hears IN_MODIFY and IN_ATTRIB about itself;
            // being removed or moved is IN_DELETE_SELF/IN_MOVE_SELF, which the
            // caller reports separately.
            let self_mask = mask
                & (IN_MODIFY | IN_ATTRIB | IN_ACCESS | IN_OPEN | IN_CLOSE_WRITE | IN_CLOSE_NOWRITE);
            if watch.mask & self_mask != 0 {
                self.push_raw(Event {
                    wd,
                    mask: self_mask,
                    cookie,
                    name: Vec::new(),
                });
                hits += 1;
            }
        }
        hits
    }

    /// The watches, newest first: Linux puts each new mark at the head of
    /// the group's list, and descriptors are never reused, so that is
    /// descending `wd`.
    pub fn listing(&self) -> Vec<Listed> {
        let mut out: Vec<Listed> = self
            .watches
            .iter()
            .map(|(&wd, w)| Listed {
                wd,
                mask: w.mask & (IN_ALL_EVENTS | IN_ONESHOT | IN_EXCL_UNLINK),
                inode: w.inode,
            })
            .collect();
        out.sort_by_key(|w| std::cmp::Reverse(w.wd));
        out
    }

    pub fn has_events(&self) -> bool {
        !self.queue.is_empty()
    }

    pub fn is_watching(&self, path: &[u8]) -> bool {
        self.by_path.contains_key(path)
            || self
                .by_path
                .keys()
                .any(|w| path.starts_with(w) && path.get(w.len()) == Some(&b'/'))
    }

    /// Fills `cap` bytes with whole records, removing them from the queue.
    ///
    /// Answers the bytes written, or `EINVAL` when the buffer is too small for
    /// the event at the head — which is what Linux answers, rather than 0,
    /// because 0 from a read means end of file and an inotify descriptor never
    /// ends.
    pub fn read_into(&mut self, cap: usize) -> Result<Vec<u8>, c_int> {
        if self.queue.is_empty() {
            return Ok(Vec::new());
        }
        if self.queue[0].size() > cap {
            return Err(EINVAL);
        }
        let mut out = Vec::new();
        while let Some(event) = self.queue.first() {
            if out.len() + event.size() > cap {
                break;
            }
            let event = self.queue.remove(0);
            event.encode_into(&mut out);
        }
        if self.queue.is_empty() {
            self.overflowed = false;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_listing_is_newest_first_with_the_marks_own_bits() {
        let mut inst = Instance::new();
        let a = Inode { ino: 7, dev: 0x2d };
        inst.add_watch(b"/one", IN_CREATE | IN_ONLYDIR, a);
        inst.add_watch(b"/two", IN_MODIFY | IN_ONESHOT, Inode { ino: 9, dev: 0x2d });
        // An update keeps the inode the watch was placed on.
        inst.add_watch(b"/one", IN_DELETE | IN_MASK_ADD, Inode { ino: 8, dev: 0 });
        let got = inst.listing();
        assert_eq!(got.len(), 2);
        assert_eq!((got[0].wd, got[0].mask, got[0].inode.ino), (2, IN_MODIFY | IN_ONESHOT, 9));
        assert_eq!((got[1].wd, got[1].mask, got[1].inode), (1, IN_CREATE | IN_DELETE, a));
    }

    fn read_all(inst: &mut Instance) -> Vec<u8> {
        inst.read_into(1 << 16).unwrap()
    }

    /// The mask rule is a function of its own so that `sys_inotify_add_watch`
    /// can apply it **first** — Linux validates the mask ahead of the descriptor
    /// and the path, so `inotify_add_watch(-1, "/tmp", 0)` is `EINVAL` and not
    /// `EBADF`, and `(-1, NULL, IN_ATTRIB)` is `EBADF` and not `EFAULT`. Both
    /// were the wrong way round here until `table_probe` compared them.
    #[test]
    fn a_mask_names_something_to_watch_for() {
        assert_eq!(check_mask(0), Err(EINVAL), "no bit at all");
        // A modifier with no event to modify makes a watch that can never fire,
        // and Linux accepts it: its test is against the whole set of bits it
        // knows, modifiers included. Measured by `inotify_probe`, which is the
        // only reason this reads the way it does rather than the way it looks
        // like it should.
        assert_eq!(
            check_mask(IN_ONLYDIR),
            Ok(()),
            "a modifier alone is a watch that never fires, not an error"
        );
        assert_eq!(
            check_mask(IN_ATTRIB | 0x1000),
            Err(EINVAL),
            "a bit this kernel has no name for"
        );
        assert_eq!(
            check_mask(IN_ATTRIB | IN_MASK_ADD | IN_MASK_CREATE),
            Err(EINVAL),
            "update the existing watch, and fail if there is one"
        );

        assert_eq!(check_mask(IN_ATTRIB), Ok(()));
        assert_eq!(check_mask(IN_ALL_EVENTS), Ok(()));
        assert_eq!(check_mask(IN_CREATE | IN_ONLYDIR | IN_ONESHOT), Ok(()));
    }

    /// The offsets a guest reads by.
    #[test]
    fn the_record_is_the_one_a_guest_expects() {
        assert_eq!(HDR, 16);
        let mut out = Vec::new();
        Event {
            wd: 3,
            mask: IN_CREATE,
            cookie: 0,
            name: b"hi".to_vec(),
        }
        .encode_into(&mut out);
        assert_eq!(i32::from_le_bytes(out[0..4].try_into().unwrap()), 3);
        assert_eq!(u32::from_le_bytes(out[4..8].try_into().unwrap()), IN_CREATE);
        assert_eq!(u32::from_le_bytes(out[8..12].try_into().unwrap()), 0);
        // len is the *name field's* length, not the record's.
        assert_eq!(u32::from_le_bytes(out[12..16].try_into().unwrap()), 16);
        assert_eq!(out.len(), 32);
        assert_eq!(&out[16..18], b"hi");
        assert!(
            out[18..].iter().all(|&b| b == 0),
            "NUL and padding are zero"
        );
    }

    #[test]
    fn an_event_about_the_watch_itself_carries_no_name() {
        let mut out = Vec::new();
        Event {
            wd: 1,
            mask: IN_IGNORED,
            cookie: 0,
            name: Vec::new(),
        }
        .encode_into(&mut out);
        assert_eq!(out.len(), 16);
        assert_eq!(u32::from_le_bytes(out[12..16].try_into().unwrap()), 0);
    }

    #[test]
    fn records_follow_one_another_by_the_length_a_reader_computes() {
        let mut inst = Instance::new();
        inst.add_watch(b"/w", IN_CREATE, Inode::default());
        for name in ["a", "bbbbbbbbbbbbbbb", "c"] {
            inst.notify(b"/w", name.as_bytes(), IN_CREATE, 0);
        }
        let buf = read_all(&mut inst);
        let mut at = 0usize;
        let mut names = Vec::new();
        while at < buf.len() {
            let len = u32::from_le_bytes(buf[at + 12..at + 16].try_into().unwrap()) as usize;
            let name = &buf[at + 16..at + 16 + len];
            let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
            names.push(String::from_utf8_lossy(&name[..end]).into_owned());
            at += 16 + len;
        }
        assert_eq!(names, ["a", "bbbbbbbbbbbbbbb", "c"]);
        assert_eq!(at, buf.len(), "the last record ends exactly at the end");
    }

    #[test]
    fn a_watch_hears_about_its_children() {
        let mut inst = Instance::new();
        let wd = inst.add_watch(b"/dir", IN_CREATE | IN_DELETE, Inode::default());
        assert_eq!(wd, 1);
        assert_eq!(inst.notify(b"/dir", b"f", IN_CREATE, 0), 1);
        assert_eq!(inst.notify(b"/dir", b"f", IN_DELETE, 0), 1);
        // Not asked for.
        assert_eq!(inst.notify(b"/dir", b"f", IN_MODIFY, 0), 0);
        // Another directory.
        assert_eq!(inst.notify(b"/other", b"f", IN_CREATE, 0), 0);
    }

    #[test]
    fn a_watch_on_a_file_hears_about_itself_without_a_name() {
        let mut inst = Instance::new();
        inst.add_watch(b"/dir/f", IN_MODIFY, Inode::default());
        assert_eq!(inst.notify(b"/dir", b"f", IN_MODIFY, 0), 1);
        let buf = read_all(&mut inst);
        assert_eq!(buf.len(), 16, "no name field");
        assert_eq!(u32::from_le_bytes(buf[4..8].try_into().unwrap()), IN_MODIFY);
    }

    #[test]
    fn watching_the_same_path_twice_updates_the_watch() {
        let mut inst = Instance::new();
        let a = inst.add_watch(b"/dir", IN_CREATE, Inode::default());
        let b = inst.add_watch(b"/dir", IN_DELETE, Inode::default());
        assert_eq!(a, b, "the same descriptor");
        assert_eq!(
            inst.notify(b"/dir", b"f", IN_CREATE, 0),
            0,
            "replaced, not added"
        );
        assert_eq!(inst.notify(b"/dir", b"f", IN_DELETE, 0), 1);
    }

    #[test]
    fn in_mask_add_unions_instead_of_replacing() {
        let mut inst = Instance::new();
        inst.add_watch(b"/dir", IN_CREATE, Inode::default());
        inst.add_watch(b"/dir", IN_DELETE | IN_MASK_ADD, Inode::default());
        assert_eq!(inst.notify(b"/dir", b"f", IN_CREATE, 0), 1);
        assert_eq!(inst.notify(b"/dir", b"f", IN_DELETE, 0), 1);
    }

    #[test]
    fn in_mask_create_refuses_an_existing_watch() {
        let mut inst = Instance::new();
        inst.add_watch(b"/dir", IN_CREATE, Inode::default());
        assert_eq!(inst.add_watch(b"/dir", IN_CREATE | IN_MASK_CREATE, Inode::default()), EEXIST);
        assert_eq!(inst.add_watch(b"/new", IN_CREATE | IN_MASK_CREATE, Inode::default()), 2);
    }

    #[test]
    fn a_mask_naming_no_bit_this_kernel_knows_is_refused() {
        let mut inst = Instance::new();
        assert_eq!(inst.add_watch(b"/dir", 0, Inode::default()), EINVAL);
        assert_eq!(
            inst.add_watch(b"/dir", 0x0001_0000, Inode::default()),
            EINVAL,
            "a bit that is neither an event nor a modifier"
        );
        // A modifier on its own is a watch, not an error -- Linux's rule, and
        // `inotify_probe` is where it came from. It gets a descriptor and never
        // reports anything.
        assert!(inst.add_watch(b"/dir", IN_MASK_ADD, Inode::default()) > 0);
    }

    #[test]
    fn removing_a_watch_reports_it_and_then_refuses_the_descriptor() {
        let mut inst = Instance::new();
        let wd = inst.add_watch(b"/dir", IN_CREATE, Inode::default());
        assert_eq!(inst.rm_watch(wd), 0);
        let buf = read_all(&mut inst);
        assert_eq!(
            u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            IN_IGNORED
        );
        assert_eq!(inst.rm_watch(wd), EINVAL);
        // And it hears nothing more.
        assert_eq!(inst.notify(b"/dir", b"f", IN_CREATE, 0), 0);
    }

    #[test]
    fn a_descriptor_is_never_reused() {
        let mut inst = Instance::new();
        let a = inst.add_watch(b"/one", IN_CREATE, Inode::default());
        inst.rm_watch(a);
        let b = inst.add_watch(b"/two", IN_CREATE, Inode::default());
        assert_ne!(a, b, "a stale wd must not name a new watch");
    }

    #[test]
    fn oneshot_fires_once() {
        let mut inst = Instance::new();
        inst.add_watch(b"/dir", IN_CREATE | IN_ONESHOT, Inode::default());
        assert_eq!(inst.notify(b"/dir", b"a", IN_CREATE, 0), 1);
        assert_eq!(inst.notify(b"/dir", b"b", IN_CREATE, 0), 0);
    }

    #[test]
    fn a_buffer_too_small_for_the_first_event_is_einval() {
        let mut inst = Instance::new();
        inst.add_watch(b"/dir", IN_CREATE, Inode::default());
        inst.notify(b"/dir", b"name", IN_CREATE, 0);
        assert_eq!(inst.read_into(8), Err(EINVAL));
        // Not zero: zero from a read means end of file, and this never ends.
        assert!(inst.read_into(32).unwrap().len() == 32);
    }

    #[test]
    fn a_read_returns_whole_records_only() {
        let mut inst = Instance::new();
        inst.add_watch(b"/dir", IN_CREATE, Inode::default());
        inst.notify(b"/dir", b"a", IN_CREATE, 0);
        inst.notify(b"/dir", b"b", IN_CREATE, 0);
        // Room for one and a bit.
        let buf = inst.read_into(40).unwrap();
        assert_eq!(buf.len(), 32, "one whole record, not one and a fragment");
        assert!(inst.has_events(), "the other is still queued");
        assert_eq!(read_all(&mut inst).len(), 32);
    }

    #[test]
    fn an_empty_queue_reads_nothing() {
        let mut inst = Instance::new();
        assert!(inst.read_into(4096).unwrap().is_empty());
        assert!(!inst.has_events());
    }

    #[test]
    fn a_repeated_event_is_coalesced() {
        let mut inst = Instance::new();
        inst.add_watch(b"/dir", IN_MODIFY, Inode::default());
        for _ in 0..100 {
            inst.notify(b"/dir", b"f", IN_MODIFY, 0);
        }
        assert_eq!(read_all(&mut inst).len(), 32, "one record, not a hundred");
    }

    /// A guest that stops reading must not be able to grow this without bound.
    #[test]
    fn a_full_queue_overflows_once() {
        let mut inst = Instance::new();
        inst.add_watch(b"/dir", IN_CREATE, Inode::default());
        for i in 0..MAX_QUEUED + 100 {
            inst.notify(b"/dir", format!("f{i}").as_bytes(), IN_CREATE, 0);
        }
        assert_eq!(inst.queue.len(), MAX_QUEUED + 1, "the cap plus one marker");
        let last = inst.queue.last().unwrap();
        assert_eq!(last.mask, IN_Q_OVERFLOW);
        assert_eq!(last.wd, -1);
    }

    #[test]
    fn is_watching_covers_a_directory_and_what_is_under_it() {
        let mut inst = Instance::new();
        inst.add_watch(b"/a/b", IN_CREATE, Inode::default());
        assert!(inst.is_watching(b"/a/b"));
        assert!(inst.is_watching(b"/a/b/c"));
        assert!(!inst.is_watching(b"/a"));
        assert!(!inst.is_watching(b"/a/bc"), "a prefix is not a parent");
    }
}
