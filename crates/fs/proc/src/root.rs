//! `/proc` itself: the files at the top level, and `/proc/net`.
//!
//! These were `fs/proc/root.c` and `fs/proc/net.c`. The tables and callbacks
//! are Rust `static`s with the same shared `proc_dir_entry` ABI.
//!
//! The show callbacks build a `String` and append it once, rather than calling
//! a variadic `proc_printf` per field. `proc_printf` truncates at 4096 bytes
//! per call, which no line here reaches, but the buffer it truncates into is
//! also a 4 KB stack array per call and the formatting is unchecked.

use std::os::raw::{c_char, c_int};

use kernel_pids::PidsGuard;

use crate::ffi;

#[path = "mounts.rs"]
mod mounts;
#[path = "system.rs"]
mod system;
#[cfg(test)]
pub(crate) use mounts::{MountRow, escaped, mountinfo, options, parent_of};
pub(crate) use mounts::{proc_mountinfo_show, proc_mounts_show};
#[cfg(test)]
use system::load_average;
pub use system::{registered_name_hook_installed, set_registered_name_hook};
use system::{
    show_cpuinfo, show_filesystems, show_loadavg, show_meminfo, show_stat, show_uptime,
    show_version,
};

/// Append a formatted chunk to the buffer a `show` callback fills.
pub(crate) fn out(buf: &mut ffi::proc_data, text: &str) {
    buf.append(text.as_bytes())
}

// ---------------------------------------------------------------------------
// /proc/self and /proc/mounts
// ---------------------------------------------------------------------------

fn readlink_self(_e: &mut ffi::proc_entry, buf: &mut [u8]) -> c_int {
    // No trailing slash: on Linux /proc/self points at the bare pid, and a
    // program that reads the link to find its own pid gets "2/" out of one
    // that has one. Path resolution never needed it — a separator goes in
    // between the expanded target and the rest of the path anyway.
    let pid = taskview::current_pid();
    ffi::fill_path(buf, format!("{pid}").as_bytes())
}

/// `/proc/devices`: which driver is at which major number.
///
/// `mknod` helpers and `lsblk` read it, and a guest is root in its own kernel
/// so it can make a device node -- what it cannot do is guess the number. The
/// list is the one `crates/fs/devices` dispatches on; there are no block
/// devices at all, and the heading is still printed, because a parser that
/// splits on it expects both.
pub(crate) fn show_devices(_e: &mut ffi::proc_entry, buf: &mut ffi::proc_data) -> c_int {
    let mut s = String::from("Character devices:\n");
    for (major, name) in [
        (ffi::MEM_MAJOR, "mem"),
        (ffi::TTY_CONSOLE_MAJOR, "tty"),
        (ffi::TTY_ALTERNATE_MAJOR, "/dev/tty"),
        (ffi::TTY_PSEUDO_MASTER_MAJOR, "ptm"),
        (ffi::TTY_PSEUDO_SLAVE_MAJOR, "pts"),
        (ffi::DYN_DEV_MAJOR, "dyn"),
    ] {
        s += &format!("{major:3} {name}\n");
    }
    s += "\nBlock devices:\n";
    out(buf, &s);
    0
}

// ---------------------------------------------------------------------------
// /proc/net
// ---------------------------------------------------------------------------

fn show_net_dev(_e: &mut ffi::proc_entry, buf: &mut ffi::proc_data) -> c_int {
    out(
        buf,
        "Inter-|   Receive                                                |  Transmit\n\
         \x20face |bytes    packets errs drop fifo frame compressed multicast|bytes    \
         packets errs drop fifo colls carrier compressed\n\
         \x20   lo:       0       0    0    0    0     0          0         0        \
         0       0    0    0    0     0       0          0\n\
         \x20 eth0:       0       0    0    0    0     0          0         0        \
         0       0    0    0    0     0       0          0\n",
    );
    0
}

// ---------------------------------------------------------------------------
// The tables
// ---------------------------------------------------------------------------

/// A table of `proc_dir_entry` is shared and never written after startup —
/// which is a property this crate maintains and the C did not.
///
/// `Children<N>` wrapped a `ChildrenRepr<N>` — a count and `[entry; N]` —
/// which existed because `proc_dir_entry.children` was a
/// `*mut proc_children`, and *that* was a count and a `[entry; 0]` flexible
/// array member no Rust table could build. Two renderings of one thing, an
/// offset assertion pinning them together, and a cast at every table. The
/// field is a slice since 2026-09-14, so this is the array and nothing else.
#[repr(transparent)]
pub struct Children<const N: usize>(pub [ffi::proc_dir_entry; N]);

impl<const N: usize> Children<N> {
    /// What the field holds: the entries, with their length.
    pub const fn as_slice(&'static self) -> &'static [ffi::proc_dir_entry] {
        &self.0
    }
}

#[repr(transparent)]
pub struct Entry(pub ffi::proc_dir_entry);

pub(crate) const fn blank() -> ffi::proc_dir_entry {
    // Every field named, so an operation added to proc_dir_entry breaks this
    // build rather than leaving a silent null in fifteen tables.
    ffi::proc_dir_entry {
        name: None,
        mode: 0,
        getname: None,
        show: None,
        update: None,
        pread: None,
        pwrite: None,
        readlink: None,
        magic: None,
        jumps: false,
        unlink: None,
        children: None,
        readdir: None,
        inode: 0,
        guard: None,
        own_group_passes: false,
        links: ffi::Links::Subdirs,
        process_only: false,
        in_thread_dir: false,
    }
}

pub(crate) type ShowFn = Option<fn(&mut ffi::proc_entry, &mut ffi::proc_data) -> c_int>;

const fn file(name: &'static std::ffi::CStr, show: ShowFn) -> ffi::proc_dir_entry {
    ffi::proc_dir_entry {
        name: Some(name),
        show,
        ..blank()
    }
}

/// In alphabetical order, which is the order readdir reports them in.
///
/// `dev` was the only one until 2026-09-07, and `netstat -an` in a guest
/// answered `netstat: /proc/net/tcp: No such file or directory` -- every tool
/// that lists connections reads the other five.
#[unsafe(no_mangle)]
pub static proc_net_children: Children<10> = Children([
        file(c"arp", crate::net::SHOWS[8].1),
        file(c"dev", Some(show_net_dev)),
        file(c"raw", crate::net::SHOWS[5].1),
        file(c"raw6", crate::net::SHOWS[6].1),
        file(c"route", crate::net::SHOWS[7].1),
        file(c"tcp", crate::net::SHOWS[0].1),
        file(c"tcp6", crate::net::SHOWS[1].1),
        file(c"udp", crate::net::SHOWS[2].1),
        file(c"udp6", crate::net::SHOWS[3].1),
        file(c"unix", crate::net::SHOWS[4].1),
    ]);

const ROOT_LEN: usize = 14;
static ROOT_ENTRIES: Children<ROOT_LEN> = Children([
        file(c"cpuinfo", Some(show_cpuinfo)),
        file(c"devices", Some(show_devices)),
        file(c"filesystems", Some(show_filesystems)),
        ffi::proc_dir_entry {
            name: Some(c"iul"),
            mode: libc::S_IFDIR,
            children: Some(crate::iul::proc_iul_children.as_slice()),
            ..blank()
        },
        file(c"loadavg", Some(show_loadavg)),
        file(c"meminfo", Some(show_meminfo)),
        file(c"mountinfo", Some(proc_mountinfo_show)),
        file(c"mounts", Some(proc_mounts_show)),
        ffi::proc_dir_entry {
            name: Some(c"net"),
            mode: libc::S_IFDIR,
            children: Some(proc_net_children.as_slice()),
            ..blank()
        },
        ffi::proc_dir_entry {
            name: Some(c"self"),
            mode: libc::S_IFLNK,
            readlink: Some(readlink_self),
            ..blank()
        },
        file(c"stat", Some(show_stat)),
        crate::sysctl::entry(),
        file(c"uptime", Some(show_uptime)),
        file(c"version", Some(show_version)),
    ]);

/// Walk `/proc`: the fixed entries first, then one directory per process --
/// every thread-group leader, zombies included, and not the threads, which
/// are under their process's `task`.
fn root_readdir(
    _entry: &mut ffi::proc_entry,
    index: &mut u64,
) -> Option<ffi::proc_entry> {
    let i = *index;
    if let Some(fixed) = ROOT_ENTRIES.0.get(i as usize) {
        *index = i + 1;
        return Some(ffi::proc_entry {
            meta: Some(fixed),
            index: i,
            ..ffi::proc_entry::default()
        });
    }
    // The index past the fixed entries is the last pid reported, so the
    // whole scan costs one pass over the pid space rather than one per
    // entry — and one lock hold per step rather than one per empty slot.
    let after = (i as usize - ROOT_LEN) as c_int;
    let pid = taskcalls::task_next_listed_pid(after);
    if pid == 0 {
        return None;
    }
    *index = pid as u64 + ROOT_LEN as u64;
    // `proc_pid` is this crate's own static now; it was an `extern` in
    // fs/proc/pid.c until that file went.
    Some(ffi::proc_entry {
        meta: Some(&crate::pidentry::proc_pid.0),
        pid,
        ..ffi::proc_entry::default()
    })
}

#[unsafe(no_mangle)]
pub static proc_root: Entry = Entry(ffi::proc_dir_entry {
    mode: libc::S_IFDIR,
    readdir: Some(root_readdir),
    links: ffi::Links::One,
    ..blank()
});

/// A `/proc/<n>` the listing does not show: a thread's, named by its tid.
///
/// `/proc` lists processes, and a thread is reached through its process's
/// `task` -- but Linux's `proc_pid_lookup` finds *any* task by number, so
/// `/proc/<tid>/status` answers for a thread named directly, which is how
/// `gdb`, `perf` and a runtime reading its own threads' stacks reach one.
/// This kernel's lookup walks a directory's listing, so what the listing
/// hides it could not find; this is the fall-through for the root.
///
/// Answers only for the root directory, only for a name that is a pid as
/// Linux's `name_to_int` reads one -- digits, no leading zero, non-zero --
/// and only for a task that is there, zombie included.
pub(crate) fn lookup_hidden_pid(dir: &ffi::proc_entry, name: &[u8]) -> Option<ffi::proc_entry> {
    if !dir.meta.is_some_and(|m| std::ptr::eq(m, &proc_root.0)) {
        return None;
    }
    let pid = pid_from_name(name)?;
    // A zombie counts, as it does in the listing.
    PidsGuard::take().find(pid)?;
    Some(ffi::proc_entry {
        meta: Some(&crate::pidentry::proc_pid.0),
        pid,
        ..ffi::proc_entry::default()
    })
}

/// Linux's `name_to_int`: decimal digits, no leading zero, and a value that
/// fits -- and then `proc_pid_lookup`'s refusal of zero.
fn pid_from_name(name: &[u8]) -> Option<c_int> {
    if name.is_empty() || name.len() > 10 || !name.iter().all(u8::is_ascii_digit) {
        return None;
    }
    if name.len() > 1 && name[0] == b'0' {
        return None;
    }
    let n: i64 = std::str::from_utf8(name).ok()?.parse().ok()?;
    (n > 0 && n <= c_int::MAX as i64).then_some(n as c_int)
}

#[cfg(test)]
mod mountinfo_tests {
    use super::*;

    fn row(id: u32, point: &str, source: &str, fstype: &str, flags: u32, dev: u32) -> MountRow {
        MountRow {
            id,
            point: point.as_bytes().to_vec(),
            source: source.as_bytes().to_vec(),
            fstype: fstype.as_bytes().to_vec(),
            flags,
            dev,
        }
    }

    fn table() -> Vec<MountRow> {
        vec![
            row(1, "/", "/host/root", "real", 0, 0x0110),
            row(2, "/dev", "/host/dev", "fake", 0, 0x0110),
            row(3, "/dev/pts", "devpts", "devpts", 0, 0),
            row(
                4,
                "/proc",
                "proc",
                "proc",
                ffi::MS_READONLY_ | ffi::MS_NOSUID_,
                0,
            ),
            // A name that shares a prefix with /dev without being under it.
            row(5, "/devices", "x", "real", 0, 0),
        ]
    }

    /// The tree, which is the whole reason a caller reads `mountinfo` rather
    /// than `/proc/mounts`: `/dev/pts` is under `/dev` and `/devices` is not,
    /// though it starts with the same five bytes.
    #[test]
    fn a_parent_is_the_longest_prefix_on_a_component_boundary() {
        let t = table();
        assert_eq!(parent_of(b"/dev/pts", &t), Some(2));
        assert_eq!(parent_of(b"/devices", &t), Some(1));
        assert_eq!(parent_of(b"/dev", &t), Some(1));
        assert_eq!(parent_of(b"/proc", &t), Some(1));
        // The root has no parent; the caller reports it as its own.
        assert_eq!(parent_of(b"/", &t), None);
    }

    /// Ten fields, the `-` between the optional ones and the type, and the
    /// options printed twice -- once for the mount and once for the super
    /// block, which is what every parser splits on.
    #[test]
    fn a_line_has_the_fields_a_parser_expects() {
        let text = mountinfo(&table());
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 5);
        for l in &lines {
            let f: Vec<&str> = l.split_whitespace().collect();
            assert_eq!(f.len(), 10, "{l}");
            assert_eq!(f[6], "-", "{l}");
            assert_eq!(f[3], "/", "the subtree mounted is always the whole one");
            assert_eq!(f[5], f[9], "the two option lists are the same here");
        }
        assert!(
            lines[0].starts_with("1 1 1:16 / / rw - real /host/root rw"),
            "{}",
            lines[0]
        );
        assert!(
            lines[2].starts_with("3 2 0:0 / /dev/pts rw - devpts devpts rw"),
            "{}",
            lines[2]
        );
        assert!(lines[3].contains("ro,nosuid"), "{}", lines[3]);
    }

    /// A mount point with a space in it is escaped, because the format is
    /// space-separated and a parser would otherwise read one line as eleven
    /// fields.
    #[test]
    fn a_space_in_a_mount_point_is_escaped() {
        let t = vec![row(1, "/mnt/two words", "src", "real", 0, 0)];
        let line = mountinfo(&t);
        assert!(line.contains("two\\040words"), "{line}");
        assert_eq!(line.split_whitespace().count(), 10);
    }

    /// The options are Linux's names in Linux's order.
    #[test]
    fn the_options_are_the_mounts_own() {
        assert_eq!(options(0), "rw");
        assert_eq!(options(ffi::MS_READONLY_), "ro");
        assert_eq!(
            options(ffi::MS_READONLY_ | ffi::MS_NOSUID_ | ffi::MS_NODEV_ | ffi::MS_NOEXEC_),
            "ro,nosuid,nodev,noexec"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The load average's fixed point, which is Linux's and not a float.
    ///
    /// `SI_LOAD_SHIFT` is 16, so 65536 is 1.00 — and the interesting cases are
    /// the ones a float would round differently: the kernel adds `FIXED_1/200`
    /// before truncating, so 1.005 prints as `1.00` rather than `1.01`.
    #[test]
    fn a_load_average_prints_the_way_linux_prints_it() {
        assert_eq!(load_average(0), "0.00");
        assert_eq!(load_average(65536), "1.00");
        assert_eq!(load_average(65536 * 5 + 65536 / 100), "5.01");
        assert_eq!(load_average(65536 / 2), "0.50");
        assert_eq!(load_average(65536 / 100), "0.01");
        // 5.06, the figure the host reported while this file said 0.00.
        assert_eq!(load_average(331776), "5.06");
        // Two digits either side of the point, always: a reader parses the
        // fraction as hundredths, so `0.7` would be read as 0.70.
        assert_eq!(load_average(65536 * 3 + 65536 * 7 / 100), "3.07");
        assert_eq!(load_average(65536 * 100), "100.00");
    }

    /// What a guest is told about memory, and that the two files agree.
    ///
    /// `MemFree` used to be the *host's* free memory capped to the same 4 GB
    /// the total is capped to, so on any machine with more than 4 GB free it
    /// was exactly `MemTotal` and nothing was ever in use.
    #[test]
    fn the_free_memory_is_the_guests_own_use() {
        use kernel_hoststats::{GUEST_MAX_RAM, guest_free_ram};
        let total = GUEST_MAX_RAM;
        assert_eq!(guest_free_ram(total, 0), total, "nothing allocated");
        assert_eq!(guest_free_ram(total, 1), total - 4096);
        assert_eq!(guest_free_ram(total, -1), total / 2, "no accounting");
        // More accounted than there is: saturating, not nearly 2^64 free.
        assert_eq!(guest_free_ram(4096, 100), 0);
        assert_eq!(guest_free_ram(4096, i64::MAX), 0);
        // And the cap itself, whatever the machine has.
        assert_eq!(GUEST_MAX_RAM, 4 << 30);
    }

    /// A name is a pid the way `name_to_int` reads one, and nothing else.
    #[test]
    fn a_hidden_name_is_a_pid_only_when_linux_would_read_it_as_one() {
        assert_eq!(pid_from_name(b"1"), Some(1));
        assert_eq!(pid_from_name(b"32768"), Some(32768));
        assert_eq!(pid_from_name(b"0"), None, "pid 0 is nobody");
        assert_eq!(pid_from_name(b"01"), None, "a leading zero is not a number");
        assert_eq!(pid_from_name(b""), None);
        assert_eq!(pid_from_name(b"-1"), None);
        assert_eq!(pid_from_name(b"+1"), None);
        assert_eq!(pid_from_name(b"1a"), None);
        assert_eq!(pid_from_name(b"self"), None);
        assert_eq!(pid_from_name(b"99999999999"), None, "does not fit");
    }

    /// Only the root falls through to a pid; `/proc/<pid>/fd/<n>` for a
    /// closed descriptor is still ENOENT.
    #[test]
    fn only_the_root_looks_a_hidden_pid_up() {
        let not_root = ffi::proc_entry {
            meta: Some(&crate::pidentry::proc_pid.0),
            ..ffi::proc_entry::default()
        };
        assert!(lookup_hidden_pid(&not_root, b"1").is_none());
        // The root asks the pid table, which the stub answers empty.
        let root = ffi::proc_entry {
            meta: Some(&proc_root.0),
            ..ffi::proc_entry::default()
        };
        assert!(lookup_hidden_pid(&root, b"1").is_none());
        assert!(lookup_hidden_pid(&root, b"self").is_none());
    }

    /* Three `#[no_mangle]` doubles were here — `mounts_at`, `mount_point_of`
     * and `mount_refcount_of` — with a comment saying `show_mounts` reaches
     * them and `show_mounts` is in `ROOT_ENTRIES`, which a test below reads, so
     * the linker cannot drop them.
     *
     * The reaching is a Rust call now: `crates/fs/mounttable` is a dependency
     * and none of the three is an exported symbol, so all three defined a name
     * nothing referenced. The tests pass against the real functions, which
     * answer the same empty table — nothing here mounts anything. */

    #[test]
    fn the_mounts_format_escapes_its_own_separators() {
        // A mount point with a space in it would otherwise split a field, and
        // a reader would take the tail for the filesystem type.
        assert_eq!(escaped(b"/mnt/my disk"), "/mnt/my\\040disk");
        assert_eq!(escaped(b"/a\tb"), "/a\\011b");
        assert_eq!(escaped(b"/a\\b"), "/a\\134b");
        assert_eq!(escaped(b"/plain/path"), "/plain/path");
    }

    #[test]
    fn the_root_table_is_in_alphabetical_order() {
        // readdir reports them in table order, and a reader that bisects a
        // sorted listing gets the wrong answer from an unsorted one.
        let names: Vec<&str> = ROOT_ENTRIES
            .0
            .iter()
            .map(|e| {
                e.name.unwrap_or(c"")
                    .to_str()
                    .unwrap()
            })
            .collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
    }

    #[test]
    fn every_root_entry_can_answer_something() {
        // A table entry with no show, no readlink and no children is a file
        // that reads as an error however it is opened.
        for e in &ROOT_ENTRIES.0 {
            assert!(
                e.show.is_some() || e.readlink.is_some() || e.children.is_some(),
                "{:?} answers nothing",
                e.name.unwrap_or(c"")
            );
        }
    }

    // `the_children_layout_matches_the_c_struct` was here until 2026-09-14. It
    // asserted that `ChildrenRepr<N>` and `struct proc_children` put `count`
    // and `entries` at the same offsets, and that each table's `count` matched
    // the length of its array -- both of which are questions about two
    // renderings of one thing. The field is a slice, so there is no second
    // rendering and no count to disagree with a length. Same ending as the
    // test that compared `kernel_epoll::Ops`'s two renderings when that table
    // became a trait.
}

/* `mod c_stubs` was here until 2026-09-09: eleven `#[no_mangle]` definitions —
 * `mounts`, `mounts_lock`, `mount_id_of`, `sync_lock`, `sync_unlock`,
 * `get_cpu_usage`, `get_mem_usage`, `get_uptime` among them — with a comment
 * saying the test binary "needs every name resolved whether it calls it or
 * not", because a `static` table holding a pointer to a C `static` is a
 * link-time root.
 *
 * That was true while those were C symbols. Not one of them is an exported
 * symbol now: `crates/fs/mounttable` owns the mount list, `crates/util/locks`
 * owns the lock, and the three `get_*_usage` are Rust functions this crate
 * calls by path. So the module defined eleven symbols nothing referenced —
 * links, never runs, and says the tests substitute something they do not.
 *
 * `tools/dead-stubs.py` is the check that finds the next one. */
