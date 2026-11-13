//! `/proc/sys`: the knobs a program reads to find out what the kernel will let
//! it do.
//!
//! There was no `/proc/sys` at all, and the effect is not "a file is missing"
//! — it is that a program asking a question gets no answer and takes whatever
//! path it has for a kernel that cannot be asked. `libcap-ng` opens
//! `kernel/cap_last_cap` before it does anything (that `ENOENT` is in the trace
//! that found the signalfd defect); anything calling `F_SETPIPE_SZ` reads
//! `fs/pipe-max-size` to know what to ask for; every file watcher reads
//! `fs/inotify/max_user_watches` and warns the user when it is small; Redis and
//! PostgreSQL read `vm/overcommit_memory` and print a paragraph about it.
//!
//! # Only what this kernel decides
//!
//! Every file here reports a number this kernel actually enforces, taken from
//! the crate that enforces it — `CAP_LAST_CAP` from `crates/kernel/creds`,
//! the pipe ceiling from `crates/fs/pipe`, the inotify queue bound from
//! `crates/fs/inotify`. A knob whose value would be invented is **not here**,
//! because a missing file is what a kernel without that knob looks like and an
//! invented one is a promise. That is the same rule the `AT_RSEQ_*` keys in
//! `crates/kernel/initstack` are named for.
//!
//! # Read-only, but for what this kernel acts on
//!
//! A file is writable only when the value written changes what this kernel
//! does -- `fs/suid_dumpable`, which credential changes and `execve` read.
//! Everything else is `0444`, so a write is `EACCES`, which is what a
//! container gets because Docker mounts `/proc/sys` read-only. A kernel that
//! accepted the write and ignored it would be telling a program it had changed
//! something.

use std::ffi::c_int;

use crate::ffi;
use crate::root::{blank, out};
use guest_errno::c_int_::EINVAL;

/// A file whose whole content is one line.
macro_rules! show {
    ($name:ident, $body:expr) => {
        fn $name(_e: &mut ffi::proc_entry, buf: &mut ffi::proc_data) -> c_int {
            let text: String = $body;
            out(buf, &text);
            0
        }
    };
}

// ------------------------------------------------------------------ kernel

show!(
    show_cap_last_cap,
    format!("{}\n", kernel_creds::caps::CAP_LAST_CAP)
);
show!(show_ngroups_max, format!("{}\n", kernel_creds::MAX_GROUPS));
show!(show_pid_max, format!("{}\n", ffi::MAX_PID));
show!(show_ostype, "Linux\n".into());
show!(show_osrelease, format!("{}\n", uts_field(|u| &u.release)));
show!(
    show_kernel_version,
    format!("{}\n", uts_field(|u| &u.version))
);
show!(show_hostname, format!("{}\n", uts_field(|u| &u.hostname)));
show!(show_domainname, format!("{}\n", uts_field(|u| &u.domain)));
show!(show_boot_id, format!("{}\n", boot_id()));
show!(show_uuid, format!("{}\n", uuid()));

// ---------------------------------------------------------------------- fs

show!(show_pipe_max_size, format!("{}\n", fs_pipe::MAX_CAPACITY));
// The AIO budget `io_setup` enforces, and what the live contexts hold of it.
show!(show_aio_max_nr, format!("{}\n", aio::aio_max_nr()));
show!(show_aio_nr, format!("{}\n", aio::aio_nr()));
show!(show_max_queued_events, format!("{}\n", inotify::MAX_QUEUED));

// `fs/mqueue`: the limits `crates/kernel/mqueue` judges an `mq_open` by.
show!(show_mq_msg_default, format!("{}\n", kernel_mqueue::abi::MSG_DEFAULT));
show!(show_mq_msg_max, format!("{}\n", kernel_mqueue::abi::MSG_MAX));
show!(show_mq_msgsize_default, format!("{}\n", kernel_mqueue::abi::MSGSIZE_DEFAULT));
show!(show_mq_msgsize_max, format!("{}\n", kernel_mqueue::abi::MSGSIZE_MAX));
show!(show_mq_queues_max, format!("{}\n", kernel_mqueue::abi::QUEUES_MAX));

show!(show_suid_dumpable, format!("{}\n", kernel_procattr::suid_dumpable()));

/// `fs.suid_dumpable`: Linux's `proc_dointvec_minmax_coredump`, 0 to 2.
fn write_suid_dumpable(_e: &mut ffi::proc_entry, buf: &[u8], off: libc::off_t) -> isize {
    write_int(buf, off, kernel_procattr::set_suid_dumpable)
}

/// One integer written to a sysctl, as `proc_dointvec_minmax` takes it: the
/// bytes consumed, or the errno. A write at a non-zero offset consumes
/// nothing, which is Linux's `sysctl_writes_strict` default.
fn write_int(buf: &[u8], off: libc::off_t, set: fn(i64) -> Result<(), c_int>) -> isize {
    if off != 0 || buf.is_empty() {
        return 0;
    }
    match parse_int(buf).and_then(|(v, used)| set(v).map(|()| used)) {
        Ok(used) => used as isize,
        Err(e) => e as isize,
    }
}

/// Linux's `proc_get_long` and the whitespace on either side of it: one
/// integer in C's base-0 notation, optionally negative, which must be followed
/// by a space, a tab, a newline or the end. Answers the value and how much of
/// `buf` that took, trailing whitespace included -- `"2 1"` takes two bytes
/// and sets 2, measured with `suiddump_probe`.
fn parse_int(buf: &[u8]) -> Result<(i64, usize), c_int> {
    // `isspace`, which is what `proc_skip_spaces` asks.
    let space = |b: u8| matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r');
    let skip = |at: usize| at + buf[at..].iter().take_while(|&&b| space(b)).count();
    let mut at = skip(0);
    // Linux copies at most 21 bytes of the number out first; a number that
    // fills them is refused, since what follows cannot be seen.
    const TMPBUFLEN: usize = 22;
    let end = buf.len().min(at + TMPBUFLEN - 1);
    let neg = buf.get(at) == Some(&b'-') && end - at > 1;
    let start = at;
    if neg {
        at += 1;
    }
    if !buf.get(at).is_some_and(u8::is_ascii_digit) {
        return Err(EINVAL);
    }
    let (radix, digits_at) = match &buf[at..end] {
        [b'0', b'x' | b'X', d, ..] if d.is_ascii_hexdigit() => (16, at + 2),
        [b'0', ..] => (8, at),
        _ => (10, at),
    };
    let mut value: u64 = 0;
    at = digits_at;
    while at < end {
        let Some(d) = (buf[at] as char).to_digit(radix) else { break };
        value = value.checked_mul(u64::from(radix)).and_then(|v| v.checked_add(u64::from(d))).ok_or(EINVAL)?;
        at += 1;
    }
    if at - start == TMPBUFLEN - 1 {
        return Err(EINVAL);
    }
    if at < buf.len() && !matches!(buf[at], b' ' | b'\t' | b'\n') {
        return Err(EINVAL);
    }
    // `do_proc_dointvec_conv`: the magnitude has to fit an `int`.
    let value = if neg {
        if value > i32::MAX as u64 + 1 {
            return Err(EINVAL);
        }
        -(value as i64)
    } else {
        if value > i32::MAX as u64 {
            return Err(EINVAL);
        }
        value as i64
    };
    Ok((value, skip(at)))
}

// ---------------------------------------------------------------------- vm

// 0 is Linux's default: "heuristic overcommit". This kernel hands out
// anonymous memory against a budget and refuses past it, which is the same
// answer to the question the number is asked for -- does an allocation that
// cannot be backed fail at `mmap` or at first touch. It fails at `mmap`.
show!(show_overcommit_memory, "0\n".into());

/// The one `uname` field a sysctl reports, as a `String`. Asking `uname` is
/// what keeps this in step with the syscall: two copies of a version string is
/// the shape this tree keeps finding defects in.
fn uts_field(pick: impl Fn(&ffi::uname) -> &[libc::c_char]) -> String {
    let uts = unamecalls::uname();
    let field = plain::slice_bytes(pick(&uts));
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// One per boot, as Linux's is: a program uses it to tell one boot of the same
/// machine from another, so it must not change between two reads.
fn boot_id() -> &'static str {
    static ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ID.get_or_init(uuid)
}

/// A random version-4 UUID. `kernel/random/uuid` gives a fresh one per read,
/// which is what a program asking for one expects.
fn uuid() -> String {
    let mut b = [0u8; 16];
    kernel_random::fill(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 1
    let h = |r: &[u8]| -> String { r.iter().map(|x| format!("{x:02x}")).collect() };
    format!(
        "{}-{}-{}-{}-{}",
        h(&b[0..4]),
        h(&b[4..6]),
        h(&b[6..8]),
        h(&b[8..10]),
        h(&b[10..16])
    )
}

type ShowFn = Option<fn(&mut ffi::proc_entry, &mut ffi::proc_data) -> c_int>;

/// A read-only file. 0444: `mode` here is the permission part, and the VFS
/// adds `S_IFREG` for an entry with no type bits.
const fn ro(name: &'static std::ffi::CStr, show: ShowFn) -> ffi::proc_dir_entry {
    ffi::proc_dir_entry {
        name: Some(name),
        mode: 0o444,
        show,
        ..blank()
    }
}

const fn dir(
    name: &'static std::ffi::CStr,
    children: &'static [ffi::proc_dir_entry],
) -> ffi::proc_dir_entry {
    ffi::proc_dir_entry {
        name: Some(name),
        mode: libc::S_IFDIR | 0o555,
        children: Some(children),
        // Linux's sysctl directories report one link, `/proc/sys` included.
        links: ffi::Links::One,
        ..blank()
    }
}

// `entropy_avail` and `poolsize` have been the constant 256 since Linux
// 5.18, which is when the input pool stopped being a count that could run
// low: what they say now is "the generator is seeded", and a guest's
// `getrandom` reads the host's, which always is. Programs that wait for
// entropy at boot (haveged's scripts, some init systems) read the first.
show!(show_entropy_avail, "256\n".into());
show!(show_poolsize, "256\n".into());

const RANDOM_LEN: usize = 4;
static RANDOM: Entry2<RANDOM_LEN> = Entry2([
        ro(c"boot_id", Some(show_boot_id)),
        ro(c"entropy_avail", Some(show_entropy_avail)),
        ro(c"poolsize", Some(show_poolsize)),
        ro(c"uuid", Some(show_uuid)),
    ]);

// What `seccomp(SECCOMP_GET_ACTION_AVAIL)` answers yes to, as libseccomp reads
// it. `actions_logged` is not here: nothing is logged.
show!(show_seccomp_actions_avail, format!("{}\n", kernel_seccomp::ACTIONS_AVAIL));

const SECCOMP_LEN: usize = 1;
static SECCOMP: Entry2<SECCOMP_LEN> =
    Entry2([ro(c"actions_avail", Some(show_seccomp_actions_avail))]);

const KERNEL_LEN: usize = 10;
// Alphabetical, which is the order readdir reports.
static KERNEL: Entry2<KERNEL_LEN> = Entry2([
        ro(c"cap_last_cap", Some(show_cap_last_cap)),
        ro(c"domainname", Some(show_domainname)),
        ro(c"hostname", Some(show_hostname)),
        ro(c"ngroups_max", Some(show_ngroups_max)),
        ro(c"osrelease", Some(show_osrelease)),
        ro(c"ostype", Some(show_ostype)),
        ro(c"pid_max", Some(show_pid_max)),
        dir(c"random", RANDOM.as_slice()),
        dir(c"seccomp", SECCOMP.as_slice()),
        ro(c"version", Some(show_kernel_version)),
    ]);

const INOTIFY_LEN: usize = 1;
static INOTIFY: Entry2<INOTIFY_LEN> =
    Entry2([ro(c"max_queued_events", Some(show_max_queued_events))]);

const MQUEUE_LEN: usize = 5;
static MQUEUE: Entry2<MQUEUE_LEN> = Entry2([
        ro(c"msg_default", Some(show_mq_msg_default)),
        ro(c"msg_max", Some(show_mq_msg_max)),
        ro(c"msgsize_default", Some(show_mq_msgsize_default)),
        ro(c"msgsize_max", Some(show_mq_msgsize_max)),
        ro(c"queues_max", Some(show_mq_queues_max)),
    ]);

const FS_LEN: usize = 6;
static FS: Entry2<FS_LEN> = Entry2([
        ro(c"aio-max-nr", Some(show_aio_max_nr)),
        ro(c"aio-nr", Some(show_aio_nr)),
        dir(c"inotify", INOTIFY.as_slice()),
        dir(c"mqueue", MQUEUE.as_slice()),
        ro(c"pipe-max-size", Some(show_pipe_max_size)),
        ffi::proc_dir_entry {
            mode: 0o644,
            pwrite: Some(write_suid_dumpable),
            ..ro(c"suid_dumpable", Some(show_suid_dumpable))
        },
    ]);

const VM_LEN: usize = 1;
static VM: Entry2<VM_LEN> = Entry2([ro(c"overcommit_memory", Some(show_overcommit_memory))]);

const SYS_LEN: usize = 3;
static SYS: Entry2<SYS_LEN> = Entry2([
        dir(c"fs", FS.as_slice()),
        dir(c"kernel", KERNEL.as_slice()),
        dir(c"vm", VM.as_slice()),
    ]);

/// The `/proc/sys` entry, for the root table. `const`, because the root table
/// is a static.
pub(crate) const fn entry() -> ffi::proc_dir_entry {
    dir(c"sys", SYS.as_slice())
}

/// The same wrapper `crates/fs/proc`'s root uses: the entries, and `Sync`
/// because a `proc_dir_entry` holds a `*const c_char` name.
#[repr(transparent)]
pub struct Entry2<const N: usize>(pub [ffi::proc_dir_entry; N]);

impl<const N: usize> Entry2<N> {
    const fn as_slice(&'static self) -> &'static [ffi::proc_dir_entry] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A UUID is 36 characters in the shape a program parses, and two of them
    /// differ. The second is what says the randomness is read per call rather
    /// than once.
    #[test]
    fn a_uuid_has_the_shape_and_is_not_a_constant() {
        let a = uuid();
        assert_eq!(a.len(), 36);
        let dashes: Vec<usize> = a.match_indices('-').map(|(i, _)| i).collect();
        assert_eq!(dashes, vec![8, 13, 18, 23]);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
        // Version 4, variant 1: the two nibbles a parser checks.
        assert_eq!(a.as_bytes()[14], b'4');
        assert!(matches!(a.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
        assert_ne!(a, uuid());
    }

    /// `proc_dointvec`'s reading of a write, case for case as
    /// `suiddump_probe` measured it: what is consumed, and what is refused.
    #[test]
    fn a_written_integer_is_read_as_linux_reads_it() {
        let ok = |s: &str| parse_int(s.as_bytes());
        assert_eq!(ok("2 1"), Ok((2, 2)));
        assert_eq!(ok("1\n"), Ok((1, 2)));
        assert_eq!(ok("0x1"), Ok((1, 3)));
        assert_eq!(ok(" 2"), Ok((2, 2)));
        assert_eq!(ok("010"), Ok((8, 3)), "octal");
        assert_eq!(ok("-1"), Ok((-1, 2)), "the range is the setter's");
        assert_eq!(ok("-2147483648"), Ok((i64::from(i32::MIN), 11)));
        for bad in ["abc", "+1", "2x", "08", "0x", "-", "2147483648", "   ", "99999999999999999999999"] {
            assert_eq!(ok(bad), Err(EINVAL), "{bad:?}");
        }
        let refuse = |v: i64| if v == 3 { Err(EINVAL) } else { Ok(()) };
        assert_eq!(write_int(b"3", 0, refuse), EINVAL as isize);
        assert_eq!(write_int(b"1", 4, refuse), 0, "past the start, nothing is taken");
    }

    /// The boot id is one per boot: two reads are the same string, which is
    /// the whole property a caller uses it for.
    #[test]
    fn the_boot_id_does_not_change() {
        assert_eq!(boot_id(), boot_id());
        assert_eq!(boot_id().len(), 36);
    }

    /// Every value comes from the crate that enforces it. A copy would drift,
    /// which is what this asserts rather than the numbers themselves.
    #[test]
    fn the_numbers_are_the_enforcing_crates() {
        assert_eq!(kernel_creds::caps::CAP_LAST_CAP, 40);
        assert_eq!(kernel_creds::MAX_GROUPS, 32);
        assert_eq!(fs_pipe::MAX_CAPACITY, 1024 * 1024);
        assert_eq!(inotify::MAX_QUEUED, 16384);
        assert_eq!(
            [kernel_mqueue::abi::MSG_MAX, kernel_mqueue::abi::MSGSIZE_MAX],
            [10, 8192]
        );
        assert_eq!(kernel_mqueue::abi::QUEUES_MAX, 256);
    }
}
