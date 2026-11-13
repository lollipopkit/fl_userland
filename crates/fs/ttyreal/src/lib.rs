//! The console: the one terminal that is a **host device** rather than
//! `crates/fs/tty`'s own logic.
//!
//! What is here is the host side of it — raw mode, the reader thread, and the
//! writes — and nothing about what a terminal is. Only `/dev/tty1` is
//! connected; every other minor of the console major goes to a black hole.
//!
//! # The flag table, and the six it dropped
//!
//! `initial_termios` seeds the guest's console termios from whatever mode the
//! host terminal is in when the emulator starts. The C mapped fifteen flags and
//! **silently dropped six that this kernel defines and the host has**:
//! `IXON`, `IEXTEN`, `ECHONL`, `ECHOKE`, `ECHOPRT` and `TOSTOP`.
//!
//! Two of those matter. A cooked host terminal has `IXON` (`^S`/`^Q` flow
//! control) and `IEXTEN` (`^V` literal-next, `^O` discard) on, and a guest that
//! reads its termios before setting its own was told both were off — so a
//! program that saves the termios, changes it and restores it turns them off
//! for good. That is what shells, editors and `less` all do.
//!
//! The mapping is by *name* on both sides, and there is a test asserting that
//! every flag `fs/tty.h` defines appears in it. A table with a hole in it looks
//! exactly like a complete one, which is how this survived.

//! # `as u64` on a host `libc` flag is not redundant
//!
//! `clippy::unnecessary_cast` reports every `libc::OPOST as u64` and
//! `real.c_iflag as u64` here, because `tcflag_t` *is* `u64` on this target.
//! It is `u32` on Linux, which this tree compiles on. Taking the casts off
//! makes the tables and the conversions depend on the host's `libc`, and the
//! lint sees one target. The table below carries the long version.
#![allow(clippy::unnecessary_cast)]

use std::ffi::{c_int, c_void};
use std::os::fd::AsFd;
use std::sync::{Arc, Mutex, Weak};

use fs_tty::tty::Tty;

use ldisc::Termios;
use rustix::termios::{OptionalActions, SpecialCodeIndex};
use logline::printk;

/// Only `/dev/tty1` is connected to the host.
const REAL_TTY_NUM: c_int = 1;

/// `struct winsize_`, eight bytes, and it is **`crates/fs/tty`'s**.
///
/// This crate had a second `#[repr(C)]` struct of the same four `u16` until
/// 2026-09-12 and reached the console's initial state through
/// `transmute::<Winsize, fs_tty::tty::Winsize>`. The two happened to agree, and
/// nothing could have said so if they stopped: a `transmute` between two
/// renderings of one type is the shape `CLAUDE.md` records finding four times,
/// and `clippy::useless_transmute` is silent while they are *distinct* types —
/// it only speaks once they are the same one, which is the signal that the
/// merge was the fix rather than the start of it.
///
/// The console is a terminal before it is a host device, so the terminal owns
/// the shape and the host side converts into it from `libc::winsize`.
pub use fs_tty::tty::Winsize;

// ---------------------------------------------------------------------------
// The flag and control-character tables
// ---------------------------------------------------------------------------

/// `(host, guest)` for every flag `fs/tty.h` defines that the host also has.
///
/// Paired by **name**, which is the only correspondence there is: the numeric
/// values are two conventions that happen to agree for some of the first few.
///
/// `libc::tcflag_t` is `u64` on every Apple target, which is every host this
/// builds for. There were `as u64` casts on all eighteen and an `#[allow]` with
/// an argument about Linux hosts until 2026-09-29; the tree has had none since
/// the non-Apple branches went.
mod flags {
    pub const OUT: &[(u64, u32)] = &[
        (libc::OPOST, 1 << 0),  // OPOST_
        (libc::ONLCR, 1 << 2),  // ONLCR_
        (libc::OCRNL, 1 << 3),  // OCRNL_
        (libc::ONOCR, 1 << 4),  // ONOCR_
        (libc::ONLRET, 1 << 5), // ONLRET_
    ];
    pub const IN: &[(u64, u32)] = &[
        (libc::INLCR, 1 << 6), // INLCR_
        (libc::IGNCR, 1 << 7), // IGNCR_
        (libc::ICRNL, 1 << 8), // ICRNL_
        (libc::IXON, 1 << 10), // IXON_ -- dropped by the C
    ];
    pub const LOCAL: &[(u64, u32)] = &[
        (libc::ISIG, 1 << 0),     // ISIG_
        (libc::ICANON, 1 << 1),   // ICANON_
        (libc::ECHO, 1 << 3),     // ECHO_
        (libc::ECHOE, 1 << 4),    // ECHOE_
        (libc::ECHOK, 1 << 5),    // ECHOK_
        (libc::ECHONL, 1 << 6),   // ECHONL_ -- dropped by the C
        (libc::NOFLSH, 1 << 7),   // NOFLSH_
        (libc::TOSTOP, 1 << 8),   // TOSTOP_ -- dropped by the C
        (libc::ECHOCTL, 1 << 9),  // ECHOCTL_
        (libc::ECHOPRT, 1 << 10), // ECHOPRT_ -- dropped by the C
        (libc::ECHOKE, 1 << 11),  // ECHOKE_ -- dropped by the C
        (libc::IEXTEN, 1 << 15),  // IEXTEN_ -- dropped by the C
    ];
}

/// `(host index, guest index)` for every control character in `struct
/// termios_`'s nineteen. The host side is `rustix`'s index, which is the
/// host's `V*` number under a type that can only index a host `c_cc`.
///
/// `VSWTC_` is 7 and has no host counterpart — it is Linux's and BSD does not
/// have it — so it is not in the table and stays zero, which is what "no
/// character does this" means.
const CC: &[(SpecialCodeIndex, usize)] = &[
    (SpecialCodeIndex::VINTR, 0),
    (SpecialCodeIndex::VQUIT, 1),
    (SpecialCodeIndex::VERASE, 2),
    (SpecialCodeIndex::VKILL, 3),
    (SpecialCodeIndex::VEOF, 4),
    (SpecialCodeIndex::VTIME, 5),
    (SpecialCodeIndex::VMIN, 6),
    (SpecialCodeIndex::VSTART, 8),
    (SpecialCodeIndex::VSTOP, 9),
    (SpecialCodeIndex::VSUSP, 10),
    (SpecialCodeIndex::VEOL, 11),
    (SpecialCodeIndex::VREPRINT, 12),
    (SpecialCodeIndex::VDISCARD, 13),
    (SpecialCodeIndex::VWERASE, 14),
    (SpecialCodeIndex::VLNEXT, 15),
    (SpecialCodeIndex::VEOL2, 16),
];

fn map(host: u64, table: &[(u64, u32)]) -> u32 {
    table
        .iter()
        .filter(|(h, _)| host & h != 0)
        .fold(0, |acc, (_, g)| acc | g)
}

/// What [`from_host`] reads of a host terminal's mode: the three flag words
/// and the control characters.
///
/// A trait because `rustix::termios::Termios` has fields a caller cannot
/// fill in -- the speeds -- so a test cannot make one; the tests implement
/// this over plain numbers instead of zeroing a `libc::termios`.
pub trait HostModes {
    fn iflag(&self) -> u64;
    fn oflag(&self) -> u64;
    fn lflag(&self) -> u64;
    fn cc(&self, index: SpecialCodeIndex) -> u8;
}

impl HostModes for rustix::termios::Termios {
    fn iflag(&self) -> u64 {
        self.input_modes.bits() as u64
    }
    fn oflag(&self) -> u64 {
        self.output_modes.bits() as u64
    }
    fn lflag(&self) -> u64 {
        self.local_modes.bits() as u64
    }
    fn cc(&self, index: SpecialCodeIndex) -> u8 {
        self.special_codes[index]
    }
}

/// The guest termios that matches the host terminal's current mode.
pub fn from_host(real: &impl HostModes) -> Termios {
    let mut out = Termios {
        iflags: map(real.iflag(), flags::IN),
        oflags: map(real.oflag(), flags::OUT),
        cflags: 0,
        lflags: map(real.lflag(), flags::LOCAL),
        line: 0,
        cc: [0; 19],
    };
    for (host, guest) in CC {
        out.cc[*guest] = real.cc(*host);
    }
    out
}

// ---------------------------------------------------------------------------
// The host side
// ---------------------------------------------------------------------------

/// What the terminal was before raw mode, so it can be put back.
static SAVED: std::sync::Mutex<Option<rustix::termios::Termios>> = std::sync::Mutex::new(None);

fn saved() -> std::sync::MutexGuard<'static, Option<rustix::termios::Termios>> {
    SAVED.lock().unwrap_or_else(|e| e.into_inner())
}

/// The reader thread's handle, so `real_tty_cleanup` can cancel it, and the
/// terminal it feeds.
///
/// `pthread_cancel` rather than a flag: the thread is blocked in `read` on
/// stdin, and nothing it could poll would be looked at until a byte arrives.
///
/// The terminal is a `Weak` here and not on the thread's stack, since
/// 2026-09-30. It was the thread's `pthread_create` argument, a raw pointer
/// with no count behind it, so a byte arriving as the last user went was
/// delivered into a terminal that might already be freed -- `cleanup` runs
/// after the release and the cancel lands at the next `read`. And not a
/// `Weak` owned by the thread either: a cancelled thread runs no destructors
/// on this host, so the weak count would never come back.
struct Reader {
    thread: libc::pthread_t,
    tty: Weak<Tty>,
}

static READER: Mutex<Option<Reader>> = Mutex::new(None);

fn reader() -> std::sync::MutexGuard<'static, Option<Reader>> {
    READER.lock().unwrap_or_else(|e| e.into_inner())
}

/// One byte at a time from the host's stdin into the terminal, until the
/// terminal is gone.
extern "C" fn read_thread(_: *mut c_void) -> *mut c_void {
    loop {
        let mut ch = 0u8;
        match rustix::io::read(std::io::stdin().as_fd(), std::slice::from_mut(&mut ch)) {
            Ok(1) => {}
            Ok(n) => {
                printk(&format!("tty read returned {n}"));
                continue;
            }
            Err(e) => {
                printk(&format!("tty read returned -1 ({e})"));
                continue;
            }
        }
        if ch == 0x1c {
            // ^\ -- so that ^C still works as an emulated SIGINT. This is the
            // way out of a wedged emulator, so it puts the host terminal back
            // before raising.
            real_tty_reset_term();
            // SAFETY: raising a signal at this process has no memory contract.
            unsafe { libc::raise(libc::SIGINT) };
        }
        let Some(tty) = reader().as_ref().and_then(|r| r.tty.upgrade()) else {
            return std::ptr::null_mut();
        };
        fs_tty::tty::input(&tty, std::slice::from_ref(&ch), false);
    }
}

/// Connect the console to the host terminal.
pub fn real_tty_init(tty: &Arc<Tty>, num: c_int) -> c_int {
    if num != REAL_TTY_NUM {
        return 0;
    }

    let mut winsize = Winsize::default();
    let mut termios: Option<Termios> = None;

    let stdin = std::io::stdin();
    match rustix::termios::tcgetwinsize(stdin.as_fd()) {
        // Not a terminal is normal -- the emulator's stdin may be a pipe. Any
        // other failure is not.
        Err(rustix::io::Errno::NOTTY) => {}
        Err(e) => return kernel_errno::raised(e.raw_os_error()),
        Ok(winsz) => {
            winsize = Winsize {
                row: winsz.ws_row,
                col: winsz.ws_col,
                xpixel: winsz.ws_xpixel,
                ypixel: winsz.ws_ypixel,
            };

            let host = match rustix::termios::tcgetattr(stdin.as_fd()) {
                Ok(host) => host,
                Err(e) => return kernel_errno::raised(e.raw_os_error()),
            };
            termios = Some(from_host(&host));

            let mut raw = host.clone();
            *saved() = Some(host);
            raw.make_raw();
            if rustix::termios::tcsetattr(stdin.as_fd(), OptionalActions::Now, &raw).is_err() {
                // The guest would be typing into a terminal in a mode neither
                // side agrees about, so there is nothing to carry on with.
                panic!("failed to set terminal to raw mode");
            }
        }
    }

    fs_tty::tty::set_console_state(tty, winsize, termios);

    let mut thread: libc::pthread_t = 0;
    // Before the thread exists, so its first byte finds the terminal.
    let mut slot = reader();
    // SAFETY: `read_thread` takes no argument and returns nothing it was
    // handed; the handle is written before `pthread_create` returns.
    if unsafe { libc::pthread_create(&mut thread, std::ptr::null(), read_thread, std::ptr::null_mut()) }
        != 0
    {
        return -5; // EIO
    }
    // SAFETY: a thread just created and not yet detached or joined.
    unsafe { libc::pthread_detach(thread) };
    *slot = Some(Reader {
        thread,
        tty: Arc::downgrade(tty),
    });
    0
}

/// The end of the chain. Everything above this — `fs/tty`'s `Console` trait
/// and `fs/ttydev`'s implementation of it — carries a `&[u8]` since
/// 2026-09-15, and so does the host call since 2026-09-29.
///
/// A failure is the guest's errno. It was `libc::write`'s own answer until
/// then, and on failure that is **-1** -- which the guest reads as `EPERM`, so
/// a host terminal that went away told the guest it was not permitted to
/// write rather than that the other end had hung up.
pub fn real_tty_write(num: c_int, buf: &[u8]) -> isize {
    if num != REAL_TTY_NUM {
        // A black hole reports that it took everything, which is what makes a
        // guest writing to /dev/tty2 not block for ever.
        return buf.len() as isize;
    }
    use std::os::fd::AsFd;
    match rustix::io::write(std::io::stdout().as_fd(), buf) {
        Ok(n) => n as isize,
        Err(e) => kernel_errno::raised(e.raw_os_error()) as isize,
    }
}

/// Put the host terminal back the way it was.
///
/// Safe to call when nothing was changed, which is what makes it usable from
/// the `^\` path and from an exit handler alike.
#[unsafe(no_mangle)]
pub extern "C" fn real_tty_reset_term() {
    let mut saved = saved();
    let Some(old) = saved.as_ref() else { return };
    if let Err(e) = rustix::termios::tcsetattr(std::io::stdin().as_fd(), OptionalActions::Now, old)
        && e != rustix::io::Errno::NOTTY
    {
        // Leaving a terminal in raw mode makes the shell that started the
        // emulator unusable, and there is no second chance to fix it.
        panic!("failed to reset terminal: {e}");
    }
    *saved = None;
}

pub fn real_tty_cleanup(num: c_int) {
    if num != REAL_TTY_NUM {
        return;
    }
    real_tty_reset_term();
    if let Some(r) = reader().take() {
        // SAFETY: a live detached thread, which only ever exits through this.
        unsafe { libc::pthread_cancel(r.thread) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A failed write to the host terminal answers the guest's errno.
    ///
    /// It answered `libc::write`'s -1, which is `EPERM` to a guest. Standard
    /// output is swapped for a descriptor open only for reading, which is the
    /// one way to make the host refuse a write here: `EBADF`, which is -9 on
    /// both sides.
    #[test]
    fn a_failed_write_is_the_guests_errno() {
        let read_only = std::fs::File::open("/dev/null").unwrap();
        let saved = rustix::io::dup(std::io::stdout().as_fd()).unwrap();
        rustix::stdio::dup2_stdout(&read_only).unwrap();
        let answered = real_tty_write(REAL_TTY_NUM, b"x");
        rustix::stdio::dup2_stdout(&saved).unwrap();
        assert_eq!(answered, -9, "EBADF, not -1 (which is EPERM to a guest)");
    }

    /// Every flag this kernel defines is in the table.
    ///
    /// The C mapped fifteen and dropped six, which is invisible: a table with a
    /// hole in it reads exactly like a complete one. The guest side is written
    /// out here as the bit each name has in `fs/tty.h`, so the assertion is
    /// that the *set* is complete rather than that any one entry is right.
    #[test]
    fn every_flag_this_kernel_defines_is_mapped() {
        let guest_local: Vec<u32> = flags::LOCAL.iter().map(|(_, g)| *g).collect();
        for (name, bit) in [
            ("ISIG", 1u32 << 0),
            ("ICANON", 1 << 1),
            ("ECHO", 1 << 3),
            ("ECHOE", 1 << 4),
            ("ECHOK", 1 << 5),
            ("ECHONL", 1 << 6),
            ("NOFLSH", 1 << 7),
            ("TOSTOP", 1 << 8),
            ("ECHOCTL", 1 << 9),
            ("ECHOPRT", 1 << 10),
            ("ECHOKE", 1 << 11),
            ("IEXTEN", 1 << 15),
        ] {
            assert!(guest_local.contains(&bit), "lflag {name} is not mapped");
        }

        let guest_in: Vec<u32> = flags::IN.iter().map(|(_, g)| *g).collect();
        for (name, bit) in [
            ("INLCR", 1u32 << 6),
            ("IGNCR", 1 << 7),
            ("ICRNL", 1 << 8),
            ("IXON", 1 << 10),
        ] {
            assert!(guest_in.contains(&bit), "iflag {name} is not mapped");
        }

        let guest_out: Vec<u32> = flags::OUT.iter().map(|(_, g)| *g).collect();
        for (name, bit) in [
            ("OPOST", 1u32 << 0),
            ("ONLCR", 1 << 2),
            ("OCRNL", 1 << 3),
            ("ONOCR", 1 << 4),
            ("ONLRET", 1 << 5),
        ] {
            assert!(guest_out.contains(&bit), "oflag {name} is not mapped");
        }
    }

    /// A host terminal's mode as plain numbers, which is all [`from_host`]
    /// reads.
    #[derive(Default)]
    struct Modes {
        iflag: u64,
        oflag: u64,
        lflag: u64,
        cc: Vec<(SpecialCodeIndex, u8)>,
    }

    impl HostModes for Modes {
        fn iflag(&self) -> u64 {
            self.iflag
        }
        fn oflag(&self) -> u64 {
            self.oflag
        }
        fn lflag(&self) -> u64 {
            self.lflag
        }
        fn cc(&self, index: SpecialCodeIndex) -> u8 {
            self.cc.iter().find(|(i, _)| *i == index).map_or(0, |(_, v)| *v)
        }
    }

    /// The six the C dropped, stated as the thing that used to happen: a host
    /// with the flag set produced a guest termios without it.
    #[test]
    fn the_six_the_c_dropped() {
        let host = Modes {
            iflag: libc::IXON as u64,
            lflag: (libc::ECHONL | libc::TOSTOP | libc::ECHOPRT | libc::ECHOKE | libc::IEXTEN) as u64,
            ..Modes::default()
        };
        let out = from_host(&host);
        assert_eq!(out.iflags, 1 << 10, "IXON_");
        assert_eq!(
            out.lflags,
            (1 << 6) | (1 << 8) | (1 << 10) | (1 << 11) | (1 << 15),
            "ECHONL_, TOSTOP_, ECHOPRT_, ECHOKE_, IEXTEN_"
        );
    }

    /// No two flags in one word share a guest bit. Two that did would make the
    /// mapping lossy in the other direction — the guest could not tell them
    /// apart.
    #[test]
    fn no_two_flags_share_a_bit() {
        for table in [flags::IN, flags::OUT, flags::LOCAL] {
            let mut seen = 0u32;
            for (_, g) in table {
                assert_eq!(seen & g, 0, "two flags share bit {g:#x}");
                seen |= g;
            }
        }
    }

    /// The control characters, and the one that has no host counterpart.
    /// `VSWTC_` is 7, is Linux's alone, and stays zero — which is what "no
    /// character does this" means, and is not the same as mapping it to
    /// whatever index 7 happens to be on BSD.
    #[test]
    fn the_control_characters_pair_by_name_and_vswtc_does_not() {
        let guest: Vec<usize> = CC.iter().map(|(_, g)| *g).collect();
        assert!(!guest.contains(&7), "VSWTC_ has no host counterpart");
        for g in [0usize, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16] {
            assert!(guest.contains(&g), "cc index {g} is not mapped");
        }
        // And every host index is distinct: two guest slots reading the same
        // host character would make one of them a copy of the other.
        let hosts: std::collections::HashSet<SpecialCodeIndex> = CC.iter().map(|(h, _)| *h).collect();
        assert_eq!(hosts.len(), CC.len(), "two guest slots read one host character");
    }

    /// A host terminal in the mode a shell leaves it in produces a guest
    /// termios with the flags a program expects to find.
    #[test]
    fn a_cooked_host_terminal_maps_to_a_cooked_guest_one() {
        let host = Modes {
            iflag: (libc::ICRNL | libc::IXON) as u64,
            oflag: (libc::OPOST | libc::ONLCR) as u64,
            lflag: (libc::ISIG | libc::ICANON | libc::ECHO | libc::ECHOE | libc::IEXTEN) as u64,
            cc: vec![(SpecialCodeIndex::VINTR, 3), (SpecialCodeIndex::VEOF, 4)],
        };

        let out = from_host(&host);
        assert_ne!(out.lflags & (1 << 1), 0, "ICANON_");
        assert_ne!(out.lflags & (1 << 3), 0, "ECHO_");
        assert_ne!(out.lflags & (1 << 15), 0, "IEXTEN_");
        assert_ne!(out.iflags & (1 << 10), 0, "IXON_");
        assert_ne!(out.oflags & (1 << 0), 0, "OPOST_");
        assert_eq!(out.cc[0], 3, "VINTR_");
        assert_eq!(out.cc[4], 4, "VEOF_");
        // Nothing the host did not have.
        assert_eq!(out.iflags & !((1 << 8) | (1 << 10)), 0);
    }
}
