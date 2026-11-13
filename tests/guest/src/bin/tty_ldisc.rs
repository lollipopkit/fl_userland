//! Line discipline behaviour, through a real pty.
//!
//! The input buffer behind these is `crates/fs/ldisc`. Erase stopping at a flag,
//! the canonical-mode line boundary and the EOF character are what the ring
//! has to get right; the flat array it replaced encoded the same rules with a
//! parallel `bool[]` and a memmove per read.

use std::ffi::CStr;

use guest_tests::{Harness, check, sys};
use libc::{c_int, termios};

struct Pty {
    master: c_int,
    slave: c_int,
}

impl Pty {
    /// Open a pty pair, in canonical or raw mode.
    fn open(canonical: bool) -> Option<Pty> {
        // SAFETY: the ptmx dance is exactly what POSIX prescribes.
        let master = sys::open("/dev/ptmx", libc::O_RDWR, 0);
        if master < 0 {
            return None;
        }
        unsafe {
            libc::grantpt(master);
            libc::unlockpt(master);
        }
        let name = unsafe { libc::ptsname(master) };
        if name.is_null() {
            sys::close(master);
            return None;
        }
        let name = unsafe { CStr::from_ptr(name) }
            .to_string_lossy()
            .into_owned();
        let slave = sys::open(&name, libc::O_RDWR | libc::O_NOCTTY, 0);
        if slave < 0 {
            sys::close(master);
            return None;
        }

        let mut t: termios = unsafe { std::mem::zeroed() };
        unsafe { libc::tcgetattr(slave, &mut t) };
        if canonical {
            t.c_lflag |= libc::ICANON;
            // No echo, so the master side stays clean.
            t.c_lflag &= !libc::ECHO;
        } else {
            unsafe { libc::cfmakeraw(&mut t) };
            t.c_cc[libc::VMIN] = 1;
            t.c_cc[libc::VTIME] = 0;
        }
        unsafe { libc::tcsetattr(slave, libc::TCSANOW, &t) };
        Some(Pty { master, slave })
    }

    fn feed(&self, input: &[u8]) -> bool {
        sys::write(self.master, input) == input.len() as isize
    }

    /// Read whatever the slave has to give, as one call.
    fn take(&self) -> Option<Vec<u8>> {
        let mut buf = [0u8; 256];
        let n = sys::read(self.slave, &mut buf);
        (n >= 0).then(|| buf[..n as usize].to_vec())
    }

    /// Feed and then read, which is how a line reaches a reader.
    fn round_trip(&self, input: &[u8]) -> Option<Vec<u8>> {
        self.feed(input).then(|| self.take()).flatten()
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        sys::close(self.slave);
        sys::close(self.master);
    }
}

fn show(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).escape_debug().to_string()
}

fn t_canonical_line(h: &mut Harness) {
    h.group("canonical");
    let Some(pty) = Pty::open(true) else {
        check!(h, false, "opening a pty");
        return;
    };
    let got = pty.round_trip(b"hello\n").unwrap_or_default();
    check!(h, got == b"hello\n", "a plain line: [{}]", show(&got));
}

fn t_erase(h: &mut Harness) {
    h.group("erase");
    let Some(pty) = Pty::open(true) else {
        check!(h, false, "opening a pty");
        return;
    };
    // Backspace removes the previous character before the line is delivered.
    let got = pty.round_trip(b"abc\x7fd\n").unwrap_or_default();
    check!(
        h,
        got == b"abd\n",
        "backspace: [{}], wanted abd\\n",
        show(&got)
    );
}

fn t_kill_line(h: &mut Harness) {
    h.group("kill");
    let Some(pty) = Pty::open(true) else {
        check!(h, false, "opening a pty");
        return;
    };
    // Ctrl-U discards everything typed so far on this line.
    let got = pty.round_trip(b"garbage\x15kept\n").unwrap_or_default();
    check!(
        h,
        got == b"kept\n",
        "ctrl-U: [{}], wanted kept\\n",
        show(&got)
    );
}

fn t_erase_stops_at_a_delivered_line(h: &mut Harness) {
    h.group("erase-boundary");
    let Some(pty) = Pty::open(true) else {
        check!(h, false, "opening a pty");
        return;
    };
    // Two lines arrive together, with backspaces at the start of the second.
    // They must not eat into the first, which is already a complete line.
    if !pty.feed(b"one\n\x7f\x7f\x7f\x7f\x7ftwo\n") {
        check!(h, false, "writing");
        return;
    }
    let first = pty.take().unwrap_or_default();
    check!(
        h,
        first == b"one\n",
        "first line intact: [{}]",
        show(&first)
    );
    let second = pty.take().unwrap_or_default();
    check!(h, second == b"two\n", "second line: [{}]", show(&second));
}

fn t_eof(h: &mut Harness) {
    h.group("eof");
    let Some(pty) = Pty::open(true) else {
        check!(h, false, "opening a pty");
        return;
    };
    // Ctrl-D with a partial line delivers it without a newline.
    let got = pty.round_trip(b"partial\x04").unwrap_or_default();
    check!(h, got == b"partial", "eof after text: [{}]", show(&got));

    // Ctrl-D on an empty line is end of file: a zero-length read.
    if !pty.feed(b"\x04") {
        check!(h, false, "writing eof");
        return;
    }
    let got = pty.take();
    check!(
        h,
        got.as_deref() == Some(&[][..]),
        "eof on an empty line returned {:?}, wanted 0 bytes",
        got.map(|g| g.len())
    );
}

fn t_raw_passthrough(h: &mut Harness) {
    h.group("raw");
    let Some(pty) = Pty::open(false) else {
        check!(h, false, "opening a pty");
        return;
    };
    // In raw mode nothing is special: the backspace byte arrives as a byte.
    if !pty.feed(b"a\x7fb") {
        check!(h, false, "writing");
        return;
    }
    let mut got = Vec::new();
    while got.len() < 3 {
        match pty.take() {
            Some(part) if !part.is_empty() => got.extend_from_slice(&part),
            _ => break,
        }
    }
    check!(h, got == b"a\x7fb", "raw passthrough: [{}]", show(&got));
}

fn t_large_wrapping_transfer(h: &mut Harness) {
    h.group("wrap");
    let Some(pty) = Pty::open(false) else {
        check!(h, false, "opening a pty");
        return;
    };
    // More than one buffer's worth, read back in small pieces: the ring has to
    // wrap and stay in order.
    const CHUNK: usize = 2000;
    let mut ok = true;
    for round in 0..4u8 {
        let out: Vec<u8> = (0..CHUNK)
            .map(|i| ((round as usize * 7 + i) % 251 + 1) as u8)
            .collect();
        if !pty.feed(&out) {
            ok = false;
            break;
        }
        let mut got = Vec::with_capacity(CHUNK);
        while got.len() < CHUNK {
            let mut buf = [0u8; 64];
            let n = sys::read(pty.slave, &mut buf);
            if n <= 0 {
                break;
            }
            got.extend_from_slice(&buf[..n as usize]);
        }
        if got != out {
            ok = false;
            break;
        }
    }
    check!(h, ok, "8000 bytes through the ring in 64-byte reads");
}

const TIOCPKT: libc::c_int = 0x5420;
const TIOCGPKT: libc::c_int = 0x80045438u32 as libc::c_int;

/// A new pty starts with its per-pty state cleared.
///
/// `struct tty` carries a union — a host thread for the real driver, or the
/// pty's other end, ownership, lock flag and packet mode — and `tty_alloc`
/// mallocs it and fills the fields in one by one. Nothing set the union, so a
/// pty master got whatever the previous owner of that heap block left there.
///
/// Packet mode is the one that shows: with it on, every read from the master
/// has a status byte prepended, so a shell talking through the pty sees a
/// stray byte at the front of its output. It is off by default and has to be.
fn t_new_pty_state_is_clean(h: &mut Harness) {
    h.group("pty-fresh-state");

    // Turn packet mode on and let the pty go, so the struct goes back to the
    // allocator with the flag set in it.
    {
        let Some(pty) = Pty::open(false) else {
            check!(h, false, "opening a pty");
            return;
        };
        let on: libc::c_int = 1;
        let r = unsafe { libc::ioctl(pty.master, TIOCPKT, &on) };
        check!(h, r == 0, "TIOCPKT can be turned on: {r}");
        let mut got: libc::c_int = -1;
        let r = unsafe { libc::ioctl(pty.master, TIOCGPKT, &mut got) };
        check!(h, r == 0 && got == 1, "and reads back as on: r={r} got={got}");
    }

    // Several rounds, because which heap block comes back is not promised.
    let mut dirty = 0;
    let mut checked = 0;
    for _ in 0..8 {
        let Some(pty) = Pty::open(false) else { continue };
        let mut got: libc::c_int = -1;
        if unsafe { libc::ioctl(pty.master, TIOCGPKT, &mut got) } == 0 {
            checked += 1;
            if got != 0 {
                dirty += 1;
            }
        }
        // And the data path: with packet mode on, a read from the master has a
        // status byte in front of it. Off, the bytes are the bytes.
        if pty.feed(b"abc") {
            // Feeding the master puts data on the slave, so read the slave and
            // then write back the other way for the master's own read path.
            let _ = pty.take();
        }
        if sys::write(pty.slave, b"xyz") == 3 {
            let mut buf = [0u8; 16];
            let n = sys::read(pty.master, &mut buf);
            checked += 1;
            if n != 3 || &buf[..3] != b"xyz" {
                dirty += 1;
                println!("  master read {n} bytes: {}", show(&buf[..n.max(0) as usize]));
            }
        }
    }
    check!(
        h,
        checked > 0,
        "the fresh-pty checks ran ({checked} of them)"
    );
    check!(
        h,
        dirty == 0,
        "a fresh pty has packet mode off and a clean data path ({dirty} of {checked} did not)"
    );
}

/// What ERASE and KILL put on the screen, which depends on four flag bits.
///
/// `fs/tty.c` carried `// FIXME ECHOE and ECHOK are supposed to enable these`
/// over this and read the flags the wrong way round: it started from ECHOK for
/// both and switched to ECHOE only when erasing a character that was there, so
/// ERASE rubbed out under the KILL flag and ECHOKE was never consulted at all.
/// The rules are: ECHOE makes ERASE rub the character off, ECHOK makes KILL
/// print a newline, ECHOKE makes KILL rub the whole line off instead, and all
/// of them need ECHO.
fn t_erase_kill_echo(h: &mut Harness) {
    h.group("erase-echo");

    // A pty with echo on, so what the discipline writes comes back on the
    // master. `lflags` is set explicitly rather than by cfmakeraw.
    fn open_echoing(extra: libc::tcflag_t, without: libc::tcflag_t) -> Option<Pty> {
        let pty = Pty::open(true)?;
        let mut t: termios = unsafe { std::mem::zeroed() };
        unsafe { libc::tcgetattr(pty.slave, &mut t) };
        t.c_lflag |= libc::ICANON | libc::ECHO | extra;
        t.c_lflag &= !without;
        t.c_oflag &= !libc::OPOST;
        unsafe { libc::tcsetattr(pty.slave, libc::TCSANOW, &t) };
        Some(pty)
    }

    /// Everything the master has to say right now.
    fn drain(pty: &Pty) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 256];
        // Non-blocking, so an empty echo is an answer rather than a hang.
        let flags = unsafe { libc::fcntl(pty.master, libc::F_GETFL) };
        unsafe { libc::fcntl(pty.master, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        loop {
            let n = sys::read(pty.master, &mut buf);
            if n <= 0 {
                break;
            }
            out.extend_from_slice(&buf[..n as usize]);
        }
        unsafe { libc::fcntl(pty.master, libc::F_SETFL, flags) };
        out
    }

    // ERASE with ECHOE rubs the character off: backspace, space, backspace.
    if let Some(pty) = open_echoing(libc::ECHOE, 0) {
        pty.feed(b"ab");
        drain(&pty);
        pty.feed(&[0x7f]);
        let got = drain(&pty);
        check!(h, got == b"\x08 \x08", "ERASE with ECHOE rubs out: [{}]", show(&got));
    } else {
        check!(h, false, "opening an echoing pty");
    }

    // Without ECHOE the character goes from the line but not from the screen.
    if let Some(pty) = open_echoing(0, libc::ECHOE) {
        pty.feed(b"ab");
        drain(&pty);
        pty.feed(&[0x7f]);
        let got = drain(&pty);
        check!(h, got.is_empty(), "ERASE without ECHOE is silent: [{}]", show(&got));
        // And the character really is gone from the line.
        let line = pty.round_trip(b"c\n").unwrap_or_default();
        check!(h, line == b"ac\n", "but the line is edited: [{}]", show(&line));
    }

    // KILL with ECHOK and not ECHOKE ends the line, leaving it visible above.
    if let Some(pty) = open_echoing(libc::ECHOK, libc::ECHOKE) {
        pty.feed(b"abc");
        drain(&pty);
        pty.feed(&[21]);
        let got = drain(&pty);
        check!(h, got == b"\n", "KILL with ECHOK ends the line: [{}]", show(&got));
    }

    // KILL with ECHOKE rubs the whole line off instead.
    if let Some(pty) = open_echoing(libc::ECHOKE, libc::ECHOK) {
        pty.feed(b"abc");
        drain(&pty);
        pty.feed(&[21]);
        let got = drain(&pty);
        check!(
            h,
            got == b"\x08 \x08".repeat(3),
            "KILL with ECHOKE rubs the line out: [{}]",
            show(&got)
        );
    }

    // ECHONL echoes the newline even with ECHO off, which is what a password
    // prompt wants: the typing invisible, the Enter not.
    if let Some(pty) = Pty::open(true) {
        let mut t: termios = unsafe { std::mem::zeroed() };
        unsafe { libc::tcgetattr(pty.slave, &mut t) };
        t.c_lflag |= libc::ICANON | libc::ECHONL;
        t.c_lflag &= !libc::ECHO;
        t.c_oflag &= !libc::OPOST;
        unsafe { libc::tcsetattr(pty.slave, libc::TCSANOW, &t) };
        pty.feed(b"secret\n");
        let got = drain(&pty);
        check!(h, got == b"\r\n", "ECHONL echoes only the newline: [{}]", show(&got));
    }

    // With ECHO off, none of them write anything.
    if let Some(pty) = Pty::open(true) {
        let mut t: termios = unsafe { std::mem::zeroed() };
        unsafe { libc::tcgetattr(pty.slave, &mut t) };
        t.c_lflag |= libc::ICANON | libc::ECHOE | libc::ECHOK | libc::ECHOKE;
        t.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(pty.slave, libc::TCSANOW, &t) };
        pty.feed(b"abc");
        pty.feed(&[0x7f]);
        pty.feed(&[21]);
        let got = drain(&pty);
        check!(h, got.is_empty(), "ECHO off silences all of them: [{}]", show(&got));
    }
}

/// The `/dev/pts` node a pty gets, which comes from the registry in
/// `crates/fs/ttyreg`.
///
/// The ownership and mode used to live inside the terminal, so reading them
/// took `ttys_lock` and then the terminal's own lock. They describe the node,
/// so they live beside the number now — and a number handed out again has to
/// come back with default permissions rather than the last owner's.
fn t_devpts_node(h: &mut Harness) {
    h.group("devpts");
    let Some(pty) = Pty::open(true) else {
        check!(h, false, "opening a pty");
        return;
    };
    let name = unsafe { libc::ptsname(pty.master) };
    let name = unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned();

    let stat_of = |path: &str| -> Option<libc::stat> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let c = std::ffi::CString::new(path).ok()?;
        (unsafe { libc::stat(c.as_ptr(), &mut st) } == 0).then_some(st)
    };

    let Some(st) = stat_of(&name) else {
        check!(h, false, "stat {name}");
        return;
    };
    check!(
        h,
        st.st_mode & 0o7777 == 0o620,
        "a fresh pty is mode 0620, got {:o}",
        st.st_mode & 0o7777
    );

    // It is listed.
    let listed = std::fs::read_dir("/dev/pts")
        .map(|d| d.flatten().filter(|e| !e.file_name().to_string_lossy().starts_with('.')).count())
        .unwrap_or(0);
    check!(h, listed >= 1, "/dev/pts lists it, got {listed} entries");

    // chmod goes through the registry and comes back.
    let c = std::ffi::CString::new(name.clone()).unwrap();
    check!(
        h,
        unsafe { libc::chmod(c.as_ptr(), 0o600) } == 0,
        "chmod on the slave node: errno {}",
        sys::errno()
    );
    let after = stat_of(&name).map(|s| s.st_mode & 0o7777).unwrap_or(0);
    check!(h, after == 0o600, "and it reads back, got {after:o}");

    // Closing it and opening a fresh one must not inherit those permissions.
    drop(pty);
    if let Some(again) = Pty::open(true) {
        let name2 = unsafe { libc::ptsname(again.master) };
        let name2 = unsafe { CStr::from_ptr(name2) }.to_string_lossy().into_owned();
        let mode = stat_of(&name2).map(|s| s.st_mode & 0o7777).unwrap_or(0);
        check!(
            h,
            mode == 0o620,
            "a reused number comes back at 0620, not the last owner's {mode:o}"
        );
    }
}

fn main() -> std::process::ExitCode {
    let mut h = Harness::new();
    t_new_pty_state_is_clean(&mut h);
    t_canonical_line(&mut h);
    t_erase(&mut h);
    t_erase_kill_echo(&mut h);
    t_devpts_node(&mut h);
    t_kill_line(&mut h);
    t_erase_stops_at_a_delivered_line(&mut h);
    t_eof(&mut h);
    t_raw_passthrough(&mut h);
    t_large_wrapping_transfer(&mut h);
    std::process::ExitCode::from(h.finish() as u8)
}
