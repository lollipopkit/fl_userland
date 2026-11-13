//! What a terminal answers.
//!
//! **A report, not a check** — the tenth in the shape `mmap_probe` established.
//! One line per case, never fails, diffed against an arm64 container by
//! `tests/integration/probe_diff.sh`.
//!
//! Every interactive program depends on this and every mistake in it is
//! silent: a `c_lflag` bit that does not take makes a shell echo each character
//! twice, a `VMIN`/`VTIME` pair that is ignored makes a raw-mode reader block
//! for ever, and a `TIOCGWINSZ` that answers zeroes makes an editor draw one
//! line.
//!
//! # It allocates its own terminal
//!
//! Neither side's standard input is reliably a tty — a container without `-t`
//! has a pipe, and the emulator's depends on how it was started — so every case
//! runs against a pseudoterminal this program opens for itself. That also makes
//! the *pair* visible: `TIOCGPTN`, `TIOCSPTLCK` and the master's own answers are
//! half of what a terminal is, and a probe using an inherited descriptor never
//! sees the master at all.

use std::os::fd::AsRawFd;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn name(e: i32) -> String {
    let s = match e {
        libc::EINVAL => "EINVAL",
        libc::ENOTTY => "ENOTTY",
        libc::EBADF => "EBADF",
        libc::EPERM => "EPERM",
        libc::EACCES => "EACCES",
        libc::EAGAIN => "EAGAIN",
        libc::EIO => "EIO",
        libc::ENOSYS => "ENOSYS",
        libc::ENXIO => "ENXIO",
        libc::EFAULT => "EFAULT",
        libc::ERANGE => "ERANGE",
        libc::ENOENT => "ENOENT",
        _ => return format!("errno {e}"),
    };
    s.into()
}

fn report(what: &str, r: i64) {
    if r < 0 {
        println!("{what:<52} -> {}", name(errno()));
    } else {
        println!("{what:<52} -> ok");
    }
}

fn value(what: &str, v: i64) {
    println!("{what:<52} -> {v}");
}

fn text(what: &str, v: &str) {
    println!("{what:<52} -> {v}");
}

const TIOCGPTN: i32 = 0x80045430u32 as i32;
const TIOCSPTLCK: i32 = 0x40045431u32 as i32;
const TIOCGPTPEER: i32 = 0x5441;
const TIOCOUTQ: i32 = 0x5411;
const TCFLSH: i32 = 0x540b;
const TCSBRK: i32 = 0x5409;
const TIOCEXCL: i32 = 0x540c;
const TIOCNXCL: i32 = 0x540d;
/// Named but not exercised, and it is in the group the comment below calls "about the *caller's*
/// session", which this probe reaches a different way.
#[allow(dead_code)]
const TIOCGSID: i32 = 0x5429;

/// A pseudoterminal pair, master first.
fn pty() -> Option<(i32, i32)> {
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    if master < 0 {
        return None;
    }
    if unsafe { libc::grantpt(master) } < 0 || unsafe { libc::unlockpt(master) } < 0 {
        unsafe { libc::close(master) };
        return None;
    }
    let mut buf = [0u8; 256];
    if unsafe { libc::ptsname_r(master, buf.as_mut_ptr(), buf.len()) } != 0 {
        unsafe { libc::close(master) };
        return None;
    }
    let slave = unsafe { libc::open(buf.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
    if slave < 0 {
        unsafe { libc::close(master) };
        return None;
    }
    Some((master, slave))
}

fn main() {
    let Some((m, s)) = pty() else {
        // Both sides must print the same lines, so a failure here has to be
        // one line and then nothing -- not a partial run.
        println!("could not open a pseudoterminal");
        return;
    };

    println!("## what each end is");
    value("the master isatty", unsafe { libc::isatty(m) } as i64);
    value("the slave isatty", unsafe { libc::isatty(s) } as i64);
    {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        unsafe { libc::fstat(s, &mut st) };
        value("  the slave is a character device",
              ((st.st_mode & libc::S_IFMT) == libc::S_IFCHR) as i64);
        value("  its permission bits", (st.st_mode & 0o7777) as i64);
        let mut mst: libc::stat = unsafe { std::mem::zeroed() };
        unsafe { libc::fstat(m, &mut mst) };
        value("  the master is a character device",
              ((mst.st_mode & libc::S_IFMT) == libc::S_IFCHR) as i64);
    }

    println!("## the default termios of a fresh slave");
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    report("tcgetattr(slave)", unsafe { libc::tcgetattr(s, &mut t) } as i64);
    // The flag words as a fresh pty has them. A shell reads these, turns some
    // off and puts them back, so the *starting* value is what every terminal
    // program's idea of "normal" is built on.
    value("  c_iflag", t.c_iflag as i64);
    value("  c_oflag", t.c_oflag as i64);
    value("  c_cflag", t.c_cflag as i64);
    value("  c_lflag", t.c_lflag as i64);
    // The control characters, by index. VINTR 0, VQUIT 1, VERASE 2, VKILL 3,
    // VEOF 4, VTIME 5, VMIN 6, VSTART 8, VSTOP 9, VSUSP 10.
    for (n, i) in [
        ("VINTR", 0usize), ("VQUIT", 1), ("VERASE", 2), ("VKILL", 3),
        ("VEOF", 4), ("VTIME", 5), ("VMIN", 6), ("VSWTC", 7),
        ("VSTART", 8), ("VSTOP", 9), ("VSUSP", 10), ("VEOL", 11),
        ("VREPRINT", 12), ("VDISCARD", 13), ("VWERASE", 14), ("VLNEXT", 15),
        ("VEOL2", 16),
    ] {
        value(&format!("  c_cc[{n}]"), t.c_cc[i] as i64);
    }
    value("  cfgetispeed", unsafe { libc::cfgetispeed(&t) } as i64);
    value("  cfgetospeed", unsafe { libc::cfgetospeed(&t) } as i64);

    println!("## setting and reading back");
    {
        let mut raw = t;
        unsafe { libc::cfmakeraw(&mut raw) };
        report("tcsetattr(TCSANOW, raw)", unsafe {
            libc::tcsetattr(s, libc::TCSANOW, &raw)
        } as i64);
        let mut back: libc::termios = unsafe { std::mem::zeroed() };
        unsafe { libc::tcgetattr(s, &mut back) };
        // Every bit cfmakeraw touched must have taken. A flag word that is
        // stored but not honoured is the failure this cannot see; a flag word
        // that is not even stored is the one it can.
        value("  c_iflag came back", (back.c_iflag == raw.c_iflag) as i64);
        value("  c_oflag came back", (back.c_oflag == raw.c_oflag) as i64);
        value("  c_lflag came back", (back.c_lflag == raw.c_lflag) as i64);
        value("  c_cflag came back", (back.c_cflag == raw.c_cflag) as i64);
        value("  VMIN came back", (back.c_cc[6] == raw.c_cc[6]) as i64);
        value("  VTIME came back", (back.c_cc[5] == raw.c_cc[5]) as i64);
        // ECHO off is the one a password prompt depends on.
        value("  ECHO is off", ((back.c_lflag & libc::ECHO) == 0) as i64);
        value("  ICANON is off", ((back.c_lflag & libc::ICANON) == 0) as i64);
        // Put it back.
        unsafe { libc::tcsetattr(s, libc::TCSANOW, &t) };
    }
    {
        // A bit no flag defines. Linux stores what it is given and reports it
        // back rather than refusing.
        let mut odd = t;
        odd.c_lflag |= 0x8000_0000;
        report("tcsetattr(an undefined c_lflag bit)", unsafe {
            libc::tcsetattr(s, libc::TCSANOW, &odd)
        } as i64);
        let mut back: libc::termios = unsafe { std::mem::zeroed() };
        unsafe { libc::tcgetattr(s, &mut back) };
        value("  it came back", ((back.c_lflag & 0x8000_0000) != 0) as i64);
        unsafe { libc::tcsetattr(s, libc::TCSANOW, &t) };
    }
    for (n, action) in [
        ("TCSANOW", libc::TCSANOW),
        ("TCSADRAIN", libc::TCSADRAIN),
        ("TCSAFLUSH", libc::TCSAFLUSH),
        ("an undefined action (99)", 99),
    ] {
        report(&format!("tcsetattr({n})"), unsafe {
            libc::tcsetattr(s, action, &t)
        } as i64);
    }

    println!("## the termios2 ioctls");
    {
        // **What a modern glibc's `tcgetattr` and `isatty` actually call.**
        // These probes are musl, which uses `TCGETS`, so the raw numbers are
        // the only way to ask — and `TCGETS2` was `ENOTTY` here, which made
        // `isatty()` false for every terminal on a glibc distribution. sshd's
        // `openpty` then failed `ttyname` and it refused every interactive
        // session.
        const TCGETS2: libc::c_int = 0x802c_542au32 as libc::c_int;
        const TCSETS2: libc::c_int = 0x402c_542b;
        const TCSETSW2: libc::c_int = 0x402c_542c;
        const TCSETSF2: libc::c_int = 0x402c_542d;
        // 44 bytes: `struct termios` and two speeds. Written as an array
        // rather than a struct so that the probe carries no second definition
        // of the layout.
        let mut t2 = [0u8; 44];
        report("ioctl(slave, TCGETS2)", unsafe {
            libc::ioctl(s, TCGETS2, t2.as_mut_ptr())
        } as i64);
        let word = |b: &[u8; 44], at: usize| u32::from_ne_bytes(b[at..at + 4].try_into().unwrap());
        // The prefix is `struct termios`, so the four flag words agree with
        // what `tcgetattr` reported.
        let mut plain: libc::termios = unsafe { std::mem::zeroed() };
        unsafe { libc::tcgetattr(s, &mut plain) };
        value("  c_iflag matches tcgetattr", (word(&t2, 0) == plain.c_iflag) as i64);
        value("  c_oflag matches tcgetattr", (word(&t2, 4) == plain.c_oflag) as i64);
        value("  c_cflag matches tcgetattr", (word(&t2, 8) == plain.c_cflag) as i64);
        value("  c_lflag matches tcgetattr", (word(&t2, 12) == plain.c_lflag) as i64);
        // The two speeds are at 36 and 40, and a pty reports 38400.
        value("  c_ispeed is 38400", (word(&t2, 36) == 38400) as i64);
        value("  c_ospeed is 38400", (word(&t2, 40) == 38400) as i64);
        // Setting through TCSETS2 and reading back.
        let mut set = t2;
        set[12..16].copy_from_slice(&(word(&t2, 12) & !(libc::ECHO as u32)).to_ne_bytes());
        report("ioctl(slave, TCSETS2)", unsafe {
            libc::ioctl(s, TCSETS2, set.as_ptr())
        } as i64);
        let mut back = [0u8; 44];
        unsafe { libc::ioctl(s, TCGETS2, back.as_mut_ptr()) };
        value("  ECHO came off", ((word(&back, 12) & libc::ECHO as u32) == 0) as i64);
        report("ioctl(slave, TCSETSW2)", unsafe {
            libc::ioctl(s, TCSETSW2, t2.as_ptr())
        } as i64);
        report("ioctl(slave, TCSETSF2)", unsafe {
            libc::ioctl(s, TCSETSF2, t2.as_ptr())
        } as i64);
        report("ioctl(master, TCGETS2)", unsafe {
            libc::ioctl(m, TCGETS2, back.as_mut_ptr())
        } as i64);
        // `BOTHER` in CBAUD means the two speed fields are the rate, and a
        // caller that sets one expects to read it back.
        let mut other = t2;
        let cflag = (word(&t2, 8) & !0o010017) | 0o010000;
        other[8..12].copy_from_slice(&cflag.to_ne_bytes());
        other[36..40].copy_from_slice(&123_456u32.to_ne_bytes());
        other[40..44].copy_from_slice(&123_456u32.to_ne_bytes());
        report("ioctl(slave, TCSETS2 with BOTHER)", unsafe {
            libc::ioctl(s, TCSETS2, other.as_ptr())
        } as i64);
        unsafe { libc::ioctl(s, TCGETS2, back.as_mut_ptr()) };
        value("  the explicit speed came back", (word(&back, 36) == 123_456) as i64);
        // Put it back.
        unsafe { libc::ioctl(s, TCSETSF2, t2.as_ptr()) };
    }

    println!("## the window size");
    {
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        report("TIOCGWINSZ on a fresh pty", unsafe {
            libc::ioctl(s, libc::TIOCGWINSZ, &mut ws)
        } as i64);
        value("  rows", ws.ws_row as i64);
        value("  cols", ws.ws_col as i64);
        let set = libc::winsize { ws_row: 40, ws_col: 100, ws_xpixel: 7, ws_ypixel: 13 };
        report("TIOCSWINSZ(40x100)", unsafe {
            libc::ioctl(s, libc::TIOCSWINSZ, &set)
        } as i64);
        let mut got: libc::winsize = unsafe { std::mem::zeroed() };
        unsafe { libc::ioctl(s, libc::TIOCGWINSZ, &mut got) };
        value("  rows came back", got.ws_row as i64);
        value("  cols came back", got.ws_col as i64);
        value("  pixels came back", (got.ws_xpixel as i64) * 1000 + got.ws_ypixel as i64);
        // The master sees the same size: that is the whole point of setting it
        // on one end.
        let mut mws: libc::winsize = unsafe { std::mem::zeroed() };
        unsafe { libc::ioctl(m, libc::TIOCGWINSZ, &mut mws) };
        value("  the master agrees", (mws.ws_row == 40 && mws.ws_col == 100) as i64);
    }

    println!("## the pty pair's own ioctls");
    {
        let mut n = 0i32;
        report("TIOCGPTN on the master", unsafe {
            libc::ioctl(m, TIOCGPTN, &mut n)
        } as i64);
        value("  the number is not negative", (n >= 0) as i64);
        let mut n2 = 0i32;
        report("TIOCGPTN on the slave", unsafe {
            libc::ioctl(s, TIOCGPTN, &mut n2)
        } as i64);
        let unlock = 0i32;
        report("TIOCSPTLCK(0) on the master", unsafe {
            libc::ioctl(m, TIOCSPTLCK, &unlock)
        } as i64);
        report("TIOCSPTLCK on the slave", unsafe {
            libc::ioctl(s, TIOCSPTLCK, &unlock)
        } as i64);
        report("TIOCGPTPEER", unsafe {
            let r = libc::ioctl(m, TIOCGPTPEER, libc::O_RDWR);
            if r >= 0 {
                libc::close(r);
            }
            r
        } as i64);
    }

    println!("## queues and flushing");
    {
        let mut n = 0i32;
        report("TIOCINQ on an idle slave", unsafe {
            libc::ioctl(s, libc::FIONREAD, &mut n)
        } as i64);
        value("  it says", n as i64);
        // Write from the master; the slave's input queue grows.
        unsafe { libc::write(m, b"hello\r".as_ptr() as *const libc::c_void, 6) };
        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut n2 = 0i32;
        unsafe { libc::ioctl(s, libc::FIONREAD, &mut n2) };
        value("after the master wrote 6 bytes it says", n2 as i64);
        let mut out = 0i32;
        report("TIOCOUTQ", unsafe { libc::ioctl(s, TIOCOUTQ, &mut out) } as i64);
        for (n, q) in [("TCIFLUSH", 0i32), ("TCOFLUSH", 1), ("TCIOFLUSH", 2), ("an undefined queue (9)", 9)] {
            report(&format!("TCFLSH({n})"), unsafe {
                libc::ioctl(s, TCFLSH, q)
            } as i64);
        }
        let mut after = 0i32;
        unsafe { libc::ioctl(s, libc::FIONREAD, &mut after) };
        value("after TCIOFLUSH the input queue says", after as i64);
        report("TCSBRK(0)", unsafe { libc::ioctl(s, TCSBRK, 0) } as i64);
    }

    println!("## exclusive mode");
    {
        report("TIOCEXCL", unsafe { libc::ioctl(s, TIOCEXCL, 0) } as i64);
        report("TIOCNXCL", unsafe { libc::ioctl(s, TIOCNXCL, 0) } as i64);
    }

    // ## job control -- removed, twice.
    //
    // TIOCSCTTY, TIOCGPGRP, TIOCSPGRP and TIOCGSID are about the *caller's*
    // controlling terminal, and neither attempt to ask them here measured a
    // kernel.
    //
    // The first asked from whatever session this program was started in. The
    // container's process has a controlling terminal (docker gives it one) and
    // the emulator's does not, so three cases differed for a reason that was
    // entirely the harness's.
    //
    // The second forked a child, gave it a session with setsid() and had it
    // claim the pty with TIOCSCTTY -- which makes every answer determined, and
    // which the container refused: TIOCSCTTY was EPERM, /dev/tty would not
    // open, and every ioctl after it was ENOTTY. *Every* case in the block
    // failing on one side is the signature CLAUDE.md names for an environment
    // restriction rather than a rule, the same way Docker's seccomp profile
    // answers EPERM to every argument of clock_settime. Working out which of
    // devpts, the ptmx bind mount or the container's own session is
    // responsible would be measuring docker.
    //
    // So they are removed rather than weakened, which is what was done to
    // clock_abi's nine checks for the same reason. Job control *is* covered,
    // inside the emulator where it is well defined: tests/guest/src/bin/
    // setpgid_rules.rs has fifty checks and crates/fs/jobctl owns the rules.

    println!("## what is not a terminal");
    {
        let f = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
        let mut tt: libc::termios = unsafe { std::mem::zeroed() };
        report("tcgetattr(/dev/null)", unsafe { libc::tcgetattr(f, &mut tt) } as i64);
        value("  isatty", unsafe { libc::isatty(f) } as i64);
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        report("TIOCGWINSZ(/dev/null)", unsafe {
            libc::ioctl(f, libc::TIOCGWINSZ, &mut ws)
        } as i64);
        unsafe { libc::close(f) };
        let mut fds = [0i32; 2];
        unsafe { libc::pipe(fds.as_mut_ptr()) };
        report("tcgetattr(a pipe)", unsafe { libc::tcgetattr(fds[0], &mut tt) } as i64);
        report("an unknown ioctl on a tty", unsafe {
            libc::ioctl(s, 0x1234_5678i32, 0)
        } as i64);
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }

    println!("## what the line discipline does with a line");
    {
        // Canonical mode: the slave read returns a whole line, and the
        // terminating newline is part of it.
        let mut c = t;
        c.c_lflag |= libc::ICANON | libc::ECHO;
        unsafe { libc::tcsetattr(s, libc::TCSANOW, &c) };
        unsafe { libc::write(m, b"abc\r".as_ptr() as *const libc::c_void, 4) };
        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut buf = [0u8; 32];
        let n = unsafe { libc::read(s, buf.as_mut_ptr() as *mut libc::c_void, 32) };
        value("a canonical read of \"abc\\r\" returns", n as i64);
        text("  the bytes",
             &buf[..n.max(0) as usize].iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(""));
        // ICRNL is on by default, so the \r arrived as \n. Whether the master
        // sees an echo is ONLCR's business.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut echo = [0u8; 64];
        unsafe { libc::fcntl(m, libc::F_SETFL, libc::O_NONBLOCK) };
        let e = unsafe { libc::read(m, echo.as_mut_ptr() as *mut libc::c_void, 64) };
        text("  what the master saw echoed",
             &echo[..e.max(0) as usize].iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(""));
    }
    {
        // Raw mode with VMIN=1: a read returns as soon as one byte is there.
        let mut r = t;
        unsafe { libc::cfmakeraw(&mut r) };
        r.c_cc[6] = 1; // VMIN
        r.c_cc[5] = 0; // VTIME
        unsafe { libc::tcsetattr(s, libc::TCSANOW, &r) };
        unsafe { libc::write(m, b"xy".as_ptr() as *const libc::c_void, 2) };
        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut buf = [0u8; 8];
        let n = unsafe { libc::read(s, buf.as_mut_ptr() as *mut libc::c_void, 8) };
        value("a raw read of two bytes returns", n as i64);
        text("  the bytes",
             &buf[..n.max(0) as usize].iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(""));
    }

    // Named so the import is used and the pair is closed the same way on both
    // sides.
    let keep = unsafe { std::fs::File::from(std::os::fd::OwnedFd::from_raw_fd(m)) };
    value("the master descriptor is still open", (keep.as_raw_fd() >= 0) as i64);
    drop(keep);
    unsafe { libc::close(s) };
}

use std::os::fd::FromRawFd;
