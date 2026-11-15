//! What a terminal does, tested without a kernel.
//!
//! Two things have to be stood in for. The lock's primitive is C — see
//! `crates/util/guestlock` for why — so [`stub`] provides the same five
//! operations over raw pthread objects, which is what `util/guestlock.c` is.
//! And the task side is a table of callbacks; [`fake_task`] answers them from
//! statics a test can set.
//!
//! What that buys is the terminal's own rules under test: the canonical and raw
//! read shapes, the background rules, the pty pair's lifetime, and the hangup.

use super::ioctl::{self, Arg};
use super::ops::{self, Pid};
use super::pty;
use super::tty::{self, Kind, Tty, Winsize};
use ldisc::Termios;
use pollset::Watchers;
use std::ffi::c_int;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

// The lock these tests run under is `crates/util/guestlock`, the real one.
//
// This used to be a **parallel implementation** of the eight `guest_lock_*`
// functions on pthreads, from when the primitive was `util/guestlock.c` and a
// Rust test binary linked no C. The primitive has been Rust since 2026-09-03
// and `crates/util/guestlock-teststub` stubs the layer *below* it instead --
// so the tests exercise the real allocation, the real `Drop` order and the
// real bounds check on a condition index. A parallel implementation tests the
// parallel implementation.
//
// It was also seven duplicate symbols: `util_guestlock` reaches this test link
// and `ld` was choosing between two definitions of each.
use kernel_sighand as _;
use kernel_sigqueue as _;

// ---------------------------------------------------------------------------
// A task that answers from statics.

static PGID: AtomicI32 = AtomicI32::new(100);
static SID: AtomicI32 = AtomicI32::new(100);
static SESSION_LEADER: AtomicI32 = AtomicI32::new(1);
static HAS_TTY: AtomicI32 = AtomicI32::new(0);
static CONTROLLING: Mutex<Vec<ops::TtyId>> = Mutex::new(Vec::new());
static ORPHANED: AtomicI32 = AtomicI32::new(0);
static IGNORES: AtomicI32 = AtomicI32::new(0);
static SIGNALS: Mutex<Vec<(Pid, c_int)>> = Mutex::new(Vec::new());
static HANGUPS: Mutex<Vec<Pid>> = Mutex::new(Vec::new());
static CONSOLE_OUT: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static PIDS_DEPTH: AtomicUsize = AtomicUsize::new(0);

fn pgid() -> Pid {
    PGID.load(Ordering::SeqCst)
}
fn sid() -> Pid {
    SID.load(Ordering::SeqCst)
}
fn pid() -> Pid {
    SID.load(Ordering::SeqCst)
}
fn is_leader() -> bool {
    SESSION_LEADER.load(Ordering::SeqCst) != 0
}
fn has_tty() -> bool {
    HAS_TTY.load(Ordering::SeqCst) != 0
}
unsafe fn is_controlling(raw: ops::TtyId) -> bool {
    // The rule this stub exists to enforce, as well as to answer: the process
    // layer takes a lock of its own here, and the call that *sets* a group's
    // controlling terminal holds that lock while it calls `tty_claim`, which
    // takes the terminal's. Asking with the terminal's lock held closes the
    // cycle, and two threads of one process are enough to do it -- one reading
    // a terminal it does not control, one doing TIOCSCTTY.
    //
    // tools/lock-order.py cannot see it, because one of the two locks is
    // Rust's. This is what sees it: every path that reaches the callback in
    // these tests proves it is not holding the lock. Three were not, on
    // 2026-08-31.
    let tty = unsafe { &*raw.as_ptr() };
    let held = tty.try_lock();
    assert!(
        held.is_some(),
        "is_controlling was asked with the terminal's own lock held"
    );
    drop(held);
    CONTROLLING.lock().unwrap().contains(&raw)
}
fn sys_admin() -> bool {
    false
}
fn orphaned(_: Pid) -> bool {
    ORPHANED.load(Ordering::SeqCst) != 0
}
fn ignores(_: c_int) -> bool {
    IGNORES.load(Ordering::SeqCst) != 0
}
fn signal_group_locked(pgid: Pid, sig: c_int) {
    assert!(
        PIDS_DEPTH.load(Ordering::SeqCst) > 0,
        "a group signal that needs pids_lock was sent without it"
    );
    SIGNALS.lock().unwrap().push((pgid, sig));
}
fn signal_group(pgid: Pid, sig: c_int) {
    assert_eq!(
        PIDS_DEPTH.load(Ordering::SeqCst),
        0,
        "the input path must not hold pids_lock"
    );
    SIGNALS.lock().unwrap().push((pgid, sig));
}
fn pgrp_session(want: Pid) -> Option<Pid> {
    // Every group in this test lives in the caller's session.
    (want != 0).then(|| SID.load(Ordering::SeqCst))
}
fn set_controlling(raw: ops::TtyId) {
    CONTROLLING.lock().unwrap().push(raw);
    HAS_TTY.store(1, Ordering::SeqCst);
}
fn steal_controlling(_: Pid, raw: ops::TtyId) {
    CONTROLLING.lock().unwrap().retain(|&c| c != raw);
}
fn hangup_session(sid: Pid) {
    HANGUPS.lock().unwrap().push(sid);
}
fn pids_lock() {
    // The real one is a plain pthread mutex, so a second acquisition on the
    // same thread is a deadlock rather than a wrong answer -- which is what
    // `-DLOCK_DEBUG=1` exists to catch in a guest and what this catches here,
    // for free, on every test that closes a terminal. `tty::hangup` takes the
    // lock itself as of 2026-09-16 and this is the assertion that says nothing
    // above it already had.
    assert_eq!(
        PIDS_DEPTH.fetch_add(1, Ordering::SeqCst),
        0,
        "pids_lock is not recursive"
    );
}
fn pids_unlock() {
    PIDS_DEPTH.fetch_sub(1, Ordering::SeqCst);
}
fn fsids() -> (u32, u32) {
    (1000, 5)
}

fn console_write(_: c_int, buf: &[u8]) -> isize {
    CONSOLE_OUT.lock().unwrap().extend_from_slice(buf);
    buf.len() as isize
}
fn console_init(_: &std::sync::Arc<crate::tty::Tty>, _: c_int) -> c_int {
    0
}
fn console_cleanup(_: c_int) {}
fn console_enabled(_: c_int) -> bool {
    true
}

/// The process layer these tests pretend to have: atomics and a `Vec`, so a
/// test can set a pgid and read back what was signalled.
struct FakeTask;

impl ops::TaskOps for FakeTask {
    fn pgid(&self) -> Pid {
        pgid()
    }
    fn sid(&self) -> Pid {
        sid()
    }
    fn pid(&self) -> Pid {
        pid()
    }
    fn is_session_leader(&self) -> bool {
        is_leader()
    }
    fn has_tty(&self) -> bool {
        has_tty()
    }
    fn sys_admin(&self) -> bool {
        sys_admin()
    }
    fn orphaned(&self, _pids: &ops::PidsHeld, pgid: Pid) -> bool {
        orphaned(pgid)
    }
    fn ignores(&self, sig: c_int) -> bool {
        ignores(sig)
    }
    fn signal_group_locked(&self, _pids: &ops::PidsHeld, pgid: Pid, sig: c_int) {
        signal_group_locked(pgid, sig);
    }
    fn signal_group(&self, pgid: Pid, sig: c_int) {
        signal_group(pgid, sig);
    }
    fn session_of(&self, _pids: &ops::PidsHeld, want: Pid) -> Option<Pid> {
        pgrp_session(want)
    }
    fn hangup(&self, _pids: &ops::PidsHeld, sid: Pid) {
        hangup_session(sid);
    }
    fn caller_ids(&self) -> (u32, u32) {
        fsids()
    }
    fn is_controlling(&self, raw: ops::TtyId) -> bool {
        // SAFETY: the caller's contract.
        unsafe { is_controlling(raw) }
    }
    fn set_controlling(&self, _pids: &ops::PidsHeld, tty: &Arc<tty::Tty>) {
        set_controlling(ops::TtyId::of(tty));
    }
    fn steal_controlling(&self, _pids: &ops::PidsHeld, sid: Pid, raw: ops::TtyId) {
        steal_controlling(sid, raw);
    }
    fn locked(&self, f: &mut dyn FnMut()) {
        pids_lock();
        f();
        pids_unlock();
    }
}

static TASK: FakeTask = FakeTask;

/// The host terminal these tests pretend to have: a `Vec` the write path
/// appends to.
struct FakeConsole;

impl ops::ConsoleOps for FakeConsole {
    fn init(&self, tty: &std::sync::Arc<crate::tty::Tty>, num: c_int) -> c_int {
        console_init(tty, num)
    }
    fn write(&self, num: c_int, buf: &[u8]) -> isize {
        console_write(num, buf)
    }
    fn cleanup(&self, num: c_int) {
        console_cleanup(num);
    }
    fn enabled(&self, major: c_int) -> bool {
        console_enabled(major)
    }
}

static CONSOLE: FakeConsole = FakeConsole;

static BOUND: OnceLock<()> = OnceLock::new();

/// Everything here shares one terminal table, so the tests take this.
static SERIAL: Mutex<()> = Mutex::new(());

fn setup() -> std::sync::MutexGuard<'static, ()> {
    let guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    BOUND.get_or_init(|| ops::tty_bind_ops(&TASK, &CONSOLE));
    PGID.store(100, Ordering::SeqCst);
    SID.store(100, Ordering::SeqCst);
    SESSION_LEADER.store(1, Ordering::SeqCst);
    HAS_TTY.store(0, Ordering::SeqCst);
    ORPHANED.store(0, Ordering::SeqCst);
    IGNORES.store(0, Ordering::SeqCst);
    CONTROLLING.lock().unwrap().clear();
    SIGNALS.lock().unwrap().clear();
    HANGUPS.lock().unwrap().clear();
    CONSOLE_OUT.lock().unwrap().clear();
    guard
}

fn watchers() -> Arc<Watchers> {
    Arc::new(Watchers::default())
}

/// A pty pair with the slave unlocked and both ends open.
fn pair() -> (Arc<Tty>, Arc<Tty>) {
    let master = pty::open_master().expect("a master").into_arc();
    let slave = master.other().expect("its slave");
    slave.lock().locked = false;
    (master, slave)
}

// ---------------------------------------------------------------------------

#[test]
fn a_master_makes_its_slave_and_outlives_nothing() {
    let _serial = setup();
    let (master, slave) = pair();
    assert_eq!(slave.kind, Kind::PtySlave);
    assert_eq!(slave.num, master.num);
    assert!(tty::pty_exists(slave.num));
    // The master holds one user of the slave, which is what makes the slave
    // outlive it.
    assert_eq!(tty::users(&slave), 1);

    tty::release(&master);
    // The master going hangs the slave up and gives back its user, so the
    // slave's number is free again.
    assert!(!tty::pty_exists(slave.num));
    assert!(slave.lock().hung_up);
}

#[test]
fn a_slave_cannot_be_opened_while_the_master_has_it_locked() {
    let _serial = setup();
    let master = pty::open_master().expect("a master").into_arc();
    let slave = master.other().expect("its slave");
    assert_eq!(pty::open_slave(&slave), tty::EIO, "locked");
    slave.lock().locked = false;
    assert_eq!(pty::open_slave(&slave), 0);
    tty::release(&master);
}

#[test]
fn a_write_to_one_end_is_a_read_on_the_other() {
    let _serial = setup();
    let (master, slave) = pair();
    let m = tty::Open::of(&master);
    let s = tty::Open::of(&slave);
    // Raw mode on the slave, so a read does not wait for a line.
    slave.lock().termios.lflags &= !tty::ICANON;

    assert_eq!(tty::write(&m, b"hello", false), 5);
    let mut out = [0u8; 8];
    assert_eq!(tty::read(&s, &mut out, true), 5);
    assert_eq!(&out[..5], b"hello");
    tty::release(&master);
}

#[test]
fn a_canonical_read_waits_for_a_whole_line() {
    let _serial = setup();
    let (master, slave) = pair();
    let m = tty::Open::of(&master);
    let s = tty::Open::of(&slave);
    assert_eq!(tty::write(&m, b"partial", false), 7);
    let mut out = [0u8; 32];
    // Nonblocking, so "no line yet" is EAGAIN rather than a hang.
    assert_eq!(tty::read(&s, &mut out, true), tty::EAGAIN as isize);
    assert_eq!(tty::write(&m, b"\r", false), 1);
    // ICRNL turns the carriage return into the newline that ends the line.
    let n = tty::read(&s, &mut out, true);
    assert_eq!(n, 8);
    assert_eq!(&out[..8], b"partial\n");
    tty::release(&master);
}

#[test]
fn what_a_terminal_echoes_comes_back_out_of_the_other_end() {
    let _serial = setup();
    let (master, _slave) = pair();
    let m = tty::Open::of(&master);
    // The slave echoes by default; the echo is written to the master.
    assert_eq!(tty::write(&m, b"hi\r", false), 3);
    let mut out = [0u8; 32];
    let n = tty::read(&m, &mut out, true);
    assert!(n > 0, "the master saw nothing echoed back");
    assert!(
        out[..n as usize].starts_with(b"hi"),
        "echoed {:?}",
        &out[..n as usize]
    );
    // Nothing more queued is "try again", not end of file.
    assert_eq!(tty::read(&m, &mut out, true), tty::EAGAIN as isize);
    tty::release(&master);
}

#[test]
fn a_read_from_a_hung_up_terminal_is_end_of_file() {
    let _serial = setup();
    let (master, slave) = pair();
    let s = tty::Open::of(&slave);
    tty::hangup(&slave);
    let mut out = [0u8; 8];
    // Not an error: a hung-up terminal is at end of file, which is what a
    // shell reads as "the user is gone".
    assert_eq!(tty::read(&s, &mut out, true), 0);
    assert_eq!(tty::write(&s, b"x", false), tty::EIO as isize);
    let all = tty::POLL_READ | tty::POLL_WRITE | tty::POLL_ERR | tty::POLL_HUP;
    assert_eq!(tty::poll(&s), all);
    let mut word = 0u32;
    assert_eq!(ioctl::ioctl(&s, ioctl::TIOCSPGRP, Arg::Word(&mut word)), tty::ENOTTY);
    assert_eq!(ioctl::ioctl(&s, pty::TIOCGPTN, Arg::Word(&mut word)), tty::EIO);
    tty::release(&master);
}

/// A hangup is the descriptions', not the terminal's: one opened after it
/// works, and the ones open at the time stay hung up. It was one flag on the
/// terminal until 2026-11-12, so a terminal hung up once -- by `vhangup`, or a
/// session leader leaving the console -- answered `EIO` for ever.
#[test]
fn a_terminal_opened_after_a_hangup_works_and_the_old_descriptions_do_not() {
    let _serial = setup();
    let (master, slave) = pair();
    let m = tty::Open::of(&master);
    let old = tty::Open::of(&slave);
    tty::write(&m, b"queued", false);
    tty::hangup(&slave);
    // Arriving before anything reopens it, for nobody.
    assert_eq!(tty::write(&m, b"lost\r", false), 5);

    slave.lock().termios.lflags &= !tty::ICANON;
    let new = tty::Open::of(&slave);
    let mut out = [0u8; 16];
    assert_eq!(tty::read(&new, &mut out, true), tty::EAGAIN as isize, "the queue went with the hangup");
    assert_eq!(tty::write(&m, b"new", false), 3);
    assert_eq!(tty::read(&new, &mut out, true), 3);
    assert_eq!(tty::write(&new, b"y", false), 1);
    assert_eq!(tty::poll(&new) & tty::POLL_HUP, 0);
    assert_eq!(tty::read(&old, &mut out, true), 0, "still hung up");
    assert_eq!(tty::write(&old, b"x", false), tty::EIO as isize);
    // The slave's hung-up descriptions are still open, so the master is not
    // half closed by a hangup.
    drop(new);
    assert!(!master.half_closed_master());
    tty::release(&master);
}

#[test]
fn a_hangup_tells_the_session_that_owned_the_terminal_once() {
    let _serial = setup();
    let (master, slave) = pair();
    slave.lock().jobctl.claim(100, 100);
    CONTROLLING.lock().unwrap().push(ops::TtyId::of(&slave));
    tty::hangup(&slave);
    assert_eq!(*HANGUPS.lock().unwrap(), vec![100]);
    // The session loses it, and nothing owns it any more.
    assert!(CONTROLLING.lock().unwrap().is_empty(), "the session kept the terminal");
    assert!(slave.lock().jobctl.unowned());
    assert_eq!(slave.lock().jobctl.fg_group(), 0);
    // A pty teardown closes both ends and each close reaches here; a session
    // already told it lost its terminal must not be told again.
    tty::hangup(&slave);
    assert_eq!(HANGUPS.lock().unwrap().len(), 1);
    tty::release(&master);
}

#[test]
fn a_background_read_stops_the_whole_group() {
    let _serial = setup();
    let (master, slave) = pair();
    let s = tty::Open::of(&slave);
    CONTROLLING
        .lock()
        .unwrap()
        .push(ops::TtyId::of(&slave));
    slave.lock().jobctl.claim(100, 100);
    // The caller is in a different group from the foreground one.
    PGID.store(200, Ordering::SeqCst);

    let mut out = [0u8; 8];
    assert_eq!(tty::read(&s, &mut out, true), tty::EINTR as isize);
    assert_eq!(*SIGNALS.lock().unwrap(), vec![(200, tty::SIGTTIN)]);
    tty::release(&master);
}

#[test]
fn an_orphaned_background_group_gets_eio_rather_than_being_stopped() {
    let _serial = setup();
    let (master, slave) = pair();
    let s = tty::Open::of(&slave);
    CONTROLLING
        .lock()
        .unwrap()
        .push(ops::TtyId::of(&slave));
    slave.lock().jobctl.claim(100, 100);
    PGID.store(200, Ordering::SeqCst);
    // Stopping it would be a hang: nobody is left who could send SIGCONT.
    ORPHANED.store(1, Ordering::SeqCst);

    let mut out = [0u8; 8];
    assert_eq!(tty::read(&s, &mut out, true), tty::EIO as isize);
    assert!(SIGNALS.lock().unwrap().is_empty());
    tty::release(&master);
}

#[test]
fn a_background_write_is_allowed_until_tostop_is_set() {
    let _serial = setup();
    let (master, slave) = pair();
    let s = tty::Open::of(&slave);
    CONTROLLING
        .lock()
        .unwrap()
        .push(ops::TtyId::of(&slave));
    slave.lock().jobctl.claim(100, 100);
    PGID.store(200, Ordering::SeqCst);

    // The default: a background job's output interleaves with the shell's.
    assert_eq!(tty::write(&s, b"bg", false), 2);
    assert!(SIGNALS.lock().unwrap().is_empty());

    // TOSTOP is the flag that governs exactly this, and it was read by
    // nothing: `stty tostop` succeeded and changed nothing.
    slave.lock().termios.lflags |= tty::TOSTOP;
    assert_eq!(tty::write(&s, b"bg", false), tty::EINTR as isize);
    assert_eq!(*SIGNALS.lock().unwrap(), vec![(200, tty::SIGTTOU)]);
    tty::release(&master);
}

#[test]
fn changing_the_settings_from_the_background_is_refused_whatever_tostop_says() {
    let _serial = setup();
    let (master, slave) = pair();
    let s = tty::Open::of(&slave);
    CONTROLLING
        .lock()
        .unwrap()
        .push(ops::TtyId::of(&slave));
    slave.lock().jobctl.claim(100, 100);
    PGID.store(200, Ordering::SeqCst);

    let mut termios = slave.lock().termios;
    assert_eq!(
        ioctl::ioctl(&s, ioctl::TCSETS, Arg::Termios(&mut termios)),
        tty::EINTR
    );
    assert_eq!(*SIGNALS.lock().unwrap(), vec![(200, tty::SIGTTOU)]);
    // Reading them is not refused.
    SIGNALS.lock().unwrap().clear();
    assert_eq!(
        ioctl::ioctl(&s, ioctl::TCGETS, Arg::Termios(&mut termios)),
        0
    );
    assert!(SIGNALS.lock().unwrap().is_empty());
    tty::release(&master);
}

#[test]
fn the_masters_settings_are_the_slaves() {
    let _serial = setup();
    let (master, slave) = pair();
    let m = tty::Open::of(&master);
    let s = tty::Open::of(&slave);
    let mut termios = Termios {
        lflags: tty::ISIG,
        ..Default::default()
    };
    // tcsetattr on the master changes the slave's line discipline: they are
    // one terminal with two ends.
    assert_eq!(
        ioctl::ioctl(&m, ioctl::TCSETS, Arg::Termios(&mut termios)),
        0
    );
    assert_eq!(slave.lock().termios.lflags, tty::ISIG);

    let mut winsize = Winsize {
        row: 24,
        col: 80,
        xpixel: 0,
        ypixel: 0,
    };
    assert_eq!(
        ioctl::ioctl(&m, ioctl::TIOCSWINSZ, Arg::Winsize(&mut winsize)),
        0
    );
    let mut read_back = Winsize::default();
    assert_eq!(
        ioctl::ioctl(&s, ioctl::TIOCGWINSZ, Arg::Winsize(&mut read_back)),
        0
    );
    assert_eq!(read_back, winsize);
    tty::release(&master);
}

#[test]
fn resizing_signals_the_foreground_group() {
    let _serial = setup();
    let (master, slave) = pair();
    let m = tty::Open::of(&master);
    slave.lock().jobctl.claim(100, 100);
    let mut winsize = Winsize {
        row: 40,
        col: 100,
        xpixel: 0,
        ypixel: 0,
    };
    assert_eq!(
        ioctl::ioctl(&m, ioctl::TIOCSWINSZ, Arg::Winsize(&mut winsize)),
        0
    );
    assert_eq!(*SIGNALS.lock().unwrap(), vec![(100, tty::SIGWINCH)]);
    tty::release(&master);
}

#[test]
fn the_foreground_group_can_only_be_set_to_one_in_this_session() {
    let _serial = setup();
    let (master, slave) = pair();
    let s = tty::Open::of(&slave);
    CONTROLLING
        .lock()
        .unwrap()
        .push(ops::TtyId::of(&slave));
    slave.lock().jobctl.claim(100, 100);

    // A negative number is EINVAL, and it is checked *before* whether the
    // terminal is the caller's -- which is Linux's order and not the order the
    // checks read in.
    let mut negative = (-1i32) as u32;
    assert_eq!(
        ioctl::ioctl(&s, ioctl::TIOCSPGRP, Arg::Word(&mut negative)),
        tty::EINVAL
    );
    // And a refusal changes nothing.
    assert_eq!(slave.lock().jobctl.fg_group(), 100);

    let mut want = 200u32;
    assert_eq!(
        ioctl::ioctl(&s, ioctl::TIOCSPGRP, Arg::Word(&mut want)),
        0
    );
    assert_eq!(slave.lock().jobctl.fg_group(), 200);

    // And now the caller is in the background, so the *background* rule
    // answers first -- before the argument is even looked at. That is Linux's
    // order too: tiocspgrp calls tty_check_change before get_user.
    assert_eq!(
        ioctl::ioctl(&s, ioctl::TIOCSPGRP, Arg::Word(&mut negative)),
        tty::EINTR
    );
    assert_eq!(slave.lock().jobctl.fg_group(), 200);
    tty::release(&master);
}

#[test]
fn the_master_reports_the_slaves_number_and_takes_the_lock_off() {
    let _serial = setup();
    let master = pty::open_master().expect("a master").into_arc();
    let slave = master.other().expect("its slave");
    let m = tty::Open::of(&master);
    let s = tty::Open::of(&slave);
    let mut number = 0u32;
    assert_eq!(
        ioctl::ioctl(&m, pty::TIOCGPTN, Arg::Word(&mut number)),
        0
    );
    assert_eq!(number as c_int, slave.num);

    let mut unlock = 0u32;
    assert_eq!(
        ioctl::ioctl(&m, pty::TIOCSPTLCK, Arg::Word(&mut unlock)),
        0
    );
    assert!(!slave.lock().locked);
    // A slave asked the same question answers ENOTTY: it is the master's.
    assert_eq!(
        ioctl::ioctl(&s, pty::TIOCGPTN, Arg::Word(&mut number)),
        tty::ENOTTY
    );
    tty::release(&master);
}

#[test]
fn a_poll_of_a_pty_asks_the_other_end_whether_it_has_room() {
    let _serial = setup();
    let (master, slave) = pair();
    let m = tty::Open::of(&master);
    let s = tty::Open::of(&slave);
    slave.lock().termios.lflags &= !tty::ICANON;
    assert_eq!(tty::poll(&m) & tty::POLL_WRITE, tty::POLL_WRITE);
    assert_eq!(tty::poll(&s) & tty::POLL_READ, 0);

    tty::write(&m, b"x", false);
    assert_eq!(tty::poll(&s) & tty::POLL_READ, tty::POLL_READ);

    // Filling the slave's buffer makes the master unwritable, which is the
    // whole point: a program that polls before writing used to be told to go
    // ahead and then blocked.
    let filler = vec![b'x'; ldisc::SIZE];
    tty::write(&m, &filler, true);
    assert_eq!(tty::poll(&m) & tty::POLL_WRITE, 0);
    tty::release(&master);
}

/// Linux's `TTY_OTHER_CLOSED`, measured by `ttyhup_probe`: what the slave
/// wrote is still read, then `EIO`; a write is accepted; reopening the slave
/// puts it back. It answered end of file at once, and for good -- the slave's
/// last close hung the master up -- until 2026-11-12.
#[test]
fn a_master_whose_slave_has_closed_reads_what_is_left_then_eio() {
    let _serial = setup();
    let (master, slave) = pair();
    let m = tty::Open::of(&master);
    let s = tty::Open::of(&slave);
    assert_eq!(tty::write(&s, b"a", false), 1);
    assert!(!master.half_closed_master());
    drop(s);
    assert!(master.half_closed_master());
    assert_eq!(tty::poll(&m) & (tty::POLL_READ | tty::POLL_HUP), tty::POLL_READ | tty::POLL_HUP);

    let mut out = [0u8; 4];
    assert_eq!(tty::read(&m, &mut out, true), 1);
    assert_eq!(tty::read(&m, &mut out, true), tty::EIO as isize);
    assert_eq!(tty::poll(&m) & (tty::POLL_READ | tty::POLL_HUP), tty::POLL_HUP);
    assert_eq!(tty::write(&m, b"b", false), 1);

    let again = tty::Open::of(&slave);
    assert!(!master.half_closed_master());
    assert_eq!(tty::poll(&m) & tty::POLL_HUP, 0);
    drop(again);
    tty::release(&master);
}

/// `disassociate_ctty(1)` for a pty: the foreground group gets `SIGHUP`
/// alone, the session loses the terminal, and the terminal keeps working.
#[test]
fn a_session_leader_leaving_a_pty_signals_the_foreground_and_hangs_nothing_up() {
    let _serial = setup();
    let (master, slave) = pair();
    let s = tty::Open::of(&slave);
    slave.lock().jobctl.claim(100, 200);
    CONTROLLING.lock().unwrap().push(ops::TtyId::of(&slave));
    tty::session_leader_exited(tty::User::take(&slave));
    assert_eq!(*SIGNALS.lock().unwrap(), vec![(200, tty::SIGHUP)]);
    assert!(HANGUPS.lock().unwrap().is_empty(), "nobody else is told");
    assert!(CONTROLLING.lock().unwrap().is_empty(), "the session kept the terminal");
    assert!(slave.lock().jobctl.unowned());
    assert_eq!(tty::write(&s, b"x", false), 1, "and it still works");
    tty::release(&master);
}

/// Any other terminal is hung up as well, which signals the leader's session.
#[test]
fn a_session_leader_leaving_the_console_hangs_it_up() {
    let _serial = setup();
    let console = tty::get(Kind::Console, 2).expect("a console");
    let c = tty::Open::of(&console);
    console.lock().jobctl.claim(100, 200);
    tty::session_leader_exited(tty::User::take(&console));
    assert_eq!(*HANGUPS.lock().unwrap(), vec![100]);
    assert_eq!(*SIGNALS.lock().unwrap(), vec![(200, tty::SIGHUP)]);
    assert_eq!(tty::write(&c, b"x", false), tty::EIO as isize);
    drop(c);
    tty::release(&console);
}

#[test]
fn a_console_write_goes_to_the_host() {
    let _serial = setup();
    let console = tty::get(Kind::Console, 1).expect("a console");
    let c = tty::Open::of(&console);
    assert_eq!(tty::write(&c, b"out\n", false), 4);
    // OPOST|ONLCR is on by default, so the newline is a carriage return pair.
    assert_eq!(&*CONSOLE_OUT.lock().unwrap(), b"out\r\n");
    tty::release(&console);
}

#[test]
fn a_descriptor_opened_on_a_terminal_is_woken_by_its_input() {
    let _serial = setup();
    let (master, slave) = pair();
    let m = tty::Open::of(&master);
    slave.lock().termios.lflags &= !tty::ICANON;
    let list = watchers();
    let open = tty::Open::new(tty::User::take(&slave), &list, 0).expect("an open");

    let waiter = pollset::Waiter::new();
    assert!(list.add_waiter(&waiter));
    assert_eq!(waiter.acquire(|| -5), 0);
    tty::write(&m, b"x", false);
    let mut probe = libc::pollfd {
        fd: waiter.read_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(
        unsafe { libc::poll(&mut probe, 1, 0) },
        1,
        "input did not wake the descriptor"
    );
    waiter.drain();
    waiter.release();
    tty::close(open, &list);
    tty::release(&master);
}

#[test]
fn a_number_past_the_end_of_the_table_is_enxio() {
    let _serial = setup();
    // Reachable from a guest: `mknod /dev/x c 136 65535`.
    let err = |kind, num| tty::get(kind, num).map(|_| ()).unwrap_err();
    assert_eq!(err(Kind::PtySlave, tty::MAX_PTYS as c_int), tty::ENXIO);
    assert_eq!(
        err(Kind::Console, tty::MAX_CONSOLES as c_int + 1),
        tty::ENXIO
    );
    // And a slave nobody has made is not something to make.
    assert_eq!(err(Kind::PtySlave, 3000), tty::EIO);
}

/// A terminal handed across the C ABI is freed when its last user goes.
///
/// `User::into_raw` hands over one strong count with the user. Until
/// 2026-09-29 `tty_release` and `tty_close` only *borrowed* that pointer, so
/// the count was never given back and no terminal the ABI had handed out was
/// ever freed -- one allocation per console and pty, for the life of the
/// process.
#[test]
fn a_terminal_the_abi_handed_out_is_freed_by_its_last_release() {
    let _serial = setup();
    let user = tty::User::get(Kind::Console, 7).expect("console 7");
    let weak = Arc::downgrade(user.tty());
    // A second user, as a descriptor or a controlling terminal takes one.
    let second = tty::User::take(user.tty());
    let raw = user.into_raw();
    drop(second);
    assert!(weak.upgrade().is_some(), "one user is left");
    unsafe { super::abi::tty_release(raw) };
    assert!(weak.upgrade().is_none(), "the last release kept the terminal alive");
}

fn noop_external_write(_: &Tty, buf: &[u8], _: bool) -> c_int {
    buf.len() as c_int
}

#[test]
fn hanging_up_an_external_terminal_wakes_a_blocked_large_input() {
    let _serial = setup();
    let raw = super::abi::tty_open_external(noop_external_write).expect("external tty");
    let tty_ref = unsafe { &*raw };
    let num = tty_ref.num;
    tty_ref.lock().termios.lflags &= !(tty::ECHO | tty::ICANON);

    assert!(tty::pty_exists(num));
    assert!(!tty_ref.is_external_closed());

    let raw_addr = raw as usize;
    let writer = std::thread::spawn(move || {
        let payload = vec![b'x'; 16384];
        unsafe { super::abi::tty_input(raw_addr as *const Tty, &payload, true) }
    });

    for _ in 0..500 {
        if tty_ref.lock().ldisc.buffer.is_full() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    assert!(
        tty_ref.lock().ldisc.buffer.is_full(),
        "input queue should fill and block the writer"
    );
    std::thread::sleep(std::time::Duration::from_millis(20));

    unsafe { super::abi::tty_hangup(raw) };
    let written = writer.join().expect("writer thread should exit on hangup");

    assert_eq!(written, 16384);
    assert!(tty_ref.is_external_closed());
    assert!(!tty::pty_exists(num));
    {
        let borrowed = std::mem::ManuallyDrop::new(unsafe { Arc::from_raw(raw) });
        assert_eq!(pty::open_slave(&borrowed), tty::EIO);
    }
    unsafe { super::abi::tty_release(raw) };
}
