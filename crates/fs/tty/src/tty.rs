//! The terminal itself: what it is, how long it lives, and what a read, a
//! write and a poll of one do.

use crate::ops::{Pid, TtyId, console, task};
use jobctl::{Access, JobControl, Sig};
use ldisc::discipline::{B38400, CREAD, CS8};
use ldisc::{Discipline, Step, Termios};
use pollset::{WakeSet, Watchers};
use std::ffi::c_int;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use ttyreg::Registry;
use util_guestlock::{GuestGuard, GuestLock, Woke};

#[path = "io.rs"]
mod io;
pub(crate) use io::is_controlling_terminal;
pub use io::{input, poll, read, write};

pub const CONSOLE_MAJOR: c_int = 4;
pub const PTY_MASTER_MAJOR: c_int = 128;
pub const PTY_SLAVE_MAJOR: c_int = 136;

/// How many pseudoterminals there can be. `/dev/pts` is indexed by this.
pub const MAX_PTYS: usize = 1 << 12;
/// The console driver's minors.
pub const MAX_CONSOLES: usize = 64;

pub use guest_errno::c_int_::{
    EAGAIN, EBUSY, EINTR, EINVAL, EIO, ENOMEM, ENOSPC, ENOTTY, ENXIO, EPERM,
};

pub const POLL_READ: c_int = 1;
pub const POLL_PRI: c_int = 2;
pub const POLL_WRITE: c_int = 4;
pub const POLL_ERR: c_int = 8;
pub const POLL_HUP: c_int = 16;

pub const O_NONBLOCK: c_int = 0o4000;

pub const SIGHUP: c_int = 1;
pub const SIGTTIN: c_int = 21;
pub const SIGTTOU: c_int = 22;
pub const SIGWINCH: c_int = 28;

/// The two conditions a terminal has.
const PRODUCED: u32 = 0;
const CONSUMED: u32 = 1;

pub use ldisc::discipline::{ECHO, ECHOCTL, ECHOE, ECHOK, ECHOKE, ICANON, ICRNL, ISIG};

/// The flags `crates/fs/ldisc` does not interpret, because they are about
/// *output* or about what a terminal may do to a background process rather
/// than about what an arriving byte means. `fs/tty.h` had the same numbering.
pub const IXON: u32 = 1 << 10;
pub const OPOST: u32 = 1 << 0;
pub const ONLCR: u32 = 1 << 2;
pub const OCRNL: u32 = 1 << 3;
pub const ONOCR: u32 = 1 << 4;
pub const ONLRET: u32 = 1 << 5;
pub const IEXTEN: u32 = 1 << 15;
pub const TOSTOP: u32 = 1 << 8;

pub const VTIME: usize = 5;
pub const VMIN: usize = 6;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Winsize {
    pub row: u16,
    pub col: u16,
    pub xpixel: u16,
    pub ypixel: u16,
}

plain::plain!(Winsize { row, col, xpixel, ypixel });

/// Which driver a terminal belongs to. It used to be a table of function
/// pointers per major; two of the three are this crate's own logic and the
/// third is a host device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Console,
    PtyMaster,
    PtySlave,
}

impl Kind {
    pub fn of(major: c_int) -> Option<Kind> {
        match major {
            CONSOLE_MAJOR => Some(Kind::Console),
            PTY_MASTER_MAJOR => Some(Kind::PtyMaster),
            PTY_SLAVE_MAJOR => Some(Kind::PtySlave),
            _ => None,
        }
    }

    pub fn major(self) -> c_int {
        match self {
            Kind::Console => CONSOLE_MAJOR,
            Kind::PtyMaster => PTY_MASTER_MAJOR,
            Kind::PtySlave => PTY_SLAVE_MAJOR,
        }
    }

    fn is_pty(self) -> bool {
        matches!(self, Kind::PtyMaster | Kind::PtySlave)
    }
}

/// Everything the terminal's own lock protects.
pub struct State {
    /// How many hangups there have been. A description records the number
    /// it was opened under, and one opened under an earlier number is hung
    /// up: Linux's `tty_hung_up_p`, which is a property of the *file*, not of
    /// the terminal. The terminal itself can be opened again and works.
    pub generation: u64,
    /// Hung up, and not opened since. Input arriving meanwhile has no reader
    /// and is dropped, as Linux drops what reaches a hung-up line.
    pub hung_up: bool,
    /// Open descriptions, hung up or not. A pty master whose slave has none
    /// is at end of file.
    pub descriptions: usize,
    pub ever_opened: bool,
    /// The status byte a packet-mode master prepends to a read.
    pub packet_flags: u8,
    pub packet_mode: bool,
    /// `TIOCSPTLCK`: a slave that has not been unlocked cannot be opened.
    pub locked: bool,
    /// `TIOCEXCL`: further opens answer `EBUSY`. Cleared by `TIOCNXCL` and by
    /// the last close, which is what stops a process that set it and died
    /// from making the terminal unusable.
    pub exclusive: bool,
    pub winsize: Winsize,
    pub termios: Termios,
    /// `c_ispeed` and `c_ospeed`, which only `TCGETS2`/`TCSETS2` carry.
    ///
    /// Kept beside the settings rather than derived from `CBAUD`, because
    /// `BOTHER` means "the rate is in these two fields" and a caller that sets
    /// one expects to read it back. Nothing here acts on a baud rate — every
    /// terminal is a pty or the host's — so what they are for is being
    /// reported.
    pub ispeed: u32,
    pub ospeed: u32,
    pub ldisc: Discipline,
    pub jobctl: JobControl,
}

impl State {
    /// `TCSETS2` and its two siblings: the settings and, when `CBAUD` is
    /// `BOTHER`, the two explicit speeds.
    ///
    /// Linux ignores `c_ispeed`/`c_ospeed` unless the caller asked for
    /// `BOTHER`, because otherwise the rate is the one `CBAUD` encodes and the
    /// fields are outputs.
    pub fn set_termios2(&mut self, new: &ldisc::Termios2) {
        self.termios = new.settings();
        if new.cflags & ldisc::CBAUD == ldisc::BOTHER {
            self.ispeed = new.ispeed;
            self.ospeed = new.ospeed;
        }
    }

    fn new(kind: Kind) -> State {
        State {
            generation: 0,
            hung_up: false,
            descriptions: 0,
            ever_opened: false,
            packet_flags: 0,
            packet_mode: false,
            // A slave is locked until the master unlocks it; anything else is
            // usable as soon as it exists.
            locked: kind == Kind::PtySlave,
            exclusive: false,
            winsize: Winsize::default(),
            termios: default_termios(kind),
            // 38400, which is what `INIT_C_CFLAG`'s `B38400` names and what
            // every pty reports.
            ispeed: 38400,
            ospeed: 38400,
            ldisc: Discipline::new(),
            jobctl: JobControl::new(),
        }
    }
}

/// What a terminal starts with.
///
/// A pty master's is raw -- it is the side a terminal emulator holds, and
/// echoing or canonicalising there would do it twice -- with the default
/// control characters, as Linux's `ptm_driver->init_termios` has. It was all
/// zeroes until 2026-11-12, and a zero `VMIN` made a read of an empty master
/// answer 0, end of file, where Linux blocks or answers `EAGAIN`.
fn default_termios(kind: Kind) -> Termios {
    let settings = Termios {
        iflags: ICRNL | IXON,
        oflags: OPOST | ONLCR,
        // B38400 | CS8 | CREAD, which is `include/asm-generic/termios.h`'s
        // `INIT_C_CFLAG`. This was **zero**, and the two things that follow
        // from that are both wrong in a way nothing reports:
        //
        // - `cfgetospeed` answered `B0`, which does not mean "no speed set".
        //   It means *hang up the line*, and a program checking whether the
        //   terminal is still connected reads it as disconnected.
        // - `c_cflag & CSIZE` was `CS5`, five bits per character, where every
        //   terminal since the 1980s is eight.
        //
        // Measured: a fresh pty on a real arm64 kernel reports 191, which is
        // exactly these three.
        cflags: B38400 | CS8 | CREAD,
        lflags: ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN,
        line: 0,
        // include/asm-generic/termios.h's defaults.
        cc: [
            3, 28, 127, 21, 4, 0, 1, 0, 17, 19, 26, 0, 18, 15, 23, 22, 0, 0, 0,
        ],
    };
    if kind == Kind::PtyMaster {
        return Termios { iflags: 0, oflags: 0, lflags: 0, ..settings };
    }
    settings
}

/// Where a write goes when a terminal has no other end: an embedder that
/// collects its session's output itself. ServerBox's session is one.
///
/// A **Rust** function pointer, though the destination is an embedder's C
/// callback. What is installed here is always `crates/fs/ttydev`'s
/// `external_write`, which loads the embedder's own `extern "C"` pointer out
/// of `tty_driver_ops` and calls that; no C hands a value to this type.
///
/// A `&Tty` and a slice since 2026-10-17; it was an `unsafe fn` over a raw
/// terminal, a `*const c_void` and a length, whose one caller had all three
/// as borrows.
pub type ExternalWrite = fn(tty: &Tty, buf: &[u8], blocking: bool) -> c_int;

pub struct Tty {
    pub kind: Kind,
    pub num: c_int,
    /// Set once, at creation, and never after: an embedder's terminal is one
    /// from the moment it exists.
    external: Option<ExternalWrite>,
    external_closed: AtomicBool,
    /// How many holders there are. The registry's entry is not one: when this
    /// reaches zero the entry goes and the object with it.
    users: AtomicUsize,
    state: GuestLock<State>,
    /// Every descriptor open on this terminal, as the reverse edges they carry.
    fds: WakeSet,
    /// The other end of a pseudoterminal pair. Weak both ways: the strong
    /// reference is the registry's, and the master holds one *user* of the
    /// slave, which is what makes the slave outlive it.
    other: Mutex<std::sync::Weak<Tty>>,
}

impl Tty {
    fn new(kind: Kind, num: c_int) -> Arc<Tty> {
        Tty::new_with(kind, num, None)
    }

    fn new_with(kind: Kind, num: c_int, external: Option<ExternalWrite>) -> Arc<Tty> {
        Arc::new(Tty {
            kind,
            num,
            external,
            external_closed: AtomicBool::new(false),
            users: AtomicUsize::new(0),
            state: GuestLock::new(State::new(kind), 2),
            fds: WakeSet::default(),
            other: Mutex::new(std::sync::Weak::new()),
        })
    }

    pub fn lock(&self) -> GuestGuard<'_, State> {
        self.state.lock()
    }

    pub fn try_lock(&self) -> Option<GuestGuard<'_, State>> {
        self.state.try_lock()
    }

    pub fn other(&self) -> Option<Arc<Tty>> {
        self.other
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .upgrade()
    }

    fn set_other(&self, other: &Arc<Tty>) {
        *self.other.lock().unwrap_or_else(|e| e.into_inner()) = Arc::downgrade(other);
    }

    fn clear_other(&self) {
        *self.other.lock().unwrap_or_else(|e| e.into_inner()) = std::sync::Weak::new();
    }

    /// The side a terminal's settings and job control live on. For a pty pair
    /// that is always the slave: `tcsetattr` on either end changes the same
    /// line discipline, and the foreground group is the slave's.
    pub fn settings_side(self: &Arc<Tty>) -> Arc<Tty> {
        match self.kind {
            Kind::PtyMaster => self.other().unwrap_or_else(|| Arc::clone(self)),
            _ => Arc::clone(self),
        }
    }

    /// The foreground process group, which lives on the settings side: a
    /// signal the line discipline raises goes to the *slave's* foreground
    /// group whichever end produced it.
    pub fn foreground_group(self: &Arc<Tty>) -> c_int {
        self.settings_side().lock().jobctl.fg_group()
    }

    pub fn retain(&self) {
        self.users.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn is_external_closed(&self) -> bool {
        self.external_closed.load(Ordering::Acquire)
    }

    /// Wake every descriptor open on this terminal.
    ///
    /// Never with the terminal's own lock held: a watcher may ask the
    /// description for its readiness, and answering that takes this lock.
    pub fn wake_pollers(&self, events: c_int) {
        self.fds.notify(events as u32);
    }

    pub fn notify_produced(&self) {
        self.state.notify(PRODUCED);
    }

    pub fn notify_consumed(&self) {
        self.state.notify(CONSUMED);
    }

    /// Whether this is a master whose slave has been opened and has no open
    /// description left: Linux's `TTY_OTHER_CLOSED`. A read of one answers
    /// what is queued and then `EIO`, and a poll `POLLHUP`; a write still
    /// goes to the slave, and opening the slave again undoes it.
    ///
    /// A hung-up slave description is still open, so a slave that was hung up
    /// rather than closed leaves the master as it was.
    ///
    /// The one place two terminal locks are held at once, and always in this
    /// direction: master, then slave.
    pub fn half_closed_master(self: &Arc<Tty>) -> bool {
        if self.kind != Kind::PtyMaster {
            return false;
        }
        let Some(slave) = self.other() else {
            return true;
        };
        let state = slave.lock();
        state.ever_opened && state.descriptions == 0
    }
}

// ---------------------------------------------------------------------------
// The table of every terminal there is.

#[derive(Default)]
struct Terminals {
    /// One per driver, and the two pty halves are two drivers. They must be:
    /// a master and its slave share a *number*, and one table would have them
    /// collide on it. Written with one, `posix_openpt` published the slave and
    /// then found it again when it went to publish the master, took it for a
    /// master another thread had made, and handed back a slave with no other
    /// end — which the first run of this crate's tests said in one line.
    console: Option<Registry<Tty>>,
    pty_masters: Option<Registry<Tty>>,
    pty_slaves: Option<Registry<Tty>>,
    /// The strong reference for every live terminal, beside its registry slot.
    /// The registry stores an opaque pointer; this is what owns it.
    live: Vec<Arc<Tty>>,
}

impl Terminals {
    fn registry(&mut self, kind: Kind) -> &mut Registry<Tty> {
        match kind {
            Kind::Console => self
                .console
                .get_or_insert_with(|| Registry::new(MAX_CONSOLES)),
            Kind::PtyMaster => self
                .pty_masters
                .get_or_insert_with(|| Registry::new(MAX_PTYS)),
            Kind::PtySlave => self
                .pty_slaves
                .get_or_insert_with(|| Registry::new(MAX_PTYS)),
        }
    }

    fn find(&mut self, kind: Kind, num: c_int) -> Option<Arc<Tty>> {
        // The registry answers an identity; `live` is what owns the terminal.
        // Both sides were a `usize` until 2026-09-16, with `0` for "nothing
        // there" -- see `crates/fs/ttyreg`.
        let want = self.registry(kind).get(num)?;
        self.live
            .iter()
            .find(|tty| TtyId::of(tty) == want)
            .cloned()
    }

    fn insert(&mut self, tty: &Arc<Tty>) -> bool {
        if self.live.try_reserve(1).is_err() {
            return false;
        }
        if !self.registry(tty.kind).set(tty.num, Some(TtyId::of(tty))) {
            return false;
        }
        self.live.push(Arc::clone(tty));
        true
    }

    fn remove(&mut self, tty: &Arc<Tty>) {
        self.registry(tty.kind).clear(tty.num);
        self.live.retain(|live| !Arc::ptr_eq(live, tty));
    }
}

/// One lock for the whole table, taken before any terminal's own.
static TERMINALS: Mutex<Option<Terminals>> = Mutex::new(None);

fn terminals() -> MutexGuard<'static, Option<Terminals>> {
    TERMINALS.lock().unwrap_or_else(|e| e.into_inner())
}

fn with_terminals<T>(f: impl FnOnce(&mut Terminals) -> T) -> T {
    let mut guard = terminals();
    f(guard.get_or_insert_with(Terminals::default))
}

/// Find or make the terminal at `major`/`minor`, taking one user.
pub fn get(kind: Kind, num: c_int) -> Result<Arc<Tty>, c_int> {
    // Made outside the table lock when it turns out to be needed, because a
    // pty master's creation makes its slave too and that is more table work.
    let tty = with_terminals(|terminals| {
        let registry = terminals.registry(kind);
        // A number the registry does not have at all -- a minor past the
        // driver's limit, which a device node can name because a dev_t's minor
        // is 20 bits. Reachable from a guest: `mknod /dev/x c 136 65535`.
        if registry.get(num).is_none() && !registry.is_vacant(num) {
            return Err(ENXIO);
        }
        Ok(terminals.find(kind, num))
    })?;

    if let Some(tty) = tty {
        tty.retain();
        return Ok(tty);
    }

    // A slave is only ever made by its master.
    if kind == Kind::PtySlave {
        return Err(EIO);
    }
    let tty = Tty::new(kind, num);
    if kind == Kind::PtyMaster {
        crate::pty::make_pair(&tty)?;
    } else if let Some(console) = console() {
        let error = console.init(&tty, num);
        if error < 0 {
            crate::pty::unmake_pair(&tty);
            return Err(error);
        }
    }
    let inserted = with_terminals(|terminals| {
        // Another thread may have made it while this one was not holding the
        // table lock. Its object wins and this one is thrown away.
        if let Some(existing) = terminals.find(kind, num) {
            return Err(existing);
        }
        Ok(terminals.insert(&tty))
    });
    match inserted {
        Err(existing) => {
            crate::pty::unmake_pair(&tty);
            existing.retain();
            Ok(existing)
        }
        Ok(false) => {
            crate::pty::unmake_pair(&tty);
            Err(ENOMEM)
        }
        Ok(true) => {
            tty.retain();
            Ok(tty)
        }
    }
}

/// One user of a terminal -- Linux's `tty->count` -- together with the strong
/// count that keeps it allocated, both given back when this is dropped.
///
/// The two were paired by hand until 2026-09-30, and
/// `docs/changelog/2026-09-30-no-terminal-was-ever-freed.md` is what that
/// costs: a release that gave back the user and not the strong count left
/// every terminal allocated for the life of the process. A descriptor holds
/// one of these now, so the pairing is a type and not a convention.
pub struct User(Arc<Tty>);

impl User {
    /// Take back a user [`Self::into_raw`] handed across the C ABI.
    ///
    /// # Safety
    /// `raw` came from `into_raw`, and is not used again: this is its only
    /// owner.
    pub unsafe fn from_raw(raw: *const Tty) -> User {
        // SAFETY: the caller's contract; the strong count is the one
        // `Arc::into_raw` handed out with the user.
        User(unsafe { Arc::from_raw(raw) })
    }

    /// A new user of `tty`, with a strong count of its own.
    pub fn take(tty: &Arc<Tty>) -> User {
        tty.retain();
        User(Arc::clone(tty))
    }

    /// Find or make the terminal at `kind`/`num` and become a user of it.
    pub fn get(kind: Kind, num: c_int) -> Result<User, c_int> {
        get(kind, num).map(User)
    }

    /// An `Arc` that already carries one user, which [`get`] and the pty and
    /// external constructors answer.
    pub(crate) fn adopt(tty: Arc<Tty>) -> User {
        User(tty)
    }

    /// Hand the user and its strong count across the C ABI, for
    /// [`Self::from_raw`] to take back. The `Arc` is never dropped, so the
    /// count it holds goes with the pointer.
    pub fn into_raw(self) -> *const Tty {
        Arc::as_ptr(&std::mem::ManuallyDrop::new(self).0)
    }

    pub fn tty(&self) -> &Arc<Tty> {
        &self.0
    }

    /// The terminal with the user still taken, for a test that gives it back
    /// with [`release`] by hand.
    #[cfg(test)]
    pub(crate) fn into_arc(self) -> Arc<Tty> {
        let tty = Arc::clone(&self.0);
        tty.retain();
        tty
    }
}

impl Drop for User {
    fn drop(&mut self) {
        release(&self.0);
    }
}

/// Give up one user. The last one tears the terminal down.
pub fn release(tty: &Arc<Tty>) {
    // The count and the table go together: a lookup that finds a terminal
    // takes a user under the same lock, so it cannot find one this call is
    // about to remove.
    let last = with_terminals(|terminals| {
        let before = tty.users.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(before > 0, "released a terminal nobody held");
        if before != 1 {
            return false;
        }
        terminals.remove(tty);
        true
    });
    if last {
        crate::pty::cleanup(tty);
        if tty.kind == Kind::Console
            && let Some(console) = console()
        {
            console.cleanup(tty.num);
        }
    }
}

/// The lowest free pty number, reserved so nothing else takes it.
pub(crate) fn reserve_pty() -> Option<c_int> {
    with_terminals(|terminals| terminals.registry(Kind::PtySlave).reserve())
}

pub(crate) fn release_pty_reservation(num: c_int) {
    with_terminals(|terminals| terminals.registry(Kind::PtySlave).release_reservation(num));
}

/// Publish a slave the master has just made. The master holds one user of it.
pub(crate) fn publish_slave(slave: &Arc<Tty>) -> bool {
    slave.retain();
    with_terminals(|terminals| terminals.insert(slave))
}

/// Put an embedder's terminal in the table. Unlike a slave, the caller already
/// holds its user.
pub(crate) fn publish_external(terminal: &Arc<Tty>) -> bool {
    with_terminals(|terminals| terminals.insert(terminal))
}

pub(crate) fn unpublish_slave(slave: &Arc<Tty>) {
    with_terminals(|terminals| terminals.remove(slave));
}

/// What `/dev/pts` needs. Each completes under the table lock, so there is no
/// window between deciding a pty exists and using what it says.
///
/// A slave whose master has gone is not listed, though descriptions hung up
/// with it may keep it alive: Linux's `devpts_pty_kill` takes the node away
/// when the master closes, so opening it by name is `ENOENT`.
pub(crate) fn pty_exists(num: c_int) -> bool {
    with_terminals(|terminals| listed(terminals, num))
}

fn listed(terminals: &mut Terminals, num: c_int) -> bool {
    terminals.registry(Kind::PtySlave).is_live(num)
        && terminals.find(Kind::PtySlave, num).is_some_and(|slave| {
            (slave.external.is_some() && !slave.is_external_closed()) || slave.other().is_some()
        })
}

pub(crate) fn pty_attrs(num: c_int) -> Option<(u32, u32, u32)> {
    with_terminals(|terminals| {
        if !listed(terminals, num) {
            return None;
        }
        terminals.registry(Kind::PtySlave).attrs(num)
    })
}

pub(crate) fn pty_set_attrs(num: c_int, uid: u32, gid: u32, perms: u32) -> bool {
    with_terminals(|terminals| {
        terminals
            .registry(Kind::PtySlave)
            .set_attrs(num, uid, gid, perms)
    })
}

pub(crate) fn pty_set_attr(num: c_int, which: c_int, value: u32) -> bool {
    with_terminals(|terminals| {
        terminals
            .registry(Kind::PtySlave)
            .set_attr(num, which, value)
    })
}

pub(crate) fn pty_next(from: c_int) -> Option<c_int> {
    with_terminals(|terminals| {
        let mut at = from;
        loop {
            let num = terminals.registry(Kind::PtySlave).next_live(at)?;
            if listed(terminals, num) {
                return Some(num);
            }
            at = num + 1;
        }
    })
}

/// Whether the console driver has been enabled by an embedder.
pub fn console_enabled(major: c_int) -> bool {
    console().is_some_and(|c| c.enabled(major))
}

// ---------------------------------------------------------------------------
// Opening and closing.

/// One open file description of a terminal: the user it holds, and the
/// hangup it was opened after.
///
/// Every read, write, poll and ioctl names one of these rather than the
/// terminal, because whether it is hung up is a property of the description:
/// a hangup leaves every description open at that moment answering end of
/// file, `EIO` and `POLLHUP`, while the terminal is opened again and works.
pub struct Open {
    user: User,
    generation: u64,
}

impl Open {
    /// Attach a description to the terminal `user` is of. `watchers` is its
    /// reverse edge, `flags` its open flags.
    pub fn new(user: User, watchers: &Arc<Watchers>, flags: c_int) -> Result<Open, c_int> {
        let err = attach(user.tty(), watchers, flags);
        if err < 0 {
            return Err(err);
        }
        let generation = {
            let mut state = user.tty().lock();
            state.descriptions += 1;
            state.ever_opened = true;
            state.hung_up = false;
            state.generation
        };
        Ok(Open { user, generation })
    }

    pub fn tty(&self) -> &Arc<Tty> {
        self.user.tty()
    }

    /// Whether the terminal has been hung up since this was opened.
    pub fn hung_up(&self) -> bool {
        self.tty().lock().generation != self.generation
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    /// A description for a test that calls the operations directly, opened
    /// `O_NOCTTY` so it claims nothing.
    #[cfg(test)]
    pub(crate) fn of(tty: &Arc<Tty>) -> Open {
        Open::new(User::take(tty), &Arc::new(Watchers::default()), jobctl::O_NOCTTY)
            .expect("an open")
    }
}

/// Attach a descriptor. `watchers` is its reverse edge, `flags` its open flags.
///
/// What every open does; [`Open::new`] is this and the description's record.
/// `abi::tty_open`, the embedder's, is this alone.
pub(crate) fn attach(tty: &Arc<Tty>, watchers: &Arc<Watchers>, flags: c_int) -> c_int {
    // A descriptor the terminal cannot record is one its wakeups would never
    // reach, which is a hang rather than a failed open.
    if !tty.fds.add(watchers) {
        return ENOMEM;
    }

    // A pty *master* never becomes a controlling terminal, whatever the flags
    // say. Linux's tty_open sets its `noctty` unconditionally for one: the
    // master is the side a terminal emulator holds, and the process group being
    // controlled is on the slave. Letting it be claimed meant that a session
    // leader with no terminal -- which is every guest started without a console
    // -- acquired one by calling posix_openpt, and then closing the master hung
    // up its own session.
    if !JobControl::open_claims(flags, tty.kind == Kind::PtyMaster) {
        return 0;
    }
    crate::ops::with_pids_lock(|pids| {
        let claim = {
            let state = tty.lock();
            state.jobctl.unowned() && task().is_session_leader()
        };
        if claim {
            task().set_controlling(pids, tty);
        }
    });
    0
}

/// Detach a description and give up the user its open took, which is the
/// description going out of scope at the end.
pub fn close(open: Open, watchers: &Arc<Watchers>) {
    open.tty().fds.remove(watchers);
    drop(open);
}

impl Drop for Open {
    fn drop(&mut self) {
        let tty = self.user.tty();
        let last = {
            let mut state = tty.lock();
            state.descriptions -= 1;
            state.descriptions == 0
        };
        // The slave's last description makes its master half closed: a
        // reader blocked on it is woken to find `EIO`, and a poller `POLLHUP`.
        // The master is *not* hung up -- it was until 2026-11-12, for good, so
        // reopening the slave left the master at end of file for ever, where
        // Linux's `TTY_OTHER_CLOSED` is undone by the next open.
        if last
            && tty.kind == Kind::PtySlave
            && let Some(master) = tty.other()
        {
            master.notify_produced();
            master.wake_pollers(POLL_HUP | POLL_READ);
        }
    }
}

// ---------------------------------------------------------------------------
// Hanging up.

/// Linux's `__tty_hangup`: every description open now is hung up, the
/// queued input goes, the session loses the terminal, and its leader is told.
///
/// The terminal itself survives. A description opened after this is an
/// ordinary one -- which is what makes `vhangup` usable, and why a hangup
/// was a flag on the terminal until 2026-11-12 and is a count now: the flag
/// was permanent, so a terminal hung up once could never be used again.
pub fn hangup(tty: &Arc<Tty>) {
    let session = {
        let mut state = tty.lock();
        state.generation += 1;
        state.hung_up = true;
        state.ldisc.buffer.clear();
        drop(state.ldisc.take_echo());
        // Taken here, so a second hangup -- a pty teardown reaches this from
        // both ends -- finds nobody to tell.
        let session = state.jobctl.hangup_target();
        state.jobctl.detach();
        session
    };
    tty.notify_produced();
    tty.notify_consumed();
    // Without the terminal's lock: a watcher may ask the description for its
    // readiness, and answering that takes it. This used to be an open-coded
    // copy of poll_wakeup with a trylock, because it is reached from a terminal
    // being destroyed on the host's main thread during exit and taking the
    // descriptor lock there deadlocked -- so a hangup was dropped whenever that
    // lock was busy. There is no such lock any more.
    tty.wake_pollers(POLL_HUP | POLL_READ | POLL_WRITE | POLL_ERR);
    if let Some(session) = session {
        // **This is the one place that reaches the process layer without an
        // ioctl above it**, and until 2026-09-16 it called `hangup` with
        // `pids_lock` held by nobody -- while the implementation walks the pid
        // registry with `session_at`, whose safety note says the lock is held.
        // The other five "pids_lock held" methods are called from `ioctl`,
        // `open` and `set_winsize`, which all take it; a hangup arrives from a
        // *descriptor closing* or from `vhangup`, which do not.
        //
        // It cannot already be held, and the reason is a property of what owns
        // a terminal rather than a survey of callers: the paths that release a
        // terminal reference under `pids_lock` are a thread group giving up its
        // controlling one (`Ctty::drop`, `clear_if`, `task_leave_session`), and
        // a controlling terminal is never a pty *master* (see `open_claims`
        // above) while a pty *slave* has a user held by its master for as long
        // as the master exists (`publish_slave`). So the reference a session
        // gives back is never the last one, and the teardown that reaches here
        // never runs underneath it. Every caller holds a user of `tty` across
        // this call for the same reason: the references `steal_controlling`
        // drops under the lock are then never the last. `-DLOCK_DEBUG=1` is
        // what checks that, since getting it wrong is recursive locking rather
        // than a wrong answer.
        crate::ops::with_pids_lock(|pids| {
            task().steal_controlling(pids, session, TtyId::of(tty));
            task().hangup(pids, session);
        });
    }
}

/// Close the embedder side of a `pty_open_fake` terminal, once: hides its
/// `/dev/pts` node, refuses new opens, and hangs up open descriptions as
/// closing a pty master does.
pub fn close_external(tty: &Arc<Tty>) {
    if tty.external.is_some() && !tty.external_closed.swap(true, Ordering::AcqRel) {
        hangup(tty);
    }
}

/// The session leader `held`'s terminal belongs to has exited: Linux's
/// `disassociate_ctty(1)`. `held` is the leader's own reference, taken from
/// its group by the exit.
///
/// The foreground group gets `SIGHUP` -- without the `SIGCONT` a hangup
/// sends, because the leader is not there to resume -- and every process in
/// the session loses the terminal. A pty is left working, since whoever holds
/// its master is still there; any other terminal is hung up as well.
pub fn session_leader_exited(held: User) {
    let tty = held.tty();
    let (session, fg) = {
        let state = tty.lock();
        (state.jobctl.session(), state.jobctl.fg_group())
    };
    if !tty.kind.is_pty() {
        hangup(tty);
    }
    crate::ops::with_pids_lock(|pids| {
        if fg > 0 {
            task().signal_group_locked(pids, fg, crate::tty::SIGHUP);
        }
        if session != 0 {
            task().steal_controlling(pids, session, TtyId::of(tty));
        }
    });
    tty.lock().jobctl.detach();
    // Given back without `pids_lock`: it may be the last user.
    drop(held);
}

// ---------------------------------------------------------------------------

/// The window size, and the SIGWINCH that goes with changing it.
pub(crate) fn set_winsize(tty: &Arc<Tty>, winsize: Winsize) {
    crate::ops::with_pids_lock(|pids| {
        let settings = tty.settings_side();
        let fg = {
            let mut state = settings.lock();
            state.winsize = winsize;
            state.jobctl.fg_group()
        };
        if fg != 0 {
            task().signal_group_locked(pids, fg, SIGWINCH);
        }
    });
}

/// Give up this terminal's claim on a session that is going away.
pub fn disown(tty: &Arc<Tty>) {
    tty.lock().jobctl.disown();
}

pub fn users(tty: &Tty) -> usize {
    tty.users.load(Ordering::Relaxed)
}

/// Record that a session owns this terminal. The reference is the caller's to
/// take: `set_controlling` on the task side does both together.
pub fn claim(tty: &Arc<Tty>, sid: Pid, pgid: Pid) {
    tty.settings_side().lock().jobctl.claim(sid, pgid);
}

pub fn termios(tty: &Arc<Tty>) -> Termios {
    tty.settings_side().lock().termios
}

/// The window size and termios the console driver read off the host, before
/// anything has opened it. `None` leaves the default termios: the host's
/// stdin is not a terminal.
pub fn set_console_state(tty: &Tty, winsize: Winsize, termios: Option<Termios>) {
    let mut state = tty.lock();
    state.winsize = winsize;
    if let Some(termios) = termios {
        state.termios = termios;
    }
}

pub(crate) fn set_termios(tty: &Arc<Tty>, termios: Termios) {
    tty.settings_side().lock().termios = termios;
}

// ---------------------------------------------------------------------------
// What the pty half needs of the object.

/// A terminal that is not in the table yet. Only a master's creation of its
/// slave uses this; everything else goes through [`get`].
pub(crate) fn make(kind: Kind, num: c_int) -> Arc<Tty> {
    Tty::new(kind, num)
}

/// A terminal whose writes go to an embedder rather than to another end.
pub(crate) fn make_external(num: c_int, write: ExternalWrite) -> Arc<Tty> {
    Tty::new_with(Kind::PtySlave, num, Some(write))
}

pub(crate) fn is_external(tty: &Tty) -> bool {
    tty.external.is_some()
}

pub(crate) fn link_pair(master: &Arc<Tty>, slave: &Arc<Tty>) {
    master.set_other(slave);
    slave.set_other(master);
}

pub(crate) fn unlink_pair(master: &Arc<Tty>, slave: &Arc<Tty>) {
    master.clear_other();
    slave.clear_other();
}
