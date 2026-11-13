//! Terminal settings and input state types.

// The termios bits this reads. Values from fs/tty.h, which takes them from
// Linux; asserted against the guest's own headers by tests/guest/src/bin/
// tty_ldisc.rs rather than trusted here.
pub const ISIG: u32 = 1 << 0;
pub const ICANON: u32 = 1 << 1;
pub const ECHO: u32 = 1 << 3;
pub const ECHOE: u32 = 1 << 4;
pub const ECHOK: u32 = 1 << 5;
pub const ECHONL: u32 = 1 << 6;
pub const NOFLSH: u32 = 1 << 7;
pub const ECHOCTL: u32 = 1 << 9;
/// 1 << 11. `fs/tty.h` had it as `1 << 6`, which is `ECHONL` -- see the note
/// there. Nothing read the bit until this file started honouring it.
pub const ECHOKE: u32 = 1 << 11;

// c_cflag. The discipline does not read these -- they describe the line rather
// than the editing -- but a terminal's *default* is made of them, and a
// default of zero says the line is hung up and characters are five bits wide.
/// The baud rate field.
pub const CBAUD: u32 = 0o10017;
/// 38400 baud, which is what `INIT_C_CFLAG` uses and what every pty reports.
/// **Zero is not "unset"**: `B0` means hang up the line.
pub const B38400: u32 = 0o17;
/// The character-size field, and its only sensible value.
pub const CSIZE: u32 = 0o60;
pub const CS8: u32 = 0o60;
/// Enable the receiver. A terminal with this clear accepts no input.
pub const CREAD: u32 = 0o200;

pub const INLCR: u32 = 1 << 6;
pub const IGNCR: u32 = 1 << 7;
pub const ICRNL: u32 = 1 << 8;

// Indices into c_cc.
pub const VINTR: usize = 0;
pub const VQUIT: usize = 1;
pub const VERASE: usize = 2;
pub const VKILL: usize = 3;
pub const VEOF: usize = 4;
pub const VSTART: usize = 8;
pub const VSTOP: usize = 9;
pub const VSUSP: usize = 10;
pub const VEOL: usize = 11;

pub const SIGINT: i32 = 2;
pub const SIGQUIT: i32 = 3;
pub const SIGTSTP: i32 = 20;

/// The terminal settings the discipline reads, as the guest's `struct termios`
/// holds them.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Termios {
    pub iflags: u32,
    pub oflags: u32,
    pub cflags: u32,
    pub lflags: u32,
    pub line: u8,
    pub cc: [u8; 19],
}

/// The guest's `struct termios2`: the same settings and two explicit speeds.
///
/// **This is what a modern glibc's `tcgetattr` and `isatty` actually use.**
/// `TCGETS2` was not implemented, so `isatty()` answered *false for every
/// terminal* on Ubuntu — sshd's `openpty` then failed `ttyname` and refused
/// every interactive session. musl uses `TCGETS`, which is why alpine was
/// unaffected and why nothing here had noticed.
///
/// The layout is `struct termios` followed by `c_ispeed` and `c_ospeed`, and
/// the ioctl number carries the size: `TCGETS2` is `0x802c542a`, whose `0x2c`
/// is 44. `the_termios2_layout_is_the_guests` asserts every offset, because
/// this is a wire format and the rule in this tree is that one goes where its
/// offsets can be checked.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Termios2 {
    pub iflags: u32,
    pub oflags: u32,
    pub cflags: u32,
    pub lflags: u32,
    pub line: u8,
    pub cc: [u8; 19],
    pub ispeed: u32,
    pub ospeed: u32,
}

plain::plain! {
    Termios { iflags, oflags, cflags, lflags, line, cc }
    Termios2 { iflags, oflags, cflags, lflags, line, cc, ispeed, ospeed }
}

/// The value in `CBAUD` that means "the two speed fields are the answer" —
/// Linux's `BOTHER`. Everything else in that field encodes a rate.
pub const BOTHER: u32 = 0o010000;

impl Termios2 {
    /// The 36-byte prefix, which is what `TCGETS` reports.
    pub fn settings(&self) -> Termios {
        Termios {
            iflags: self.iflags,
            oflags: self.oflags,
            cflags: self.cflags,
            lflags: self.lflags,
            line: self.line,
            cc: self.cc,
        }
    }

    /// The whole thing, from the settings and the two speeds a terminal keeps
    /// beside them.
    pub fn of(t: &Termios, ispeed: u32, ospeed: u32) -> Termios2 {
        Termios2 {
            iflags: t.iflags,
            oflags: t.oflags,
            cflags: t.cflags,
            lflags: t.lflags,
            line: t.line,
            cc: t.cc,
            ispeed,
            ospeed,
        }
    }
}

/// What happened to one byte.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    /// Taken. Echo may have been produced and a signal may be due.
    Consumed(Outcome),
    /// The buffer is full. The caller waits for a reader to make room and
    /// offers the same byte again; nothing was echoed and nothing was taken.
    NeedRoom,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// A signal for the foreground process group, or 0.
    pub signal: i32,
    /// A reader may now have a complete line, or in raw mode any byte at all.
    pub wake: bool,
}
