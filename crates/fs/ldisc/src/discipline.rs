//! The line discipline proper: what a byte arriving from a terminal means.
//!
//! This is the part `fs/tty.c` used to do inline, holding `tty->lock`, in one
//! function with a `goto` into the middle of a loop. It is a state machine
//! over the termios flags and it touches nothing but the buffer beside it, so
//! it belongs here — and it is where the subtle bugs are, because "what does
//! backspace do" has about eight answers depending on four flag bits.
//!
//! What stays in C is what this cannot do: block when the buffer is full, and
//! deliver a signal to a process group. [`Step::NeedRoom`] hands the first
//! back to the caller, and [`Outcome::signal`] hands back the second.
//!
//! Echo is accumulated here rather than written, because the caller must write
//! it *after* dropping `tty->lock` — for a pty the echo goes to the other end,
//! whose input path takes the other end's lock, and doing that under this one
//! deadlocked.

use crate::buffer::LineBuffer;

#[path = "types.rs"]
mod types;
pub use types::*;

/// Whether a character is echoed as `^X` rather than itself.
fn is_ctl_echo(t: &Termios, ch: u8) -> bool {
    t.lflags & ECHOCTL != 0
        && (ch < b' ' || ch == 0x7f)
        && ch != b'\t'
        && ch != b'\n'
        && ch != t.cc[VSTART]
        && ch != t.cc[VSTOP]
}

pub struct Discipline {
    pub buffer: LineBuffer,
    /// Echo bytes produced but not yet written out, because the caller has to
    /// drop the terminal's lock first.
    echo: Vec<u8>,
}

impl Default for Discipline {
    fn default() -> Self {
        Self::new()
    }
}

impl Discipline {
    pub fn new() -> Discipline {
        Discipline {
            buffer: LineBuffer::new(),
            echo: Vec::new(),
        }
    }

    fn echo_bytes(&mut self, bytes: &[u8]) {
        // The echo of a terminal that nobody drains is not worth an
        // unbounded allocation; a line's worth is generous.
        if self.echo.len() + bytes.len() > 4096 {
            return;
        }
        self.echo.extend_from_slice(bytes);
    }

    /// Echoes a character the way it should appear: `^X` for a control
    /// character when ECHOCTL is on, otherwise itself.
    fn echo_char(&mut self, t: &Termios, ch: u8) {
        if is_ctl_echo(t, ch) {
            self.echo_bytes(b"^");
            self.echo_bytes(&[ch ^ 0x40]);
        } else {
            self.echo_bytes(&[ch]);
        }
    }

    /// Erases one character from the buffer and from the screen.
    fn erase_one(&mut self, t: &Termios, visible: bool) -> bool {
        match self.buffer.erase() {
            Some(erased) => {
                if visible {
                    self.echo_bytes(b"\x08 \x08");
                    // A control character was echoed as two columns, so two
                    // have to be rubbed out.
                    if is_ctl_echo(t, erased) {
                        self.echo_bytes(b"\x08 \x08");
                    }
                }
                true
            }
            None => false,
        }
    }

    /// The signal a character raises, if any, before anything else looks at it.
    fn signal_for(&self, t: &Termios, ch: u8) -> Option<i32> {
        if t.lflags & ISIG == 0 || ch == 0 {
            // A c_cc entry of 0 is disabled, so a NUL matches nothing.
            return None;
        }
        if ch == t.cc[VINTR] {
            Some(SIGINT)
        } else if ch == t.cc[VQUIT] {
            Some(SIGQUIT)
        } else if ch == t.cc[VSUSP] {
            Some(SIGTSTP)
        } else {
            None
        }
    }

    /// Feeds one byte.
    pub fn input(&mut self, t: &Termios, ch: u8) -> Step {
        if t.lflags & ICANON != 0 {
            self.canonical(t, ch)
        } else {
            self.raw(t, ch)
        }
    }

    fn raw(&mut self, t: &Termios, ch: u8) -> Step {
        if let Some(sig) = self.signal_for(t, ch) {
            if t.lflags & NOFLSH == 0 {
                self.buffer.clear();
            }
            // Consumed: a signal character is not delivered to the reader.
            return Step::Consumed(Outcome {
                signal: sig,
                wake: false,
            });
        }
        if self.buffer.is_full() {
            return Step::NeedRoom;
        }
        self.buffer.push(ch, false);
        if t.lflags & ECHO != 0 {
            self.echo_char(t, ch);
        }
        Step::Consumed(Outcome {
            signal: 0,
            wake: true,
        })
    }

    fn canonical(&mut self, t: &Termios, ch: u8) -> Step {
        // Input translation comes first, and IGNCR drops the byte outright.
        let ch = if t.iflags & INLCR != 0 && ch == b'\n' {
            b'\r'
        } else if t.iflags & ICRNL != 0 && ch == b'\r' {
            b'\n'
        } else {
            ch
        };
        if t.iflags & IGNCR != 0 && ch == b'\r' {
            return Step::Consumed(Outcome::default());
        }

        // A c_cc entry of 0 disables it, so NUL is an ordinary character and
        // must not match any of the comparisons below.
        if ch != 0 {
            if ch == t.cc[VERASE] {
                return self.erase(t, false);
            }
            if ch == t.cc[VKILL] {
                return self.erase(t, true);
            }
            if ch == t.cc[VEOF] {
                // End of file: a flag with no character, so a reader sees a
                // complete line of length zero and reports end of input.
                if self.buffer.is_full() {
                    return Step::NeedRoom;
                }
                self.buffer.push(0, true);
                return Step::Consumed(Outcome {
                    signal: 0,
                    wake: true,
                });
            }
            if ch == b'\n' || ch == t.cc[VEOL] {
                if self.buffer.is_full() {
                    return Step::NeedRoom;
                }
                // Echoed before the line is handed over, so it appears ahead
                // of whatever the reader prints. ECHONL asks for the newline
                // to be echoed even with ECHO off, which is what a password
                // prompt wants: the typing is invisible and the Enter is not.
                if t.lflags & ECHO != 0 || t.lflags & ECHONL != 0 {
                    self.echo_bytes(b"\r\n");
                }
                self.buffer.push(ch, true);
                return Step::Consumed(Outcome {
                    signal: 0,
                    wake: true,
                });
            }
            if let Some(sig) = self.signal_for(t, ch) {
                if t.lflags & NOFLSH == 0 {
                    self.buffer.clear();
                }
                return Step::Consumed(Outcome {
                    signal: sig,
                    wake: false,
                });
            }
        }

        if self.buffer.is_full() {
            return Step::NeedRoom;
        }
        self.buffer.push(ch, false);
        if t.lflags & ECHO != 0 {
            self.echo_char(t, ch);
        }
        Step::Consumed(Outcome::default())
    }

    /// ERASE removes one character, KILL removes the line.
    ///
    /// The C had `// FIXME ECHOE and ECHOK are supposed to enable these` over
    /// this, and it read the flags the wrong way round: it started from ECHOK
    /// for both and switched to ECHOE only when erasing a character that was
    /// there. What the flags actually mean:
    ///
    /// - `ECHOE`: ERASE rubs the character off the screen. Without it the
    ///   character is removed from the buffer and the screen is left alone.
    /// - `ECHOK`: KILL prints a newline, so the discarded line stays visible
    ///   above the fresh one.
    /// - `ECHOKE`: KILL rubs the whole line off the screen instead, and takes
    ///   precedence over `ECHOK`.
    ///
    /// All of them require `ECHO`; with echo off, nothing is ever written.
    fn erase(&mut self, t: &Termios, whole_line: bool) -> Step {
        let echoing = t.lflags & ECHO != 0;
        if !whole_line {
            let visible = echoing && t.lflags & ECHOE != 0;
            self.erase_one(t, visible);
            return Step::Consumed(Outcome::default());
        }

        // KILL.
        let rub_out = echoing && t.lflags & ECHOKE != 0;
        while self.erase_one(t, rub_out) {}
        if echoing && !rub_out && t.lflags & ECHOK != 0 {
            self.echo_bytes(b"\n");
        }
        Step::Consumed(Outcome::default())
    }

    /// Takes the accumulated echo, leaving nothing behind.
    pub fn take_echo(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.echo)
    }

    pub fn echo_len(&self) -> usize {
        self.echo.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `struct termios2`'s layout, which is the wire format `TCGETS2` carries.
    ///
    /// The ioctl number encodes it: `TCGETS2` is `0x802c542a` and `0x2c` is 44.
    /// A wrong offset here is a `tcgetattr` that reads the wrong field, which
    /// is a terminal in the wrong mode and no error anywhere.
    #[test]
    fn the_termios2_layout_is_the_guests() {
        use std::mem::{offset_of, size_of};
        assert_eq!(size_of::<Termios>(), 36);
        assert_eq!(size_of::<Termios2>(), 44, "the 0x2c in TCGETS2");
        assert_eq!(offset_of!(Termios2, iflags), 0);
        assert_eq!(offset_of!(Termios2, oflags), 4);
        assert_eq!(offset_of!(Termios2, cflags), 8);
        assert_eq!(offset_of!(Termios2, lflags), 12);
        assert_eq!(offset_of!(Termios2, line), 16);
        assert_eq!(offset_of!(Termios2, cc), 17);
        assert_eq!(offset_of!(Termios2, ispeed), 36);
        assert_eq!(offset_of!(Termios2, ospeed), 40);
        // And the prefix is `struct termios` field for field, which is what
        // lets `TCGETS` and `TCGETS2` answer from one stored value.
        assert_eq!(offset_of!(Termios, iflags), offset_of!(Termios2, iflags));
        assert_eq!(offset_of!(Termios, cc), offset_of!(Termios2, cc));
        let t = Termios {
            iflags: 1,
            oflags: 2,
            cflags: 3,
            lflags: 4,
            line: 5,
            cc: [6; 19],
        };
        let two = Termios2::of(&t, 38400, 9600);
        assert_eq!(two.ispeed, 38400);
        assert_eq!(two.ospeed, 9600);
        let back = two.settings();
        assert_eq!(
            (back.iflags, back.oflags, back.cflags, back.lflags),
            (1, 2, 3, 4)
        );
        assert_eq!((back.line, back.cc), (5, [6; 19]));
    }

    fn cooked() -> Termios {
        let mut t = Termios {
            lflags: ICANON | ECHO | ISIG | ECHOE | ECHOK | ECHOCTL,
            ..Default::default()
        };
        t.iflags = ICRNL;
        t.cc[VINTR] = 3; // ^C
        t.cc[VQUIT] = 28; // ^\
        t.cc[VERASE] = 0x7f; // DEL
        t.cc[VKILL] = 21; // ^U
        t.cc[VEOF] = 4; // ^D
        t.cc[VSUSP] = 26; // ^Z
        t.cc[VEOL] = 0;
        t.cc[VSTART] = 17;
        t.cc[VSTOP] = 19;
        t
    }

    fn raw_mode() -> Termios {
        let mut t = cooked();
        t.lflags &= !(ICANON | ECHO);
        t
    }

    fn feed(d: &mut Discipline, t: &Termios, s: &[u8]) -> Vec<i32> {
        let mut signals = Vec::new();
        for &ch in s {
            match d.input(t, ch) {
                Step::Consumed(o) => {
                    if o.signal != 0 {
                        signals.push(o.signal);
                    }
                }
                Step::NeedRoom => panic!("unexpectedly full"),
            }
        }
        signals
    }

    fn line(d: &mut Discipline) -> Vec<u8> {
        let n = d.buffer.canon_len().expect("a complete line");
        let mut out = vec![0u8; n];
        let got = d.buffer.read(&mut out);
        out.truncate(got);
        out
    }

    #[test]
    fn a_line_is_available_only_once_it_is_ended() {
        let t = cooked();
        let mut d = Discipline::new();
        feed(&mut d, &t, b"hi");
        assert_eq!(d.buffer.canon_len(), None, "no newline yet");
        feed(&mut d, &t, b"\n");
        assert_eq!(line(&mut d), b"hi\n");
    }

    #[test]
    fn carriage_return_becomes_a_newline_with_icrnl() {
        let t = cooked();
        let mut d = Discipline::new();
        feed(&mut d, &t, b"hi\r");
        assert_eq!(line(&mut d), b"hi\n");
    }

    #[test]
    fn ignored_carriage_returns_are_dropped() {
        let mut t = cooked();
        t.iflags = IGNCR;
        let mut d = Discipline::new();
        feed(&mut d, &t, b"a\rb\n");
        assert_eq!(line(&mut d), b"ab\n");
    }

    #[test]
    fn newlines_become_carriage_returns_with_inlcr() {
        let mut t = cooked();
        t.iflags = INLCR;
        let mut d = Discipline::new();
        // Translated to \r, which is not a line ending, so nothing completes.
        feed(&mut d, &t, b"a\n");
        assert_eq!(d.buffer.canon_len(), None);
    }

    #[test]
    fn echo_repeats_what_was_typed() {
        let t = cooked();
        let mut d = Discipline::new();
        feed(&mut d, &t, b"ab\n");
        assert_eq!(d.take_echo(), b"ab\r\n");
    }

    #[test]
    fn echonl_echoes_the_newline_even_with_echo_off() {
        let mut t = cooked();
        t.lflags &= !ECHO;
        t.lflags |= ECHONL;
        let mut d = Discipline::new();
        feed(&mut d, &t, b"secret\n");
        // The typing is invisible; the Enter is not. This is what a password
        // prompt asks for.
        assert_eq!(d.take_echo(), b"\r\n");
        assert_eq!(line(&mut d), b"secret\n");
    }

    #[test]
    fn echo_off_writes_nothing() {
        let mut t = cooked();
        t.lflags &= !ECHO;
        let mut d = Discipline::new();
        feed(&mut d, &t, b"ab\n");
        assert!(d.take_echo().is_empty());
        assert_eq!(line(&mut d), b"ab\n", "and the line is still read");
    }

    #[test]
    fn a_control_character_echoes_as_caret_with_echoctl() {
        let t = cooked();
        let mut d = Discipline::new();
        feed(&mut d, &t, &[1]); // ^A
        assert_eq!(d.take_echo(), b"^A");
    }

    #[test]
    fn tab_and_newline_are_not_caret_escaped() {
        let t = cooked();
        let mut d = Discipline::new();
        feed(&mut d, &t, b"\t");
        assert_eq!(d.take_echo(), b"\t");
    }

    // --- the ERASE/KILL rules, which the C had the wrong way round ---

    #[test]
    fn erase_with_echoe_rubs_the_character_off_the_screen() {
        let t = cooked(); // ECHOE on
        let mut d = Discipline::new();
        feed(&mut d, &t, b"ab");
        d.take_echo();
        feed(&mut d, &t, &[0x7f]);
        assert_eq!(d.take_echo(), b"\x08 \x08");
        feed(&mut d, &t, b"\n");
        assert_eq!(line(&mut d), b"a\n");
    }

    #[test]
    fn erase_without_echoe_removes_the_character_but_not_the_ink() {
        let mut t = cooked();
        t.lflags &= !ECHOE;
        let mut d = Discipline::new();
        feed(&mut d, &t, b"ab");
        d.take_echo();
        feed(&mut d, &t, &[0x7f]);
        assert!(d.take_echo().is_empty(), "nothing rubbed out");
        feed(&mut d, &t, b"\n");
        assert_eq!(line(&mut d), b"a\n", "but the character is gone");
    }

    #[test]
    fn erasing_a_control_character_rubs_out_both_columns() {
        let t = cooked();
        let mut d = Discipline::new();
        feed(&mut d, &t, &[1]); // ^A, echoed as two columns
        d.take_echo();
        feed(&mut d, &t, &[0x7f]);
        assert_eq!(d.take_echo(), b"\x08 \x08\x08 \x08");
    }

    #[test]
    fn erase_at_the_start_of_a_line_does_nothing() {
        let t = cooked();
        let mut d = Discipline::new();
        feed(&mut d, &t, &[0x7f]);
        assert!(d.take_echo().is_empty());
        assert_eq!(d.buffer.len(), 0);
    }

    #[test]
    fn erase_will_not_cross_into_a_finished_line() {
        let t = cooked();
        let mut d = Discipline::new();
        feed(&mut d, &t, b"one\n");
        d.take_echo();
        feed(&mut d, &t, &[0x7f]);
        assert!(
            d.take_echo().is_empty(),
            "the previous line is not editable"
        );
        assert_eq!(line(&mut d), b"one\n");
    }

    #[test]
    fn kill_with_echok_ends_the_line_so_it_stays_visible() {
        let mut t = cooked();
        t.lflags &= !ECHOKE; // ECHOK only
        let mut d = Discipline::new();
        feed(&mut d, &t, b"hello");
        d.take_echo();
        feed(&mut d, &t, &[21]); // ^U
        assert_eq!(d.take_echo(), b"\n");
        assert_eq!(d.buffer.len(), 0, "the line is discarded either way");
    }

    #[test]
    fn kill_with_echoke_rubs_the_whole_line_off() {
        let mut t = cooked();
        t.lflags |= ECHOKE;
        let mut d = Discipline::new();
        feed(&mut d, &t, b"abc");
        d.take_echo();
        feed(&mut d, &t, &[21]);
        assert_eq!(d.take_echo(), b"\x08 \x08".repeat(3));
        assert_eq!(d.buffer.len(), 0);
    }

    #[test]
    fn kill_without_either_flag_is_silent() {
        let mut t = cooked();
        t.lflags &= !(ECHOK | ECHOKE);
        let mut d = Discipline::new();
        feed(&mut d, &t, b"abc");
        d.take_echo();
        feed(&mut d, &t, &[21]);
        assert!(d.take_echo().is_empty());
        assert_eq!(d.buffer.len(), 0);
    }

    #[test]
    fn kill_with_echo_off_writes_nothing_whatever_the_other_flags_say() {
        let mut t = cooked();
        t.lflags &= !ECHO;
        t.lflags |= ECHOK | ECHOKE;
        let mut d = Discipline::new();
        feed(&mut d, &t, b"abc");
        feed(&mut d, &t, &[21]);
        assert!(d.take_echo().is_empty());
    }

    // --- signals ---

    #[test]
    fn interrupt_raises_a_signal_and_discards_the_line() {
        let t = cooked();
        let mut d = Discipline::new();
        feed(&mut d, &t, b"half");
        let sigs = feed(&mut d, &t, &[3]); // ^C
        assert_eq!(sigs, vec![SIGINT]);
        assert_eq!(d.buffer.len(), 0, "NOFLSH is off, so the line goes");
    }

    #[test]
    fn noflsh_keeps_the_line() {
        let mut t = cooked();
        t.lflags |= NOFLSH;
        let mut d = Discipline::new();
        feed(&mut d, &t, b"half");
        assert_eq!(feed(&mut d, &t, &[3]), vec![SIGINT]);
        assert_eq!(d.buffer.len(), 4);
    }

    #[test]
    fn isig_off_makes_the_character_ordinary() {
        let mut t = cooked();
        t.lflags &= !ISIG;
        let mut d = Discipline::new();
        assert!(feed(&mut d, &t, &[3]).is_empty());
        feed(&mut d, &t, b"\n");
        assert_eq!(line(&mut d), b"\x03\n");
    }

    #[test]
    fn quit_and_suspend_raise_their_own_signals() {
        let t = cooked();
        let mut d = Discipline::new();
        assert_eq!(feed(&mut d, &t, &[28]), vec![SIGQUIT]);
        assert_eq!(feed(&mut d, &t, &[26]), vec![SIGTSTP]);
    }

    /// A `c_cc` entry of zero means "disabled", so a NUL byte must not match
    /// every unset entry at once.
    #[test]
    fn a_nul_byte_matches_no_disabled_control_character() {
        let mut t = cooked();
        t.cc[VINTR] = 0;
        t.cc[VERASE] = 0;
        t.cc[VKILL] = 0;
        t.cc[VEOF] = 0;
        let mut d = Discipline::new();
        assert!(feed(&mut d, &t, &[0]).is_empty(), "no signal");
        feed(&mut d, &t, b"\n");
        assert_eq!(line(&mut d), b"\0\n", "and it is an ordinary byte");
    }

    #[test]
    fn end_of_file_completes_a_line_without_a_character() {
        let t = cooked();
        let mut d = Discipline::new();
        feed(&mut d, &t, &[4]); // ^D on an empty line
        assert_eq!(d.buffer.canon_len(), Some(1), "a flag is there");
        let got = line(&mut d);
        assert_eq!(got, b"\0", "which a reader turns into end of input");
    }

    #[test]
    fn end_of_file_after_text_hands_over_what_was_typed() {
        let t = cooked();
        let mut d = Discipline::new();
        feed(&mut d, &t, b"abc");
        feed(&mut d, &t, &[4]);
        assert_eq!(line(&mut d), b"abc\0");
    }

    // --- raw mode ---

    #[test]
    fn raw_mode_hands_over_every_byte_at_once() {
        let t = raw_mode();
        let mut d = Discipline::new();
        feed(&mut d, &t, b"a");
        assert_eq!(d.buffer.len(), 1, "no line ending needed");
    }

    #[test]
    fn raw_mode_does_not_translate_or_erase() {
        let t = raw_mode();
        let mut d = Discipline::new();
        feed(&mut d, &t, b"a\r");
        feed(&mut d, &t, &[0x7f]);
        let mut out = vec![0u8; 8];
        let n = d.buffer.read(&mut out);
        out.truncate(n);
        assert_eq!(out, b"a\r\x7f", "the erase character is just a byte");
    }

    #[test]
    fn raw_mode_still_raises_signals_when_isig_is_on() {
        let mut t = raw_mode();
        t.lflags |= ISIG;
        let mut d = Discipline::new();
        assert_eq!(feed(&mut d, &t, &[3]), vec![SIGINT]);
    }

    #[test]
    fn raw_mode_echo_works_when_asked_for() {
        let mut t = raw_mode();
        t.lflags |= ECHO;
        let mut d = Discipline::new();
        feed(&mut d, &t, b"xy");
        assert_eq!(d.take_echo(), b"xy");
    }

    // --- backpressure ---

    #[test]
    fn a_full_buffer_asks_for_room_and_takes_nothing() {
        let t = cooked();
        let mut d = Discipline::new();
        while !d.buffer.is_full() {
            d.buffer.push(b'x', false);
        }
        let before = d.buffer.len();
        assert_eq!(d.input(&t, b'y'), Step::NeedRoom);
        assert_eq!(d.buffer.len(), before, "nothing was taken");
        assert!(d.take_echo().is_empty(), "and nothing was echoed");
    }

    /// A signal character is answered even when there is no room for it, since
    /// it is never stored.
    #[test]
    fn a_full_buffer_still_answers_an_interrupt() {
        let t = cooked();
        let mut d = Discipline::new();
        while !d.buffer.is_full() {
            d.buffer.push(b'x', false);
        }
        match d.input(&t, 3) {
            Step::Consumed(o) => assert_eq!(o.signal, SIGINT),
            Step::NeedRoom => panic!("an interrupt must not wait for room"),
        }
    }

    /// Erase makes room, so the byte after it fits.
    #[test]
    fn erase_when_full_makes_room() {
        let t = cooked();
        let mut d = Discipline::new();
        while !d.buffer.is_full() {
            d.buffer.push(b'x', false);
        }
        assert!(matches!(d.input(&t, 0x7f), Step::Consumed(_)));
        assert!(!d.buffer.is_full());
    }

    #[test]
    fn the_echo_accumulator_does_not_grow_without_bound() {
        let mut t = cooked();
        t.lflags |= ECHO;
        let mut d = Discipline::new();
        for _ in 0..100_000 {
            // Erase on an empty buffer produces nothing; use ordinary bytes
            // and drop the buffer each time so only the echo accumulates.
            d.input(&t, b'z');
            d.buffer.clear();
        }
        assert!(d.echo_len() <= 4096 + 2, "got {}", d.echo_len());
    }
}
