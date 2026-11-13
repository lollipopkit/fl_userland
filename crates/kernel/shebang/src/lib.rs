//! The `#!` line.
//!
//! ```text
//! #! [blanks] interpreter [blanks] argument
//! ```
//!
//! One argument, not several: everything after the interpreter and the blanks
//! that follow it is **one string**, internal spaces included. `#!/bin/awk -f`
//! works because of that and `#!/usr/bin/env python3 -u` does not do what its
//! author meant, on Linux as here.
//!
//! ## Why this is not a five-line parse
//!
//! The kernel reads a fixed prefix of the file, so every question is really
//! about the **end** of that prefix, and the answers are not obvious. All three
//! below were measured against a real arm64 kernel rather than read:
//!
//! - **The buffer is 256 bytes.** Linux's `BINPRM_BUF_SIZE`. This kernel read
//!   128, so a script whose `#!` line was longer had its *argument* silently
//!   cut in half: `#!/bin/echo <180 x's>` passed 115 of them here and 180 on
//!   Linux.
//! - **A truncated interpreter path is `ENOEXEC`**, not something to execute.
//!   If there is no newline in the buffer and no blank after the path, the path
//!   may be the beginning of a longer one — and running the file that name
//!   happens to hit is running a different program than the script asked for.
//!   This kernel executed it: the same script gave 127 here and 0 on Linux,
//!   where `ENOEXEC` sent the shell back to interpreting it itself.
//! - **A truncated *argument* is fine.** The interpreter can re-read the script
//!   to parse the line properly, which is what `env` and `awk` do.
//!
//! Trailing spaces and tabs are stripped, so a line that is nothing but blanks
//! after the `#!` has no interpreter rather than an empty one.

/// Linux's `BINPRM_BUF_SIZE`.
pub const BUF_SIZE: usize = 256;

/// A parsed `#!` line, as offsets into the buffer it came from.
///
/// Offsets rather than slices because the caller is C and wants to NUL-
/// terminate in place; [`parse`] returns the same thing as `&[u8]`s for a
/// Rust caller.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Line {
    pub interp: (usize, usize),
    /// `None` when the line is just an interpreter.
    pub argument: Option<(usize, usize)>,
}

fn is_blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Parse the first bytes of a file. `None` means "not a script", which the
/// caller answers `ENOEXEC`.
///
/// `header` is **what was read**, at most [`BUF_SIZE`] bytes, and must not be
/// padded: a buffer shorter than [`BUF_SIZE`] is how this knows the file ended,
/// and padding it would turn "the file says no more" into "we stopped looking".
///
/// A short read is not an error. A file containing exactly `#!/bin/sh` with no
/// trailing newline is a script Linux runs — its buffer is zero-padded when the
/// file is shorter, so the line ends at the padding.
pub fn parse(header: &[u8]) -> Option<Line> {
    let header = &header[..header.len().min(BUF_SIZE)];
    if header.len() < 2 || header[0] != b'#' || header[1] != b'!' {
        return None;
    }

    // Where the line ends, and whether the ending is trustworthy.
    //
    // A newline, or a NUL from a file shorter than the buffer, both mean the
    // line is complete. Reaching the end of the buffer without either means it
    // may have been cut, and that is the case the truncation rule is about.
    let newline = header.iter().position(|&b| b == b'\n');
    let nul = header.iter().position(|&b| b == 0);
    let (end, complete) = match (newline, nul) {
        (Some(n), Some(z)) => (n.min(z), true),
        (Some(n), None) => (n, true),
        (None, Some(z)) => (z, true),
        // Neither. The line is complete only if the *file* ended -- which a
        // short read says, and a full buffer does not. `header` is what was
        // read and must not be padded by the caller, because padding is exactly
        // the difference between "the file says no more" and "we stopped
        // looking".
        (None, None) => (header.len(), header.len() < BUF_SIZE),
    };

    let line = &header[2..end];

    // Trailing blanks first, so that a line which is nothing but blanks after
    // the `#!` has no interpreter rather than an empty one.
    let line_end = line
        .iter()
        .rposition(|&b| !is_blank(b))
        .map_or(0, |i| i + 1);
    let line = &line[..line_end];

    let start = line.iter().position(|&b| !is_blank(b))?;
    let interp_start = 2 + start;
    let interp_len = line[start..]
        .iter()
        .position(|&b| is_blank(b))
        .unwrap_or(line.len() - start);

    // The truncation rule. A path that runs to the end of an incomplete buffer
    // may be the beginning of a longer one, and executing whatever that
    // shortened name hits is executing a different program.
    //
    // A path followed by a blank is complete however the buffer ended: the
    // blank is the terminator. Only the *argument* is then in doubt, and a
    // truncated argument is not this kernel's problem -- the interpreter can
    // re-read the script.
    let interp_end = interp_start + interp_len;
    if !complete && interp_end >= header.len() {
        return None;
    }

    let rest = &line[start + interp_len..];
    let arg_start = rest.iter().position(|&b| !is_blank(b));
    let argument = arg_start.map(|off| {
        let at = interp_end + off;
        (at, 2 + line_end - at)
    });

    Some(Line {
        interp: (interp_start, interp_len),
        argument,
    })
}

// ---------------------------------------------------------------------------
// C ABI
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The interpreter and argument as strings, for readable assertions.
    fn parts(s: &[u8]) -> Option<(String, Option<String>)> {
        let line = parse(s)?;
        let interp = String::from_utf8_lossy(&s[line.interp.0..line.interp.0 + line.interp.1]);
        let arg = line
            .argument
            .map(|(o, l)| String::from_utf8_lossy(&s[o..o + l]).into_owned());
        Some((interp.into_owned(), arg))
    }

    #[test]
    fn the_plain_case() {
        assert_eq!(parts(b"#!/bin/sh\n"), Some(("/bin/sh".into(), None)));
    }

    #[test]
    fn one_argument() {
        assert_eq!(
            parts(b"#!/bin/awk -f\n"),
            Some(("/bin/awk".into(), Some("-f".into())))
        );
    }

    /// Everything after the interpreter is **one** string, internal spaces
    /// included. `#!/usr/bin/env python3 -u` therefore passes `env` a single
    /// argument `"python3 -u"`, which is why it does not work — on Linux as
    /// here.
    #[test]
    fn the_argument_keeps_its_internal_spaces() {
        assert_eq!(
            parts(b"#!/bin/echo a b   c\n"),
            Some(("/bin/echo".into(), Some("a b   c".into())))
        );
    }

    #[test]
    fn tabs_are_blanks_too() {
        assert_eq!(
            parts(b"#!\t/bin/sh\t-x\n"),
            Some(("/bin/sh".into(), Some("-x".into())))
        );
    }

    /// Measured: `#!/bin/echo   \t  ` runs `echo` with only the script's path.
    #[test]
    fn trailing_blanks_are_stripped() {
        assert_eq!(
            parts(b"#!/bin/echo   \t  \n"),
            Some(("/bin/echo".into(), None))
        );
        assert_eq!(parts(b"#!/bin/sh \n"), Some(("/bin/sh".into(), None)));
    }

    #[test]
    fn a_line_of_nothing_but_blanks_is_not_a_script() {
        assert_eq!(parts(b"#!   \t \n"), None);
        assert_eq!(parts(b"#!\n"), None);
        assert_eq!(parts(b"#!"), None);
    }

    #[test]
    fn something_that_is_not_a_shebang() {
        assert_eq!(parts(b"#x/bin/sh\n"), None);
        assert_eq!(parts(b"!/bin/sh\n"), None);
        assert_eq!(parts(b""), None);
        assert_eq!(parts(b"#"), None);
        assert_eq!(parts(b"\x7fELF"), None);
    }

    /// A file containing exactly `#!/bin/sh` with no trailing newline is a
    /// script. Linux's buffer is zero-padded when the file is shorter, so the
    /// line ends at the padding; here the slice simply ends.
    #[test]
    fn a_file_with_no_trailing_newline_is_still_a_script() {
        assert_eq!(parts(b"#!/bin/sh"), Some(("/bin/sh".into(), None)));
    }

    #[test]
    fn a_nul_ends_the_line_as_a_newline_does() {
        assert_eq!(parts(b"#!/bin/sh\0garbage"), Some(("/bin/sh".into(), None)));
    }

    // ------------------------------------------------------- the buffer's end

    /// The measured defect: a 128-byte buffer cut `#!/bin/echo <180 x's>` to
    /// 115 of them. 256 is Linux's `BINPRM_BUF_SIZE`, and a line that fits it
    /// exactly comes out whole.
    #[test]
    fn a_line_that_fills_the_buffer_is_complete() {
        let mut s = b"#!/bin/echo ".to_vec();
        let pad = BUF_SIZE - s.len() - 1;
        s.extend(std::iter::repeat_n(b'x', pad));
        s.push(b'\n');
        assert_eq!(s.len(), BUF_SIZE);
        let (interp, arg) = parts(&s).unwrap();
        assert_eq!(interp, "/bin/echo");
        assert_eq!(arg.unwrap().len(), pad, "the whole argument");
    }

    /// **The one with teeth.** No newline, and the path runs to the end of the
    /// buffer, so it may be the beginning of a longer one. Executing whatever
    /// that shortened name hits is executing a different program than the
    /// script asked for.
    ///
    /// Measured: the same script exits 0 on Linux — `ENOEXEC` sends the shell
    /// back to interpreting it, and the `#!` line is then a comment — and
    /// exited 127 here, which is the shell reporting that the truncated path
    /// did not exist.
    #[test]
    fn a_truncated_interpreter_path_is_not_a_script() {
        let mut s = b"#!/bin/echo".to_vec();
        s.extend(std::iter::repeat_n(b'A', BUF_SIZE));
        assert_eq!(parse(&s), None);
    }

    /// A truncated *argument* is fine: the interpreter can re-read the script,
    /// which is what `env` and `awk` do. The path is complete because a blank
    /// follows it, whatever happened after that.
    #[test]
    fn a_truncated_argument_is_still_a_script() {
        let mut s = b"#!/bin/echo ".to_vec();
        s.extend(std::iter::repeat_n(b'A', BUF_SIZE));
        let (interp, arg) = parts(&s).unwrap();
        assert_eq!(interp, "/bin/echo");
        assert!(arg.unwrap().len() > 200, "as much as fit");
    }

    /// A newline anywhere in the buffer means nothing was cut, however long the
    /// path is.
    #[test]
    fn a_newline_makes_a_long_path_trustworthy() {
        let mut s = b"#!/".to_vec();
        s.extend(std::iter::repeat_n(b'a', 200));
        s.push(b'\n');
        let (interp, _) = parts(&s).unwrap();
        assert_eq!(interp.len(), 201);
    }

    #[test]
    fn bytes_past_the_buffer_are_not_read() {
        let mut s = b"#!/bin/sh".to_vec();
        s.extend(std::iter::repeat_n(b'A', BUF_SIZE * 2));
        s.push(b'\n');
        // The newline is past BUF_SIZE, so this is the truncated-path case.
        assert_eq!(parse(&s), None);
    }

    // ------------------------------------------------- offsets, not slices

    // Line carries offsets rather than slices, and crates/kernel/execcalls
    // indexes the buffer it read with them. These say the offsets are the
    // caller's -- which is the whole reason for the shape now that the C ABI
    // that needed it is gone.

    #[test]
    fn the_offsets_index_the_caller_s_own_buffer() {
        let s = b"#!  /bin/awk  -f -v x=1\n";
        let line = parse(s).expect("a script");
        let (io, il) = line.interp;
        let (ao, al) = line.argument.expect("an argument");
        assert_eq!(&s[io..io + il], b"/bin/awk");
        assert_eq!(&s[ao..ao + al], b"-f -v x=1");
    }

    #[test]
    fn a_line_with_no_argument_reports_none_rather_than_an_empty_span() {
        // An empty span at some offset and "there is no argument" are
        // different things to a caller that appends one.
        assert_eq!(parse(b"#!/bin/sh\n").expect("a script").argument, None);
    }

    #[test]
    fn something_that_is_not_a_script_is_none() {
        assert_eq!(parse(b"\x7fELF"), None);
    }
}
