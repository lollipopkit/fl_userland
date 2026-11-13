//! The CLI's options.
//!
//! `getopt(argc, argv, "+r:f:d:c:n:")` in the C, and the `+` is the part that
//! matters: option parsing **stops at the first non-option argument**, because
//! everything after it is the guest program's own command line. `iul -f root
//! /bin/ls -l` runs `ls -l`, not `iul` with an `-l`.
//!
//! Written out rather than called into `libc`, for one reason: `getopt` keeps
//! its state in globals and there is no way to test it without a process. This
//! is a function over a slice with the rules in one place.

/// Which filesystem the root is mounted with.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Root {
    /// `-r`: the host's directory, passed through.
    Real,
    /// `-f`: a fakefs directory, which is `data/` plus a `meta.db`.
    Fake,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Options {
    /// `-r` or `-f`, and which. `None` when neither was given, which mounts
    /// the host's `/`.
    pub root: Option<(Root, String)>,
    /// `-d`: where the guest starts. `None` means the host's working
    /// directory when no root was named, and the guest's `/` when one was.
    pub workdir: Option<String>,
    /// `-c`: the console device the first process gets as stdio.
    pub console: String,
    /// `-n`: a program to run natively rather than emulate. Repeatable.
    pub native: Vec<String>,
    /// Everything from the first non-option argument on: the guest's command.
    pub command: Vec<String>,
    /// Options that are not options, in the order they were seen. The C's
    /// `getopt` printed a message and carried on, and so does this.
    pub unknown: Vec<String>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            root: None,
            workdir: None,
            console: "/dev/tty1".to_string(),
            native: Vec::new(),
            command: Vec::new(),
            unknown: Vec::new(),
        }
    }
}

/// Parse `args`, which does **not** include `argv[0]`.
pub fn parse<I, S>(args: I) -> Options
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let args: Vec<String> = args.into_iter().map(Into::into).collect();
    let mut o = Options::default();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        // `--` ends options and is not itself an argument; a bare `-` is a
        // filename by convention and is not an option either.
        if a == "--" {
            i += 1;
            break;
        }
        if !a.starts_with('-') || a == "-" {
            break;
        }
        // Every option this takes has an argument, which may be joined to the
        // letter (`-rroot`) or be the next word (`-r root`).
        let letter = a.as_bytes()[1] as char;
        let joined = &a[2..];
        let value = if !joined.is_empty() {
            i += 1;
            joined.to_string()
        } else if i + 1 < args.len() {
            i += 2;
            args[i - 1].clone()
        } else {
            // An option at the end with nothing after it. `getopt` answers `?`
            // for this; there is nothing to do with it but say so.
            o.unknown.push(a.clone());
            i += 1;
            continue;
        };
        match letter {
            'r' => o.root = Some((Root::Real, value)),
            'f' => o.root = Some((Root::Fake, value)),
            'd' => o.workdir = Some(value),
            'c' => o.console = value,
            'n' => o.native.push(value),
            _ => o.unknown.push(a.clone()),
        }
    }
    o.command = args[i..].to_vec();
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_root_can_be_joined_or_separate() {
        assert_eq!(
            parse(["-r", "/tmp/x", "/bin/sh"]).root,
            Some((Root::Real, "/tmp/x".into()))
        );
        assert_eq!(
            parse(["-r/tmp/x", "/bin/sh"]).root,
            Some((Root::Real, "/tmp/x".into()))
        );
    }

    /// `-f` is `-r` plus "this is a fakefs". The C shared the `case` and set a
    /// second variable, which is what makes the pair one field here.
    #[test]
    fn f_names_a_fakefs_and_r_does_not() {
        assert_eq!(parse(["-f", "a"]).root, Some((Root::Fake, "a".into())));
        assert_eq!(parse(["-r", "a"]).root, Some((Root::Real, "a".into())));
        // The last one wins, as `getopt` gives it.
        assert_eq!(
            parse(["-r", "a", "-f", "b"]).root,
            Some((Root::Fake, "b".into()))
        );
    }

    /// The `+` in the option string. Everything from the first non-option on
    /// belongs to the guest, **including things that look like options**.
    #[test]
    fn parsing_stops_at_the_first_non_option() {
        let o = parse(["-r", "root", "/bin/ls", "-l", "-r", "no"]);
        assert_eq!(o.root, Some((Root::Real, "root".into())));
        assert_eq!(o.command, vec!["/bin/ls", "-l", "-r", "no"]);
    }

    #[test]
    fn a_double_dash_ends_options_without_being_a_command() {
        let o = parse(["-r", "root", "--", "-l"]);
        assert_eq!(o.command, vec!["-l"]);
        // And a bare `-` is a command, not an option.
        assert_eq!(parse(["-"]).command, vec!["-"]);
    }

    #[test]
    fn native_is_repeatable() {
        let o = parse(["-n", "ffmpeg", "-n", "ffprobe=/usr/bin/ffprobe", "x"]);
        assert_eq!(o.native, vec!["ffmpeg", "ffprobe=/usr/bin/ffprobe"]);
        assert_eq!(o.command, vec!["x"]);
    }

    #[test]
    fn the_console_has_a_default() {
        assert_eq!(parse::<[&str; 0], &str>([]).console, "/dev/tty1");
        assert_eq!(parse(["-c", "/dev/console"]).console, "/dev/console");
    }

    /// An unknown option does not stop the parse: `getopt` prints a message and
    /// returns `?`, and the C's `switch` had no `default`, so it carried on.
    #[test]
    fn an_unknown_option_is_reported_and_skipped() {
        let o = parse(["-z", "value", "-r", "root", "cmd"]);
        assert_eq!(o.unknown, vec!["-z"]);
        assert_eq!(o.root, Some((Root::Real, "root".into())));
        assert_eq!(o.command, vec!["cmd"]);
    }

    /// An option whose argument is missing has nothing to consume, and must
    /// not run off the end of the list.
    #[test]
    fn an_option_with_no_argument_is_not_a_panic() {
        let o = parse(["-r"]);
        assert_eq!(o.root, None);
        assert_eq!(o.unknown, vec!["-r"]);
        assert!(o.command.is_empty());
    }

    /// No arguments at all: every default, and no command — which the caller
    /// answers `ENOENT` for.
    #[test]
    fn nothing_is_every_default() {
        let o = parse::<[&str; 0], &str>([]);
        assert_eq!(o, Options::default());
    }
}
