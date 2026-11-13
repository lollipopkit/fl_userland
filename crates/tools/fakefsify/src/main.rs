//! Convert between a rootfs tarball and a fakefs directory.
//!
//! Installed under two names: `fakefsify` imports, `unfakefsify` exports. The
//! build symlinks the second to the first and the program decides from
//! argv[0], which is what the C version did.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

enum Command {
    Import,
    Export,
}

fn main() -> ExitCode {
    // No `setlocale`: names are bytes end to end since libarchive went on
    // 2026-10-17, so the `"C"` locale no longer turns a non-ASCII symlink
    // target into an aborted import. `tests/roundtrip.rs`'s
    // `a_symlink_target_that_is_not_ascii` holds it to that without one.
    let args: Vec<PathBuf> = std::env::args_os().map(PathBuf::from).collect();

    // argv[0] can be absent entirely — execve permits an empty argv — so this
    // does not index into it. The C version passed it straight to basename().
    let program = args
        .first()
        .and_then(|p| p.file_name())
        .unwrap_or_else(|| OsStr::new("fakefsify"));
    let command = if program == OsStr::new("unfakefsify") {
        Command::Export
    } else {
        Command::Import
    };

    if args.len() == 2 && args[1] == OsStr::new("--print-schema") {
        print!("{}", fakeschema::SCHEMA);
        return ExitCode::SUCCESS;
    }
    if args.len() == 3 && args[1] == OsStr::new("--index") {
        return report(program, fakefsify::index(&args[2]));
    }

    if args.len() != 3 {
        eprintln!("wrong number of arguments");
        let program = Path::new(program).display();
        match command {
            Command::Import => eprintln!("usage: {program} <rootfs.tar.gz> <fakefs>"),
            Command::Export => eprintln!("usage: {program} <fakefs> <rootfs.tar.gz>"),
        }
        eprintln!("       {program} --index <fakefs>   (describe an existing <fakefs>/data)");
        eprintln!("       {program} --print-schema");
        return ExitCode::FAILURE;
    }

    let result = match command {
        Command::Import => fakefsify::import(&args[1], &args[2]),
        Command::Export => fakefsify::export(&args[1], &args[2]),
    };

    report(program, result)
}

fn report(program: &OsStr, result: fakefsify::Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{}: {e}", Path::new(program).display());
            ExitCode::FAILURE
        }
    }
}
