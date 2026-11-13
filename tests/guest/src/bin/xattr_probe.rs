//! What the twelve extended-attribute syscalls answer.
//!
//! **A report, not a check** — one line per case, never fails, run here and in
//! an arm64 container and diffed by `tests/integration/probe_diff.sh`.
//!
//! All twelve landed on one stub returning `ENOTSUP` until 2026-09-07. The host
//! has them — Darwin's `getxattr` and its siblings, which is why
//! `crates/kernel/errno` has mapped Darwin's `ENOATTR` to Linux's `ENODATA`
//! since before anything called it — so this is the shape `CLAUDE.md` records
//! for `O_PATH|O_NOFOLLOW`: a true statement about the general case ("this
//! kernel has no extended attributes") applied to a particular one where the
//! host does.
//!
//! # What is being asked
//!
//! Not "does it work" — the interesting part of xattr is the **rules**, and
//! every one of them is a refusal:
//!
//! - a name with no namespace prefix, or one nobody defines;
//! - `user.*` on something that is not a regular file or a directory;
//! - `trusted.*`, which needs a capability;
//! - `XATTR_CREATE` over a name that exists, and `XATTR_REPLACE` over one that
//!   does not;
//! - a buffer too small, which is `ERANGE` and not a truncated answer;
//! - a size of 0, which asks the *length* and writes nothing;
//! - the limits: 255 bytes of name, 64 KiB of value;
//! - a size *above* them, which is a number the caller chose and not a buffer
//!   anybody owns — the kernel allocates against it, so what it does with
//!   `1 << 48` is a question about the kernel and not about the file.
//!
//! A kernel that implements the calls and none of the rules passes every "does
//! it work" test and silently accepts what Linux refuses, which is the half
//! that matters to anything relying on the namespace — `security.capability`
//! is a file capability, and `user.*` is the only one an unprivileged program
//! may write.

use std::io::Write;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<58} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> String {
    match e {
        0 => "no error",
        libc::EINVAL => "EINVAL",
        libc::EPERM => "EPERM",
        libc::EACCES => "EACCES",
        libc::ENOENT => "ENOENT",
        libc::ENODATA => "ENODATA",
        libc::ERANGE => "ERANGE",
        libc::E2BIG => "E2BIG",
        libc::EEXIST => "EEXIST",
        libc::ENOTSUP => "ENOTSUP/EOPNOTSUPP",
        libc::EFAULT => "EFAULT",
        libc::ENAMETOOLONG => "ENAMETOOLONG",
        libc::EDQUOT => "EDQUOT",
        libc::ENOSPC => "ENOSPC",
        libc::ELOOP => "ELOOP",
        libc::EBADF => "EBADF",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

const XATTR_CREATE: i32 = 1;
const XATTR_REPLACE: i32 = 2;

fn cstr(s: &str) -> std::ffi::CString {
    std::ffi::CString::new(s).unwrap()
}

fn setxattr(path: &str, name: &str, value: &[u8], flags: i32) -> i64 {
    let p = cstr(path);
    let n = cstr(name);
    unsafe {
        libc::syscall(
            libc::SYS_setxattr,
            p.as_ptr(),
            n.as_ptr(),
            value.as_ptr(),
            value.len(),
            flags,
        )
    }
}

fn getxattr(path: &str, name: &str, buf: &mut [u8]) -> i64 {
    let p = cstr(path);
    let n = cstr(name);
    unsafe {
        libc::syscall(
            libc::SYS_getxattr,
            p.as_ptr(),
            n.as_ptr(),
            buf.as_mut_ptr(),
            buf.len(),
        )
    }
}

fn listxattr(path: &str, buf: &mut [u8]) -> i64 {
    let p = cstr(path);
    unsafe { libc::syscall(libc::SYS_listxattr, p.as_ptr(), buf.as_mut_ptr(), buf.len()) }
}

/// The two above pass `buf.len()`, which is what a caller does and is therefore
/// the one length a probe never sees the kernel *decide* anything about. These
/// pass a size of their own: the argument is a number in a register and nothing
/// makes it the length of anything.
fn getxattr_sized(path: &str, name: &str, buf: &mut [u8], size: usize) -> i64 {
    let p = cstr(path);
    let n = cstr(name);
    unsafe {
        libc::syscall(
            libc::SYS_getxattr,
            p.as_ptr(),
            n.as_ptr(),
            buf.as_mut_ptr(),
            size,
        )
    }
}

fn listxattr_sized(path: &str, buf: &mut [u8], size: usize) -> i64 {
    let p = cstr(path);
    unsafe { libc::syscall(libc::SYS_listxattr, p.as_ptr(), buf.as_mut_ptr(), size) }
}

fn removexattr(path: &str, name: &str) -> i64 {
    let p = cstr(path);
    let n = cstr(name);
    unsafe { libc::syscall(libc::SYS_removexattr, p.as_ptr(), n.as_ptr()) }
}

/// A call's answer: the value it returned, or the errno.
fn r(v: i64) -> String {
    if v < 0 { named(errno()) } else { v.to_string() }
}

/// The same, without the length — for a call whose *number* depends on which
/// of the earlier sets the caller was allowed to make, which differs between a
/// container running as root and a guest that is not.
fn answered(v: i64) -> String {
    if v < 0 {
        named(errno())
    } else {
        "a length".to_string()
    }
}

/// Whether a name is in the list `listxattr` produced. The order is the
/// filesystem's, so membership is the comparable question and position is not.
fn listed(buf: &[u8], n: i64, name: &str) -> bool {
    if n <= 0 {
        return false;
    }
    buf[..n as usize].split(|b| *b == 0).any(|s| s == name.as_bytes())
}

fn main() {
    let dir = "/tmp/xattrprobe";
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).expect("scratch directory");
    let f = format!("{dir}/f");
    std::fs::write(&f, b"x").expect("a file");
    let sub = format!("{dir}/d");
    std::fs::create_dir(&sub).expect("a directory");
    let link = format!("{dir}/l");
    let _ = std::os::unix::fs::symlink("f", &link);
    let fifo = format!("{dir}/p");
    unsafe { libc::mkfifo(cstr(&fifo).as_ptr(), 0o644) };

    let mut buf = [0u8; 4096];

    println!("########## does the filesystem have them at all ##########");
    // The first question, and the one every caller asks first: a list on a file
    // with none. Zero, not an error, on a filesystem that supports them.
    line("listxattr on a file with none", r(listxattr(&f, &mut buf)));
    line("getxattr for a name that is not set", r(getxattr(&f, "user.nope", &mut buf)));
    line("removexattr for a name that is not set", r(removexattr(&f, "user.nope")));

    println!("\n########## the round trip ##########");
    line("setxattr user.a = \"one\"", r(setxattr(&f, "user.a", b"one", 0)));
    let n = getxattr(&f, "user.a", &mut buf);
    line("getxattr user.a", r(n));
    line("  and its value", if n > 0 { String::from_utf8_lossy(&buf[..n as usize]).to_string() } else { "-".into() });
    let n = listxattr(&f, &mut buf);
    line("listxattr after one set", r(n));
    line("  user.a is in the list", listed(&buf, n, "user.a"));
    line("setxattr user.b = \"two\"", r(setxattr(&f, "user.b", b"two", 0)));
    let n = listxattr(&f, &mut buf);
    line("  both are in the list", listed(&buf, n, "user.a") && listed(&buf, n, "user.b"));
    line("removexattr user.a", r(removexattr(&f, "user.a")));
    let n = listxattr(&f, &mut buf);
    line("  user.a is gone and user.b is not", !listed(&buf, n, "user.a") && listed(&buf, n, "user.b"));
    line("getxattr user.a after removing it", r(getxattr(&f, "user.a", &mut buf)));

    println!("\n########## a size of 0 asks the length ##########");
    let mut empty: [u8; 0] = [];
    line("getxattr user.b, size 0", r(getxattr(&f, "user.b", &mut empty)));
    line("listxattr, size 0", r(listxattr(&f, &mut empty)));
    // And a buffer too small is ERANGE rather than a truncated answer, which is
    // the difference between a caller that retries and one that reads rubbish.
    let mut small = [0u8; 1];
    line("getxattr user.b into 1 byte", r(getxattr(&f, "user.b", &mut small)));
    line("listxattr into 1 byte", r(listxattr(&f, &mut small)));

    println!("\n########## XATTR_CREATE and XATTR_REPLACE ##########");
    line("setxattr user.b, XATTR_CREATE, already set", r(setxattr(&f, "user.b", b"x", XATTR_CREATE)));
    line("setxattr user.new, XATTR_CREATE", r(setxattr(&f, "user.new", b"x", XATTR_CREATE)));
    line("setxattr user.gone, XATTR_REPLACE, not set", r(setxattr(&f, "user.gone", b"x", XATTR_REPLACE)));
    line("setxattr user.b, XATTR_REPLACE", r(setxattr(&f, "user.b", b"y", XATTR_REPLACE)));
    line("setxattr both flags at once", r(setxattr(&f, "user.b", b"z", XATTR_CREATE | XATTR_REPLACE)));
    line("setxattr an unknown flag bit", r(setxattr(&f, "user.b", b"z", 0x40)));
    // Both flags on a name that is *not* set. `XATTR_CREATE` is checked first
    // and passes, then `XATTR_REPLACE` is checked and does not -- so which of
    // the two errors comes back says which order the kernel applies them in,
    // and neither the man page nor the pair above settles it.
    line(
        "setxattr both flags, name not set",
        r(setxattr(&f, "user.neither", b"z", XATTR_CREATE | XATTR_REPLACE)),
    );

    println!("\n########## the namespace rules ##########");
    // Linux refuses a name with no known prefix outright: the namespace is what
    // decides who may write it, so a name without one has no rule to apply.
    for name in ["nodots", "bogus.a", "userx.a", "user", "user.", ".", ""] {
        line(
            &format!("setxattr {name:?}"),
            r(setxattr(&f, name, b"x", 0)),
        );
    }
    line("setxattr trusted.a (needs CAP_SYS_ADMIN)", r(setxattr(&f, "trusted.a", b"x", 0)));
    line("getxattr trusted.a", r(getxattr(&f, "trusted.a", &mut buf)));
    line("setxattr security.a", r(setxattr(&f, "security.a", b"x", 0)));
    line("setxattr system.a", r(setxattr(&f, "system.a", b"x", 0)));

    println!("\n########## what a user.* attribute may be put on ##########");
    // Only a regular file or a directory: on anything else the permission the
    // namespace grants -- write access -- means nothing, so Linux says EPERM.
    line("setxattr user.a on a directory", r(setxattr(&sub, "user.a", b"x", 0)));
    line("setxattr user.a on a fifo", r(setxattr(&fifo, "user.a", b"x", 0)));
    line("setxattr user.a on a symlink (followed)", r(setxattr(&link, "user.a", b"x", 0)));

    println!("\n########## the l* variants ##########");
    let l = cstr(&link);
    let nm = cstr("user.a");
    let v = unsafe {
        libc::syscall(libc::SYS_lsetxattr, l.as_ptr(), nm.as_ptr(), b"x".as_ptr(), 1usize, 0)
    };
    line("lsetxattr on a symlink itself", r(v));
    let v = unsafe {
        libc::syscall(libc::SYS_lgetxattr, l.as_ptr(), nm.as_ptr(), buf.as_mut_ptr(), buf.len())
    };
    line("lgetxattr on a symlink itself", r(v));
    let v = unsafe { libc::syscall(libc::SYS_llistxattr, l.as_ptr(), buf.as_mut_ptr(), buf.len()) };
    line("llistxattr on a symlink itself", r(v));
    // The fourth l* variant, and the one that had no case here at all: three
    // of the four were covered and `lremovexattr` was not, which is the
    // untested-sibling shape CLAUDE.md names -- a family whose members share a
    // helper and differ by one argument, where only some are asked about. A
    // wrong `follow` flag on this one removes the attribute from the symlink's
    // *target* and nothing here would have noticed.
    let v = unsafe { libc::syscall(libc::SYS_lremovexattr, l.as_ptr(), nm.as_ptr()) };
    line("lremovexattr on a symlink itself", r(v));
    // And the target's attribute is still there, which is what says the remove
    // went to the link rather than through it.
    let v = unsafe {
        libc::syscall(libc::SYS_getxattr, cstr(&f).as_ptr(), nm.as_ptr(), buf.as_mut_ptr(), buf.len())
    };
    line("the target's user.a after it", r(v));

    println!("\n########## the f* variants ##########");
    let fd = unsafe { libc::open(cstr(&f).as_ptr(), libc::O_RDWR) };
    line("fsetxattr user.f", {
        let v = unsafe {
            libc::syscall(libc::SYS_fsetxattr, fd, cstr("user.f").as_ptr(), b"v".as_ptr(), 1usize, 0)
        };
        r(v)
    });
    line("fgetxattr user.f", {
        let v = unsafe {
            libc::syscall(libc::SYS_fgetxattr, fd, cstr("user.f").as_ptr(), buf.as_mut_ptr(), buf.len())
        };
        r(v)
    });
    // Membership, not the length: what is on this file by now depends on which
    // of the `trusted.` and `security.` sets above the caller was allowed to
    // make, and that is a question about the caller's capabilities rather than
    // about `flistxattr`.
    line("flistxattr lists user.f", {
        let v = unsafe { libc::syscall(libc::SYS_flistxattr, fd, buf.as_mut_ptr(), buf.len()) };
        if v < 0 { named(errno()) } else { listed(&buf, v, "user.f").to_string() }
    });
    line("fremovexattr user.f", {
        let v = unsafe { libc::syscall(libc::SYS_fremovexattr, fd, cstr("user.f").as_ptr()) };
        r(v)
    });
    unsafe { libc::close(fd) };
    line("fgetxattr on a closed descriptor", {
        let v = unsafe {
            libc::syscall(libc::SYS_fgetxattr, fd, cstr("user.f").as_ptr(), buf.as_mut_ptr(), buf.len())
        };
        r(v)
    });

    println!("\n########## the limits ##########");
    // 255 bytes of name including the prefix, and 64 KiB of value.
    let long = format!("user.{}", "n".repeat(250));
    line("setxattr a 255-byte name", r(setxattr(&f, &long, b"x", 0)));
    let longer = format!("user.{}", "n".repeat(251));
    line("setxattr a 256-byte name", r(setxattr(&f, &longer, b"x", 0)));
    let big = vec![b'v'; 65536];
    line("setxattr a 64 KiB value", r(setxattr(&f, "user.big", &big, 0)));
    let bigger = vec![b'v'; 65537];
    line("setxattr a 64 KiB + 1 value", r(setxattr(&f, "user.big", &bigger, 0)));
    line("setxattr an empty value", r(setxattr(&f, "user.empty", b"", 0)));
    line("getxattr an empty value", r(getxattr(&f, "user.empty", &mut buf)));

    println!("\n########## the size argument is a number, not a buffer ##########");
    // A get and a list are answered into a buffer the *kernel* allocates, and
    // the only thing naming its length is a register the caller filled. Linux
    // clamps it to XATTR_SIZE_MAX before allocating, so every one of these is
    // answered exactly as the same call with a 64 KiB size would be.
    //
    // This emulator allocated the number instead, and `1 << 48` was
    // `memory allocation of 281474976710656 bytes failed` -- an abort of the
    // whole process, from an unprivileged guest, in one syscall. The real
    // buffer below stays small on purpose: what is being asked is what the
    // kernel does with the number, and the answers here are all short enough
    // to fit whatever it copies back.
    let mut small = [0u8; 64];
    for (label, size) in [
        ("64 KiB + 1", 65537usize),
        ("1 GiB", 1 << 30),
        ("256 TiB", 1 << 48),
        ("SIZE_MAX", usize::MAX),
    ] {
        line(
            &format!("getxattr user.b, size {label}"),
            r(getxattr_sized(&f, "user.b", &mut small, size)),
        );
    }
    line(
        "getxattr a name not set, size SIZE_MAX",
        r(getxattr_sized(&f, "user.nope", &mut small, usize::MAX)),
    );
    // Answered or refused, not the length: what is on this file by now depends
    // on which of the `trusted.` and `security.` sets above the caller was
    // allowed to make, and a container runs them as root. Same reason as
    // `flistxattr lists user.f` further up.
    line(
        "listxattr, size SIZE_MAX",
        answered(listxattr_sized(&f, &mut small, usize::MAX)),
    );
    let fd_big = unsafe { libc::open(cstr(&f).as_ptr(), libc::O_RDWR) };
    line("fgetxattr user.b, size SIZE_MAX", {
        let v = unsafe {
            libc::syscall(
                libc::SYS_fgetxattr,
                fd_big,
                cstr("user.b").as_ptr(),
                small.as_mut_ptr(),
                usize::MAX,
            )
        };
        r(v)
    });
    line("flistxattr, size SIZE_MAX", {
        let v = unsafe {
            libc::syscall(libc::SYS_flistxattr, fd_big, small.as_mut_ptr(), usize::MAX)
        };
        answered(v)
    });
    unsafe { libc::close(fd_big) };

    println!("\n########## a name that is not there ##########");
    line("setxattr on a missing path", r(setxattr(&format!("{dir}/nope"), "user.a", b"x", 0)));
    line("getxattr on a missing path", r(getxattr(&format!("{dir}/nope"), "user.a", &mut buf)));
    line("listxattr on a missing path", r(listxattr(&format!("{dir}/nope"), &mut buf)));

    let _ = std::fs::remove_dir_all(dir);
}
