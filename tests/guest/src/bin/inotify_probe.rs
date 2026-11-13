//! What the four `inotify` syscalls do with their arguments, and what one
//! event looks like on the wire.
//!
//! # Why this exists
//!
//! An inotify instance is a **fixed-layout record with a length field**, read
//! out of a descriptor into a buffer the caller sizes. That is the combination
//! this tree keeps finding defects in — `crates/fs/cmsg` was the i386 layout so
//! passing a descriptor over a unix socket passed nothing, and `crates/fs/dirent`
//! had a record length computed in two places that disagreed.
//!
//! The event is `{ wd: i32, mask: u32, cookie: u32, len: u32, name: [u8; len] }`
//! and `len` is **not** the length of the name: it is the padded size of what
//! follows, so a reader walks the buffer by it. A kernel that pads differently
//! hands back a stream that cannot be walked, and the caller sees garbage rather
//! than an error.
//!
//! # Every case gets its own directory
//!
//! A watch is on a path, and an event names the path's *child*. Sharing a
//! directory between cases means one case's leftover file is another case's
//! event, in an order that depends on which ran first. `fs_probe` reported eight
//! differences that were one for exactly this reason.

use std::ffi::CString;
use std::io::Write;

unsafe fn sys(n: i64, a: i64, b: i64, c: i64) -> i64 {
    let ret: i64;
    unsafe {
        std::arch::asm!(
            "svc #0",
            in("x8") n,
            inlateout("x0") a => ret,
            in("x1") b, in("x2") c,
            options(nostack)
        );
    }
    ret
}

const NR_INOTIFY_INIT1: i64 = 26;
const NR_INOTIFY_ADD_WATCH: i64 = 27;
const NR_INOTIFY_RM_WATCH: i64 = 28;
const NR_READ: i64 = 63;
const NR_CLOSE: i64 = 57;

// The mask bits, as `inotify(7)` numbers them.
const IN_ACCESS: i64 = 0x001;
const IN_MODIFY: i64 = 0x002;
const IN_ATTRIB: i64 = 0x004;
const IN_CREATE: i64 = 0x100;
const IN_DELETE: i64 = 0x200;
const IN_DELETE_SELF: i64 = 0x400;
const IN_MOVED_FROM: i64 = 0x040;
const IN_MOVED_TO: i64 = 0x080;
const IN_ALL_EVENTS: i64 = 0xfff;
const IN_ONLYDIR: i64 = 0x0100_0000;
const IN_DONT_FOLLOW: i64 = 0x0200_0000;
const IN_EXCL_UNLINK: i64 = 0x0400_0000;
const IN_MASK_CREATE: i64 = 0x1000_0000;
const IN_MASK_ADD: i64 = 0x2000_0000;
const IN_ONESHOT: i64 = -0x8000_0000i64; // 0x80000000, which does not fit an i32
const IN_ISDIR: u32 = 0x4000_0000;

const IN_NONBLOCK: i64 = 0o4000;
const IN_CLOEXEC: i64 = 0o2000000;

fn errname(e: i32) -> String {
    let n = match e {
        1 => "EPERM", 2 => "ENOENT", 9 => "EBADF", 11 => "EAGAIN", 12 => "ENOMEM",
        13 => "EACCES", 14 => "EFAULT", 17 => "EEXIST", 20 => "ENOTDIR",
        22 => "EINVAL", 24 => "EMFILE", 28 => "ENOSPC", 36 => "ENAMETOOLONG",
        40 => "ELOOP",
        _ => return format!("errno {e}"),
    };
    n.into()
}

fn r(v: i64) -> String {
    if v < 0 && v > -4096 {
        format!("-{}", errname(-v as i32))
    } else {
        v.to_string()
    }
}

/// A watch descriptor's *number* is comparable — both kernels hand out small
/// increasing integers from 1 — but only within one instance, so each case that
/// cares says which instance it opened.
fn say(what: &str, s: String) {
    println!("  {what:<52} {s}");
    let _ = std::io::stdout().flush();
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn main() {
    let base = std::env::args().nth(1).unwrap_or_else(|| "/tmp/inprobe".into());
    let _ = std::fs::remove_dir_all(&base);
    let _ = std::fs::create_dir_all(&base);

    println!("## inotify");

    println!("## inotify_init1 flags");
    for (flags, name) in [
        (0i64, "0"),
        (IN_NONBLOCK, "IN_NONBLOCK"),
        (IN_CLOEXEC, "IN_CLOEXEC"),
        (IN_NONBLOCK | IN_CLOEXEC, "both"),
        (1, "bit 0, which is neither"),
        (-1, "every bit"),
    ] {
        let fd = unsafe { sys(NR_INOTIFY_INIT1, flags, 0, 0) };
        say(&format!("inotify_init1({name})"), if fd < 0 { r(fd) } else { "ok".into() });
        if fd >= 0 {
            unsafe { sys(NR_CLOSE, fd, 0, 0) };
        }
    }

    println!("## the mask");
    // Which of the mask, the descriptor and the path is judged first is the
    // question here, and each case makes exactly one of the three wrong.
    let inst = unsafe { sys(NR_INOTIFY_INIT1, IN_NONBLOCK, 0, 0) };
    let dir = format!("{base}/watched");
    let _ = std::fs::create_dir_all(&dir);
    let dirp = c(&dir);
    for (mask, name) in [
        (0i64, "0, which asks for nothing"),
        (IN_ONLYDIR, "IN_ONLYDIR alone, a modifier with no event"),
        (IN_MASK_ADD | IN_MASK_CREATE | IN_ATTRIB, "MASK_ADD and MASK_CREATE together"),
        (IN_ATTRIB | 0x1000, "a bit that is not a mask bit"),
        (IN_ALL_EVENTS, "IN_ALL_EVENTS"),
        (IN_ATTRIB, "IN_ATTRIB"),
        (IN_ATTRIB | IN_ONLYDIR | IN_ONESHOT, "ATTRIB with two modifiers"),
        (-1, "every bit"),
    ] {
        say(&format!("add_watch({name})"), r(unsafe {
            sys(NR_INOTIFY_ADD_WATCH, inst, dirp.as_ptr() as i64, mask)
        }));
    }
    // A bad mask, a bad descriptor and a bad path, one at a time and together.
    say("bad mask, bad fd", r(unsafe {
        sys(NR_INOTIFY_ADD_WATCH, -1, dirp.as_ptr() as i64, 0)
    }));
    say("good mask, bad fd", r(unsafe {
        sys(NR_INOTIFY_ADD_WATCH, -1, dirp.as_ptr() as i64, IN_ATTRIB)
    }));
    say("good mask, bad fd, null path", r(unsafe {
        sys(NR_INOTIFY_ADD_WATCH, -1, 0, IN_ATTRIB)
    }));
    say("good mask, good fd, null path", r(unsafe {
        sys(NR_INOTIFY_ADD_WATCH, inst, 0, IN_ATTRIB)
    }));
    say("good mask, good fd, unmapped path", r(unsafe {
        sys(NR_INOTIFY_ADD_WATCH, inst, 0x10, IN_ATTRIB)
    }));
    say("a path that does not exist", r(unsafe {
        sys(NR_INOTIFY_ADD_WATCH, inst, c(&format!("{base}/nothing")).as_ptr() as i64, IN_ATTRIB)
    }));
    // IN_ONLYDIR on a file is ENOTDIR, which is the modifier doing its job.
    let file = format!("{base}/afile");
    let _ = std::fs::write(&file, b"x");
    say("IN_ONLYDIR on a regular file", r(unsafe {
        sys(NR_INOTIFY_ADD_WATCH, inst, c(&file).as_ptr() as i64, IN_ATTRIB | IN_ONLYDIR)
    }));
    say("no IN_ONLYDIR on a regular file", r(unsafe {
        sys(NR_INOTIFY_ADD_WATCH, inst, c(&file).as_ptr() as i64, IN_ATTRIB)
    }));
    // An instance descriptor that is not an inotify.
    say("add_watch on a plain file descriptor", r(unsafe {
        let f = libc::open(c(&file).as_ptr(), libc::O_RDONLY);
        let e = sys(NR_INOTIFY_ADD_WATCH, f as i64, dirp.as_ptr() as i64, IN_ATTRIB);
        libc::close(f);
        e
    }));

    println!("## watch descriptors");
    // A fresh instance so the numbers start where they start.
    let wds = unsafe { sys(NR_INOTIFY_INIT1, IN_NONBLOCK, 0, 0) };
    let a = format!("{base}/wd_a");
    let b = format!("{base}/wd_b");
    let _ = std::fs::create_dir_all(&a);
    let _ = std::fs::create_dir_all(&b);
    let w1 = unsafe { sys(NR_INOTIFY_ADD_WATCH, wds, c(&a).as_ptr() as i64, IN_ATTRIB) };
    say("the first watch", r(w1));
    let w2 = unsafe { sys(NR_INOTIFY_ADD_WATCH, wds, c(&b).as_ptr() as i64, IN_ATTRIB) };
    say("the second watch", r(w2));
    // The same path again is the same watch, not a new one.
    let again = unsafe { sys(NR_INOTIFY_ADD_WATCH, wds, c(&a).as_ptr() as i64, IN_ATTRIB) };
    say("the first path again", format!("{}", if again == w1 { "the same wd" } else { "a different wd" }));
    // ...unless IN_MASK_CREATE says it must be new.
    say("again with IN_MASK_CREATE", r(unsafe {
        sys(NR_INOTIFY_ADD_WATCH, wds, c(&a).as_ptr() as i64, IN_ATTRIB | IN_MASK_CREATE)
    }));
    say("a new path with IN_MASK_CREATE", r(unsafe {
        let n = format!("{base}/wd_c");
        let _ = std::fs::create_dir_all(&n);
        sys(NR_INOTIFY_ADD_WATCH, wds, c(&n).as_ptr() as i64, IN_ATTRIB | IN_MASK_CREATE)
    }));

    println!("## inotify_rm_watch");
    say("remove the second watch", r(unsafe { sys(NR_INOTIFY_RM_WATCH, wds, w2, 0) }));
    say("remove it again", r(unsafe { sys(NR_INOTIFY_RM_WATCH, wds, w2, 0) }));
    say("remove a watch that never was", r(unsafe { sys(NR_INOTIFY_RM_WATCH, wds, 9999, 0) }));
    say("remove wd 0", r(unsafe { sys(NR_INOTIFY_RM_WATCH, wds, 0, 0) }));
    say("remove wd -1", r(unsafe { sys(NR_INOTIFY_RM_WATCH, wds, -1, 0) }));
    say("remove from a bad descriptor", r(unsafe { sys(NR_INOTIFY_RM_WATCH, -1, w1, 0) }));
    unsafe { sys(NR_CLOSE, wds, 0, 0) };

    println!("## reading");
    let rd = unsafe { sys(NR_INOTIFY_INIT1, IN_NONBLOCK, 0, 0) };
    let rdir = format!("{base}/reading");
    let _ = std::fs::create_dir_all(&rdir);
    let rw = unsafe {
        sys(NR_INOTIFY_ADD_WATCH, rd, c(&rdir).as_ptr() as i64, IN_ALL_EVENTS)
    };
    let mut buf = [0u8; 4096];
    let bp = buf.as_mut_ptr() as i64;
    say("nothing pending, non-blocking", r(unsafe { sys(NR_READ, rd, bp, 0) }));
    say("  with a real buffer", r(unsafe { sys(NR_READ, rd, bp, 4096) }));

    // One event, and every field of it.
    let _ = std::fs::write(format!("{rdir}/created"), b"");
    let n = unsafe { sys(NR_READ, rd, bp, 4096) };
    if n <= 0 {
        say("a create event", r(n));
    } else {
        let wd = i32::from_ne_bytes(buf[0..4].try_into().unwrap());
        let mask = u32::from_ne_bytes(buf[4..8].try_into().unwrap());
        let cookie = u32::from_ne_bytes(buf[8..12].try_into().unwrap());
        let len = u32::from_ne_bytes(buf[12..16].try_into().unwrap()) as usize;
        let name_end = 16 + len;
        let name = &buf[16..name_end.min(buf.len())];
        let nul = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        say("a create event: the wd is the one we got", format!("{}", wd == rw as i32));
        say("  the mask is IN_CREATE", format!("{:#x}", mask & !IN_ISDIR));
        say("  the cookie is zero", format!("{}", cookie == 0));
        say("  the name", format!("{:?}", String::from_utf8_lossy(&name[..nul])));
        // `len` is the padded size of what follows the header, so it is a
        // multiple of the alignment and strictly greater than the name.
        say("  len covers the name and a terminator", format!("{}", len > nul));
        say("  len is a multiple of 16", format!("{}", len % 16 == 0));
        say("  the read returned exactly one event", format!("{}", n as usize == 16 + len));
    }

    // A buffer too small for one event. Linux answers EINVAL rather than a
    // short read, because a partial event cannot be walked.
    //
    // Each refusal is followed by a `poll`, which consumes nothing, so a
    // refusal that eats the event is named rather than being attributed to
    // whichever one ran last. That distinction is the whole finding: `read`
    // into a bad buffer and `read` into a small one fail through different
    // code, and only one of them can put the event back.
    let pending = |what: &str| {
        let mut pfd = libc::pollfd { fd: rd as i32, events: libc::POLLIN, revents: 0 };
        let n = unsafe { libc::poll(&mut pfd, 1, 0) };
        say(what, format!("{}", n == 1 && pfd.revents & libc::POLLIN != 0));
    };
    let _ = std::fs::write(format!("{rdir}/second"), b"");
    pending("  an event is pending");
    say("read into 8 bytes", r(unsafe { sys(NR_READ, rd, bp, 8) }));
    pending("  still pending after that");
    say("read into 16 bytes", r(unsafe { sys(NR_READ, rd, bp, 16) }));
    pending("  still pending after that");
    say("read into an unmapped buffer", r(unsafe { sys(NR_READ, rd, 0x10, 4096) }));
    pending("  still pending after that");
    // A buffer big enough for the header and the name but not the padding is
    // the boundary `len` is for: the record is 16 + len and nothing smaller
    // will do, even though the name itself fits.
    say("read into 16 + strlen(name) + 1", r(unsafe { sys(NR_READ, rd, bp, 16 + 7) }));
    pending("  still pending after that");
    let n2 = unsafe { sys(NR_READ, rd, bp, 4096) };
    say("the event survived the refusals", format!("{}", n2 > 0));

    // A rename inside the directory is two events sharing a cookie, which is
    // the only thing the cookie is for.
    let _ = std::fs::write(format!("{rdir}/from"), b"");
    let _ = unsafe { sys(NR_READ, rd, bp, 4096) };
    let _ = std::fs::rename(format!("{rdir}/from"), format!("{rdir}/to"));
    let n3 = unsafe { sys(NR_READ, rd, bp, 4096) };
    if n3 as usize >= 32 {
        let m1 = u32::from_ne_bytes(buf[4..8].try_into().unwrap());
        let c1 = u32::from_ne_bytes(buf[8..12].try_into().unwrap());
        let l1 = u32::from_ne_bytes(buf[12..16].try_into().unwrap()) as usize;
        let at = 16 + l1;
        let m2 = u32::from_ne_bytes(buf[at + 4..at + 8].try_into().unwrap());
        let c2 = u32::from_ne_bytes(buf[at + 8..at + 12].try_into().unwrap());
        say("a rename: the first mask", format!("{m1:#x}"));
        say("  the second mask", format!("{m2:#x}"));
        say("  they share a cookie", format!("{}", c1 == c2 && c1 != 0));
    } else {
        say("a rename gave two events", format!("{n3} bytes"));
    }
    unsafe { sys(NR_CLOSE, rd, 0, 0) };
    unsafe { sys(NR_CLOSE, inst, 0, 0) };

    let _ = std::fs::remove_dir_all(&base);
    let _ = (IN_ACCESS, IN_MODIFY, IN_CREATE, IN_DELETE, IN_DELETE_SELF, IN_MOVED_FROM,
             IN_MOVED_TO, IN_DONT_FOLLOW, IN_EXCL_UNLINK);
}
