//! inotify: whether anything is actually reported.
//!
//! `inotify_args` checks that a watch validates its arguments, and passed
//! throughout while `kernel/inotify.c` said outright that "nothing generates
//! events, so a read has nothing to return and never will". A watcher was
//! handed a watch descriptor and then waited for ever. That is the same shape
//! as `sock_race` passing while `SCM_RIGHTS` passed no descriptors: a test can
//! check every argument of a call that does nothing.
//!
//! So these ask what arrives.

use guest_tests::{Harness, check, check_fails, sys};

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

const IN_MODIFY: u32 = 0x0000_0002;
const IN_ATTRIB: u32 = 0x0000_0004;
const IN_CLOSE_WRITE: u32 = 0x0000_0008;
const IN_MOVED_FROM: u32 = 0x0000_0040;
const IN_MOVED_TO: u32 = 0x0000_0080;
const IN_CREATE: u32 = 0x0000_0100;
const IN_DELETE: u32 = 0x0000_0200;
const IN_ALL_EVENTS: u32 = 0x0000_0fff;
const IN_IGNORED: u32 = 0x0000_8000;
const IN_ISDIR: u32 = 0x4000_0000;
const IN_ONESHOT: u32 = 0x8000_0000;
const IN_MASK_ADD: u32 = 0x2000_0000;
const IN_ONLYDIR: u32 = 0x0100_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Ev {
    wd: i32,
    mask: u32,
    cookie: u32,
    name: String,
}

fn init() -> i32 {
    unsafe { libc::inotify_init1(libc::IN_NONBLOCK) }
}

fn add(fd: i32, path: &str, mask: u32) -> i32 {
    unsafe { libc::inotify_add_watch(fd, cstr(path).as_ptr(), mask) }
}

/// Every event queued, parsed the way a reader parses them: by `len`, which is
/// the name field's length and not the record's.
fn drain(fd: i32) -> Vec<Ev> {
    let mut out = Vec::new();
    loop {
        let mut buf = [0u8; 8192];
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            break;
        }
        let n = n as usize;
        let mut at = 0usize;
        while at + 16 <= n {
            let wd = i32::from_le_bytes(buf[at..at + 4].try_into().unwrap());
            let mask = u32::from_le_bytes(buf[at + 4..at + 8].try_into().unwrap());
            let cookie = u32::from_le_bytes(buf[at + 8..at + 12].try_into().unwrap());
            let len = u32::from_le_bytes(buf[at + 12..at + 16].try_into().unwrap()) as usize;
            if at + 16 + len > n {
                break;
            }
            let raw = &buf[at + 16..at + 16 + len];
            let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
            out.push(Ev {
                wd,
                mask,
                cookie,
                name: String::from_utf8_lossy(&raw[..end]).into_owned(),
            });
            at += 16 + len;
        }
    }
    out
}

fn has(events: &[Ev], mask: u32, name: &str) -> bool {
    events.iter().any(|e| e.mask & mask == mask && e.name == name)
}

fn t_directory_events(h: &mut Harness, dir: &str) {
    h.group("directory");
    let watched = format!("{dir}/watched");
    let _ = std::fs::remove_dir_all(&watched);
    unsafe { libc::mkdir(cstr(&watched).as_ptr(), 0o755) };

    let fd = init();
    if fd < 0 {
        check!(h, false, "inotify_init1: errno {}", sys::errno());
        return;
    }
    let wd = add(fd, &watched, IN_ALL_EVENTS);
    check!(h, wd > 0, "adding a watch: {wd} errno {}", sys::errno());

    // Creating a file.
    let f = unsafe {
        libc::open(cstr(&format!("{watched}/a")).as_ptr(),
                   libc::O_CREAT | libc::O_WRONLY, 0o644)
    };
    check!(h, f >= 0, "creating a file in the watched directory");
    let events = drain(fd);
    check!(h, has(&events, IN_CREATE, "a"), "IN_CREATE for it: {events:?}");
    check!(
        h,
        events.iter().all(|e| e.wd == wd),
        "reported against the watch descriptor that was handed out: {events:?}"
    );

    // Writing to it.
    sys::write(f, b"hello");
    let events = drain(fd);
    check!(h, has(&events, IN_MODIFY, "a"), "IN_MODIFY for a write: {events:?}");

    // Closing it.
    sys::close(f);
    let events = drain(fd);
    check!(
        h,
        has(&events, IN_CLOSE_WRITE, "a"),
        "IN_CLOSE_WRITE for the close: {events:?}"
    );

    // Renaming, which is two halves sharing a cookie.
    unsafe {
        libc::rename(
            cstr(&format!("{watched}/a")).as_ptr(),
            cstr(&format!("{watched}/b")).as_ptr(),
        )
    };
    let events = drain(fd);
    check!(h, has(&events, IN_MOVED_FROM, "a"), "IN_MOVED_FROM: {events:?}");
    check!(h, has(&events, IN_MOVED_TO, "b"), "IN_MOVED_TO: {events:?}");
    let from = events.iter().find(|e| e.mask & IN_MOVED_FROM != 0).map(|e| e.cookie);
    let to = events.iter().find(|e| e.mask & IN_MOVED_TO != 0).map(|e| e.cookie);
    check!(
        h,
        from.is_some() && from == to && from != Some(0),
        "and the two halves share a non-zero cookie: {from:?} {to:?}"
    );

    // A directory, which carries IN_ISDIR.
    unsafe { libc::mkdir(cstr(&format!("{watched}/d")).as_ptr(), 0o755) };
    let events = drain(fd);
    check!(
        h,
        has(&events, IN_CREATE | IN_ISDIR, "d"),
        "IN_CREATE with IN_ISDIR for a directory: {events:?}"
    );
    unsafe { libc::rmdir(cstr(&format!("{watched}/d")).as_ptr()) };
    let events = drain(fd);
    check!(
        h,
        has(&events, IN_DELETE | IN_ISDIR, "d"),
        "IN_DELETE with IN_ISDIR for its removal: {events:?}"
    );

    // Unlinking.
    unsafe { libc::unlink(cstr(&format!("{watched}/b")).as_ptr()) };
    let events = drain(fd);
    check!(h, has(&events, IN_DELETE, "b"), "IN_DELETE: {events:?}");

    sys::close(fd);
}

fn t_only_what_was_asked_for(h: &mut Harness, dir: &str) {
    h.group("mask");
    let watched = format!("{dir}/narrow");
    let _ = std::fs::remove_dir_all(&watched);
    unsafe { libc::mkdir(cstr(&watched).as_ptr(), 0o755) };

    let fd = init();
    let wd = add(fd, &watched, IN_DELETE);
    check!(h, wd > 0, "a watch for IN_DELETE alone");

    // Creating is not IN_DELETE.
    let f = unsafe {
        libc::open(cstr(&format!("{watched}/x")).as_ptr(),
                   libc::O_CREAT | libc::O_WRONLY, 0o644)
    };
    sys::write(f, b"x");
    sys::close(f);
    let events = drain(fd);
    check!(h, events.is_empty(), "reports nothing for a create: {events:?}");

    unsafe { libc::unlink(cstr(&format!("{watched}/x")).as_ptr()) };
    let events = drain(fd);
    check!(h, has(&events, IN_DELETE, "x"), "and reports the delete: {events:?}");

    // Another directory is not this one.
    let other = format!("{dir}/other");
    let _ = std::fs::remove_dir_all(&other);
    unsafe { libc::mkdir(cstr(&other).as_ptr(), 0o755) };
    let _ = std::fs::write(format!("{other}/y"), b"y");
    unsafe { libc::unlink(cstr(&format!("{other}/y")).as_ptr()) };
    let events = drain(fd);
    check!(
        h,
        events.is_empty(),
        "and nothing about a directory it is not watching: {events:?}"
    );
    sys::close(fd);
}

fn t_watch_a_file(h: &mut Harness, dir: &str) {
    h.group("file");
    let path = format!("{dir}/single");
    let _ = std::fs::write(&path, b"start");

    let fd = init();
    let wd = add(fd, &path, IN_MODIFY | IN_ATTRIB);
    check!(h, wd > 0, "watching a file rather than a directory: errno {}", sys::errno());

    let f = unsafe { libc::open(cstr(&path).as_ptr(), libc::O_WRONLY, 0) };
    sys::write(f, b"more");
    sys::close(f);
    let events = drain(fd);
    // An event about the watched thing itself carries no name.
    check!(
        h,
        events.iter().any(|e| e.mask & IN_MODIFY != 0 && e.name.is_empty()),
        "IN_MODIFY about the file itself, with no name: {events:?}"
    );
    sys::close(fd);
}

fn t_watch_management(h: &mut Harness, dir: &str) {
    h.group("watches");
    let a = format!("{dir}/wa");
    let b = format!("{dir}/wb");
    for p in [&a, &b] {
        let _ = std::fs::remove_dir_all(p);
        unsafe { libc::mkdir(cstr(p).as_ptr(), 0o755) };
    }
    let fd = init();

    let wa = add(fd, &a, IN_CREATE);
    let wb = add(fd, &b, IN_CREATE);
    check!(h, wa > 0 && wb > 0 && wa != wb, "two directories get two watches: {wa} {wb}");

    // The same path again is the same descriptor, not a second one.
    check!(h, add(fd, &a, IN_CREATE) == wa, "watching the same path again reuses it");

    // IN_MASK_ADD unions rather than replacing.
    check!(h, add(fd, &a, IN_DELETE | IN_MASK_ADD) == wa, "IN_MASK_ADD keeps the descriptor");
    let _ = std::fs::write(format!("{a}/f"), b"f");
    unsafe { libc::unlink(cstr(&format!("{a}/f")).as_ptr()) };
    let events = drain(fd);
    check!(
        h,
        has(&events, IN_CREATE, "f") && has(&events, IN_DELETE, "f"),
        "and both events arrive: {events:?}"
    );

    // Removing a watch reports IN_IGNORED and then refuses the descriptor.
    check!(h, unsafe { libc::inotify_rm_watch(fd, wa) } == 0, "removing a watch");
    let events = drain(fd);
    check!(
        h,
        events.iter().any(|e| e.mask & IN_IGNORED != 0 && e.wd == wa),
        "IN_IGNORED for the removal: {events:?}"
    );
    check_fails!(
        h,
        unsafe { libc::inotify_rm_watch(fd, wa) },
        libc::EINVAL,
        "removing it twice"
    );
    // And it hears nothing more.
    let _ = std::fs::write(format!("{a}/g"), b"g");
    let events = drain(fd);
    check!(h, events.is_empty(), "a removed watch is silent: {events:?}");

    sys::close(fd);
}

fn t_errors(h: &mut Harness, dir: &str) {
    h.group("errors");
    let fd = init();
    check!(h, fd >= 0, "inotify_init1");

    check_fails!(
        h,
        add(fd, &format!("{dir}/does-not-exist"), IN_CREATE),
        libc::ENOENT,
        "watching a path that does not exist"
    );
    check_fails!(h, add(fd, dir, 0), libc::EINVAL, "a mask naming no event");
    check_fails!(
        h,
        add(fd, dir, 0x0001_0000),
        libc::EINVAL,
        "a mask naming a bit that is not an event"
    );

    // IN_ONLYDIR on a file.
    let file = format!("{dir}/plain");
    let _ = std::fs::write(&file, b"p");
    check_fails!(
        h,
        add(fd, &file, IN_CREATE | IN_ONLYDIR),
        libc::ENOTDIR,
        "IN_ONLYDIR on a file"
    );

    check_fails!(
        h,
        unsafe { libc::inotify_add_watch(9999, cstr(dir).as_ptr(), IN_CREATE) },
        libc::EBADF,
        "a descriptor that is not open"
    );
    // A descriptor that is open but is not an inotify.
    let notinotify = unsafe { libc::open(cstr(dir).as_ptr(), libc::O_RDONLY, 0) };
    check_fails!(
        h,
        unsafe { libc::inotify_add_watch(notinotify, cstr(dir).as_ptr(), IN_CREATE) },
        libc::EINVAL,
        "a descriptor that is not an inotify"
    );
    sys::close(notinotify);

    // Reading with nothing queued, on a non-blocking descriptor.
    let mut buf = [0u8; 64];
    check_fails!(
        h,
        unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) } as i64,
        libc::EAGAIN,
        "a non-blocking read with nothing queued"
    );

    // A buffer too small for the event at the head is EINVAL, not 0 -- 0 from
    // a read means end of file and an inotify descriptor never ends.
    let wd = add(fd, dir, IN_CREATE);
    check!(h, wd > 0, "a watch to generate one");
    let _ = std::fs::write(format!("{dir}/tiny"), b"t");
    let mut small = [0u8; 8];
    check_fails!(
        h,
        unsafe { libc::read(fd, small.as_mut_ptr().cast(), small.len()) } as i64,
        libc::EINVAL,
        "a buffer too small for the first event"
    );
    // And the event is still there.
    let events = drain(fd);
    check!(h, has(&events, IN_CREATE, "tiny"), "the event survived: {events:?}");
    sys::close(fd);
}

fn t_oneshot(h: &mut Harness, dir: &str) {
    h.group("oneshot");
    let watched = format!("{dir}/once");
    let _ = std::fs::remove_dir_all(&watched);
    unsafe { libc::mkdir(cstr(&watched).as_ptr(), 0o755) };
    let fd = init();
    let wd = add(fd, &watched, IN_CREATE | IN_ONESHOT);
    check!(h, wd > 0, "a one-shot watch");

    let _ = std::fs::write(format!("{watched}/first"), b"1");
    let events = drain(fd);
    check!(h, has(&events, IN_CREATE, "first"), "fires once: {events:?}");

    let _ = std::fs::write(format!("{watched}/second"), b"2");
    let events = drain(fd);
    check!(
        h,
        !has(&events, IN_CREATE, "second"),
        "and not again: {events:?}"
    );
    sys::close(fd);
}

fn t_poll(h: &mut Harness, dir: &str) {
    h.group("poll");
    let watched = format!("{dir}/polled");
    let _ = std::fs::remove_dir_all(&watched);
    unsafe { libc::mkdir(cstr(&watched).as_ptr(), 0o755) };
    let fd = init();
    add(fd, &watched, IN_CREATE);

    let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    let n = unsafe { libc::poll(&mut pfd, 1, 0) };
    check!(
        h,
        n == 0,
        "an inotify with nothing queued is not ready: {n} revents {:#x}",
        pfd.revents
    );

    let _ = std::fs::write(format!("{watched}/p"), b"p");
    let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    let n = unsafe { libc::poll(&mut pfd, 1, 1000) };
    check!(
        h,
        n == 1 && pfd.revents & libc::POLLIN != 0,
        "and becomes readable when something happens: {n} revents {:#x}",
        pfd.revents
    );
    sys::close(fd);
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp/inoev".into());
    let _ = std::fs::remove_dir_all(&dir);
    unsafe { libc::mkdir(cstr(&dir).as_ptr(), 0o755) };
    let mut h = Harness::new();
    t_directory_events(&mut h, &dir);
    t_only_what_was_asked_for(&mut h, &dir);
    t_watch_a_file(&mut h, &dir);
    t_watch_management(&mut h, &dir);
    t_errors(&mut h, &dir);
    t_oneshot(&mut h, &dir);
    t_poll(&mut h, &dir);
    std::process::exit(h.finish());
}
