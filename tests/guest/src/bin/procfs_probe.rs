//! What the files under `/proc` look like.
//!
//! **A report, not a check** — the ninth in the shape `mmap_probe` established.
//! One line per case, never fails, diffed against an arm64 container by
//! `tests/integration/probe_diff.sh`.
//!
//! `/proc` is read by more real programs than any other interface here that
//! nothing compares. glibc's `pthread_getattr_np` parses `/proc/self/maps` to
//! find the main thread's stack — `kernel/mmap.c` carries a comment about the
//! startup crash that caused — the Go runtime reads it too, and the JVM reads
//! `/proc/meminfo` and `/proc/self/status`. A field that is missing, in the
//! wrong order, or in the wrong units is read as a number and used.
//!
//! # What is compared, and what cannot be
//!
//! **Structure, not values.** Two kernels will never agree about how many
//! bytes of memory are free or what a process's pid is, so printing those
//! would be noise on every line. What they must agree about is the *shape*:
//! which fields exist, in what order, how many there are, and which are
//! plausible.
//!
//! So a line here is a field name, a count, or a predicate — never a
//! measurement. Where a value is printed it is one that is fixed by the format
//! rather than by the machine: the number of fields in `/proc/self/stat`, the
//! separator `/proc/self/cmdline` uses, whether `/proc/self/maps` names
//! `[stack]`.

use std::fs;

fn line(what: &str, v: &str) {
    println!("{what:<50} -> {v}");
}

fn value(what: &str, v: i64) {
    println!("{what:<50} -> {v}");
}

fn read(path: &str) -> Option<String> {
    fs::read(path).ok().map(|b| String::from_utf8_lossy(&b).into_owned())
}

/// The field names of a `name:\tvalue` file, in order — which is the whole of
/// what a parser depends on.
fn field_names(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.split_once(':').map(|(k, _)| k.trim().to_string()))
        .collect()
}

/// Touch `bytes` further down the stack than the caller, so the pages below
/// have been faulted in. Recursive rather than a big array, because a single
/// large frame can skip a guard page rather than growing through it.
#[inline(never)]
fn grow_the_stack(bytes: usize) {
    let mut chunk = [0u8; 4096];
    chunk[0] = 1;
    chunk[4095] = 1;
    std::hint::black_box(&chunk);
    if bytes > 4096 {
        grow_the_stack(bytes - 4096);
    }
}

fn main() {
    println!("## /proc/self/stat");
    match read("/proc/self/stat") {
        Some(t) => {
            // The format is positional and 52 fields long, and everything
            // after field 2 is space-separated -- field 2 is `comm` in
            // parentheses and may contain spaces, so a parser splits on the
            // last ')'.
            let after = t.rsplit_once(')').map(|(_, r)| r.trim().to_string());
            match after {
                Some(rest) => {
                    value("fields after comm", rest.split_whitespace().count() as i64);
                    let f: Vec<&str> = rest.split_whitespace().collect();
                    // Field 3 (index 0 here) is the state character.
                    line("state", f.first().copied().unwrap_or("-"));
                    // ppid, pgrp, session, tty_nr, tpgid: all plausible?
                    value("ppid parses", f.get(1).and_then(|s| s.parse::<i64>().ok()).is_some() as i64);
                    value("pgrp parses", f.get(2).and_then(|s| s.parse::<i64>().ok()).is_some() as i64);
                    value("session parses", f.get(3).and_then(|s| s.parse::<i64>().ok()).is_some() as i64);
                    // num_threads is field 20, index 17.
                    value("num_threads is at least 1",
                          f.get(17).and_then(|s| s.parse::<i64>().ok()).is_some_and(|n| n >= 1) as i64);
                    // starttime is field 22, index 19.
                    value("starttime parses", f.get(19).and_then(|s| s.parse::<u64>().ok()).is_some() as i64);
                    // vsize (23) and rss (24).
                    value("vsize is non-zero",
                          f.get(20).and_then(|s| s.parse::<u64>().ok()).is_some_and(|n| n > 0) as i64);
                    value("rss parses", f.get(21).and_then(|s| s.parse::<i64>().ok()).is_some() as i64);
                }
                None => line("fields after comm", "no ')' in the line"),
            }
            value("comm is parenthesised", t.contains('(') as i64);
            value("the line ends with a newline", t.ends_with('\n') as i64);
        }
        None => line("/proc/self/stat", "unreadable"),
    }

    println!("## /proc/self/status");
    match read("/proc/self/status") {
        Some(t) => {
            let names = field_names(&t);
            value("field count", names.len() as i64);
            // The names themselves, in order. A count says the two differ
            // without saying which fields, and the answer to "twelve fewer" is
            // twelve *specific* names -- the same reason the auxv block below
            // lists its keys.
            line("the fields, in order", &names.join(","));
            // The ones a real program looks for, by name. Printed as present
            // or not rather than as their values, which differ by machine.
            for want in [
                "Name", "Umask", "State", "Tgid", "Ngid", "Pid", "PPid",
                "TracerPid", "Uid", "Gid", "FDSize", "Groups", "Threads",
                "SigQ", "SigPnd", "ShdPnd", "SigBlk", "SigIgn", "SigCgt",
                "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb",
                "NoNewPrivs", "Seccomp", "Cpus_allowed", "Mems_allowed",
                "voluntary_ctxt_switches", "nonvoluntary_ctxt_switches",
                "VmPeak", "VmSize", "VmRSS", "VmData", "VmStk", "VmExe",
            ] {
                value(&format!("  has {want}"), names.iter().any(|n| n == want) as i64);
            }
            // Values that are the same on every arm64 machine: a flag printed
            // as a number, and the top-byte-ignore mask. This said `false`
            // and `0xffffffffffffffff` until 2026-10-18.
            for f in ["NoNewPrivs", "untag_mask"] {
                let v = t.lines().find_map(|l| l.strip_prefix(&format!("{f}:")));
                line(&format!("  {f}"), v.map_or("absent", str::trim));
            }
            // Uid and Gid are four numbers: real, effective, saved, fs.
            for f in ["Uid", "Gid"] {
                let n = t
                    .lines()
                    .find(|l| l.starts_with(&format!("{f}:")))
                    .map(|l| l.split_whitespace().count() - 1)
                    .unwrap_or(0);
                value(&format!("  {f} has four ids"), (n == 4) as i64);
            }
            // The signal masks are 16 hex digits.
            for f in ["SigBlk", "SigIgn", "SigCgt"] {
                let ok = t
                    .lines()
                    .find(|l| l.starts_with(&format!("{f}:")))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .is_some_and(|v| v.len() == 16 && v.chars().all(|c| c.is_ascii_hexdigit()));
                value(&format!("  {f} is 16 hex digits"), ok as i64);
            }
        }
        None => line("/proc/self/status", "unreadable"),
    }

    println!("## /proc/self/statm");
    match read("/proc/self/statm") {
        Some(t) => {
            let f: Vec<&str> = t.split_whitespace().collect();
            value("field count", f.len() as i64);
            value("all fields parse",
                  f.iter().all(|s| s.parse::<u64>().is_ok()) as i64);
            value("size is non-zero",
                  f.first().and_then(|s| s.parse::<u64>().ok()).is_some_and(|n| n > 0) as i64);
        }
        None => line("/proc/self/statm", "unreadable"),
    }

    println!("## /proc/self/maps");
    // **Grow the stack first**, or the checks below are vacuous.
    //
    // The defect they exist for is in the page a stack *grows into*, and this
    // program's stack never left its first page — so with the fix backed out
    // the probe still reported one clean `[stack]` mapping. A filter that
    // matches nothing passes.
    grow_the_stack(256 * 1024);
    match read("/proc/self/maps") {
        Some(t) => {
            let lines: Vec<&str> = t.lines().collect();
            value("has at least one mapping", (!lines.is_empty()) as i64);
            // Every line is `start-end perms offset dev inode [path]`.
            let well_formed = lines.iter().all(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                f.len() >= 5
                    && f[0].contains('-')
                    && f[1].len() == 4
                    && f[1].chars().all(|c| "rwxsp-".contains(c))
                    && u64::from_str_radix(f[2], 16).is_ok()
                    && f[3].contains(':')
                    && f[4].parse::<u64>().is_ok()
            });
            value("every line has the six fields", well_formed as i64);
            // The address range parses and is not empty.
            let ranges_ok = lines.iter().all(|l| {
                l.split_whitespace().next().and_then(|r| r.split_once('-')).is_some_and(|(a, b)| {
                    match (u64::from_str_radix(a, 16), u64::from_str_radix(b, 16)) {
                        (Ok(a), Ok(b)) => b > a,
                        _ => false,
                    }
                })
            });
            value("every range is non-empty and ordered", ranges_ok as i64);
            // Ascending, which is what a parser walking to find its stack
            // relies on.
            let ascending = lines
                .windows(2)
                .all(|w| {
                    let s = |l: &str| {
                        l.split_whitespace()
                            .next()
                            .and_then(|r| r.split_once('-'))
                            .and_then(|(a, _)| u64::from_str_radix(a, 16).ok())
                            .unwrap_or(0)
                    };
                    s(w[0]) <= s(w[1])
                });
            value("the mappings are in ascending order", ascending as i64);
            for tag in ["[stack]", "[heap]", "[vdso]", "[vvar]"] {
                value(&format!("  names {tag}"), t.contains(tag) as i64);
            }
            // **One** `[stack]` line, and readable and writable.
            //
            // This is not tidiness. glibc's `pthread_getattr_np` finds the
            // mapping holding `__libc_stack_end` and takes the *previous*
            // mapping's end as the stack's floor, so a stack split in two
            // reports the size of its top piece. It was split here, because a
            // page the stack grew into was mapped without the read bit and so
            // did not merge with the one above it — and Python 3.14 asks at
            // startup and aborts with "Unrecoverable stack overflow (used
            // 4 kB)" before running a line.
            let stack: Vec<&&str> = lines.iter().filter(|l| l.ends_with("[stack]")).collect();
            value("  exactly one [stack] mapping", (stack.len() == 1) as i64);
            value(
                "  and it is readable and writable",
                stack.first().is_some_and(|l| {
                    l.split_whitespace().nth(1).is_some_and(|p| {
                        p.starts_with("rw")
                    })
                }) as i64,
            );
            // No mapping is write-without-read, which is a combination no
            // kernel produces: `brk` had it, then the stack did.
            value(
                "  no mapping is write-only",
                !lines.iter().any(|l| {
                    l.split_whitespace().nth(1).is_some_and(|p| p.starts_with("-w"))
                }) as i64,
            );
            // What a program actually asks: how much stack it has.
            //
            // These probes are musl, and musl answers from its own bookkeeping
            // rather than from `/proc/self/maps` — so this line is about musl
            // and says the same thing on both sides. **glibc is the one that
            // parses the file**, which is why the two `[stack]` checks above
            // are where the sharpness is: they are what its arithmetic reads.
            let mut attr: libc::pthread_attr_t = unsafe { std::mem::zeroed() };
            let got = unsafe { libc::pthread_getattr_np(libc::pthread_self(), &mut attr) };
            let mut base = std::ptr::null_mut();
            let mut size = 0usize;
            if got == 0 {
                unsafe { libc::pthread_attr_getstack(&attr, &mut base, &mut size) };
            }
            value("pthread_getattr_np on the main thread", (got == 0) as i64);
            value("  it reports a non-empty stack", (size > 0) as i64);
            value("  whose base is not null", (!base.is_null()) as i64);
            // A file-backed mapping names an absolute path.
            let has_file = lines.iter().any(|l| {
                l.split_whitespace().nth(5).is_some_and(|p| p.starts_with('/'))
            });
            value("  some mapping names a file", has_file as i64);
        }
        None => line("/proc/self/maps", "unreadable"),
    }

    println!("## /proc/self/limits");
    match read("/proc/self/limits") {
        Some(t) => {
            let lines: Vec<&str> = t.lines().collect();
            value("row count including the header", lines.len() as i64);
            value("the header starts with Limit",
                  lines.first().is_some_and(|l| l.starts_with("Limit")) as i64);
            for want in [
                "Max cpu time", "Max file size", "Max data size", "Max stack size",
                "Max core file size", "Max resident set", "Max processes",
                "Max open files", "Max locked memory", "Max address space",
                "Max file locks", "Max pending signals", "Max msgqueue size",
                "Max nice priority", "Max realtime priority", "Max realtime timeout",
            ] {
                value(&format!("  has \"{want}\""),
                      lines.iter().any(|l| l.starts_with(want)) as i64);
            }
            // A row with no unit ends after the hard limit's column: Linux
            // prints the `%-10s` unit only when there is one. This printed
            // ten more spaces until 2026-10-18.
            let width = |name: &str| lines.iter().find(|l| l.starts_with(name)).map_or(-1, |l| l.len() as i64);
            value("  row width with a unit (Max cpu time)", width("Max cpu time"));
            value("  row width without one (Max nice priority)", width("Max nice priority"));
        }
        None => line("/proc/self/limits", "unreadable"),
    }

    println!("## the NUL-separated files");
    for f in ["/proc/self/cmdline", "/proc/self/environ"] {
        match fs::read(f) {
            Ok(b) => {
                value(&format!("{f}: non-empty"), (!b.is_empty()) as i64);
                value("  ends with a NUL", b.last().is_some_and(|c| *c == 0) as i64);
                value("  has no newline", (!b.contains(&b'\n')) as i64);
            }
            Err(_) => line(f, "unreadable"),
        }
    }
    match read("/proc/self/comm") {
        Some(t) => {
            value("/proc/self/comm ends with a newline", t.ends_with('\n') as i64);
            value("  is at most 16 bytes with the newline",
                  (t.len() <= 16) as i64);
        }
        None => line("/proc/self/comm", "unreadable"),
    }

    println!("## /proc/self/auxv");
    match fs::read("/proc/self/auxv") {
        Ok(b) => {
            value("length is a multiple of 16", (b.len() % 16 == 0) as i64);
            let mut keys = Vec::new();
            for c in b.chunks_exact(16) {
                let k = u64::from_le_bytes(c[0..8].try_into().unwrap());
                keys.push(k);
            }
            value("entry count", keys.len() as i64);
            value("ends with AT_NULL", (keys.last() == Some(&0)) as i64);
            // The keys themselves, sorted. A count alone says the two sides
            // differ without saying which entries -- and the answer to "four
            // fewer" is usually four *specific* names.
            let mut sorted = keys.clone();
            sorted.sort_unstable();
            sorted.dedup();
            let joined: Vec<String> = sorted.iter().map(|k| k.to_string()).collect();
            line("the keys present", &joined.join(","));
            // The ones a loader needs. AT_PHDR 3, AT_PHENT 4, AT_PHNUM 5,
            // AT_PAGESZ 6, AT_BASE 7, AT_ENTRY 9, AT_UID 11, AT_EUID 12,
            // AT_GID 13, AT_EGID 14, AT_SECURE 23, AT_RANDOM 25, AT_HWCAP 16,
            // AT_CLKTCK 17, AT_EXECFN 31.
            for (n, k) in [
                ("AT_PHDR", 3u64), ("AT_PHENT", 4), ("AT_PHNUM", 5),
                ("AT_PAGESZ", 6), ("AT_BASE", 7), ("AT_ENTRY", 9),
                ("AT_UID", 11), ("AT_EUID", 12), ("AT_GID", 13), ("AT_EGID", 14),
                ("AT_HWCAP", 16), ("AT_CLKTCK", 17), ("AT_SECURE", 23),
                ("AT_RANDOM", 25), ("AT_EXECFN", 31),
            ] {
                value(&format!("  has {n}"), keys.contains(&k) as i64);
            }
        }
        Err(_) => line("/proc/self/auxv", "unreadable"),
    }

    println!("## the symlinks");
    for f in ["/proc/self/exe", "/proc/self/cwd", "/proc/self/root"] {
        match fs::read_link(f) {
            Ok(p) => {
                let s = p.to_string_lossy();
                value(&format!("{f} is absolute"), s.starts_with('/') as i64);
            }
            Err(_) => line(f, "unreadable"),
        }
    }
    // /proc/self/fd holds a link per open descriptor, and 0/1/2 are always
    // there.
    match fs::read_dir("/proc/self/fd") {
        Ok(d) => {
            let mut names: Vec<String> =
                d.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect();
            names.sort();
            value("/proc/self/fd has 0, 1 and 2",
                  ["0", "1", "2"].iter().all(|n| names.iter().any(|m| m == n)) as i64);
            value("  every name is a number",
                  names.iter().all(|n| n.parse::<u32>().is_ok()) as i64);
        }
        Err(_) => line("/proc/self/fd", "unreadable"),
    }

    println!("## what /proc/self/fd names a descriptor with no path");
    {
        // A descriptor that names no file still has a name here: the kind of
        // object, and for a pipe or a socket its inode. `lsof`, `ls -l
        // /proc/<pid>/fd` and a runtime finding its own pipes read these.
        // The number is masked, because it is the kernel's to choose.
        let mut fds: Vec<(&str, i32)> = Vec::new();
        let mut pipe = [0i32; 2];
        unsafe { libc::pipe(pipe.as_mut_ptr()) };
        fds.push(("a pipe's read end", pipe[0]));
        fds.push(("a pipe's write end", pipe[1]));
        let mut pair = [0i32; 2];
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) };
        fds.push(("a unix socket", pair[0]));
        fds.push(("an eventfd", unsafe { libc::eventfd(0, 0) }));
        fds.push(("an epoll", unsafe { libc::epoll_create1(0) }));
        fds.push(("a timerfd", unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, 0) }));
        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGUSR1);
        }
        fds.push(("a signalfd", unsafe { libc::signalfd(-1, &set, 0) }));
        fds.push(("an inotify", unsafe { libc::inotify_init1(0) }));
        fds.push(("a pidfd", unsafe { libc::syscall(434, libc::getpid(), 0) as i32 }));
        for (what, fd) in fds {
            let shown = match fs::read_link(format!("/proc/self/fd/{fd}")) {
                Ok(p) => mask_number(&p.to_string_lossy()),
                Err(e) => errname(e.raw_os_error().unwrap_or(0)).to_string(),
            };
            line(what, &shown);
        }
    }

    println!("## the system-wide files");
    for (f, want) in [
        ("/proc/uptime", vec![]),
        ("/proc/loadavg", vec![]),
        ("/proc/version", vec!["Linux version"]),
        ("/proc/filesystems", vec![]),
        ("/proc/meminfo", vec!["MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached", "SwapTotal", "SwapFree"]),
        ("/proc/stat", vec!["cpu ", "btime", "processes"]),
        ("/proc/cpuinfo", vec![]),
        ("/proc/mounts", vec![]),
    ] {
        match read(f) {
            Some(t) => {
                value(&format!("{f}: non-empty"), (!t.is_empty()) as i64);
                for w in &want {
                    value(&format!("  mentions {w}"), t.contains(w) as i64);
                }
            }
            None => line(f, "unreadable"),
        }
    }
    // /proc/uptime is two numbers, and /proc/loadavg is five fields.
    if let Some(t) = read("/proc/uptime") {
        let f: Vec<&str> = t.split_whitespace().collect();
        value("/proc/uptime has two fields", (f.len() == 2) as i64);
        value("  both parse as floats",
              f.iter().all(|s| s.parse::<f64>().is_ok()) as i64);
    }
    if let Some(t) = read("/proc/loadavg") {
        let f: Vec<&str> = t.split_whitespace().collect();
        value("/proc/loadavg has five fields", (f.len() == 5) as i64);
        value("  the fourth is running/total",
              f.get(3).is_some_and(|s| s.contains('/')) as i64);
        // The three averages parse and have two decimal places, which is what
        // a reader that splits on '.' and multiplies by 100 depends on. They
        // were the literal string "0.00 0.00 0.00" until 2026-09-04, so an
        // idle-looking machine was the only machine this ever reported.
        value(
            "  the three averages have two decimal places",
            f.iter()
                .take(3)
                .all(|s| s.parse::<f64>().is_ok() && s.split_once('.').is_some_and(|(_, d)| d.len() == 2))
                as i64,
        );
    }
    // /proc/meminfo's lines are `Name:   N kB`.
    if let Some(t) = read("/proc/meminfo") {
        let ok = t.lines().all(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            f.len() >= 2 && f[0].ends_with(':') && f[1].parse::<u64>().is_ok()
        });
        value("/proc/meminfo lines are `Name: N [kB]`", ok as i64);
        let field = |name: &str| -> Option<u64> {
            t.lines()
                .find(|l| l.starts_with(&format!("{name}:")))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u64>().ok())
        };
        value("  MemTotal is non-zero", field("MemTotal").is_some_and(|n| n > 0) as i64);
        // Some of the machine is in use, and that is not a truism: MemFree was
        // the *host's* free memory capped to the same 4 GB the total is capped
        // to, so on any machine with more than 4 GB free it was exactly
        // MemTotal and nothing was ever accounted.
        let total = field("MemTotal").unwrap_or(0);
        let free = field("MemFree").unwrap_or(0);
        value("  MemFree is below MemTotal", (free < total) as i64);
        value("  and above three quarters of it", (free * 4 > total * 3) as i64);
        // Exactly half is the sentinel the accounting falls back to when its
        // count has gone negative, which is what it did for every glibc guest.
        value("  and is not exactly half", (free != total / 2) as i64);
    }

    println!("## /proc/self/fd names a path");
    {
        // A descriptor open on a **mount root** answered `<point>/` here where
        // Linux answers `<point>`: `/dev` is a mount of its own in this kernel,
        // so `readlink /proc/self/fd/<n>` gave `/dev/`. That trailing slash
        // then reached the path walk, which appends a component as `/` + name
        // and so produced `/dev//shm`.
        for dir in ["/", "/etc", "/dev", "/tmp", "/proc"] {
            let fd = unsafe { libc::open(format!("{dir}\0").as_ptr().cast(), libc::O_RDONLY) };
            if fd < 0 {
                line(&format!("open {dir}"), "failed");
                continue;
            }
            let link = format!("/proc/self/fd/{fd}");
            let got = std::fs::read_link(&link).map(|p| p.display().to_string()).unwrap_or_default();
            value(&format!("  {dir} reads back as itself"), (got == dir) as i64);
            // And never with a trailing slash, whatever it is.
            value(
                &format!("  {dir} has no trailing slash"),
                (got == "/" || !got.ends_with('/')) as i64,
            );
            unsafe { libc::close(fd) };
        }
    }

    println!("## threads");
    {
        // Two threads that name themselves and park, so that they are there to
        // be listed; their tids come back over a channel.
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let (tx, rx) = std::sync::mpsc::channel();
        let mut handles = Vec::new();
        for i in 0..2 {
            let barrier = barrier.clone();
            let tx = tx.clone();
            handles.push(std::thread::spawn(move || {
                let name = format!("probe-thread-{i}\0");
                unsafe { libc::prctl(libc::PR_SET_NAME, name.as_ptr()) };
                tx.send((i, gettid())).unwrap();
                barrier.wait();
            }));
        }
        // Which thread reports first is scheduling, so the tid is picked by
        // the thread's number and not by arrival -- the first version read
        // `probe-thread-1` here and `probe-thread-0` in the container.
        let mut named: Vec<(usize, i32)> = (0..2).map(|_| rx.recv().unwrap()).collect();
        named.sort();
        let tids: Vec<i32> = named.iter().map(|&(_, t)| t).collect();
        let me = unsafe { libc::getpid() };
        let root = numbered("/proc");
        value("/proc lists the process", root.contains(&me) as i64);
        value("/proc lists a thread by its tid", tids.iter().any(|t| root.contains(t)) as i64);
        let task = numbered("/proc/self/task");
        value("/proc/self/task entries", task.len() as i64);
        value("  includes the leader", task.contains(&me) as i64);
        value("  includes both threads", tids.iter().all(|t| task.contains(t)) as i64);

        let tid = tids[0];
        let dir = format!("/proc/self/task/{tid}");
        value("/proc/self/task/<tid> is a directory",
              fs::metadata(&dir).map(|m| m.is_dir()).unwrap_or(false) as i64);
        for name in ["stat", "status", "comm", "maps", "fd", "cwd", "task"] {
            value(&format!("  has {name}"), fs::metadata(format!("{dir}/{name}")).is_ok() as i64);
        }
        match read(&format!("{dir}/status")) {
            Some(s) => {
                value("  status: Pid is the tid", (status_field(&s, "Pid") == tid.to_string()) as i64);
                value("  status: Tgid is the process", (status_field(&s, "Tgid") == me.to_string()) as i64);
                line("  status: Name", &status_field(&s, "Name"));
                line("  status: Threads", &status_field(&s, "Threads"));
            }
            None => line("  status", "unreadable"),
        }
        match read(&format!("{dir}/stat")) {
            Some(s) => value("  stat: first field is the tid", s.starts_with(&format!("{tid} (")) as i64),
            None => line("  stat", "unreadable"),
        }
        line("  comm", read(&format!("{dir}/comm")).map(|s| s.trim().to_string()).as_deref().unwrap_or("unreadable"));
        // A thread's directory can be named directly, even though /proc does
        // not list it.
        match read(&format!("/proc/{tid}/status")) {
            Some(s) => value("/proc/<tid>/status by number: Pid is the tid",
                             (status_field(&s, "Pid") == tid.to_string()) as i64),
            None => line("/proc/<tid>/status by number", "unreadable"),
        }
        barrier.wait();
        for h in handles {
            h.join().unwrap();
        }
    }

    println!("## a zombie");
    {
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe { libc::_exit(3) };
        }
        // Left unreaped; it is a zombie once stat says so.
        let stat_path = format!("/proc/{pid}/stat");
        let mut state = String::new();
        for _ in 0..400 {
            if let Some(s) = read(&stat_path) {
                state = stat_fields(&s).first().copied().unwrap_or("").to_string();
            }
            if state == "Z" {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        line("/proc/<zombie>/stat: state", if state.is_empty() { "unreadable" } else { &state });
        if let Some(s) = read(&stat_path) {
            let f = stat_fields(&s);
            value("  fields after comm", f.len() as i64);
            line("  vsize", f.get(20).unwrap_or(&"-"));
            line("  rss", f.get(21).unwrap_or(&"-"));
            line("  exit_code", f.get(49).unwrap_or(&"-"));
        }
        value("/proc/<zombie> is listed in /proc", numbered("/proc").contains(&pid) as i64);
        match read(&format!("/proc/{pid}/status")) {
            Some(s) => {
                line("/proc/<zombie>/status: State", &status_field(&s, "State"));
                line("  Threads", &status_field(&s, "Threads"));
                line("  FDSize", &status_field(&s, "FDSize"));
                let names = field_names(&s);
                for n in ["Umask", "VmSize", "VmRSS", "SigPnd", "Cpus_allowed"] {
                    value(&format!("  has {n}"), names.iter().any(|x| x == n) as i64);
                }
            }
            None => line("/proc/<zombie>/status", "unreadable"),
        }
        for f in ["cmdline", "environ", "auxv", "maps", "comm", "statm", "limits"] {
            match read_or_errno(&format!("/proc/{pid}/{f}")) {
                Ok(b) if f == "statm" || f == "comm" => line(&format!("/proc/<zombie>/{f}"), String::from_utf8_lossy(&b).trim()),
                // Lines, not bytes: the values are the environment's rlimits,
                // and the question is whether a zombie's limits read at all.
                Ok(b) if f == "limits" => value("/proc/<zombie>/limits: lines", b.split(|&c| c == b'\n').filter(|l| !l.is_empty()).count() as i64),
                Ok(b) => value(&format!("/proc/<zombie>/{f}: bytes"), b.len() as i64),
                Err(e) => line(&format!("/proc/<zombie>/{f}"), errname(e)),
            }
        }
        match read_or_errno(&format!("/proc/{pid}/mem")) {
            Ok(b) => value("/proc/<zombie>/mem: bytes", b.len() as i64),
            Err(e) => line("/proc/<zombie>/mem", errname(e)),
        }
        for f in ["exe", "cwd", "root"] {
            match fs::read_link(format!("/proc/{pid}/{f}")) {
                Ok(_) => line(&format!("/proc/<zombie>/{f}"), "ok"),
                Err(e) => line(&format!("/proc/<zombie>/{f}"), errname(e.raw_os_error().unwrap_or(0))),
            }
        }
        match fs::read_dir(format!("/proc/{pid}/fd")) {
            Ok(d) => value("/proc/<zombie>/fd: entries", d.count() as i64),
            Err(e) => line("/proc/<zombie>/fd", errname(e.raw_os_error().unwrap_or(0))),
        }
        let mut st = 0;
        unsafe { libc::waitpid(pid, &mut st, 0) };
        value("after reaping, /proc/<pid>/stat is gone", read(&stat_path).is_none() as i64);
    }

    sysctl();
    mount_tables();
    smaps();
    dot_entries();
    link_counts();
    niceness();
    oom_adjust();
}

/// `/proc/self/oom_score_adj` and the legacy `oom_adj`: read, written, out of
/// range, and inherited. Missing until 2026-10-18, so a daemon that sets its
/// own (PostgreSQL's postmaster, Chromium) failed the open. Run in a child,
/// so the value does not follow the cases after it.
fn oom_adjust() {
    println!("## oom_score_adj");
    fn put(f: &str, v: &str) -> String {
        match fs::write(f, v) {
            Ok(()) => "ok".into(),
            Err(e) => errname(e.raw_os_error().unwrap_or(0)).into(),
        }
    }
    fn get(f: &str) -> String {
        read(f).map_or_else(|| "unreadable".into(), |t| t.trim().to_string())
    }
    // SAFETY: the child prints and exits without returning.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let adj = "/proc/self/oom_score_adj";
        let old = "/proc/self/oom_adj";
        line("initially", &get(adj));
        // `echo 5 > file` opens with O_TRUNC: a proc file's truncation is
        // accepted and changes nothing, and its mode cannot be changed.
        let c = std::ffi::CString::new(adj).unwrap();
        // SAFETY: a path.
        let t = unsafe { libc::truncate(c.as_ptr(), 0) };
        line("truncate", if t == 0 { "ok" } else { errname(errno()) });
        // SAFETY: a path.
        let m = unsafe { libc::chmod(c.as_ptr(), 0o600) };
        line("chmod", if m == 0 { "ok" } else { errname(errno()) });
        line("write 500", &put(adj, "500"));
        line("  reads", &get(adj));
        line("  oom_adj reads", &get(old));
        line("write 1001", &put(adj, "1001"));
        line("write -1001", &put(adj, "-1001"));
        line("write abc", &put(adj, "abc"));
        line("write \" 42\\n\"", &put(adj, " 42\n"));
        line("  reads", &get(adj));
        line("oom_adj write 15", &put(old, "15"));
        line("  oom_score_adj reads", &get(adj));
        line("oom_adj write 16", &put(old, "16"));
        line("write 300", &put(adj, "300"));
        // A child sees the parent's value.
        let inherited = std::process::Command::new("/bin/cat").arg(adj).output();
        line("a child reads", &inherited.map_or("no child".into(), |o| String::from_utf8_lossy(&o.stdout).trim().to_string()));
        // Lowering needs CAP_SYS_RESOURCE -- below the floor through
        // `oom_score_adj`, at all through `oom_adj` -- which a container's
        // root lacks and this kernel's root has, so it is not asked here; nor
        // is an
        // unprivileged writer, whom Linux refuses at the open because the
        // process stops being dumpable when it changes uid.
        use std::io::Write;
        let _ = std::io::stdout().flush();
        // SAFETY: ends the child.
        unsafe { libc::_exit(0) };
    }
    let mut st = 0;
    // SAFETY: our own child.
    unsafe { libc::waitpid(pid, &mut st, 0) };
}

/// Fields 18 and 19 of `/proc/self/stat`, priority and nice, after `nice(5)`:
/// Linux's 25 and 5. They were the constants 20 and 0 until 2026-10-18. In a
/// child, because lowering this process's priority would slow every case
/// after it.
fn niceness() {
    println!("## priority and nice in stat");
    // SAFETY: the child prints and exits without returning.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // SAFETY: no pointers.
        unsafe { libc::nice(5) };
        let fields = read("/proc/self/stat").map(|t| {
            let after = &t[t.rfind(')').unwrap_or(0) + 1..];
            after.split_whitespace().skip(15).take(2).collect::<Vec<_>>().join(" ")
        });
        line("after nice(5): priority nice", &fields.unwrap_or_else(|| "unreadable".into()));
        use std::io::Write;
        let _ = std::io::stdout().flush();
        // SAFETY: ends the child.
        unsafe { libc::_exit(0) };
    }
    let mut st = 0;
    // SAFETY: our own child.
    unsafe { libc::waitpid(pid, &mut st, 0) };
}

/// `st_nlink` in /proc. Everything was 0 -- "deleted" -- until 2026-10-18.
/// A file or a link is 1, the sysctl tree is 1, and another directory is 2
/// plus the subdirectories it lists: `fd` lists none, `task` this one thread.
/// `/proc` itself is not compared: Linux counts every process on the machine
/// (`nr_processes`), which a container's pid namespace does not list.
fn link_counts() {
    use std::os::unix::fs::MetadataExt;
    println!("## link counts");
    for f in [
        "/proc/self/status", "/proc/uptime", "/proc/sys/kernel/ostype",
        "/proc/sys", "/proc/sys/kernel", "/proc/self/fd", "/proc/self/task",
    ] {
        value(&format!("{f}: nlink"), fs::metadata(f).map_or(-1, |m| m.nlink() as i64));
    }
    value("/proc/self/exe: nlink", fs::symlink_metadata("/proc/self/exe").map_or(-1, |m| m.nlink() as i64));
}

/// The `.` and `..` a procfs directory lists first.
///
/// `std::fs::read_dir` drops both, so this reads with `readdir`. Every
/// procfs directory listed neither until 2026-10-18, so `ls -a /proc` began
/// at `1`. The inodes are compared rather than printed: `.` is the
/// directory itself, and `..` its parent -- or itself at the mount's root.
fn dot_entries() {
    println!("## . and .. in a procfs listing");
    fn ino(path: &str) -> u64 {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(path).map_or(0, |m| m.ino())
    }
    for (dir, parent) in [
        ("/proc", "/proc"),
        ("/proc/self", "/proc"),
        ("/proc/self/fd", "/proc/self"),
        ("/proc/sys", "/proc"),
        ("/proc/sys/kernel", "/proc/sys"),
    ] {
        let c = std::ffi::CString::new(dir).unwrap();
        // SAFETY: a NUL-terminated path; the stream is closed below.
        let d = unsafe { libc::opendir(c.as_ptr()) };
        if d.is_null() {
            line(dir, errname(errno()));
            continue;
        }
        let mut first = Vec::new();
        while first.len() < 2 {
            // SAFETY: an open stream; the entry is read before the next call.
            let e = unsafe { libc::readdir(d) };
            if e.is_null() {
                break;
            }
            // SAFETY: as above.
            let e = unsafe { &*e };
            // SAFETY: `d_name` is NUL-terminated.
            let name = unsafe { std::ffi::CStr::from_ptr(e.d_name.as_ptr()) };
            first.push((name.to_string_lossy().into_owned(), e.d_ino, e.d_type));
        }
        // SAFETY: opened above.
        unsafe { libc::closedir(d) };
        let names: Vec<&str> = first.iter().map(|f| f.0.as_str()).collect();
        line(&format!("{dir}: the first two names"), &names.join(" "));
        if let [(_, dot, dt), (_, dotdot, ddt)] = first[..] {
            value("  . is the directory itself", (dot == ino(dir)) as i64);
            value("  .. is its parent", (dotdot == ino(parent)) as i64);
            value("  both are DT_DIR", (dt == libc::DT_DIR && ddt == libc::DT_DIR) as i64);
        }
    }
}

/// `/proc/self/mountinfo`, `/proc/self/mounts` and `/proc/devices`.
///
/// The *content* is the machine's -- a container has different mounts -- so
/// what is compared is the shape every parser depends on: how many fields a
/// line has, that the ids are unique and that each parent id names a line, and
/// that the two headings `/proc/devices` is split on are both there.
/// `/proc/<pid>/smaps` and `smaps_rollup`.
///
/// The last section is the one with a program behind it. Redis's
/// `checkLinuxMadvFreeForkBug` runs on every arm64 start: it maps three pages,
/// writes the middle one, `madvise(MADV_FREE)`s it, writes it again, forks, and
/// in the **child** reads `Shared_Dirty:` for the mapping holding that page. A
/// zero means the kernel corrupts background saves and a missing file means the
/// test could not run; either way `redis-server` calls `exit(1)` before opening
/// a socket, which is what it did here until `smaps` existed.
///
/// The values are the machine's, so what is compared is the shape: which fields
/// are there, in what order, and the sign of the one answer a program acts on.
fn smaps() {
    println!("## /proc/self/smaps");
    let text = read("/proc/self/smaps").unwrap_or_default();
    value("smaps is non-empty", (!text.trim().is_empty()) as i64);

    // A block is a maps line followed by `Name:` lines. Take the first.
    // A header is a hex range; a field line is `Name:`. The maps line has a
    // colon in it too -- the `00:00` device column -- so telling them apart on
    // the colon does not work, which is what the first version of this did.
    let is_header = |l: &str| {
        l.split_once(' ')
            .and_then(|(r, _)| r.split_once('-'))
            .is_some_and(|(a, b)| {
                !a.is_empty()
                    && !b.is_empty()
                    && a.chars().all(|c| c.is_ascii_hexdigit())
                    && b.chars().all(|c| c.is_ascii_hexdigit())
            })
    };
    let mut names: Vec<String> = Vec::new();
    let mut seen_header = false;
    for l in text.lines() {
        if is_header(l) {
            if seen_header {
                break;
            }
            seen_header = true;
            continue;
        }
        if seen_header {
            if let Some((n, _)) = l.split_once(':') {
                names.push(n.to_string());
            }
        }
    }
    // The names a reader looks for, in the order the kernel writes them. Not
    // the whole list: `KSM` arrived in 6.6 and `Pss_Dirty` in 5.13, so a
    // container on an older kernel would differ for a reason that is not a
    // defect.
    for want in [
        "Size",
        "KernelPageSize",
        "MMUPageSize",
        "Rss",
        "Pss",
        "Shared_Clean",
        "Shared_Dirty",
        "Private_Clean",
        "Private_Dirty",
        "Referenced",
        "Anonymous",
        "Swap",
        "Locked",
        "VmFlags",
    ] {
        value(&format!("  has {want}"), names.iter().any(|n| n == want) as i64);
    }
    // Relative order, which is what a reader scanning forward depends on.
    let at = |n: &str| names.iter().position(|x| x == n);
    value(
        "  Rss comes before Pss",
        (at("Rss") < at("Pss")) as i64,
    );
    value(
        "  Shared_Dirty comes before Private_Dirty",
        (at("Shared_Dirty") < at("Private_Dirty")) as i64,
    );
    value("  VmFlags is last", (at("VmFlags") == Some(names.len() - 1)) as i64);
    // Every `kB` line puts its unit in the same column, which is what makes
    // the file parseable by column.
    let columns: Vec<usize> = text
        .lines()
        .filter(|l| l.ends_with(" kB"))
        .map(|l| l.len())
        .collect();
    value(
        "  every kB line is the same width",
        columns.windows(2).all(|w| w[0] == w[1]) as i64,
    );
    value("  and there are some", (!columns.is_empty()) as i64);

    // Rss is at most Size, per mapping. A resident count above the span would
    // be an accounting error rather than a difference between kernels.
    let mut ok = true;
    let mut size = 0u64;
    for l in text.lines() {
        if let Some(v) = l.strip_prefix("Size:") {
            size = v.trim().trim_end_matches(" kB").trim().parse().unwrap_or(0);
        } else if let Some(v) = l.strip_prefix("Rss:") {
            let rss: u64 = v.trim().trim_end_matches(" kB").trim().parse().unwrap_or(0);
            if rss > size {
                ok = false;
            }
        }
    }
    value("  Rss never exceeds Size", ok as i64);

    println!("## /proc/self/smaps_rollup");
    let roll = read("/proc/self/smaps_rollup").unwrap_or_default();
    value("smaps_rollup is non-empty", (!roll.trim().is_empty()) as i64);
    value(
        "  the header names it [rollup]",
        roll.lines().next().is_some_and(|l| l.contains("[rollup]")) as i64,
    );
    for want in ["Rss", "Pss", "Private_Dirty", "Locked"] {
        value(
            &format!("  has {want}"),
            roll.lines().any(|l| l.starts_with(&format!("{want}:"))) as i64,
        );
    }
    value(
        "  it has no per-mapping fields",
        !roll.lines().any(|l| l.starts_with("Size:") || l.starts_with("VmFlags:")) as i64,
    );

    redis_cow_question();
}

/// Redis's question, asked the way Redis asks it.
fn redis_cow_question() {
    println!("## the copy-on-write question redis asks");
    let page = 4096usize;
    let map = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page * 3,
            libc::PROT_READ,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if map == libc::MAP_FAILED {
        value("mmap of three pages", 0);
        return;
    }
    let q = unsafe { (map as *mut u8).add(page) };
    // The middle page read-write, which on Linux also splits the mapping in
    // three so that the counts below are about that page alone.
    let r = unsafe { libc::mprotect(q.cast(), page, libc::PROT_READ | libc::PROT_WRITE) };
    value("mprotect the middle page", (r == 0) as i64);
    unsafe { std::ptr::write_volatile(q, 0) };
    let r = unsafe { libc::madvise(q.cast(), page, libc::MADV_FREE) };
    // Refused is a legitimate answer -- Redis reads EINVAL as "too old to have
    // the bug" -- so what is compared is that it is one of the two.
    value("madvise(MADV_FREE) is accepted or EINVAL", (r == 0 || errno() == libc::EINVAL) as i64);
    unsafe { std::ptr::write_volatile(q, 0) };

    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        value("pipe", 0);
        return;
    }
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let v = shared_dirty_of(q as usize);
        let b = v.to_le_bytes();
        unsafe { libc::write(fds[1], b.as_ptr().cast(), b.len()) };
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::close(fds[1]) };
    let mut b = [0u8; 8];
    let n = unsafe { libc::read(fds[0], b.as_mut_ptr().cast(), b.len()) };
    unsafe {
        libc::close(fds[0]);
        libc::waitpid(pid, std::ptr::null_mut(), 0);
    }
    let child = if n == 8 { i64::from_le_bytes(b) } else { -2 };
    // The whole of what Redis acts on: -1 is "no answer" and 0 is "this kernel
    // corrupts background saves". Anything above zero is the healthy answer,
    // and how much is the machine's business.
    value("the child's Shared_Dirty is above zero", (child > 0) as i64);
    unsafe { libc::munmap(map, page * 3) };
}

/// `smapsGetSharedDirty` from redis's `syscheck.c`: the first `Shared_Dirty:`
/// after the mapping line that contains `addr`. -1 when there is none.
fn shared_dirty_of(addr: usize) -> i64 {
    let Some(text) = read("/proc/self/smaps") else {
        return -1;
    };
    let mut inside = false;
    for l in text.lines() {
        if let Some((range, _)) = l.split_once(' ') {
            if let Some((from, to)) = range.split_once('-') {
                if let (Ok(a), Ok(b)) = (
                    u64::from_str_radix(from, 16),
                    u64::from_str_radix(to, 16),
                ) {
                    inside = a <= addr as u64 && (addr as u64) < b;
                }
            }
        }
        if inside {
            if let Some(v) = l.strip_prefix("Shared_Dirty:") {
                return v.trim().trim_end_matches(" kB").trim().parse().unwrap_or(-1);
            }
        }
    }
    -1
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn mount_tables() {
    println!("## the mount tables");
    let info = read("/proc/self/mountinfo").unwrap_or_default();
    value("/proc/self/mountinfo is non-empty", (!info.trim().is_empty()) as i64);
    let lines: Vec<&str> = info.lines().filter(|l| !l.trim().is_empty()).collect();
    // Every line: at least ten fields, and a `-` separating the optional ones
    // from the filesystem type.
    let well_formed = lines.iter().all(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        f.len() >= 10 && f.iter().any(|x| *x == "-")
    });
    value("  every line has the fields and the separator", well_formed as i64);
    // The first field is an id, and no two lines share one.
    let ids: Vec<&str> = lines.iter().filter_map(|l| l.split_whitespace().next()).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    sorted.dedup();
    value("  the ids are unique", (sorted.len() == ids.len()) as i64);
    value("  the ids are numbers", ids.iter().all(|i| i.parse::<u64>().is_ok()) as i64);
    // The parent ids make a tree. **At most one** may name a line that is not
    // here: in a mount namespace the root's parent is a mount outside it, and
    // a container has exactly that. Requiring all of them to resolve is a
    // check that passes here and fails on a real kernel, which is the wrong
    // way round.
    let parents: Vec<&str> = lines.iter().filter_map(|l| l.split_whitespace().nth(1)).collect();
    let dangling = parents.iter().filter(|p| !ids.contains(p)).count();
    value("  at most one parent id is not a mount", (dangling <= 1) as i64);
    value("  the parent ids are numbers", parents.iter().all(|p| p.parse::<u64>().is_ok()) as i64);
    // The fourth field is the subtree of the filesystem that is mounted, and
    // the fifth is where. The root filesystem is in there somewhere.
    value(
        "  a line mounts something at /",
        lines
            .iter()
            .any(|l| l.split_whitespace().nth(4) == Some("/")) as i64,
    );
    // The same mounts, the other way round: /proc/mounts has six fields.
    let mounts = read("/proc/self/mounts").unwrap_or_default();
    let six = mounts
        .lines()
        .filter(|l| !l.trim().is_empty())
        .all(|l| l.split_whitespace().count() == 6);
    value("/proc/self/mounts has six fields a line", six as i64);
    value(
        "  it has as many lines as mountinfo",
        (mounts.lines().filter(|l| !l.trim().is_empty()).count() == lines.len()) as i64,
    );
    // And the root's own copy is the same table.
    value(
        "/proc/mounts agrees with /proc/self/mounts",
        (read("/proc/mounts").unwrap_or_default() == mounts) as i64,
    );

    let dev = read("/proc/devices").unwrap_or_default();
    value("/proc/devices names both headings", (dev.contains("Character devices:") && dev.contains("Block devices:")) as i64);
    // Every entry is a number and a name.
    let entries_ok = dev
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.ends_with(':'))
        .all(|l| {
            let mut f = l.split_whitespace();
            f.next().map(|n| n.parse::<u32>().is_ok()).unwrap_or(false) && f.next().is_some()
        });
    value("  every entry is a major and a name", entries_ok as i64);
    // The three a guest actually makes a node for.
    for (major, what) in [(1u32, "mem"), (5, "the tty alternate"), (136, "pts")] {
        value(
            &format!("  major {major} ({what}) is listed"),
            dev.lines().any(|l| l.split_whitespace().next() == Some(&major.to_string())) as i64,
        );
    }
}

/// `/proc/sys`: the knobs a program reads before it decides what to ask for.
///
/// Most of the *values* are the machine's and cannot be compared -- a
/// container's `pid_max` is 4194304 and this kernel's is 32768 -- so what is
/// compared is that the file is there, that it parses, and the handful whose
/// value is a documented default that both sides should agree on.
fn sysctl() {
    println!("## /proc/sys");
    for f in [
        "/proc/sys/kernel/cap_last_cap",
        "/proc/sys/kernel/hostname",
        "/proc/sys/kernel/ngroups_max",
        "/proc/sys/kernel/osrelease",
        "/proc/sys/kernel/ostype",
        "/proc/sys/kernel/pid_max",
        "/proc/sys/kernel/version",
        "/proc/sys/kernel/random/boot_id",
        "/proc/sys/kernel/random/uuid",
        "/proc/sys/fs/pipe-max-size",
        "/proc/sys/fs/inotify/max_queued_events",
        "/proc/sys/vm/overcommit_memory",
    ] {
        match read(f) {
            Some(t) => value(&format!("{f}: non-empty"), (!t.trim().is_empty()) as i64),
            None => line(f, "unreadable"),
        }
    }

    // The ones whose value is a number, whatever number it is.
    for f in [
        "/proc/sys/kernel/cap_last_cap",
        "/proc/sys/kernel/ngroups_max",
        "/proc/sys/kernel/pid_max",
        "/proc/sys/fs/pipe-max-size",
        "/proc/sys/fs/inotify/max_queued_events",
        "/proc/sys/vm/overcommit_memory",
    ] {
        let ok = read(f)
            .and_then(|t| t.trim().parse::<u64>().ok())
            .is_some();
        value(&format!("{f} parses as a number"), ok as i64);
    }

    // The ones both sides should agree on exactly: a string this kernel
    // chooses, and two Linux defaults.
    line("/proc/sys/kernel/ostype", read("/proc/sys/kernel/ostype").unwrap_or_default().trim());
    line(
        "/proc/sys/fs/pipe-max-size",
        read("/proc/sys/fs/pipe-max-size").unwrap_or_default().trim(),
    );
    // Not compared by value: the queue bound is the machine's, and a
    // container's kernel uses a much larger default than mainline's 16384.
    // That it is a number is checked above.

    // cap_last_cap is what libcap-ng reads before it does anything, and it has
    // to be at least as large as the capabilities this kernel names.
    let last = read("/proc/sys/kernel/cap_last_cap")
        .and_then(|t| t.trim().parse::<u64>().ok())
        .unwrap_or(0);
    value("cap_last_cap is at least 37", (last >= 37) as i64);

    // A UUID per read, and one boot id for the life of the process.
    let (u1, u2) = (read("/proc/sys/kernel/random/uuid"), read("/proc/sys/kernel/random/uuid"));
    value("two uuids differ", (u1 != u2) as i64);
    value(
        "a uuid is 36 characters",
        u1.map(|u| u.trim().len() == 36).unwrap_or(false) as i64,
    );
    let (b1, b2) = (read("/proc/sys/kernel/random/boot_id"), read("/proc/sys/kernel/random/boot_id"));
    value("two boot_ids agree", (b1 == b2 && b1.is_some()) as i64);

    // The hostname agrees with uname's, which is the same question asked two
    // ways -- a kernel with two copies of it answers differently.
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    unsafe { libc::uname(&mut uts) };
    let from_uname: String = uts
        .nodename
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8 as char)
        .collect();
    value(
        "kernel/hostname agrees with uname",
        (read("/proc/sys/kernel/hostname").unwrap_or_default().trim() == from_uname) as i64,
    );

    // Writing is refused, and *which* refusal is not comparable: a container
    // mounts /proc/sys read-only, so it answers before the file is reached,
    // and here the file itself has no write. What both sides agree on is that
    // the value does not change.
    let before = read("/proc/sys/kernel/hostname");
    let fd = unsafe {
        libc::open(
            c"/proc/sys/kernel/hostname".as_ptr(),
            libc::O_WRONLY | libc::O_TRUNC,
        )
    };
    if fd >= 0 {
        unsafe {
            libc::write(fd, b"changed".as_ptr().cast(), 7);
            libc::close(fd);
        }
    }
    value("writing kernel/hostname changes nothing", (read("/proc/sys/kernel/hostname") == before) as i64);
    // A directory in it is a directory.
    line(
        "/proc/sys/kernel is a directory",
        &match std::fs::metadata("/proc/sys/kernel") {
            Ok(m) => if m.is_dir() { "yes".into() } else { "no".into() },
            Err(e) => errname(e.raw_os_error().unwrap_or(0)),
        },
    );
}

fn gettid() -> i32 {
    unsafe { libc::syscall(libc::SYS_gettid) as i32 }
}

/// The numeric entries of a directory.
fn numbered(dir: &str) -> Vec<i32> {
    fs::read_dir(dir)
        .map(|d| {
            d.filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().to_string_lossy().parse::<i32>().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// One `Name:\tvalue` field of a status file, or empty.
fn status_field(text: &str, name: &str) -> String {
    text.lines()
        .find_map(|l| l.split_once(':').filter(|(k, _)| *k == name).map(|(_, v)| v.trim().to_string()))
        .unwrap_or_default()
}

/// The fields of a stat line after `(comm)`, so that field 3 is index 0 — a
/// comm with a space in it cannot shift them.
fn stat_fields(text: &str) -> Vec<&str> {
    text.rsplit_once(')')
        .map(|(_, rest)| rest.split_whitespace().collect())
        .unwrap_or_default()
}

/// `pipe:[12345]` as `pipe:[#]`: the shape is the answer, the number is not.
fn mask_number(name: &str) -> String {
    let mut out = String::new();
    let mut in_digits = false;
    for c in name.chars() {
        if c.is_ascii_digit() {
            if !in_digits {
                out.push('#');
                in_digits = true;
            }
        } else {
            in_digits = false;
            out.push(c);
        }
    }
    out
}

fn read_or_errno(path: &str) -> Result<Vec<u8>, i32> {
    fs::read(path).map_err(|e| e.raw_os_error().unwrap_or(0))
}

fn errname(e: i32) -> &'static str {
    match e {
        libc::ENOENT => "ENOENT",
        libc::ESRCH => "ESRCH",
        libc::EACCES => "EACCES",
        libc::EINVAL => "EINVAL",
        libc::EIO => "EIO",
        libc::EPERM => "EPERM",
        0 => "ok",
        _ => "other",
    }
}
