//! The shape of the `/proc` files everything parses.
//!
//! `free`, `top`, `vmstat` and every runtime that sizes a heap read these, and
//! a wrong number is silent — nothing fails, the program just believes it.
//!
//! The values differ between a container and this kernel, so what is compared
//! is the **shape**: how many fields a line has, which keys exist, and the
//! relationships that have to hold whatever the machine is. One of those
//! relationships catches a wrong unit: `/proc/meminfo`'s `MemTotal` and
//! `sysinfo`'s `totalram` are the same quantity in different units, so they can
//! be checked against each other without knowing either.

use guest_tests::{Harness, check};

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// The numbers on a `/proc/stat` line, after the label.
fn fields(line: &str) -> Vec<u64> {
    line.split_whitespace().skip(1).filter_map(|f| f.parse().ok()).collect()
}

fn meminfo_kb(text: &str, key: &str) -> Option<u64> {
    for line in text.lines() {
        let (name, rest) = line.split_once(':')?;
        if name == key {
            return rest.trim().trim_end_matches(" kB").trim().parse().ok();
        }
    }
    None
}

fn main() {
    let mut h = Harness::new();

    h.group("uptime");
    let uptime = read("/proc/uptime");
    let parts: Vec<f64> = uptime.split_whitespace().filter_map(|f| f.parse().ok()).collect();
    check!(h, parts.len() == 2, "two fields: {uptime:?}");
    if parts.len() == 2 {
        check!(h, parts[0] > 0.0, "the first is how long we have been up: {}", parts[0]);
        // The second is idle time summed over every processor, so on anything
        // with more than one it is larger -- often several times. Reporting the
        // uptime twice is what a kernel that has not implemented it does, and
        // anything computing an idle fraction from the pair then sees 100%.
        check!(h, parts[1] > parts[0],
            "the second is idle time over all processors, so it is larger: {} vs {}",
            parts[1], parts[0]);
    } else {
        for _ in 0..2 {
            check!(h, false, "two fields");
        }
    }
    // Two decimal places, both of them: a reader parses the fraction as
    // hundredths, so `.7` is read as `.70`.
    for f in uptime.split_whitespace() {
        let frac = f.split_once('.').map(|(_, d)| d.len()).unwrap_or(0);
        check!(h, frac == 2, "each field has two decimal places: {f:?}");
    }

    h.group("stat");
    let stat = read("/proc/stat");
    let cpu_line = stat.lines().find(|l| l.starts_with("cpu ")).unwrap_or("").to_string();
    check!(h, !cpu_line.is_empty(), "there is an aggregate cpu line");
    // user nice system idle iowait irq softirq steal guest guest_nice. Ten
    // since 2.6.33, and a reader indexes them: one that stops at four leaves
    // whoever wanted iowait or steal reading whatever was next in its buffer.
    check!(h, fields(&cpu_line).len() == 10,
        "with ten fields: {} in {cpu_line:?}", fields(&cpu_line).len());
    let percpu: Vec<&str> = stat.lines()
        .filter(|l| l.starts_with("cpu") && !l.starts_with("cpu "))
        .collect();
    check!(h, !percpu.is_empty(), "and at least one per-processor line");
    check!(h, percpu.iter().all(|l| fields(l).len() == 10),
        "each with ten as well: {:?}",
        percpu.iter().map(|l| fields(l).len()).collect::<Vec<_>>());
    // The per-cpu lines have to add up to the aggregate, or a reader that sums
    // them disagrees with the line above.
    let agg = fields(&cpu_line);
    if agg.len() == 10 && !percpu.is_empty() {
        let mut summed = vec![0u64; 10];
        for l in &percpu {
            for (i, v) in fields(l).iter().enumerate().take(10) {
                summed[i] += v;
            }
        }
        // Within one tick per processor per column: the split is integer
        // division and the remainder has nowhere to go.
        let slack = percpu.len() as u64;
        check!(h,
            (0..10).all(|i| agg[i] >= summed[i] && agg[i] - summed[i] <= slack),
            "and they add up to it: {agg:?} vs {summed:?}");
    } else {
        check!(h, false, "and they add up to it");
    }
    for key in ["btime ", "ctxt ", "processes ", "procs_running ", "procs_blocked "] {
        check!(h, stat.lines().any(|l| l.starts_with(key)),
            "there is a {:?} line", key.trim());
    }
    let btime: u64 = stat.lines().find(|l| l.starts_with("btime "))
        .and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse().ok()).unwrap_or(0);
    check!(h, btime > 1_000_000_000, "btime is a time since the epoch: {btime}");

    h.group("meminfo");
    let meminfo = read("/proc/meminfo");
    check!(h, !meminfo.is_empty(), "there is one");
    // Every line is `Name:` then a number then `kB`. A reader splits on the
    // colon and takes the first word after it.
    let malformed: Vec<&str> = meminfo.lines()
        .filter(|l| {
            let Some((_, rest)) = l.split_once(':') else { return true };
            let mut it = rest.split_whitespace();
            let num = it.next().and_then(|v| v.parse::<u64>().ok());
            num.is_none() || it.next() != Some("kB")
        })
        .collect();
    check!(h, malformed.is_empty(), "every line is `Name: N kB`: {malformed:?}");
    let total = meminfo_kb(&meminfo, "MemTotal").unwrap_or(0);
    let free = meminfo_kb(&meminfo, "MemFree").unwrap_or(u64::MAX);
    let avail = meminfo_kb(&meminfo, "MemAvailable").unwrap_or(u64::MAX);
    check!(h, total > 0, "MemTotal is a number: {total}");
    check!(h, free <= total, "MemFree is within it: {free} of {total}");
    check!(h, avail <= total, "MemAvailable is within it: {avail} of {total}");

    h.group("meminfo-agrees-with-sysinfo");
    // The same quantity in two units, so they check each other without this
    // test having to know how much memory the machine has. `kB` in
    // /proc/meminfo is 1024 bytes, not 1000 -- a kernel that divides by the
    // wrong one reports 2.4% more memory than exists, and nothing says so.
    let mut si: libc::sysinfo = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::sysinfo(&mut si) };
    check!(h, r == 0, "sysinfo: r={r}");
    let unit = if si.mem_unit == 0 { 1u64 } else { si.mem_unit as u64 };
    let sysinfo_kb = (si.totalram as u64).saturating_mul(unit) / 1024;
    // Within a kibibyte of each other; both are integer divisions of the same
    // byte count.
    check!(h, total.abs_diff(sysinfo_kb) <= 1,
        "MemTotal is sysinfo's totalram in kibibytes: {total} vs {sysinfo_kb}");

    h.group("version-and-cpuinfo");
    let version = read("/proc/version");
    check!(h, version.starts_with("Linux version "),
        "/proc/version starts as everything expects: {:?}", version.lines().next());
    let cpuinfo = read("/proc/cpuinfo");
    check!(h, !cpuinfo.is_empty(), "there is a /proc/cpuinfo");
    // One block per processor, and a reader counts the `processor` lines.
    let processors = cpuinfo.lines().filter(|l| l.starts_with("processor")).count();
    check!(h, processors >= 1, "with at least one processor: {processors}");
    check!(h, processors == percpu.len(),
        "as many as /proc/stat has per-cpu lines: {processors} vs {}", percpu.len());

    // ------------------------------------------------------------------
    // /proc/net/{tcp,unix}
    //
    // Five of the seven files in this directory did not exist until
    // 2026-09-07, and `netstat -an` in a guest answered
    // `netstat: /proc/net/tcp: No such file or directory`. What is checked here
    // is the *tie*: the inode column is how a tool matches a socket to the
    // process holding it, through `/proc/<pid>/fd/<n>` reading `socket:[N]`.
    // A file that lists sockets with a wrong or shared inode reads as working
    // and attributes every connection to the wrong process.
    h.group("proc-net");

    for f in ["tcp", "tcp6", "udp", "udp6", "unix", "raw", "raw6"] {
        let text = read(&format!("/proc/net/{f}"));
        check!(h, !text.is_empty(), "/proc/net/{f} has a header");
    }
    check!(
        h,
        read("/proc/net/tcp").lines().next().unwrap_or("").contains("local_address"),
        "and it is the header a parser expects"
    );

    // A listening socket on a port this test picked.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    check!(h, fd >= 0, "socket()");
    if fd >= 0 {
        let one: i32 = 1;
        unsafe {
            libc::setsockopt(
                fd, libc::SOL_SOCKET, libc::SO_REUSEADDR,
                (&raw const one).cast(), std::mem::size_of::<i32>() as u32,
            )
        };
        let mut a: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        a.sin_family = libc::AF_INET as u16;
        a.sin_port = 0x5c11; // 4444, network order
        a.sin_addr.s_addr = 0x0100_007f; // 127.0.0.1, network order
        let bound = unsafe {
            libc::bind(fd, (&raw const a).cast(), std::mem::size_of::<libc::sockaddr_in>() as u32)
        };
        check!(h, bound == 0, "bind 127.0.0.1:4444");
        check!(h, unsafe { libc::listen(fd, 5) } == 0, "listen");

        let text = read("/proc/net/tcp");
        // 127.0.0.1 prints as 0100007F -- the network-order bytes read as a
        // little-endian word, which is the one thing in this format that looks
        // wrong and is right. 4444 is 115C.
        let line = text.lines().find(|l| l.contains("0100007F:115C"));
        check!(h, line.is_some(), "the socket is in /proc/net/tcp:\n{text}");
        if let Some(line) = line {
            let f: Vec<&str> = line.split_whitespace().collect();
            check!(h, f.get(3) == Some(&"0A"), "and its state is LISTEN: {line}");
            check!(h, f.get(2) == Some(&"00000000:0000"), "with no remote end");

            // The tie. `/proc/self/fd/<n>` reads `socket:[N]`, and N is the
            // inode column -- which is what lsof matches on.
            let want = std::fs::read_link(format!("/proc/self/fd/{fd}"))
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let inode = f.get(9).copied().unwrap_or("");
            check!(
                h,
                want == format!("socket:[{inode}]"),
                "the inode column matches /proc/self/fd: {want:?} vs {inode:?}"
            );
        }

        // A second socket must not share the first's inode, which is what a
        // tool relies on to tell two connections apart.
        let fd2 = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        if fd2 >= 0 {
            let a = std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap_or_default();
            let b = std::fs::read_link(format!("/proc/self/fd/{fd2}")).unwrap_or_default();
            check!(h, a != b, "two sockets have two inodes: {a:?} and {b:?}");
            unsafe { libc::close(fd2) };
        }
        unsafe { libc::close(fd) };

        // And it is gone once closed: a stale entry is worse than none,
        // because a caller reads this file to find out what is still up.
        let after = read("/proc/net/tcp");
        check!(
            h,
            !after.contains("0100007F:115C"),
            "the closed socket is out of the list"
        );
    }

    std::process::exit(h.finish());
}
