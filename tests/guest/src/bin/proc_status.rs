//! `/proc/<pid>/status`, `environ`, `root`, and `stat`'s memory fields.
//!
//! `status` did not exist at all: `ps`, `top`, container detection and every
//! runtime that sizes itself from `VmRSS` read it and got `ENOENT`. `stat`'s
//! fields 23 and 24 were hardcoded zeroes, so `ps` showed `VSZ 0` for every
//! process. `environ` did not exist either, and `mm->env_start`/`env_end`
//! existed but were never written.
//!
//! Every check compares a field against something the guest can ask for
//! directly, so a formatter that is internally consistent and wrong does not
//! pass.

use guest_tests::{Harness, check};
use std::collections::HashMap;

fn read_status(path: &str) -> HashMap<String, String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.to_string(), v.trim().to_string()))
        .collect()
}

fn kb(m: &HashMap<String, String>, key: &str) -> u64 {
    m.get(key)
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn main() {
    let mut h = Harness::new();

    h.group("self");
    let s = read_status("/proc/self/status");
    check!(h, !s.is_empty(), "/proc/self/status exists and parses");
    if s.is_empty() {
        std::process::exit(h.finish());
    }

    let pid = unsafe { libc::getpid() };
    let ppid = unsafe { libc::getppid() };
    check!(h, s.get("Pid").map(String::as_str) == Some(pid.to_string().as_str()),
        "Pid matches getpid(): {:?} vs {pid}", s.get("Pid"));
    check!(h, s.get("PPid").map(String::as_str) == Some(ppid.to_string().as_str()),
        "PPid matches getppid(): {:?} vs {ppid}", s.get("PPid"));
    check!(h, s.get("Tgid").map(String::as_str) == Some(pid.to_string().as_str()),
        "Tgid matches for a single-threaded process: {:?}", s.get("Tgid"));
    check!(h, s.get("Name").map(String::as_str) == Some("proc_status"),
        "Name is the executable: {:?}", s.get("Name"));

    // Four values, in Linux's order: real, effective, saved, filesystem.
    let ids = |k: &str| -> Vec<u32> {
        s.get(k).map(|v| v.split_whitespace().filter_map(|x| x.parse().ok()).collect())
            .unwrap_or_default()
    };
    let uids = ids("Uid");
    check!(h, uids.len() == 4, "Uid has four values: {uids:?}");
    if uids.len() == 4 {
        check!(h, uids[0] == unsafe { libc::getuid() }, "and the first is getuid(): {}", uids[0]);
        check!(h, uids[1] == unsafe { libc::geteuid() }, "and the second is geteuid(): {}", uids[1]);
    }
    let gids = ids("Gid");
    check!(h, gids.len() == 4 && gids[0] == unsafe { libc::getgid() },
        "Gid's first value is getgid(): {gids:?}");

    let old_umask = unsafe { libc::umask(0o027) };
    let s2 = read_status("/proc/self/status");
    check!(h, s2.get("Umask").map(String::as_str) == Some("0027"),
        "Umask follows umask(): {:?}", s2.get("Umask"));
    unsafe { libc::umask(old_umask) };

    h.group("threads");
    let before: usize = s.get("Threads").and_then(|v| v.parse().ok()).unwrap_or(0);
    check!(h, before == 1, "a single-threaded process reports 1: {before}");
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut handles = Vec::new();
    for _ in 0..3 {
        let stop = stop.clone();
        handles.push(std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }));
    }
    std::thread::sleep(std::time::Duration::from_millis(120));
    let during: usize = read_status("/proc/self/status")
        .get("Threads").and_then(|v| v.parse().ok()).unwrap_or(0);
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for t in handles { t.join().unwrap(); }
    check!(h, during == 4, "and 4 with three more running: {during}");

    h.group("memory");
    let s3 = read_status("/proc/self/status");
    check!(h, s3.get("VmRSS").map(|v| v.ends_with("kB")).unwrap_or(false),
        "VmRSS carries its unit: {:?}", s3.get("VmRSS"));
    let before_kb = kb(&s3, "VmRSS");
    check!(h, before_kb > 0, "and is not zero: {before_kb} kB");
    // Touch 16 MB and watch it move: a formatter reporting a constant passes
    // everything above.
    let mut big = vec![0u8; 16 << 20];
    for i in (0..big.len()).step_by(4096) { big[i] = 1; }
    std::hint::black_box(&big);
    let after_kb = kb(&read_status("/proc/self/status"), "VmRSS");
    check!(h, after_kb >= before_kb + 8000,
        "and grows when 16 MB is touched: {before_kb} -> {after_kb} kB");

    h.group("stat-agrees-with-status");
    // `ps` reads VSZ and RSS from stat's fields 23 and 24, not from status.
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let after_paren = stat.rsplit_once(')').map(|(_, r)| r).unwrap_or("");
    let f: Vec<&str> = after_paren.split_whitespace().collect();
    let vsize: u64 = f.get(23 - 3).and_then(|v| v.parse().ok()).unwrap_or(0);
    let rss_pages: u64 = f.get(24 - 3).and_then(|v| v.parse().ok()).unwrap_or(0);
    check!(h, vsize > 0, "stat field 23 (vsize) is not zero: {vsize}");
    check!(h, rss_pages > 0, "stat field 24 (rss) is not zero: {rss_pages}");

    // Within a few pages rather than exactly: the two files are separate reads
    // and reading the second one allocates, so the address space really has
    // moved in between. An exact comparison failed by one page, which is the
    // buffer the second read grew.
    let s4 = read_status("/proc/self/status");
    // A page or two of tolerance is not enough on a real kernel: the same
    // comparison against Linux differed by 208 kB, because the allocator moves
    // more between two reads there. 4 MB is still far below the 16 MB the
    // group above deliberately touches, so a formatter reporting a constant
    // does not slip through.
    let near = |a: u64, b: u64| a.abs_diff(b) <= 4096;
    check!(h, near(vsize / 1024, kb(&s4, "VmSize")),
        "stat's vsize and status's VmSize agree: {} kB vs {} kB", vsize / 1024, kb(&s4, "VmSize"));
    check!(h, near(rss_pages * 4, kb(&s4, "VmRSS")),
        "stat's rss and status's VmRSS agree: {} kB vs {} kB", rss_pages * 4, kb(&s4, "VmRSS"));

    h.group("environ");
    // The exec-time environment, which is what Linux reports: a later setenv
    // changes the process's own copy and not this range.
    let env = std::fs::read("/proc/self/environ").unwrap_or_default();
    check!(h, !env.is_empty(), "/proc/self/environ is not empty: {} bytes", env.len());
    let vars: Vec<String> = env.split(|b| *b == 0)
        .filter(|v| !v.is_empty())
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .collect();
    check!(h, !vars.is_empty() && vars.iter().all(|v| v.contains('=')),
        "every entry is NAME=value: {:?}", vars.iter().find(|v| !v.contains('=')));
    // Against what the process itself sees, for a variable it was started with.
    let mut compared = 0;
    for (k, v) in std::env::vars() {
        if k == "HOME" || k == "PATH" {
            compared += 1;
            check!(h, vars.iter().any(|e| *e == format!("{k}={v}")),
                "{k} in environ matches getenv: {v:?}");
        }
    }
    check!(h, compared > 0, "at least one variable was there to compare");

    h.group("root-and-cmdline");
    let root = std::fs::read_link("/proc/self/root")
        .map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    check!(h, root == "/", "/proc/self/root points at the root: {root:?}");
    let cmd = std::fs::read("/proc/self/cmdline").unwrap_or_default();
    let argv0 = cmd.split(|b| *b == 0).next().unwrap_or(&[]);
    check!(h, String::from_utf8_lossy(argv0).contains("proc_status"),
        "cmdline starts with argv[0]: {:?}", String::from_utf8_lossy(argv0));

    h.group("limits");
    // Cross-checked against getrlimit, so the file cannot be internally
    // consistent and wrong. Linux's own column widths, which `ulimit -a` and
    // every other reader line up on.
    let limits = std::fs::read_to_string("/proc/self/limits").unwrap_or_default();
    check!(h, limits.lines().count() == 17,
        "a header and sixteen limits: {} lines", limits.lines().count());
    check!(h, limits.starts_with("Limit                     Soft Limit"),
        "the header is where Linux puts it: {:?}", limits.lines().next());

    let row = |name: &str| -> (String, String) {
        limits.lines()
            .find(|l| l.starts_with(name))
            .map(|l| {
                let rest = &l[25..];
                let soft = rest[..20].trim().to_string();
                let hard = rest[21..41].trim().to_string();
                (soft, hard)
            })
            .unwrap_or_default()
    };
    let spell = |v: u64| if v == u64::MAX { "unlimited".to_string() } else { v.to_string() };
    for (name, res) in [("Max open files", libc::RLIMIT_NOFILE),
                        ("Max stack size", libc::RLIMIT_STACK),
                        ("Max core file size", libc::RLIMIT_CORE),
                        ("Max processes", libc::RLIMIT_NPROC)] {
        let mut rl: libc::rlimit = unsafe { std::mem::zeroed() };
        unsafe { libc::getrlimit(res, &mut rl) };
        let (soft, hard) = row(name);
        check!(h, soft == spell(rl.rlim_cur as u64) && hard == spell(rl.rlim_max as u64),
            "{name}: file says {soft}/{hard}, getrlimit says {}/{}",
            spell(rl.rlim_cur as u64), spell(rl.rlim_max as u64));
    }

    // And it follows a change the guest makes.
    let mut rl: libc::rlimit = unsafe { std::mem::zeroed() };
    unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) };
    let lowered = libc::rlimit { rlim_cur: 512, rlim_max: rl.rlim_max };
    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lowered) };
    let limits2 = std::fs::read_to_string("/proc/self/limits").unwrap_or_default();
    let after = limits2.lines().find(|l| l.starts_with("Max open files")).unwrap_or("");
    check!(h, after.contains("512"), "and follows setrlimit: {after:?}");
    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rl) };

    h.group("filesystems");
    // What `mount -t` accepts, one per line. `mount` reads this when it is not
    // given a type and tries each in turn.
    let fs = std::fs::read_to_string("/proc/filesystems").unwrap_or_default();
    check!(h, !fs.is_empty(), "/proc/filesystems is not empty");
    let types: Vec<&str> = fs.lines()
        .filter_map(|l| l.rsplit('\t').next())
        .collect();
    for want in ["tmpfs", "proc", "devpts"] {
        check!(h, types.contains(&want), "{want} is listed: {types:?}");
    }
    // Every line is `<flags>\t<name>`, where the flags field is `nodev` for a
    // type that needs no block device and *empty* otherwise -- so a line may
    // begin with a bare tab.
    //
    // This asserted `nodev\t` on every line, which is true here -- none of
    // these filesystems is backed by a block device -- and false on Linux,
    // which prints `\tvfat` and `\tfuseblk` among the rest. Running the same
    // binary against a real kernel is what found it
    // (tests/integration/differential.sh). Left as it was, the assertion would
    // have rejected a correct change later: adding a block-backed mount type
    // would have failed a test that was wrong about the ABI.
    let well_formed = |l: &str| match l.split_once('\t') {
        Some((flags, name)) => (flags == "nodev" || flags.is_empty())
            && !name.is_empty() && !name.contains('\t'),
        None => false,
    };
    check!(h, fs.lines().all(|l| well_formed(l)),
        "every line is <flags>\\t<name> with flags nodev or empty: {:?}",
        fs.lines().find(|l| !well_formed(l)));
    // Every type listed must be one the kernel will actually mount, or `mount`
    // with no -t would try it and fail. tmpfs is the one a guest can mount
    // without a device or a prepared directory.
    let r = unsafe {
        libc::mount(guest_tests::cpath("none").as_ptr(), guest_tests::cpath("/mnt").as_ptr(),
                    guest_tests::cpath("tmpfs").as_ptr(), 0, std::ptr::null())
    };
    check!(h, r == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL),
        "a listed type is mountable: mount -t tmpfs gave {r} errno {}",
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0));

    h.group("another-pid");
    let s1 = read_status("/proc/1/status");
    check!(h, s1.get("Pid").map(String::as_str) == Some("1"),
        "/proc/1/status reports Pid 1: {:?}", s1.get("Pid"));

    std::process::exit(h.finish());
}
