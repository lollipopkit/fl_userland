//! `/proc` system information formatting and filesystem registry output.

use super::*;

// ---------------------------------------------------------------------------
// /proc/version, /proc/uptime, /proc/stat, /proc/cpuinfo, /proc/meminfo
// ---------------------------------------------------------------------------

pub(super) fn show_version(_e: &mut ffi::proc_entry, buf: &mut ffi::proc_data) -> c_int {
    let uts = unamecalls::uname();
    let f = |b: &[c_char]| {
        std::ffi::CStr::from_bytes_until_nul(plain::slice_bytes(b))
            .map(|c| c.to_string_lossy().into_owned())
            .unwrap_or_default()
    };
    out(
        buf,
        &format!(
            "{} version {} {}\n",
            f(&uts.system),
            f(&uts.release),
            f(&uts.version)
        ),
    );
    0
}

/// `/proc/filesystems`: the types `mount` may be given, one per line.
///
/// `mount` reads this when it is not told a type, and tries each in turn. The
/// leading `nodev` marks a filesystem that does not take a device — every one
/// here is, since none is backed by a block device, so every line carries it.
/// Linux writes a bare tab for the others; nothing here produces that line and
/// a reader that splits on the tab sees an empty first field either way.
///
/// `fake` is absent on purpose. A fakefs mount needs a source directory holding
/// `data/` and `meta.db`, which the embedder supplies -- `mount -t fake` cannot
/// build one and answers EINVAL. Listing it would have `mount` try it when it
/// is given no type, and fail. This file is what `mount -t` accepts, which is
/// what the array in fs/mount.c holds.
/// The names of the registered filesystems — the list `mount -t` accepts,
/// which `crates/fs/mountcalls` keeps. It answered one name per index, null
/// past the end, until 2026-10-17: a C string protocol between two Rust crates,
/// read back with `CStr::from_ptr`.
///
/// A hook, since 2026-09-09. It was `mountcalls::fs_registered_name` called
/// directly, and that one call was the *whole* of this crate's dependency on
/// that one — which made `mountcalls` unable to name the four filesystem tables
/// as ordinary dependencies, because `procfs` is one of the four. Four
/// `extern "C"` statics under a keep-c-abi marker were the consequence.
///
/// **An empty list before anything installs it, which is not a fallback.**
/// `mountcalls` installs this when it seeds the registry, on the first
/// `mount(2)` — and reading `/proc/filesystems` needs procfs *mounted*, so the
/// seeding has provably happened. Before it, "no filesystems registered" is the
/// truth.
static FS_NAMES: std::sync::OnceLock<fn() -> Vec<&'static std::ffi::CStr>> = std::sync::OnceLock::new();

/// Install it. See [`FS_NAMES`].
pub fn set_registered_name_hook(f: fn() -> Vec<&'static std::ffi::CStr>) {
    let _ = FS_NAMES.set(f);
}

/// Whether it has been installed — for the test in `crates/fs/mountcalls`.
/// `/proc/filesystems` is empty either way before the first mount, so no
/// assertion about its contents distinguishes them.
pub fn registered_name_hook_installed() -> bool {
    FS_NAMES.get().is_some()
}

pub(super) fn show_filesystems(_e: &mut ffi::proc_entry, buf: &mut ffi::proc_data) -> c_int {
    let mut text = String::new();
    for name in FS_NAMES.get().map(|f| f()).unwrap_or_default() {
        text += &format!("nodev\t{}\n", name.to_string_lossy());
    }
    out(buf, &text);
    0
}

/// `/proc/loadavg`: five fields, `1min 5min 15min running/total lastpid`.
///
/// It did not exist, so `uptime`, `w`, `top` and every monitoring agent that
/// opens it got ENOENT — and a Go or Java runtime that sizes a pool from the
/// load average falls back to a default it did not choose.
///
/// **The three averages are the host's**, which is the same source
/// `sysinfo(2)` reports them from — and until 2026-09-04 these two answers to
/// one question disagreed: `sysinfo` passed the host's through and this file
/// printed `0.00 0.00 0.00`, with a comment arguing that zero was the honest
/// answer because nothing here maintains a run queue.
///
/// That argument is backwards. A guest thread **is** a host thread, so the
/// host's run queue is the one the guest's threads are on: its load average
/// counts them, along with everything else on the machine. Printing zero told
/// `uptime`, `w`, `top` and every monitoring agent that the machine was idle
/// while the guest was pegging four cores.
///
/// The fixed point is Linux's `SI_LOAD_SHIFT`, sixteen fractional bits, which
/// `crates/kernel/hoststats` has already rescaled Darwin's eleven into.
///
/// The two counts are real: how many guest threads exist, and the last pid
/// allocated.
/// One of the three, from Linux's sixteen-bit fixed point to the two decimal
/// places `/proc/loadavg` prints.
///
/// Linux writes it as `LOAD_INT(x).LOAD_FRAC(x)` — the integer part, then the
/// fraction times a hundred rounded the way it rounds, which is
/// `((x & 0xffff) * 100) >> 16` with the same half added first. Reproduced
/// rather than done in floating point, so the last digit is the kernel's.
pub(super) fn load_average(fixed: u64) -> String {
    const HALF: u64 = 1 << 15; // FIXED_1/200, Linux's rounding term
    let x = fixed + HALF / 100;
    let int = x >> 16;
    let frac = ((x & 0xffff) * 100) >> 16;
    format!("{int}.{frac:02}")
}

pub(super) fn show_loadavg(_e: &mut ffi::proc_entry, buf: &mut ffi::proc_data) -> c_int {
    // The same walk /proc/stat's `processes` uses: one pass over the live
    // pids, which gives both the count and the highest.
    let mut total = 0u64;
    let mut highest = 0u64;
    let mut pid = 0;
    loop {
        pid = taskcalls::task_next_live_pid(pid);
        if pid == 0 {
            break;
        }
        total += 1;
        highest = pid as u64;
    }
    // At least the one reading this file, which is what /proc/stat's
    // procs_running says for the same reason.
    let running = 1;
    let load = kernel_hoststats::get_uptime();
    let [a, b, c] = [load.load_1m, load.load_5m, load.load_15m].map(load_average);
    out(buf, &format!("{a} {b} {c} {running}/{total} {highest}\n"));
    0
}

pub(super) fn show_uptime(_e: &mut ffi::proc_entry, buf: &mut ffi::proc_data) -> c_int {
    let ticks = kernel_hoststats::get_uptime().uptime_ticks;
    // The second field is idle time summed over *every* processor, which on
    // anything with more than one is several times the first. This printed the
    // uptime twice, so anything computing an idle fraction from the pair --
    // `uptime`, `top`, every dashboard that samples /proc/uptime -- saw a
    // machine that had been completely idle since boot.
    //
    // The same idle count /proc/stat reports, so the two agree.
    let idle = kernel_hoststats::get_cpu_usage().idle_ticks;
    // Two decimal places, zero-padded: /proc/uptime's fraction is hundredths,
    // and a reader parses it as such. Unpadded, `.07` leaves as `.7` and is
    // read as `.70` — a 0.63s jump forward, after which the next honest read
    // looks like time running backwards. One value in ten.
    out(
        buf,
        &format!(
            "{}.{:02} {}.{:02}\n",
            ticks / 100,
            ticks % 100,
            idle / 100,
            idle % 100
        ),
    );
    0
}

pub(super) fn show_stat(_e: &mut ffi::proc_entry, buf: &mut ffi::proc_data) -> c_int {
    let usage = kernel_hoststats::get_cpu_usage();
    // Ten fields, which is what Linux has had since 2.6.33: user, nice, system,
    // idle, iowait, irq, softirq, steal, guest, guest_nice. A reader *indexes*
    // them, so a line that stops at four leaves whoever wanted iowait or steal
    // reading whatever came next in its buffer. The six this kernel cannot
    // measure are zero, which is what a machine with no interrupts, no waiting
    // on I/O and no virtualisation would report.
    let mut s = format!(
        "cpu  {} {} {} {} 0 0 0 0 0 0\n",
        usage.user_ticks, usage.nice_ticks, usage.system_ticks, usage.idle_ticks
    );
    // Per-cpu lines. vmstat and top read `cpu0` and up to work out how many
    // processors there are and to attribute time; with only the aggregate line
    // they report one cpu or none. The ticks are the aggregate divided evenly,
    // which is a fiction — but so is the aggregate, and a reader that adds the
    // per-cpu lines up gets the total it was given.
    let cpus = ncpu().max(1);
    for i in 0..cpus {
        s += &format!(
            "cpu{} {} {} {} {} 0 0 0 0 0 0\n",
            i,
            usage.user_ticks / cpus,
            usage.nice_ticks / cpus,
            usage.system_ticks / cpus,
            usage.idle_ticks / cpus
        );
    }

    // Boot time, as seconds since the epoch: now minus how long we have been
    // up. timespec_now and timespec_subtract are static inline in
    // util/timer.h, so bindgen emits nothing for them; the arithmetic is two
    // lines and does not need a shim.
    let uptime = kernel_hoststats::get_uptime().uptime_ticks as i64;
    let (now_sec, now_nsec) = util_timeabi::host_clock(libc::CLOCK_REALTIME).unwrap_or((0, 0));
    // The remainder is hundredths and the field it goes in is nanoseconds.
    let (up_sec, up_nsec) = (uptime / 100, (uptime % 100) * 10_000_000);
    let mut btime = now_sec - up_sec;
    if now_nsec < up_nsec {
        btime -= 1;
    }
    s += &format!("btime {btime}\n");

    // Fields busybox's top, vmstat and procps look for.
    //
    // `processes` is forks since boot, not the number alive — a reader diffs
    // consecutive samples to get a fork rate, so reporting the live count
    // would show a negative rate every time a process exited. There is no
    // fork counter to read, so this is the highest pid ever seen: monotonic,
    // which is the property that matters, and it moves once per process
    // created for as long as pids do not wrap.
    s += "ctxt 0\n";
    s += &format!("processes {}\n", pids_high_water());
    // Runnable tasks. At least the one reading this file.
    s += "procs_running 1\n";
    s += "procs_blocked 0\n";
    out(buf, &s);
    0
}

/// How many processors to report.
fn ncpu() -> u64 {
    // IUL_FAKE_NCPU is read once: a program that reads /proc/cpuinfo in a loop
    // should not pay for a getenv per read, and the answer cannot change.
    static N: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *N.get_or_init(|| {
        if let Ok(v) = std::env::var("IUL_FAKE_NCPU")
            && let Ok(n) = v.parse::<u64>()
            && n > 0
        {
            return n;
        }
        // `sysconf(_SC_NPROCESSORS_ONLN)` on Apple targets, as this was.
        std::thread::available_parallelism().map_or(1, |n| n.get() as u64)
    })
}

/// The highest pid seen so far, which never goes down.
fn pids_high_water() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static HIGH: AtomicU64 = AtomicU64::new(0);
    let mut highest = 0u64;
    let mut pid = 0;
    loop {
        pid = taskcalls::task_next_live_pid(pid);
        if pid == 0 {
            break;
        }
        highest = pid as u64;
    }
    HIGH.fetch_max(highest, Ordering::Relaxed).max(highest)
}

pub(super) fn show_cpuinfo(_e: &mut ffi::proc_entry, buf: &mut ffi::proc_data) -> c_int {
    let mut s = String::new();
    for i in 0..ncpu() {
        s += &format!("processor\t: {i}\n");
        s += "BogoMIPS\t: 48.00\n";
        // The features the guest's AArch64 actually gets.
        s += &format!("Features\t: {}\n", asbestos_features::caps::cpuinfo_features());
        s += "CPU implementer\t: 0x00\n";
        s += "CPU architecture: 8\n";
        s += "CPU variant\t: 0x0\n";
        s += "CPU part\t: 0x000\n";
        s += "CPU revision\t: 0\n\n";
    }
    out(buf, &s);
    0
}

pub(super) fn show_meminfo(_e: &mut ffi::proc_entry, buf: &mut ffi::proc_data) -> c_int {
    // The same two numbers `sysinfo(2)` reports, from the same functions, so
    // the two cannot disagree -- and they did. This read the **host's** free
    // memory and capped it to the same 4 GB the total is capped to, which on
    // any machine with more than 4 GB free is the cap: `MemFree` was always
    // exactly `MemTotal`, so every reader was told nothing was in use however
    // much the guest had allocated. `sysinfo` had the right rule all along.
    let total = kernel_hoststats::guest_total_ram();
    let used_pages = pagetable::anonbudget::anon_pages_used();
    let free = kernel_hoststats::guest_free_ram(total, used_pages);

    let mut s = String::new();
    // 1024, not 1000. `kB` in /proc/meminfo is a kibibyte -- Linux computes it
    // as `pages << (PAGE_SHIFT - 10)` -- and dividing by a thousand reported
    // 2.4% more memory than the machine has, silently, to everything that reads
    // it. 4 GiB came out as 4294967 kB where it is 4194304.
    let mut kb = |name: &str, value: u64| s += &format!("{name}{:8} kB\n", value / 1024);
    kb("MemTotal:       ", total);
    kb("MemFree:        ", free);
    // MemAvailable, which every modern reader prefers to MemFree.
    kb("MemAvailable:   ", free);
    // MemShared reported MemFree, which is not what it means. It has been 0 on
    // Linux since 2.6 and busybox only needs the field to exist.
    kb("MemShared:      ", 0);
    for name in [
        "Shmem:          ",
        "Buffers:        ",
        "Cached:         ",
        "SwapTotal:      ",
        "SwapFree:       ",
        "Dirty:          ",
        "Writeback:      ",
    ] {
        kb(name, 0);
    }
    // The anonymous pages the accounting counts, which is the same number the
    // free figure above was computed from -- so `MemTotal - MemFree` and this
    // agree, which is what a reader checking its own arithmetic expects.
    kb("AnonPages:      ", total.saturating_sub(free));
    for name in ["Mapped:         ", "Slab:           "] {
        kb(name, 0);
    }
    out(buf, &s);
    0
}
