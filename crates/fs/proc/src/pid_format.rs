use super::{LIMIT_NAMES, RLIM_INFINITY};

/// The line, with nothing held and nothing to dereference.
pub(super) fn format_stat(st: &crate::pidsnap::PidStat, comm: &str) -> String {
    let mut s = String::with_capacity(160);
    // 1-9: pid, comm, state, ppid, pgid, sid, tty, tty pgrp, flags.
    s += &format!(
        "{} ({}) {} {} {} {} {} {} {} ",
        st.pid, comm, st.state as char, st.ppid, st.pgid, st.sid, st.tty_dev, st.tty_pgrp, 0
    );
    // 10-13: page faults, minor and major, self and children. Not counted.
    s += "0 0 0 0 ";
    // 14-17: user and system time, self and children. These would come from
    // getrusage, which is not tracked per task here.
    s += "0 0 0 0 ";
    // 18-22: priority, nice, threads, itimer (deprecated), start time. The
    // last is hundredths since boot; zero made every process as old as the
    // machine, because `ps -o etime` and `top` compute an age by subtracting
    // it from the uptime. Priority is Linux's 20 + nice for a normal task;
    // both were the constants `20 0` until 2026-10-18, so `ps -o ni` showed 0
    // under `nice -n 5` (`tests/guest` procfs_probe).
    s += &format!("{} {} {} 0 {} ", 20 + st.nice, st.nice, st.nthreads, st.start_ticks);
    // 23-25: vsize in bytes, rss in pages, and the rss limit. The first two
    // were hardcoded zeroes with a note deferring to statm -- but `ps` reads
    // *this* file for VSZ and RSS, so every process showed 0. Field 25 stays 0:
    // RLIMIT_RSS is infinite here and nothing reads it.
    s += &format!("{} {} 0 ", st.vsize, st.rss_pages);
    // What a reader without ptrace access does not see, as Linux blanks it:
    // the code bounds become 1 (0 with no address space), everything else 0.
    let p = |v: u64| if st.permitted { v } else { 0 };
    let code = |v: u64| match (st.has_mm, st.permitted) {
        (false, _) => 0,
        (true, true) => v,
        (true, false) => 1,
    };
    // 26-30: startcode, endcode, stack start, kstkesp, kstkeip.
    s += &format!("{} {} {} 0 0 ", code(st.code.0), code(st.code.1), p(st.stack_start));
    // 31-34: pending, blocked, ignored, caught.
    s += &format!(
        "{} {} {} {} ",
        st.pending, st.blocked, st.ignored, st.caught
    );
    // 35-39: wchan, nswap, cnswap, exit signal, processor.
    s += &format!("{} 0 0 {} 0 ", u8::from(st.wchan), st.exit_signal);
    // 40-44: rt_priority, scheduling policy, delayacct block io, guest time,
    // children's guest time. Zero is the true answer to four of them -- there
    // is no realtime scheduling, no delay accounting and no nested guest -- and
    // policy 0 is SCHED_OTHER, which is the one this kernel implements.
    s += "0 0 0 0 0 ";
    // 45-52: start_data, end_data, start_brk, arg_start, arg_end, env_start,
    // env_end, exit_code.
    //
    // The line used to end at 39, where Linux writes 52. A reader indexes by
    // position, so everything from `rt_priority` on was missing rather than
    // wrong -- `chrt` and anything reconstructing a command line without
    // opening /proc/<pid>/cmdline found nothing there.
    //
    let exit_code = if st.permitted { st.exit_code } else { 0 };
    s += &format!(
        "{} {} {} {} {} {} {} {exit_code}\n",
        p(st.data.0),
        p(st.data.1),
        p(st.start_brk),
        p(st.arg_start),
        p(st.arg_end),
        p(st.env_start),
        p(st.env_end)
    );
    s
}
fn limit_value(v: u64) -> String {
    if v == RLIM_INFINITY {
        "unlimited".to_string()
    } else {
        v.to_string()
    }
}

pub(super) fn format_limits(soft: &[u64; 16], hard: &[u64; 16]) -> String {
    // The column widths are Linux's, from its own seq_printf:
    //     "%-25s %-20s %-20s %-10s\n"
    // `ulimit -a` and every other reader lines up on them.
    let mut s = format!(
        "{:<25} {:<20} {:<20} {:<10}\n",
        "Limit", "Soft Limit", "Hard Limit", "Units"
    );
    for (i, (name, unit)) in LIMIT_NAMES.iter().enumerate() {
        s += &format!("{:<25} {:<20} {:<20} ", name, limit_value(soft[i]), limit_value(hard[i]));
        // Linux prints the unit column only for a row that has one.
        if !unit.is_empty() {
            s += &format!("{unit:<10}");
        }
        s.push('\n');
    }
    s
}
/// The letter `stat` reports, and the word `status` spells it with.
fn state_name(state: u8) -> &'static str {
    match state {
        b'R' => "R (running)",
        b'S' => "S (sleeping)",
        b'D' => "D (disk sleep)",
        b'T' => "T (stopped)",
        b'Z' => "Z (zombie)",
        _ => "R (running)",
    }
}

/// A cpu mask as `Cpus_allowed_list` spells it: ascending ranges, `0-3,7`.
pub(super) fn cpu_list(mask: u64) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut bit = 0;
    while bit < 64 {
        if mask & (1u64 << bit) == 0 {
            bit += 1;
            continue;
        }
        let start = bit;
        while bit < 64 && mask & (1u64 << bit) != 0 {
            bit += 1;
        }
        let end = bit - 1;
        parts.push(if start == end {
            format!("{start}")
        } else {
            format!("{start}-{end}")
        });
    }
    parts.join(",")
}

pub(super) fn format_status(st: &crate::pidsnap::PidStatus, comm: &str) -> String {
    let groups: Vec<String> = st.groups[..].iter().map(|g| g.to_string()).collect();
    let mut s = String::new();
    // Tabs after the colon, which is what every parser of this file expects.
    s.push_str(&format!("Name:\t{comm}\n"));
    // Only for a task that still has filesystem state: a zombie has given its
    // up, and Linux's `task_umask` prints nothing for it.
    if st.has_fs {
        s.push_str(&format!("Umask:\t{:04o}\n", st.umask));
    }
    s.push_str(&format!("State:\t{}\n", state_name(st.state)));
    s.push_str(&format!("Tgid:\t{}\n", st.tgid));
    s.push_str("Ngid:\t0\n");
    s.push_str(&format!("Pid:\t{}\n", st.pid));
    s.push_str(&format!("PPid:\t{}\n", st.ppid));
    // Always zero: nothing here attaches a tracer. Present because a parser
    // walking the file by name expects it between PPid and Uid, and because
    // "is anyone tracing me" is a question programs ask and got no answer to.
    s.push_str("TracerPid:\t0\n");
    s.push_str(&format!(
        "Uid:\t{}\t{}\t{}\t{}\n",
        st.uid, st.euid, st.suid, st.fsuid
    ));
    s.push_str(&format!(
        "Gid:\t{}\t{}\t{}\t{}\n",
        st.gid, st.egid, st.sgid, st.fsgid
    ));
    s.push_str(&format!("FDSize:\t{}\n", st.fdsize));
    s.push_str(&format!("Groups:\t{}\n", groups.join(" ")));
    // The pid as each namespace sees it. There are no pid namespaces here, so
    // every view is the outer one — which is exactly what a Linux with one
    // namespace reports, and what a container runtime reading NSpid compares
    // against its own idea of the pid.
    s.push_str(&format!("NStgid:\t{}\n", st.nstgid));
    s.push_str(&format!("NSpid:\t{}\n", st.nspid));
    s.push_str(&format!("NSpgid:\t{}\n", st.nspgid));
    s.push_str(&format!("NSsid:\t{}\n", st.nssid));
    // A guest never sees a kernel thread: everything with a pid here ran an
    // executable.
    s.push_str("Kthread:\t0\n");
    if st.has_mm {
        push_memory_block(&mut s, st);
    }
    s.push_str(&format!("Threads:\t{}\n", st.nthreads));
    s.push_str(&format!("SigQ:\t{}/{}\n", st.sigq_count, st.sigq_limit));
    s.push_str(&format!("SigPnd:\t{:016x}\n", st.pending));
    // The process's shared set, the same in every thread's file.
    s.push_str(&format!("ShdPnd:\t{:016x}\n", st.shd_pending));
    s.push_str(&format!("SigBlk:\t{:016x}\n", st.blocked));
    s.push_str(&format!("SigIgn:\t{:016x}\n", st.ignored));
    s.push_str(&format!("SigCgt:\t{:016x}\n", st.caught));
    // `render_cap_t`: the five sets, sixteen hex digits each.
    let caps = st.caps.unwrap_or(kernel_creds::caps::Caps {
        permitted: 0,
        effective: 0,
        inheritable: 0,
        bounding: 0,
        ambient: 0,
    });
    for (name, set) in [
        ("CapInh", caps.inheritable),
        ("CapPrm", caps.permitted),
        ("CapEff", caps.effective),
        ("CapBnd", caps.bounding),
        ("CapAmb", caps.ambient),
    ] {
        s.push_str(&format!("{name}:\t{set:016x}\n"));
    }
    // A number, as Linux's `seq_put_decimal_ull`; `{}` of the bool printed
    // `false` until 2026-10-18 (`tests/guest` procfs_probe).
    s.push_str(&format!("NoNewPrivs:\t{}\n", u8::from(st.no_new_privs)));
    s.push_str(&format!("Seccomp:\t{}\n", st.seccomp_mode));
    s.push_str(&format!("Seccomp_filters:\t{}\n", st.seccomp_filters));
    s.push_str("Speculation_Store_Bypass:\tnot vulnerable\n");
    s.push_str("SpeculationIndirectBranch:\tunknown\n");
    s.push_str(&format!("Cpus_allowed:\t{:x}\n", st.cpus_allowed));
    s.push_str(&format!(
        "Cpus_allowed_list:\t{}\n",
        cpu_list(st.cpus_allowed)
    ));
    // One memory node, which is what a machine with no NUMA reports.
    s.push_str("Mems_allowed:\t1\n");
    s.push_str("Mems_allowed_list:\t0\n");
    // Not counted. Zero is the truthful answer for a number nothing
    // increments, and the fields are here because `top` and `pidstat` read
    // them by name and a missing name is a parse failure rather than a zero.
    s.push_str(&format!("voluntary_ctxt_switches:\t{}\n", st.vol_ctxt));
    s.push_str(&format!(
        "nonvoluntary_ctxt_switches:\t{}\n",
        st.nonvol_ctxt
    ));
    s
}

/// The memory block, in Linux's order, for a task that has an address space.
/// A zombie has none, and Linux's `proc_pid_status` prints none of this for
/// it -- `VmPeak` through `untag_mask` are all inside its `if (mm)`. Printing
/// zeroes instead would tell a monitor the process is empty rather than
/// gone.
///
/// Right-aligned in eight columns and followed by " kB", which is the shape
/// `ps` and every /proc reader matches on.
///
/// **VmPeak and VmHWM are the current values, not high-water marks.**
/// Nothing here records a peak, and a peak is by definition at least the
/// current size -- so this is a lower bound rather than a guess, which is
/// what a monitor sizing a pool from it needs. Recording the real thing
/// means a max in `struct mem`, updated by every map and unmap.
fn push_memory_block(s: &mut String, st: &crate::pidsnap::PidStatus) {
    s.push_str(&format!("VmPeak:\t{:8} kB\n", st.vm_size_kb));
    s.push_str(&format!("VmSize:\t{:8} kB\n", st.vm_size_kb));
    s.push_str("VmLck:\t       0 kB\n");
    s.push_str("VmPin:\t       0 kB\n");
    s.push_str(&format!("VmHWM:\t{:8} kB\n", st.vm_rss_kb));
    s.push_str(&format!("VmRSS:\t{:8} kB\n", st.vm_rss_kb));
    // The three VmRSS is the sum of, from the same walk. Shared is counted
    // first, so a shared file mapping lands in one bucket rather than two and
    // the three add up to VmRSS rather than overshooting it.
    s.push_str(&format!("RssAnon:\t{:8} kB\n", st.rss_anon_kb));
    s.push_str(&format!("RssFile:\t{:8} kB\n", st.rss_file_kb));
    s.push_str(&format!("RssShmem:\t{:8} kB\n", st.rss_shmem_kb));
    s.push_str(&format!("VmData:\t{:8} kB\n", st.vm_data_kb));
    s.push_str(&format!("VmStk:\t{:8} kB\n", st.vm_stk_kb));
    s.push_str(&format!("VmExe:\t{:8} kB\n", st.vm_exe_kb));
    s.push_str(&format!("VmLib:\t{:8} kB\n", st.vm_lib_kb));
    // The page tables are this kernel's own bookkeeping and not the guest's
    // memory; there is no guest-visible number to report.
    s.push_str("VmPTE:\t       0 kB\n");
    s.push_str("VmSwap:\t       0 kB\n");
    // Nothing here writes a core file, so nothing is ever in the middle of
    // doing so.
    s.push_str("CoreDumping:\t0\n");
    // No transparent huge pages: the page table is 4 KB throughout and
    // `madvise(MADV_HUGEPAGE)` is accepted and ignored.
    s.push_str("THP_enabled:\t0\n");
    // arm64's top-byte-ignore mask: the top byte of a guest address is not
    // part of it, as the gadgets have honoured since 51fc20ae5. Linux prints
    // the same for every arm64 process.
    s.push_str("untag_mask:\t0xffffffffffffff\n");
}
/// size, resident, shared, text, lib, data, dirty.
///
/// `lib` and `dirty` have been zero on Linux since 2.6; `text` is not tracked
/// here, and `data` is reported as the resident count for want of a better
/// answer.
pub(super) fn format_statm(total: u64, resident: u64, shared: u64) -> String {
    format!("{total} {resident} {shared} 0 0 {resident} 0 \n")
}
