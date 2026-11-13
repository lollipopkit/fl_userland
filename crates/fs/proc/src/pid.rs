//! The `/proc/<pid>` files whose work is formatting.
//!
//! `fs/proc/pid.c` keeps the parts that read kernel state, because reading it
//! means holding the locks that guard it and `current`, `pids_lock` and the
//! task table are all unreachable from stable Rust. What it hands over is a
//! snapshot the caller owns — see `proc_pid_stat_snapshot` and
//! `proc_pid_statm_counts` — and the formatting happens here, where nothing is
//! held.
//!
//! That split is not only for the migration. Formatting used to run under four
//! locks at once, `pids_lock` among them, with a `realloc` available at every
//! step.

use std::os::raw::c_int;

use crate::ffi;

#[path = "pid_format.rs"]
mod pid_format;
#[cfg(test)]
use pid_format::cpu_list;
use pid_format::{format_limits, format_stat, format_statm, format_status};

use guest_errno::c_int_::ESRCH;

fn out(buf: &mut ffi::proc_data, text: &str) {
    buf.append(text.as_bytes())
}

/// `/proc/<pid>/stat`.
///
/// The field *positions* are the interface: a reader counts them, so a field
/// this cannot answer has to be present and zero rather than absent. The ones
/// that will never be answerable are named in the comments below so that the
/// next person does not go looking for where they were dropped.
pub(crate) fn proc_pid_stat_show(
    entry: &mut ffi::proc_entry,
    buf: &mut ffi::proc_data,
) -> c_int {
    let Some(st) = crate::pidsnap::stat(entry) else {
        return ESRCH;
    };
    let comm = st.comm.clone();
    out(buf, &format_stat(&st, &comm));
    0
}

/// How many rlimits there are, and what each is called in
/// `/proc/<pid>/limits`.
///
/// The order is `RLIMIT_*`, which is the order Linux lists them in — a reader
/// of this file goes by the name in the first column, but `ulimit -a` goes by
/// position. Written out here rather than taken from `kernel/resource.h`
/// because these are `#define`s and bindgen does not see them;
/// `the_limit_table_matches_the_kernels` reads that header and fails if the
/// two ever disagree.
const LIMIT_NAMES: [(&str, &str); 16] = [
    ("Max cpu time", "seconds"),
    ("Max file size", "bytes"),
    ("Max data size", "bytes"),
    ("Max stack size", "bytes"),
    ("Max core file size", "bytes"),
    ("Max resident set", "bytes"),
    ("Max processes", "processes"),
    ("Max open files", "files"),
    ("Max locked memory", "bytes"),
    ("Max address space", "bytes"),
    ("Max file locks", "locks"),
    ("Max pending signals", "signals"),
    ("Max msgqueue size", "bytes"),
    ("Max nice priority", ""),
    ("Max realtime priority", ""),
    ("Max realtime timeout", "us"),
];

/// `RLIM_INFINITY`, which `kernel/resource.h` spells `((rlim_t_) -1)`.
const RLIM_INFINITY: u64 = u64::MAX;

/// `/proc/<pid>/limits`.
pub(crate) fn proc_pid_limits_show(
    entry: &mut ffi::proc_entry,
    buf: &mut ffi::proc_data,
) -> c_int {
    let Some(pairs) = crate::pidsnap::limits(entry) else {
        return ESRCH;
    };
    // The crate answers a pair per limit in RLIMIT_* order; the names and the
    // column widths are presentation and live here.
    if pairs.len() != LIMIT_NAMES.len() {
        return ESRCH;
    }
    let mut soft = [0u64; LIMIT_NAMES.len()];
    let mut hard = [0u64; LIMIT_NAMES.len()];
    for (i, (s, h)) in pairs.iter().enumerate() {
        soft[i] = *s;
        hard[i] = *h;
    }
    out(buf, &format_limits(&soft, &hard));
    0
}

/// `/proc/<pid>/status`.
///
/// Every field Linux prints, in Linux's order (`procfs_probe`). This doc
/// listed `TracerPid`, `ShdPnd`, `SigQ`, the capability sets and others as
/// left out long after they were printed.
///
/// `SigPnd` is the thread's own pending set and `ShdPnd` its process's, which
/// a process-directed signal waits in (`sigshared_probe`).
pub(crate) fn proc_pid_status_show(
    entry: &mut ffi::proc_entry,
    buf: &mut ffi::proc_data,
) -> c_int {
    let Some(st) = crate::pidsnap::status(entry) else {
        return ESRCH;
    };
    let comm = st.comm.clone();
    out(buf, &format_status(&st, &comm));
    0
}

/// `/proc/<pid>/statm`, in pages.
pub(crate) fn proc_pid_statm_show(
    entry: &mut ffi::proc_entry,
    buf: &mut ffi::proc_data,
) -> c_int {
    let Some(c) = crate::pidmem::proc_pid_statm_counts(entry) else {
        return ESRCH;
    };
    out(buf, &format_statm(c.total, c.resident, c.shared));
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table here is a second copy of what the `RLIMIT_*_` constants
    /// number, and two copies of a constant drift. This compares them -- the
    /// count, and every name's position.
    ///
    /// It read `kernel/resource.h` until 2026-09-08 and that header is gone;
    /// `crates/kernel/taskview` is where those constants live now, which is the
    /// definition rather than a declaration of it.
    #[test]
    fn the_limit_table_matches_the_kernels() {
        let define = |name: &str| -> usize {
            let n = match name {
                "CPU" => ffi::RLIMIT_CPU_,
                "FSIZE" => ffi::RLIMIT_FSIZE_,
                "DATA" => ffi::RLIMIT_DATA_,
                "STACK" => ffi::RLIMIT_STACK_,
                "CORE" => ffi::RLIMIT_CORE_,
                "RSS" => ffi::RLIMIT_RSS_,
                "NPROC" => ffi::RLIMIT_NPROC_,
                "NOFILE" => ffi::RLIMIT_NOFILE_,
                "MEMLOCK" => ffi::RLIMIT_MEMLOCK_,
                "AS" => ffi::RLIMIT_AS_,
                "LOCKS" => ffi::RLIMIT_LOCKS_,
                "SIGPENDING" => ffi::RLIMIT_SIGPENDING_,
                "MSGQUEUE" => ffi::RLIMIT_MSGQUEUE_,
                "NICE" => ffi::RLIMIT_NICE_,
                "RTPRIO" => ffi::RLIMIT_RTPRIO_,
                "RTTIME" => ffi::RLIMIT_RTTIME_,
                "NLIMITS" => ffi::RLIMIT_NLIMITS_,
                other => panic!("no RLIMIT_{other}_"),
            };
            n as usize
        };
        assert_eq!(
            define("NLIMITS"),
            LIMIT_NAMES.len(),
            "RLIMIT_NLIMITS_ and the name table disagree"
        );
        // Each C name against the row it must be, so a reordering in the header
        // is caught rather than silently relabelling every line.
        for (macro_name, expect) in [
            ("CPU", "Max cpu time"),
            ("FSIZE", "Max file size"),
            ("DATA", "Max data size"),
            ("STACK", "Max stack size"),
            ("CORE", "Max core file size"),
            ("RSS", "Max resident set"),
            ("NPROC", "Max processes"),
            ("NOFILE", "Max open files"),
            ("MEMLOCK", "Max locked memory"),
            ("AS", "Max address space"),
            ("LOCKS", "Max file locks"),
            ("SIGPENDING", "Max pending signals"),
            ("MSGQUEUE", "Max msgqueue size"),
            ("NICE", "Max nice priority"),
            ("RTPRIO", "Max realtime priority"),
            ("RTTIME", "Max realtime timeout"),
        ] {
            let i = define(macro_name);
            assert_eq!(
                LIMIT_NAMES[i].0, expect,
                "RLIMIT_{macro_name}_ is {i}, which this table calls {:?}",
                LIMIT_NAMES[i].0
            );
        }
    }

    /// The column widths are the interface: `ulimit -a` and every other reader
    /// lines up on them, and Linux's own seq_printf is `%-25s %-20s %-20s %-10s`.
    #[test]
    fn the_columns_are_where_linux_puts_them() {
        let soft = [0u64; 16];
        let hard = [0u64; 16];
        let text = format_limits(&soft, &hard);
        let mut lines = text.lines();
        let header = lines.next().unwrap();
        assert!(
            header.starts_with("Limit                     Soft Limit"),
            "{header:?}"
        );
        for line in text.lines() {
            assert_eq!(&line[25..26], " ", "column 26 is a separator: {line:?}");
            assert_eq!(&line[46..47], " ", "column 47 is a separator: {line:?}");
        }
    }

    #[test]
    fn infinity_is_spelled_out() {
        let mut soft = [0u64; 16];
        let mut hard = [0u64; 16];
        soft[7] = 1024;
        hard[7] = RLIM_INFINITY;
        let text = format_limits(&soft, &hard);
        let line = text
            .lines()
            .find(|l| l.starts_with("Max open files"))
            .unwrap();
        assert!(line.contains("1024"), "{line:?}");
        assert!(line.contains("unlimited"), "{line:?}");
        // And a zero is a zero, not "unlimited" -- RLIMIT_CORE is 0 by default
        // here and reporting it as unlimited would invert its meaning.
        let core = text
            .lines()
            .find(|l| l.starts_with("Max core file size"))
            .unwrap();
        assert!(core.contains(" 0 "), "{core:?}");
        assert!(!core.contains("unlimited"), "{core:?}");
    }

    #[test]
    fn every_limit_gets_a_line() {
        let text = format_limits(&[0u64; 16], &[0u64; 16]);
        assert_eq!(text.lines().count(), 1 + LIMIT_NAMES.len());
        for (name, _) in LIMIT_NAMES {
            assert!(text.contains(name), "missing {name:?}");
        }
    }

    /// Fields 23 and 24 of `stat` were hardcoded zeroes, and `ps` reads them
    /// for VSZ and RSS. Positional, so they are checked by *position* here --
    /// counting from 1, as every reader of this file does.
    #[test]
    fn stat_reports_vsize_and_rss_in_the_right_columns() {
        let mut st = sample();
        st.vsize = 4096 * 391;
        st.rss_pages = 391;
        let text = format_stat(&st, "sh");
        // comm may contain spaces; everything after the closing paren is
        // whitespace-separated, and field 3 is the first of them.
        let after = text.rsplit_once(')').expect("comm").1;
        let f: Vec<&str> = after.split_whitespace().collect();
        // f[0] is field 3, so field N is f[N - 3].
        assert_eq!(
            f[23 - 3],
            (4096u64 * 391).to_string(),
            "field 23 (vsize):\n{text}"
        );
        assert_eq!(f[24 - 3], "391", "field 24 (rss):\n{text}");
        assert_eq!(f[25 - 3], "0", "field 25 (rss limit):\n{text}");
        // Adding a value must not shift anything after it: field 26 is
        // startcode, and field 28 is the stack start.
        assert_eq!(f[26 - 3], "65536", "field 26 (startcode):\n{text}");
        assert_eq!(
            f[28 - 3],
            st.stack_start.to_string(),
            "field 28 (stack start):\n{text}"
        );
    }

    fn status_sample() -> crate::pidsnap::PidStatus {
        // A live process: it has an address space and filesystem state, so
        // every line is printed.
        crate::pidsnap::PidStatus {
            state: b'R',
            tgid: 42,
            pid: 42,
            ppid: 7,
            has_fs: true,
            has_mm: true,
            umask: 0o022,
            uid: 1000,
            euid: 1000,
            suid: 1000,
            fsuid: 1000,
            gid: 50,
            egid: 50,
            sgid: 50,
            fsgid: 50,
            fdsize: 64,
            nthreads: 3,
            vm_size_kb: 1564,
            vm_rss_kb: 900,
            cpus_allowed: 0xf,
            ..Default::default()
        }
    }

    /// Every line is `Name:\tvalue`. A reader splits on the first colon and
    /// trims, and a space where the tab belongs is the classic way to break it.
    #[test]
    fn every_line_is_a_tab_separated_pair() {
        let text = format_status(&status_sample(), "sh");
        assert!(text.ends_with('\n'));
        for line in text.lines() {
            let (name, rest) = line.split_once(':').expect(line);
            assert!(!name.is_empty(), "{line}");
            assert!(rest.starts_with('\t'), "no tab after the colon: {line:?}");
        }
    }

    #[test]
    fn the_fields_a_reader_looks_for_are_there() {
        let text = format_status(&status_sample(), "sh");
        for want in [
            "Name:\tsh",
            "State:\tR (running)",
            "Tgid:\t42",
            "Pid:\t42",
            "PPid:\t7",
            "Threads:\t3",
            "FDSize:\t64",
            "Umask:\t0022",
        ] {
            assert!(text.contains(want), "missing {want:?} in\n{text}");
        }
        // The four ids, in Linux's order: real, effective, saved, filesystem.
        assert!(text.contains("Uid:\t1000\t1000\t1000\t1000"), "{text}");
        assert!(text.contains("Gid:\t50\t50\t50\t50"), "{text}");
    }

    /// `ps` and friends match on the trailing " kB", and on the value being
    /// right-aligned in the column before it.
    #[test]
    fn the_memory_lines_carry_their_unit() {
        let text = format_status(&status_sample(), "sh");
        assert!(text.contains("VmSize:\t    1564 kB"), "{text}");
        assert!(text.contains("VmRSS:\t     900 kB"), "{text}");
    }

    /// Sixteen hex digits, which is what a 64-signal mask is on aarch64. Signal
    /// 64 is SIGRTMAX here, so the top bit is reachable and a 32-bit field
    /// would drop it.
    #[test]
    fn the_signal_masks_are_sixty_four_bits_wide() {
        let mut st = status_sample();
        st.caught = 1u64 << 63;
        let text = format_status(&st, "sh");
        assert!(text.contains("SigCgt:\t8000000000000000"), "{text}");
        assert!(text.contains("SigPnd:\t0000000000000000"), "{text}");
    }

    /// Every field Linux writes is written, and each one is either measured or
    /// true.
    ///
    /// This used to assert the opposite — that `TracerPid`, `ShdPnd`, `CapEff`
    /// and `SigQ` were *absent*, on the grounds that the format is name-keyed
    /// and a reader finding `TracerPid: 0` believes it. That argument is real
    /// and it does not survive those four names:
    ///
    /// - `TracerPid` is the tracer's pid, since 2026-11-13.
    /// - `ShdPnd` is the process's shared pending set, which exists since
    ///   2026-11-12.
    /// - `SigQ` is two measured numbers, the queue length and
    ///   `RLIMIT_SIGPENDING`.
    /// - `CapEff` is the task's effective set, which every permission check
    ///   here asks (`caps_probe`).
    ///
    /// And the cost of absence is not "the reader sees no value" — a name-keyed
    /// reader that cannot find `VmData` fails to parse or falls back to
    /// something else. `procfs_probe` measured a real kernel writing all 58.
    /// A zombie's status has no `Umask` and no memory block -- Linux prints
    /// `VmPeak` through `untag_mask` inside `if (mm)` and `Umask` only for a
    /// task with `fs` -- and still has everything else. Measured by
    /// `procfs_probe` against a real kernel: `has Umask -> 0`, `has VmSize
    /// -> 0`, `has SigPnd -> 1`, `Threads -> 1`.
    #[test]
    fn a_zombies_status_omits_what_it_no_longer_has() {
        let mut st = status_sample();
        st.state = b'Z';
        st.has_fs = false;
        st.has_mm = false;
        st.nthreads = 1;
        let text = format_status(&st, "sh");
        let names: Vec<&str> = text.lines().filter_map(|l| l.split(':').next()).collect();
        for absent in [
            "Umask",
            "VmPeak",
            "VmSize",
            "VmRSS",
            "VmSwap",
            "CoreDumping",
            "THP_enabled",
            "untag_mask",
        ] {
            assert!(!names.contains(&absent), "{absent} printed for a zombie");
        }
        for present in [
            "Name",
            "State",
            "Tgid",
            "Pid",
            "PPid",
            "Threads",
            "SigPnd",
            "SigCgt",
            "Cpus_allowed",
        ] {
            assert!(names.contains(&present), "{present} missing for a zombie");
        }
        assert!(text.contains("State:\tZ (zombie)\n"));
        assert!(text.contains("Threads:\t1\n"));
    }

    #[test]
    fn every_field_linux_writes_is_written() {
        let text = format_status(&status_sample(), "sh");
        // The order matters as much as the presence: a reader that walks the
        // file top to bottom expects Linux's.
        const ORDER: [&str; 58] = [
            "Name",
            "Umask",
            "State",
            "Tgid",
            "Ngid",
            "Pid",
            "PPid",
            "TracerPid",
            "Uid",
            "Gid",
            "FDSize",
            "Groups",
            "NStgid",
            "NSpid",
            "NSpgid",
            "NSsid",
            "Kthread",
            "VmPeak",
            "VmSize",
            "VmLck",
            "VmPin",
            "VmHWM",
            "VmRSS",
            "RssAnon",
            "RssFile",
            "RssShmem",
            "VmData",
            "VmStk",
            "VmExe",
            "VmLib",
            "VmPTE",
            "VmSwap",
            "CoreDumping",
            "THP_enabled",
            "untag_mask",
            "Threads",
            "SigQ",
            "SigPnd",
            "ShdPnd",
            "SigBlk",
            "SigIgn",
            "SigCgt",
            "CapInh",
            "CapPrm",
            "CapEff",
            "CapBnd",
            "CapAmb",
            "NoNewPrivs",
            "Seccomp",
            "Seccomp_filters",
            "Speculation_Store_Bypass",
            "SpeculationIndirectBranch",
            "Cpus_allowed",
            "Cpus_allowed_list",
            "Mems_allowed",
            "Mems_allowed_list",
            "voluntary_ctxt_switches",
            "nonvoluntary_ctxt_switches",
        ];
        let got: Vec<&str> = text
            .lines()
            .filter_map(|l| l.split_once(':').map(|(k, _)| k))
            .collect();
        assert_eq!(got, ORDER, "the field list, in order:\n{text}");
    }

    /// The one field here that is neither measured nor true.
    ///
    /// Nothing counts context switches, so this is 0 where Linux has a real
    /// number, and a reader diffing samples for a switch rate sees a process
    /// that never blocks. It is written anyway because the alternative is a
    /// name-keyed reader failing to find it at all, and 0 is what its absence
    /// would degrade to — but it is the one that would stop being a lie if
    /// somebody counted them.
    #[test]
    fn the_context_switch_counts_are_not_measured() {
        let text = format_status(&status_sample(), "sh");
        assert!(text.contains("voluntary_ctxt_switches:\t0"), "{text}");
        assert!(text.contains("nonvoluntary_ctxt_switches:\t0"), "{text}");
    }

    #[test]
    fn a_cpu_mask_becomes_a_range_list() {
        assert_eq!(cpu_list(0), "");
        assert_eq!(cpu_list(0b1), "0");
        assert_eq!(cpu_list(0b1111), "0-3");
        assert_eq!(cpu_list(0b1000_0001), "0,7");
        assert_eq!(cpu_list(0b1100_0011), "0-1,6-7");
        assert_eq!(cpu_list(u64::MAX), "0-63");
        assert_eq!(cpu_list(1u64 << 63), "63");
    }

    /// The list and the mask describe the same set, whatever the set is.
    #[test]
    fn the_list_and_the_mask_agree() {
        for mask in [0u64, 1, 0xf, 0xff00, 0x5555_5555, u64::MAX, 1 << 17] {
            let mut seen = 0u64;
            for part in cpu_list(mask).split(',').filter(|p| !p.is_empty()) {
                let (lo, hi) = match part.split_once('-') {
                    Some((a, b)) => (a.parse::<u32>().unwrap(), b.parse::<u32>().unwrap()),
                    None => {
                        let v = part.parse::<u32>().unwrap();
                        (v, v)
                    }
                };
                for b in lo..=hi {
                    seen |= 1u64 << b;
                }
            }
            assert_eq!(seen, mask, "{mask:#x} -> {:?}", cpu_list(mask));
        }
    }

    fn sample() -> crate::pidsnap::PidStat {
        crate::pidsnap::PidStat {
            pid: 1,
            state: b'R',
            pgid: 1,
            sid: 1,
            nthreads: 4,
            stack_start: 4294958320,
            code: (65536, 69632),
            data: (73728, 77824),
            permitted: true,
            has_mm: true,
            blocked: 16384,
            ignored: 12296,
            caught: 3200,
            tty_pgrp: -1,
            start_ticks: 918273,
            start_brk: 4096,
            arg_start: 8192,
            arg_end: 12288,
            env_start: 16384,
            env_end: 20480,
            ..Default::default()
        }
    }

    /// The field *count* is the interface: a reader indexes by position, so a
    /// field this kernel cannot answer has to be present and zero. 52 is what
    /// Linux writes and what a container confirms; this file reported 39 — the
    /// pre-2.6.24 count — so everything from `rt_priority` on was absent
    /// rather than wrong.
    #[test]
    fn stat_reports_fifty_two_fields() {
        let line = format_stat(&sample(), "statfields");
        assert_eq!(line.split_whitespace().count(), 52, "{line}");
        assert!(line.ends_with('\n'));
    }

    #[test]
    fn stat_matches_what_linux_lays_out() {
        // A process with four threads, a caught signal, an ignored signal and
        // a blocked signal — so comm, nthreads, blocked, ignored and caught
        // are all non-zero rather than agreeing by being empty. tpgid is -1
        // because there is no controlling terminal, which is not the same as
        // process group 0.
        let want = "1 (statfields) R 0 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 4 0 918273 0 0 0 65536 69632 \
4294958320 0 0 0 16384 12296 3200 0 0 0 0 0 0 0 0 0 0 73728 77824 4096 8192 12288 16384 20480 0\n";
        assert_eq!(format_stat(&sample(), "statfields"), want);
    }

    /// What a reader without ptrace access gets, field for field as
    /// `procaccess_probe` measured it: the code bounds are 1, the stack, the
    /// data and argument ranges, `wchan` and the exit code 0; the signal
    /// masks and everything before field 26 stay.
    #[test]
    fn stat_blanks_the_addresses_for_a_reader_without_access() {
        let st = crate::pidsnap::PidStat { permitted: false, wchan: false, exit_code: 9, ..sample() };
        let want = "1 (statfields) R 0 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 4 0 918273 0 0 0 1 1 \
0 0 0 0 16384 12296 3200 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n";
        assert_eq!(format_stat(&st, "statfields"), want);
        // And a zombie, which has no address space to bound.
        let st = crate::pidsnap::PidStat { permitted: false, has_mm: false, ..sample() };
        assert!(format_stat(&st, "z").contains(" 918273 0 0 0 0 0 0 "));
    }

    #[test]
    fn the_command_name_is_parenthesised() {
        // busybox and procps find the state character by scanning back from
        // the last ')', so the parentheses are load-bearing.
        let line = format_stat(&sample(), "sh");
        assert!(line.starts_with("1 (sh) R "), "{line}");
    }

    #[test]
    fn a_command_name_with_a_space_does_not_move_the_other_fields() {
        // Linux does not escape it either — a reader is expected to scan to
        // the last ')' rather than split on whitespace — so this pins that the
        // fields after it are still where they were.
        let line = format_stat(&sample(), "my prog");
        let after = &line[line.rfind(')').unwrap() + 1..];
        assert_eq!(after.split_whitespace().count(), 50);
    }

    #[test]
    fn statm_reports_seven_fields() {
        let line = format_statm(391, 391, 0);
        assert_eq!(line.split_whitespace().count(), 7, "{line}");
        assert_eq!(line, "391 391 0 0 0 391 0 \n");
    }

    #[test]
    fn statm_reports_data_as_the_resident_count() {
        let line = format_statm(100, 60, 5);
        let f: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(f[1], f[5], "data must track resident: {line}");
        assert_eq!(f[2], "5");
    }
}
