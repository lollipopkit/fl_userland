//! `/proc/<pid>/stat` is fifty-two fields, and a reader counts them.
//!
//! Nothing in this file is name-keyed. `ps`, `top`, and every runtime that
//! wants a process's age or its scheduling policy splits the line and indexes
//! it, so a field that is absent is not "missing" to the reader — it silently
//! shifts everything after it, or runs off the end and gets whatever the
//! parser's default is.
//!
//! This kernel wrote 39 where Linux writes 52. Fields 40 through 52 —
//! `rt_priority`, `policy`, `arg_start`, `arg_end`, `env_start`, `env_end`,
//! `exit_code` — were simply not there.
//!
//! Two of the fields it did write were wrong in ways nothing reports:
//!
//! - `tpgid` (8) was 0 rather than -1 with no controlling terminal. Zero is a
//!   real process group number, so `ps` attributes the terminal to it.
//! - `starttime` (22) was 0, which dates the process to the boot. `ps -o
//!   etime` is the uptime minus this field, so every process claimed to be as
//!   old as the machine.
//!
//! # Parsing
//!
//! `comm` is in parentheses and may contain anything, spaces and parentheses
//! included. The rule is the **last** `)` on the line, not the first — a
//! parser that splits on whitespace or finds the first `)` gets a different
//! number of fields for a process whose name has one in it. The group that
//! renames this process is there to make that rule observable rather than
//! assumed.

use guest_tests::{Harness, check};

/// Splits a stat line the way Linux says to: up to the first `(`, then to the
/// last `)`, then whitespace.
fn split(line: &str) -> Option<(Vec<String>, String)> {
    let open = line.find('(')?;
    let close = line.rfind(')')?;
    if close < open {
        return None;
    }
    let comm = line[open + 1..close].to_string();
    let mut f: Vec<String> = vec![line[..open].trim().to_string(), comm.clone()];
    f.extend(line[close + 1..].split_whitespace().map(|s| s.to_string()));
    Some((f, comm))
}

fn stat_of(path: &str) -> Option<(Vec<String>, String)> {
    split(std::fs::read_to_string(path).ok()?.trim_end())
}

/// One-based, so the numbering matches proc(5) and the comments above.
fn field(f: &[String], n: usize) -> i128 {
    f.get(n - 1).and_then(|v| v.parse().ok()).unwrap_or(i128::MIN)
}

fn uptime_ticks() -> i128 {
    let t = std::fs::read_to_string("/proc/uptime").unwrap_or_default();
    let secs: f64 = t.split_whitespace().next().and_then(|v| v.parse().ok()).unwrap_or(0.0);
    (secs * 100.0) as i128
}

fn main() {
    let mut h = Harness::new();

    h.group("the-line-has-fifty-two-fields");
    let Some((f, comm)) = stat_of("/proc/self/stat") else {
        check!(h, false, "/proc/self/stat parses");
        std::process::exit(h.finish());
    };
    check!(h, f.len() == 52, "fifty-two of them: {} in {f:?}", f.len());
    check!(h, !comm.is_empty(), "comm is not empty: {comm:?}");
    // Fifteen, not sixteen. Linux's comm is TASK_COMM_LEN bytes *including*
    // the NUL, and this binary's own name is sixteen characters -- so it is the
    // probe as well as the subject. This kernel copied all sixteen bytes at
    // execve and left no terminator, which showed a name a character longer
    // than any real kernel would and read past the array at three printk sites.
    check!(h, comm.len() <= 15, "and is at most fifteen characters: {comm:?}");
    check!(h, "proc_stat_fields".starts_with(&comm),
        "and is this program's name, truncated: {comm:?}");

    h.group("the-fields-that-name-this-process");
    let me = unsafe { libc::getpid() } as i128;
    check!(h, field(&f, 1) == me, "field 1 is the pid: {} vs {me}", field(&f, 1));
    check!(h, "RSDZTtWXxKP".contains(field(&f, 3).to_string().as_str())
              || f[2].len() == 1 && "RSDZTtWXxKP".contains(&f[2]),
        "field 3 is a state letter: {:?}", f[2]);
    check!(h, field(&f, 4) == unsafe { libc::getppid() } as i128,
        "field 4 is the parent: {}", field(&f, 4));
    check!(h, field(&f, 5) == unsafe { libc::getpgrp() } as i128,
        "field 5 is the process group: {}", field(&f, 5));
    check!(h, field(&f, 6) == unsafe { libc::getsid(0) } as i128,
        "field 6 is the session: {}", field(&f, 6));
    check!(h, field(&f, 20) >= 1, "field 20 is a thread count: {}", field(&f, 20));

    h.group("no-controlling-terminal-is-minus-one");
    // Both sides run this without one: the container has no tty unless -t is
    // given, and the guest suite redirects. Field 7 is then 0 -- no device --
    // and field 8 is -1, which is not the same as "process group 0".
    check!(h, field(&f, 7) == 0, "field 7 is no device: {}", field(&f, 7));
    check!(h, field(&f, 8) == -1,
        "field 8 is -1 rather than a process group: {}", field(&f, 8));

    h.group("starttime-is-when-this-process-started");
    let up = uptime_ticks();
    let start = field(&f, 22);
    check!(h, start > 0, "field 22 is not zero: {start}");
    check!(h, start <= up, "and is in the past: {start} vs an uptime of {up}");
    // The age `ps -o etime` computes. This process is seconds old, not as old
    // as the machine -- which is what a zero here would have made it. Ten
    // minutes of slack so a container that has just started still passes.
    check!(h, up - start < 60_000, "so its age is small: {} ticks", up - start);

    h.group("a-child-is-younger-than-its-parent");
    // The direct probe for an inherited value: `*task = *parent` would have
    // copied the parent's start time into the child, and both numbers would be
    // the same rather than one being larger.
    std::thread::sleep(std::time::Duration::from_millis(120));
    let mut pipefd = [0i32; 2];
    check!(h, unsafe { libc::pipe(pipefd.as_mut_ptr()) } == 0, "a pipe");
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::close(pipefd[0]) };
        let start = stat_of("/proc/self/stat")
            .map(|(f, _)| field(&f, 22))
            .unwrap_or(-1) as i64;
        unsafe { libc::write(pipefd[1], (&raw const start).cast(), 8) };
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::close(pipefd[1]) };
    let mut child_start: i64 = -1;
    let n = unsafe { libc::read(pipefd[0], (&raw mut child_start).cast(), 8) };
    unsafe { libc::close(pipefd[0]) };
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    check!(h, n == 8, "the child answered: n={n}");
    check!(h, child_start as i128 > start,
        "and started after its parent: {child_start} vs {start}");

    h.group("the-fields-past-thirty-nine");
    // The ones that were absent entirely. Their *values* are uninteresting --
    // no realtime priority, SCHED_OTHER, no delay accounting, no nested guest
    // -- but a reader indexing field 41 for the scheduling policy has to find
    // a number there.
    for (n, what) in [(40, "rt_priority"), (41, "policy"), (42, "delayacct_blkio_ticks"),
                      (43, "guest_time"), (44, "cguest_time"), (52, "exit_code")] {
        check!(h, field(&f, n) != i128::MIN, "field {n} ({what}) is a number: {:?}",
            f.get(n - 1));
    }
    check!(h, field(&f, 40) == 0, "rt_priority is 0 for a normal process: {}", field(&f, 40));
    check!(h, field(&f, 41) == 0, "and the policy is SCHED_OTHER: {}", field(&f, 41));

    h.group("the-argument-and-environment-strings");
    // 48-51. A reader that wants a command line without opening
    // /proc/<pid>/cmdline takes it from arg_start..arg_end, so the two have to
    // bound something and the layout has to be the one Linux uses: the
    // arguments below the environment, contiguously.
    let (arg_start, arg_end) = (field(&f, 48), field(&f, 49));
    let (env_start, env_end) = (field(&f, 50), field(&f, 51));
    check!(h, arg_start > 0 && arg_end > arg_start,
        "arg_start..arg_end is a range: {arg_start}..{arg_end}");
    check!(h, env_start >= arg_end && env_end > env_start,
        "the environment is above it: {env_start}..{env_end}");
    check!(h, field(&f, 47) > 0, "field 47 is a brk: {}", field(&f, 47));
    // The cross-check that says the addresses are the real ones: this is the
    // same span /proc/<pid>/cmdline reports, byte for byte.
    let cmdline = std::fs::read("/proc/self/cmdline").unwrap_or_default();
    check!(h, cmdline.len() as i128 == arg_end - arg_start,
        "and /proc/self/cmdline is exactly that many bytes: {} vs {}",
        cmdline.len(), arg_end - arg_start);
    let environ = std::fs::read("/proc/self/environ").unwrap_or_default();
    check!(h, environ.len() as i128 == env_end - env_start,
        "as /proc/self/environ is: {} vs {}", environ.len(), env_end - env_start);

    h.group("a-comm-with-a-parenthesis-in-it");
    // The parsing rule, made observable. `prctl(PR_SET_NAME)` takes anything,
    // and a reader that finds the *first* `)` splits this line in the wrong
    // place and counts 53 fields.
    let name = c"a )b c";
    let r = unsafe { libc::prctl(libc::PR_SET_NAME, name.as_ptr()) };
    check!(h, r == 0, "prctl(PR_SET_NAME): r={r} errno={}",
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
    let Some((f2, comm2)) = stat_of("/proc/self/stat") else {
        check!(h, false, "the line still parses");
        std::process::exit(h.finish());
    };
    check!(h, comm2 == "a )b c", "comm is what was set: {comm2:?}");
    // And PR_GET_NAME has to say the same thing, or a process has two names.
    let mut back = [0u8; 32];
    let r = unsafe { libc::prctl(libc::PR_GET_NAME, back.as_mut_ptr()) };
    let back = String::from_utf8_lossy(&back[..back.iter().position(|&b| b == 0).unwrap_or(0)])
        .to_string();
    check!(h, r == 0 && back == comm2,
        "PR_GET_NAME agrees with /proc/self/stat: {back:?} vs {comm2:?}");
    check!(h, f2.len() == 52, "and there are still fifty-two fields: {}", f2.len());
    check!(h, field(&f2, 1) == me, "field 1 is still the pid: {}", field(&f2, 1));
    check!(h, field(&f2, 22) == start, "and field 22 has not moved: {}", field(&f2, 22));

    h.group("a-comm-longer-than-the-field");
    // prctl takes anything and truncates rather than refusing, at the same
    // fifteen characters execve does.
    let long = c"0123456789abcdefghij";
    let r = unsafe { libc::prctl(libc::PR_SET_NAME, long.as_ptr()) };
    check!(h, r == 0, "prctl with a twenty-character name: r={r}");
    let (_, comm3) = stat_of("/proc/self/stat").unwrap_or_default();
    check!(h, comm3 == "0123456789abcde",
        "is truncated to fifteen characters: {comm3:?}");

    std::process::exit(h.finish());
}
