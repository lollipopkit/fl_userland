//! Changing who you are: the eleven uid and gid calls, and the rules that
//! decide which changes are allowed.
//!
//! **A report, not a check** — one line per case, never fails, run here and in
//! an arm64 container and diffed by `tests/integration/probe_diff.sh`.
//!
//! # Why this exists
//!
//! Every one of these is a *security* decision, and the rules are the ones
//! nobody remembers: `setuid` as root sets all three ids and as anyone else
//! sets only the effective one; `setresuid` may set each id to any of the three
//! it already has and nothing else; `setfsuid` reports the **previous** value
//! and cannot fail, so a caller checks it by asking twice. A kernel that is
//! more permissive than Linux here is a kernel where a process regains
//! privilege it dropped.
//!
//! `fsuid_abi` and `perm_semantics` check what the ids *mean* for a file. This
//! asks what the calls do to the ids themselves.
//!
//! # Each group runs in its own child
//!
//! A dropped privilege cannot be picked back up, so a case that drops would
//! decide every case after it. Each group forks, does its work, prints and
//! exits; the parent stays root and waits, so the lines come out in order.

use std::io::Write;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<52} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> String {
    match e {
        libc::EPERM => "EPERM",
        libc::EINVAL => "EINVAL",
        libc::EAGAIN => "EAGAIN",
        libc::EFAULT => "EFAULT",
        libc::ESRCH => "ESRCH",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

fn rc(v: i32) -> String {
    if v < 0 { named(errno()) } else { "0".into() }
}

fn uids() -> (u32, u32, u32) {
    let (mut r, mut e, mut s) = (0u32, 0u32, 0u32);
    unsafe { libc::getresuid(&mut r, &mut e, &mut s) };
    (r, e, s)
}

fn gids() -> (u32, u32, u32) {
    let (mut r, mut e, mut s) = (0u32, 0u32, 0u32);
    unsafe { libc::getresgid(&mut r, &mut e, &mut s) };
    (r, e, s)
}

fn show_uids(what: &str) {
    let (r, e, s) = uids();
    line(what, format!("real {r} effective {e} saved {s}"));
}

fn show_gids(what: &str) {
    let (r, e, s) = gids();
    line(what, format!("real {r} effective {e} saved {s}"));
}

/// Runs `body` in a child and waits. Everything a group does to its own ids
/// dies with it.
fn in_a_child(body: impl FnOnce()) {
    let _ = std::io::stdout().flush();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        body();
        let _ = std::io::stdout().flush();
        unsafe { libc::_exit(0) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
}

fn main() {
    line("running as root", (unsafe { libc::geteuid() } == 0).to_string());

    root_setuid();
    unprivileged_setuid();
    setresuid_rules();
    group_calls();
    supplementary_groups();
    fs_ids();
}

/// `setuid` as root sets **all three**, which is the whole point of it: a
/// daemon that drops with `setuid` cannot come back.
fn root_setuid() {
    println!("## setuid as root");
    in_a_child(|| {
        show_uids("  before");
        line("  setuid(1000)", rc(unsafe { libc::setuid(1000) }));
        show_uids("  after");
        line("  seteuid(0), trying to come back", rc(unsafe { libc::seteuid(0) }));
        line("  setuid(0)", rc(unsafe { libc::setuid(0) }));
        show_uids("  after that");
    });
    // seteuid alone leaves the real and saved ids, which is what a program
    // that means to come back uses.
    in_a_child(|| {
        line("  seteuid(1000) instead", rc(unsafe { libc::seteuid(1000) }));
        show_uids("  after seteuid");
        line("  seteuid(0), coming back", rc(unsafe { libc::seteuid(0) }));
        show_uids("  after coming back");
    });
}

/// What an unprivileged process may do: swap between the three ids it has and
/// nothing else.
fn unprivileged_setuid() {
    println!("## setuid unprivileged");
    in_a_child(|| {
        // Drop to 1000 keeping 1001 saved, so there is something to swap to.
        unsafe { libc::setresuid(1000, 1000, 1001) };
        show_uids("  after setresuid(1000, 1000, 1001)");
        line("  setuid(1001), one of ours", rc(unsafe { libc::setuid(1001) }));
        show_uids("  after");
        line("  setuid(1002), one that is not", rc(unsafe { libc::setuid(1002) }));
        line("  seteuid(1000), also ours", rc(unsafe { libc::seteuid(1000) }));
        show_uids("  after that");
        line("  setuid(0)", rc(unsafe { libc::setuid(0) }));
    });
}

/// `setresuid`'s rule: each of the three may be set to any of the three the
/// process already has, and to nothing else.
fn setresuid_rules() {
    println!("## setresuid");
    in_a_child(|| {
        line(
            "  as root, setresuid(1000, 1001, 1002)",
            rc(unsafe { libc::setresuid(1000, 1001, 1002) }),
        );
        show_uids("  after");
        // -1 means "leave it".
        line("  setresuid(-1, 1000, -1)", rc(unsafe { libc::setresuid(u32::MAX, 1000, u32::MAX) }));
        show_uids("  after");
        // 1002 is the saved id, so it may be taken.
        line("  setresuid(-1, 1002, -1), the saved one", rc(unsafe { libc::setresuid(u32::MAX, 1002, u32::MAX) }));
        show_uids("  after");
        // 5000 is none of them.
        line("  setresuid(-1, 5000, -1)", rc(unsafe { libc::setresuid(u32::MAX, 5000, u32::MAX) }));
        line("  setresuid(5000, -1, -1)", rc(unsafe { libc::setresuid(5000, u32::MAX, u32::MAX) }));
        show_uids("  unchanged");
    });
    // setreuid's own corner: setting the real id to something other than the
    // current one moves the saved id too.
    in_a_child(|| {
        unsafe { libc::setresuid(1000, 1000, 1000) };
        line("  as 1000, setreuid(-1, 1000)", rc(unsafe { libc::setreuid(u32::MAX, 1000) }));
        show_uids("  after");
    });
}

/// The gid calls, which have the same shape and one different rule: dropping
/// the group does not drop the ability to change it back unless the uid went
/// with it.
fn group_calls() {
    println!("## the gid calls");
    in_a_child(|| {
        show_gids("  before");
        line("  setgid(1000) as root", rc(unsafe { libc::setgid(1000) }));
        show_gids("  after");
        line("  setgid(0), coming back", rc(unsafe { libc::setgid(0) }));
        show_gids("  after that");
    });
    in_a_child(|| {
        // The order that matters: gid first, because dropping the uid takes
        // away the privilege needed to drop the gid.
        line("  setresgid(1000, 1000, 1000)", rc(unsafe { libc::setresgid(1000, 1000, 1000) }));
        line("  then setresuid(1000, 1000, 1000)", rc(unsafe { libc::setresuid(1000, 1000, 1000) }));
        line("  setgid(0) now", rc(unsafe { libc::setgid(0) }));
        show_gids("  the gids");
    });
}

/// The supplementary list.
fn supplementary_groups() {
    println!("## supplementary groups");
    // Two groups, set here so that both sides have the same list: a
    // container's first process inherits some and a guest's has none, and a
    // case that runs only when there are groups prints a different number of
    // lines on the two sides -- which reads as "one of them stopped early".
    let two = [1000u32, 1001];
    line("  setgroups(two)", rc(unsafe { libc::setgroups(two.len(), two.as_ptr()) }));
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    line("  getgroups(0, NULL) answers the count", n.to_string());
    // A buffer too small for the list is EINVAL, which is how a caller knows
    // to ask for the count first.
    let mut one = [0u32; 1];
    let r = unsafe { libc::getgroups(1, one.as_mut_ptr()) };
    line("  getgroups(1, buf) with more than one", if r < 0 { named(errno()) } else { r.to_string() });
    let mut all = [0u32; 8];
    let r = unsafe { libc::getgroups(8, all.as_mut_ptr()) };
    line(
        "  getgroups(8, buf)",
        if r < 0 { named(errno()) } else { format!("{:?}", &all[..r as usize]) },
    );
    line("  getgroups(-1, buf)", {
        let r = unsafe { libc::getgroups(-1, all.as_mut_ptr()) };
        if r < 0 { named(errno()) } else { r.to_string() }
    });
    in_a_child(|| {
        let list = [1000u32, 1001, 1002];
        line("  setgroups as root", rc(unsafe { libc::setgroups(list.len(), list.as_ptr()) }));
        let mut back = [0u32; 8];
        let n = unsafe { libc::getgroups(8, back.as_mut_ptr()) };
        line(
            "  and reading them back",
            if n < 0 { named(errno()) } else { format!("{:?}", &back[..n as usize]) },
        );
        // An empty list is legal and is what a daemon sets before dropping.
        line("  setgroups(0, NULL)", rc(unsafe { libc::setgroups(0, std::ptr::null()) }));
        line("  getgroups after", unsafe { libc::getgroups(0, std::ptr::null_mut()) });
        // Now drop and try again.
        unsafe { libc::setresuid(1000, 1000, 1000) };
        line("  setgroups unprivileged", rc(unsafe { libc::setgroups(list.len(), list.as_ptr()) }));
    });
    in_a_child(|| {
        // More groups than any kernel keeps.
        let many: Vec<u32> = (0..70_000).collect();
        line("  setgroups(70000)", rc(unsafe { libc::setgroups(many.len(), many.as_ptr()) }));
    });
}

/// `setfsuid` and `setfsgid`: they answer the **previous** value and never
/// fail, so a caller checks whether it worked by calling twice.
fn fs_ids() {
    println!("## the fs ids");
    in_a_child(|| {
        let before = unsafe { libc::syscall(151, u32::MAX) };
        line("  setfsuid(-1) answers the current one", before.to_string());
        let prev = unsafe { libc::syscall(151, 1000) };
        line("  setfsuid(1000) answers the previous", (prev == before).to_string());
        let now = unsafe { libc::syscall(151, u32::MAX) };
        line("  and it took", (now == 1000).to_string());
        // As root, back again.
        unsafe { libc::syscall(151, 0) };
        line("  back to 0", (unsafe { libc::syscall(151, u32::MAX) } == 0).to_string());

        // Unprivileged: the fs uid may become the real, effective or saved id
        // and nothing else, and a refusal is silent.
        unsafe { libc::setresuid(1000, 1000, 1000) };
        let prev = unsafe { libc::syscall(151, 5000) };
        let now = unsafe { libc::syscall(151, u32::MAX) };
        line("  unprivileged setfsuid(5000) is refused", (now != 5000).to_string());
        line("  and it answered the previous anyway", (prev == 1000).to_string());
        let _ = unsafe { libc::syscall(151, 1000) };
        line("  setfsuid to our own id", (unsafe { libc::syscall(151, u32::MAX) } == 1000).to_string());
    });
    in_a_child(|| {
        let before = unsafe { libc::syscall(152, u32::MAX) };
        line("  setfsgid(-1) answers the current one", before.to_string());
        let prev = unsafe { libc::syscall(152, 1000) };
        line("  setfsgid(1000) answers the previous", (prev == before).to_string());
        line("  and it took", (unsafe { libc::syscall(152, u32::MAX) } == 1000).to_string());
    });
}
