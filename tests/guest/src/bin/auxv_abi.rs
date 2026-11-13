//! The auxiliary vector, and the block it sits in.
//!
//! `execve` leaves `argc`, `argv`, `envp` and the auxiliary vector at the top
//! of a new process's stack, and libc reads all four **with no length**: it
//! walks to the `NULL`s and then to `AT_NULL`. So a layout one word out is not
//! a smaller answer, it is a different one.
//!
//! What this pins:
//!
//! - **`AT_UID` and friends are this process's ids.** All four were hard-coded
//!   to 0, so `getauxval(AT_UID)` told a process running as 1000 that it was
//!   root. Visible only when the process is not root, which is why
//!   `differential.sh` running this in a container as `--user` matters.
//! - **`AT_SECURE` is whether the exec crossed a privilege boundary.** libc
//!   reads it and, when set, ignores `LD_PRELOAD` and everything else in the
//!   environment that can redirect a load. Hard-coded to 0.
//! - **The block is consistent**: `/proc/self/auxv` is the same vector the
//!   stack has, ends with `AT_NULL`, and the two `NULL`s between the three
//!   lists are where libc expects.

use guest_tests::{Harness, check};

const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_ENTRY: u64 = 9;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const AT_SECURE: u64 = 23;
const AT_RANDOM: u64 = 25;
const AT_EXECFN: u64 = 31;

fn auxval(kind: u64) -> u64 {
    unsafe { libc::getauxval(kind) }
}

/// `/proc/self/auxv` as pairs, which is the same vector from the other side.
fn proc_auxv() -> Vec<(u64, u64)> {
    let bytes = std::fs::read("/proc/self/auxv").unwrap_or_default();
    bytes
        .chunks_exact(16)
        .map(|c| {
            (
                u64::from_ne_bytes(c[0..8].try_into().unwrap()),
                u64::from_ne_bytes(c[8..16].try_into().unwrap()),
            )
        })
        .collect()
}

/// Re-exec this binary as uid 1000, and report whether its checks passed.
///
/// Without this the ids above are `0 == 0` on both sides and the assertion is
/// **vacuous** — which is a failure this tree has had, with a filter that made
/// an `all()` run over an empty iterator. The emulator runs its guest as root,
/// so the only way to see what a non-root process is told is to become one.
fn recheck_as_another_user(h: &mut Harness) {
    if std::env::var_os("AUXV_ABI_CHILD").is_some() {
        return; // this *is* the child
    }
    if unsafe { libc::geteuid() } != 0 {
        return; // already unprivileged; the checks above covered it
    }
    let exe = std::env::args().next().unwrap_or_default();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            // Group first: dropping the user id would take the privilege
            // needed to drop the group one.
            if libc::setgid(1000) != 0 || libc::setuid(1000) != 0 {
                libc::_exit(101);
            }
            let path = std::ffi::CString::new(exe).unwrap();
            let arg0 = path.clone();
            let marker = c"AUXV_ABI_CHILD=1";
            let argv = [arg0.as_ptr(), std::ptr::null()];
            let envp = [marker.as_ptr(), std::ptr::null()];
            libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(102);
        }
    }
    let mut status = 0i32;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    check!(h, waited == pid, "the unprivileged child was reaped: {waited}");
    let code = libc::WEXITSTATUS(status);
    check!(
        h,
        libc::WIFEXITED(status) && code == 0,
        "and its own checks passed as uid 1000: exit {code} (101 = could not drop, 102 = could not exec)"
    );
}

fn main() {
    let mut h = Harness::new();

    h.group("the-ids-are-this-processes");
    let (uid, euid) = unsafe { (libc::getuid() as u64, libc::geteuid() as u64) };
    let (gid, egid) = unsafe { (libc::getgid() as u64, libc::getegid() as u64) };
    check!(h, auxval(AT_UID) == uid, "AT_UID {} vs getuid {uid}", auxval(AT_UID));
    check!(h, auxval(AT_EUID) == euid, "AT_EUID {} vs {euid}", auxval(AT_EUID));
    check!(h, auxval(AT_GID) == gid, "AT_GID {} vs {gid}", auxval(AT_GID));
    check!(h, auxval(AT_EGID) == egid, "AT_EGID {} vs {egid}", auxval(AT_EGID));

    h.group("at-secure-follows-the-ids");
    // This process was not exec'd across a privilege boundary, whatever ids it
    // has, so the answer is 0 either way -- what is checked is that it is
    // *derived* from them rather than a constant, which the ids above make
    // observable when they differ.
    let expect_secure = (uid != euid || gid != egid) as u64;
    check!(
        h,
        auxval(AT_SECURE) == expect_secure,
        "AT_SECURE {} with ids {uid}/{euid} {gid}/{egid}",
        auxval(AT_SECURE)
    );

    h.group("the-elf-entries-describe-this-image");
    check!(h, auxval(AT_PAGESZ) == 4096, "AT_PAGESZ {}", auxval(AT_PAGESZ));
    check!(h, auxval(AT_PHENT) == 56, "AT_PHENT {} (ELF64)", auxval(AT_PHENT));
    check!(h, auxval(AT_PHNUM) > 0, "AT_PHNUM {}", auxval(AT_PHNUM));
    check!(h, auxval(AT_PHDR) != 0, "AT_PHDR is set");
    check!(h, auxval(AT_ENTRY) != 0, "AT_ENTRY is set");

    h.group("at-random-is-sixteen-readable-bytes");
    let random = auxval(AT_RANDOM);
    check!(h, random != 0, "AT_RANDOM is set");
    if random != 0 {
        let bytes = unsafe { std::slice::from_raw_parts(random as *const u8, 16) };
        // Not a randomness test -- it is that the address is readable and the
        // sixteen bytes are there, which is what libc copies out of it.
        let all_zero = bytes.iter().all(|&b| b == 0);
        check!(h, !all_zero, "and is not sixteen zeroes");
    }

    h.group("at-execfn-names-this-program");
    let execfn = auxval(AT_EXECFN);
    check!(h, execfn != 0, "AT_EXECFN is set");
    if execfn != 0 {
        let s = unsafe { std::ffi::CStr::from_ptr(execfn as *const libc::c_char) };
        let s = s.to_string_lossy();
        check!(h, s.contains("auxv_abi"), "AT_EXECFN is {s:?}");
    }

    h.group("proc-self-auxv-is-the-same-vector");
    let v = proc_auxv();
    check!(h, !v.is_empty(), "/proc/self/auxv is readable: {} entries", v.len());
    check!(
        h,
        v.last() == Some(&(AT_NULL, 0)),
        "and ends with AT_NULL: {:?}",
        v.last()
    );
    // Every entry before the terminator is one, and no AT_NULL appears early --
    // an early one would truncate the vector for every reader.
    check!(
        h,
        v[..v.len() - 1].iter().all(|&(k, _)| k != AT_NULL),
        "with no AT_NULL before the end"
    );
    for kind in [AT_PAGESZ, AT_PHENT, AT_UID, AT_SECURE, AT_RANDOM] {
        let from_proc = v.iter().find(|&&(k, _)| k == kind).map(|&(_, val)| val);
        check!(
            h,
            from_proc == Some(auxval(kind)),
            "entry {kind}: /proc says {from_proc:?}, getauxval says {}",
            auxval(kind)
        );
    }

    h.group("argv-and-envp-survived-the-layout");
    let args: Vec<String> = std::env::args().collect();
    check!(h, !args.is_empty(), "argv is not empty");
    check!(h, args[0].contains("auxv_abi"), "argv[0] is {:?}", args[0]);
    // The environment is the block between argv's terminator and the auxv, and
    // a layout one word out reads one as the other.
    // The re-exec'd child is given one variable and no PATH, so the check is
    // that the environment is *the one it was handed* rather than that any
    // particular name is in it.
    let expect_env = if std::env::var_os("AUXV_ABI_CHILD").is_some() {
        "AUXV_ABI_CHILD"
    } else {
        "PATH"
    };
    check!(
        h,
        std::env::var_os(expect_env).is_some(),
        "{expect_env} is in the environment"
    );
    let cmdline = std::fs::read("/proc/self/cmdline").unwrap_or_default();
    check!(
        h,
        cmdline.split(|&b| b == 0).next().is_some_and(|a| !a.is_empty()),
        "/proc/self/cmdline has argv[0]"
    );

    h.group("the-same-checks-as-an-unprivileged-process");
    // Everything above is 0 == 0 for a root process, so the ids are checked
    // again from one that is not root.
    recheck_as_another_user(&mut h);

    std::process::exit(h.finish());
}
