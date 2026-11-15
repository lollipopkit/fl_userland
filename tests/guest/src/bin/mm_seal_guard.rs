//! `mseal`, `MADV_GUARD_*`, the `madvise` dispositions, `MREMAP_DONTUNMAP`,
//! `process_madvise` and `process_mrelease`: what each does to memory,
//! checked by looking at the memory afterwards.
//!
//! Every expected answer here is what an arm64 7.2 kernel gave
//! `tests/guest/src/bin/mm_modern_probe.rs`; this asserts the subset that
//! states a behaviour, so a regression fails a check rather than only moving a
//! probe line.

use guest_tests::{Harness, check, check_fails, sys};

const PAGE: usize = 4096;
const MADV_POPULATE_READ: i32 = 22;
const MADV_POPULATE_WRITE: i32 = 23;
const MADV_DONTNEED_LOCKED: i32 = 24;
const MADV_GUARD_INSTALL: i32 = 102;
const MADV_GUARD_REMOVE: i32 = 103;
const MREMAP_DONTUNMAP: i32 = 4;

fn map(pages: usize, prot: i32, flags: i32) -> *mut u8 {
    let p = unsafe { libc::mmap(std::ptr::null_mut(), pages * PAGE, prot, flags, -1, 0) };
    assert_ne!(p, libc::MAP_FAILED);
    p.cast()
}

fn anon(pages: usize, fill: u8) -> *mut u8 {
    let p = map(pages, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS);
    unsafe { std::ptr::write_bytes(p, fill, pages * PAGE) };
    p
}

fn at(p: *mut u8, page: usize) -> *mut u8 {
    p.wrapping_add(page * PAGE)
}

fn mseal(p: *mut u8, len: usize, flags: u64) -> i64 {
    unsafe { libc::syscall(462, p, len, flags) }
}

fn madvise(p: *mut u8, len: usize, adv: i32) -> i64 {
    unsafe { libc::madvise(p.cast(), len, adv) as i64 }
}

/// Whether a child touching `p` dies of SIGSEGV.
fn faults(p: *mut u8, write: bool) -> bool {
    let c = unsafe { libc::fork() };
    if c == 0 {
        unsafe {
            if write {
                std::ptr::write_volatile(p, 1);
            } else {
                std::ptr::read_volatile(p);
            }
            libc::_exit(0);
        }
    }
    let mut st = 0;
    unsafe { libc::waitpid(c, &mut st, 0) };
    libc::WIFSIGNALED(st) && libc::WTERMSIG(st) == libc::SIGSEGV
}

/// What a child reads at `p`, or -1 if it faulted.
fn child_reads(p: *mut u8) -> i32 {
    let c = unsafe { libc::fork() };
    if c == 0 {
        let v = unsafe { std::ptr::read_volatile(p) };
        unsafe { libc::_exit(i32::from(v)) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(c, &mut st, 0) };
    if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { -1 }
}

fn vm_flags_of(p: *mut u8) -> String {
    let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap_or_default();
    let a = p as usize;
    let mut inside = false;
    for l in smaps.lines() {
        if let Some((range, _)) = l.split_once(' ') {
            if let Some((lo, hi)) = range.split_once('-') {
                if let (Ok(lo), Ok(hi)) = (usize::from_str_radix(lo, 16), usize::from_str_radix(hi, 16)) {
                    inside = lo <= a && a < hi;
                    continue;
                }
            }
        }
        if inside {
            if let Some(f) = l.strip_prefix("VmFlags:") {
                return f.trim().to_owned();
            }
        }
    }
    String::new()
}

fn has_flag(p: *mut u8, f: &str) -> bool {
    vm_flags_of(p).split(' ').any(|w| w == f)
}

fn t_mseal(h: &mut Harness) {
    h.group("mseal");
    let p = anon(3, 0x22);
    let m = at(p, 1);
    check_fails!(h, mseal(m, PAGE, 1), libc::EINVAL, "flags 1");
    check_fails!(h, mseal(m.wrapping_add(1), PAGE, 0), libc::EINVAL, "an unaligned start");
    check!(h, mseal(m, 0, 0) == 0, "a zero length is success");
    check!(h, mseal(m, PAGE, 0) == 0, "seal the middle page: errno {}", sys::errno());
    check!(h, mseal(m, PAGE, 0) == 0, "sealing twice is success");
    check!(h, has_flag(m, "sl"), "smaps says sl for the sealed page: {}", vm_flags_of(m));
    check!(h, !has_flag(p, "sl"), "and not for its neighbour");
    check_fails!(h, unsafe { libc::munmap(m.cast(), PAGE) }, libc::EPERM, "munmap of the sealed page");
    check_fails!(h, unsafe { libc::munmap(p.cast(), 3 * PAGE) }, libc::EPERM, "munmap over it");
    check!(h, !faults(p, false), "the refused munmap left the first page mapped");
    check_fails!(
        h,
        unsafe { libc::mprotect(m.cast(), PAGE, libc::PROT_READ | libc::PROT_WRITE) },
        libc::EPERM,
        "mprotect to the protection it already has"
    );
    check_fails!(
        h,
        unsafe { libc::mprotect(p.cast(), 3 * PAGE, libc::PROT_READ) },
        libc::EPERM,
        "mprotect over the three"
    );
    // 7.x re-protects the vmas before the sealed one and stops there.
    check!(h, faults(p, true), "the page before the seal was made read-only");
    check!(h, !faults(m, true), "the sealed page kept its protection");
    check!(h, !faults(at(p, 2), true), "the page after it was not reached");
    let r = unsafe { libc::mremap(m.cast(), PAGE, 2 * PAGE, libc::MREMAP_MAYMOVE) };
    check!(h, r == libc::MAP_FAILED && sys::errno() == libc::EPERM, "mremap of the sealed page: errno {}", sys::errno());
    let fixed = unsafe {
        libc::mmap(m.cast(), PAGE, libc::PROT_READ, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED, -1, 0)
    };
    check!(h, fixed == libc::MAP_FAILED && sys::errno() == libc::EPERM, "MAP_FIXED over it: errno {}", sys::errno());
    check!(h, unsafe { *m } == 0x22, "and it still holds its bytes");
    // Writable private anonymous memory may still be discarded.
    check!(h, madvise(m, PAGE, libc::MADV_DONTNEED) == 0, "DONTNEED on a sealed writable page");
    check!(h, unsafe { *m } == 0, "zeroes it");
    // A fork inherits the seal.
    let c = unsafe { libc::fork() };
    if c == 0 {
        let v = unsafe { libc::munmap(m.cast(), PAGE) };
        unsafe { libc::_exit(if v == 0 { 0 } else { sys::errno() }) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(c, &mut st, 0) };
    check!(h, libc::WEXITSTATUS(st) == libc::EPERM, "a child's munmap of it: {}", libc::WEXITSTATUS(st));

    let q = anon(1, 0x33);
    unsafe { libc::mprotect(q.cast(), PAGE, libc::PROT_READ) };
    check!(h, mseal(q, PAGE, 0) == 0, "seal a read-only page");
    check_fails!(h, madvise(q, PAGE, libc::MADV_DONTNEED), libc::EPERM, "DONTNEED on a sealed read-only page");
    check_fails!(h, madvise(q, PAGE, MADV_GUARD_INSTALL), libc::EPERM, "GUARD_INSTALL on it");
    check!(h, madvise(q, PAGE, libc::MADV_COLD) == 0, "COLD on it");
    check!(h, unsafe { *q } == 0x33, "its bytes are untouched");

    let s = map(1, libc::PROT_READ, libc::MAP_SHARED | libc::MAP_ANONYMOUS);
    check!(h, mseal(s, PAGE, 0) == 0, "seal a read-only shared page");
    check!(h, madvise(s, PAGE, libc::MADV_DONTNEED) == 0, "DONTNEED on it, which is not anonymous to the rule");

    let hole = anon(3, 0);
    unsafe { libc::munmap(at(hole, 1).cast(), PAGE) };
    check_fails!(h, mseal(hole, 3 * PAGE, 0), libc::ENOMEM, "a range with a hole");
    check!(h, unsafe { libc::munmap(hole.cast(), PAGE) } == 0, "which sealed nothing");
}

fn t_guard(h: &mut Harness) {
    h.group("guard");
    let p = anon(3, 0x44);
    let g = at(p, 1);
    check!(h, madvise(g, PAGE, MADV_GUARD_INSTALL) == 0, "install: errno {}", sys::errno());
    check!(h, faults(g, false), "a read faults");
    check!(h, faults(g, true), "a write faults");
    check!(h, !faults(p, false), "the neighbour does not");
    let mut v = [9u8; 3];
    unsafe { libc::mincore(p.cast(), 3 * PAGE, v.as_mut_ptr()) };
    check!(h, v[1] & 1 == 0, "mincore says the guard has no page: {v:?}");
    check_fails!(h, madvise(p, 3 * PAGE, MADV_POPULATE_READ), libc::EFAULT, "POPULATE_READ over it");
    let mut b = [0u8; 8];
    let local = libc::iovec { iov_base: b.as_mut_ptr().cast(), iov_len: 8 };
    let remote = libc::iovec { iov_base: g.cast(), iov_len: 8 };
    check_fails!(
        h,
        unsafe { libc::process_vm_readv(libc::getpid(), &local, 1, &remote, 1, 0) },
        libc::EFAULT,
        "process_vm_readv of it"
    );
    check!(h, madvise(g, PAGE, MADV_GUARD_REMOVE) == 0, "remove: errno {}", sys::errno());
    check!(h, !faults(g, false), "readable again");
    check!(h, unsafe { *g } == 0, "and zero, since installing it zapped the page");
    check!(h, unsafe { *p } == 0x44, "the neighbour kept its bytes");
    check!(h, madvise(p, PAGE, MADV_GUARD_REMOVE) == 0, "removing a guard that is not there");
    check!(h, unsafe { *p } == 0x44, "leaves the page alone");
    madvise(g, PAGE, MADV_GUARD_INSTALL);
    let r = unsafe {
        libc::mmap(g.cast(), PAGE, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED, -1, 0)
    };
    check!(h, r != libc::MAP_FAILED && !faults(g, true), "a new mapping over a guard has none");
    let l = anon(1, 0);
    unsafe { libc::mlock(l.cast(), PAGE) };
    check_fails!(h, madvise(l, PAGE, MADV_GUARD_INSTALL), libc::EINVAL, "on locked memory");
}

fn t_populate_and_lock(h: &mut Harness) {
    h.group("populate");
    let p = anon(2, 0);
    check!(h, madvise(p, 2 * PAGE, MADV_POPULATE_WRITE) == 0, "POPULATE_WRITE of writable memory");
    unsafe { libc::mprotect(p.cast(), PAGE, libc::PROT_READ) };
    check!(h, madvise(p, PAGE, MADV_POPULATE_READ) == 0, "POPULATE_READ of read-only memory");
    check_fails!(h, madvise(p, PAGE, MADV_POPULATE_WRITE), libc::EINVAL, "POPULATE_WRITE of read-only memory");
    unsafe { libc::mprotect(p.cast(), PAGE, libc::PROT_NONE) };
    check_fails!(h, madvise(p, PAGE, MADV_POPULATE_READ), libc::EINVAL, "POPULATE_READ of PROT_NONE");

    h.group("mlock");
    let q = anon(2, 0x55);
    unsafe { libc::mlock(q.cast(), 2 * PAGE) };
    check!(h, has_flag(q, "lo"), "smaps says lo: {}", vm_flags_of(q));
    check_fails!(h, madvise(q, PAGE, libc::MADV_DONTNEED), libc::EINVAL, "DONTNEED on locked memory");
    check!(h, unsafe { *q } == 0x55, "which kept its bytes");
    check!(h, madvise(q, PAGE, MADV_DONTNEED_LOCKED) == 0, "DONTNEED_LOCKED");
    check!(h, unsafe { *q } == 0, "zeroes it");
    check!(h, unsafe { *at(q, 1) } == 0x55, "and only what it was asked to");
    unsafe { libc::munlock(q.cast(), 2 * PAGE) };
    check!(h, madvise(at(q, 1), PAGE, libc::MADV_DONTNEED) == 0, "DONTNEED after munlock");
    check!(h, unsafe { *at(q, 1) } == 0, "zeroes it");
}

fn t_fork_dispositions(h: &mut Harness) {
    h.group("fork-dispositions");
    let p = anon(1, 0x66);
    check!(h, madvise(p, PAGE, libc::MADV_DONTFORK) == 0, "DONTFORK");
    check!(h, faults(p, false), "a child has no page there");
    check!(h, madvise(p, PAGE, libc::MADV_DOFORK) == 0, "DOFORK");
    check!(h, child_reads(p) == 0x66, "a child has it again");
    check!(h, madvise(p, PAGE, libc::MADV_WIPEONFORK) == 0, "WIPEONFORK");
    check!(h, child_reads(p) == 0, "a child reads zero");
    check!(h, unsafe { *p } == 0x66, "the parent kept its bytes");
    let s = map(1, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED | libc::MAP_ANONYMOUS);
    check_fails!(h, madvise(s, PAGE, libc::MADV_WIPEONFORK), libc::EINVAL, "WIPEONFORK of shared memory");
    unsafe { *s = 0x77 };
    check!(h, madvise(s, PAGE, libc::MADV_DONTNEED) == 0, "DONTNEED of shared memory");
    check!(h, unsafe { *s } == 0x77, "keeps the shared bytes");
    check!(h, madvise(s, PAGE, libc::MADV_REMOVE) == 0, "REMOVE of shared memory: errno {}", sys::errno());
    check!(h, unsafe { *s } == 0, "punches the hole");
    check_fails!(h, madvise(p, PAGE, libc::MADV_REMOVE), libc::EINVAL, "REMOVE of private memory");
}

fn t_dontunmap(h: &mut Harness) {
    h.group("mremap-dontunmap");
    let p = anon(2, 0x66);
    let r = unsafe { libc::mremap(p.cast(), 2 * PAGE, 2 * PAGE, libc::MREMAP_MAYMOVE | MREMAP_DONTUNMAP) };
    check!(h, r != libc::MAP_FAILED, "private anonymous: errno {}", sys::errno());
    if r != libc::MAP_FAILED {
        let n = r.cast::<u8>();
        check!(h, unsafe { *at(n, 1) } == 0x66, "the new address has the bytes");
        check!(h, !faults(p, true), "the old one is still mapped");
        check!(h, unsafe { *p } == 0, "and empty");
    }
    let r = unsafe { libc::mremap(p.cast(), 2 * PAGE, 3 * PAGE, libc::MREMAP_MAYMOVE | MREMAP_DONTUNMAP) };
    check!(h, r == libc::MAP_FAILED && sys::errno() == libc::EINVAL, "a change of length");
    let r = unsafe { libc::mremap(p.cast(), 2 * PAGE, 2 * PAGE, MREMAP_DONTUNMAP) };
    check!(h, r == libc::MAP_FAILED && sys::errno() == libc::EINVAL, "without MAYMOVE");
    // Not DONTUNMAP: a fixed move into free address space, which the
    // emulator refused with EFAULT until the same change.
    let src = anon(1, 0x99);
    let hole = anon(1, 0);
    unsafe { libc::munmap(hole.cast(), PAGE) };
    let r = unsafe { libc::mremap(src.cast(), PAGE, PAGE, libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED, hole) };
    check!(h, r == hole.cast(), "MREMAP_FIXED into a hole: errno {}", sys::errno());
    if r == hole.cast() {
        check!(h, unsafe { *hole } == 0x99, "  carries the bytes");
    }
    let s = map(1, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED | libc::MAP_ANONYMOUS);
    let r = unsafe { libc::mremap(s.cast(), PAGE, PAGE, libc::MREMAP_MAYMOVE | MREMAP_DONTUNMAP) };
    check!(h, r != libc::MAP_FAILED, "shared anonymous: errno {}", sys::errno());
    if r != libc::MAP_FAILED {
        unsafe { *r.cast::<u8>() = 0x88 };
        check!(h, unsafe { *s } == 0x88, "the old range still reaches the same object");
    }
}

fn pidfd_open(pid: i32) -> i32 {
    unsafe { libc::syscall(434, pid, 0) as i32 }
}

fn pm(pidfd: i32, iov: &[libc::iovec], adv: i32, flags: u32) -> i64 {
    unsafe { libc::syscall(440, pidfd, iov.as_ptr(), iov.len(), adv, flags) }
}

fn t_process_madvise(h: &mut Harness) {
    h.group("process_madvise");
    let me = pidfd_open(unsafe { libc::getpid() });
    let p = anon(4, 0x77);
    let iov = [
        libc::iovec { iov_base: p.cast(), iov_len: PAGE },
        libc::iovec { iov_base: at(p, 2).cast(), iov_len: 2 * PAGE },
    ];
    check!(h, pm(me, &iov, libc::MADV_COLD, 0) == 3 * PAGE as i64, "self, COLD answers the bytes");
    check!(h, pm(me, &iov, libc::MADV_DONTNEED, 0) == 3 * PAGE as i64, "self, DONTNEED");
    check!(h, unsafe { *p } == 0 && unsafe { *at(p, 1) } == 0x77, "zeroed what it named and nothing else");
    check!(h, pm(-10001, &iov, libc::MADV_COLD, 0) == 3 * PAGE as i64, "PIDFD_SELF_THREAD_GROUP");
    check_fails!(h, pm(me, &iov, libc::MADV_COLD, 1), libc::EINVAL, "flags 1");
    check_fails!(h, pm(me, &iov, 999, 0), libc::EINVAL, "advice 999");
    check_fails!(h, pm(-1, &iov, libc::MADV_COLD, 0), libc::EBADF, "pidfd -1");
    check_fails!(
        h,
        unsafe { libc::syscall(440, me, iov.as_ptr(), 1025usize, libc::MADV_COLD, 0) },
        libc::EINVAL,
        "1025 iovecs"
    );
    check_fails!(h, unsafe { libc::syscall(440, me, 8usize, 1usize, libc::MADV_COLD, 0) }, libc::EFAULT, "an unreadable iovec");
    unsafe { libc::munmap(at(p, 1).cast(), PAGE) };
    let two = [
        libc::iovec { iov_base: at(p, 2).cast(), iov_len: PAGE },
        libc::iovec { iov_base: p.cast(), iov_len: 2 * PAGE },
    ];
    check!(h, pm(me, &two, libc::MADV_COLD, 0) == PAGE as i64, "a failure part-way answers the bytes before it");

    let mut fds = [0; 2];
    unsafe { libc::pipe(fds.as_mut_ptr()) };
    let c = unsafe { libc::fork() };
    if c == 0 {
        unsafe {
            libc::close(fds[1]);
            let mut b = 0u8;
            libc::read(fds[0], (&raw mut b).cast(), 1);
            libc::_exit(0);
        }
    }
    unsafe { libc::close(fds[0]) };
    let cfd = pidfd_open(c);
    let civ = [libc::iovec { iov_base: p.cast(), iov_len: PAGE }];
    check!(h, pm(cfd, &civ, libc::MADV_COLD, 0) == PAGE as i64, "a child, COLD");
    check_fails!(h, pm(cfd, &civ, libc::MADV_DONTNEED, 0), libc::EINVAL, "a child, DONTNEED");
    check_fails!(h, unsafe { libc::syscall(448, cfd, 0) }, libc::EINVAL, "process_mrelease of a live child");
    check_fails!(h, unsafe { libc::syscall(448, cfd, 1) }, libc::EINVAL, "process_mrelease, flags 1");
    check_fails!(h, unsafe { libc::syscall(448, me, 0) }, libc::EINVAL, "process_mrelease of self");
    check_fails!(h, unsafe { libc::syscall(448, -1, 0) }, libc::EBADF, "process_mrelease of -1");
    unsafe { libc::kill(c, libc::SIGKILL) };
    let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
    unsafe { libc::waitid(libc::P_PID, c as u32, &mut si, libc::WEXITED | libc::WNOWAIT) };
    check_fails!(h, pm(cfd, &civ, libc::MADV_COLD, 0), libc::ESRCH, "a zombie");
    check_fails!(h, unsafe { libc::syscall(448, cfd, 0) }, libc::ESRCH, "process_mrelease of a zombie");
    let mut st = 0;
    unsafe { libc::waitpid(c, &mut st, 0) };
    check_fails!(h, pm(cfd, &civ, libc::MADV_COLD, 0), libc::ESRCH, "a reaped child");
}

fn t_pkey(h: &mut Harness) {
    h.group("pkey");
    let pkey = unsafe { libc::syscall(289, 0, 0) };
    h.check(pkey > 0, format_args!("pkey_alloc returned {pkey}"));
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    h.check(p != libc::MAP_FAILED, format_args!("mmap for pkey_mprotect"));
    if p != libc::MAP_FAILED {
        let r = unsafe { libc::syscall(288, p as usize, 4096usize, libc::PROT_READ, pkey) };
        h.check(r == 0, format_args!("pkey_mprotect returned {r}"));
        unsafe { libc::munmap(p, 4096) };
    }
    if pkey > 0 {
        let f = unsafe { libc::syscall(290, pkey) };
        h.check(f == 0, format_args!("pkey_free returned {f}"));
        check_fails!(h, unsafe { libc::syscall(290, pkey) }, libc::EINVAL, "double pkey_free");
    }
}

fn t_not_configured(h: &mut Harness) {
    // The reference kernel has no NUMA and no shadow stacks, and says so with
    // ENOSYS for every one of these.
    h.group("not-configured");
    for (n, name) in [(235, "mbind"), (236, "get_mempolicy"), (237, "set_mempolicy"), (238, "migrate_pages"),
        (239, "move_pages"), (450, "set_mempolicy_home_node"), (453, "map_shadow_stack")] {
        check_fails!(h, unsafe { libc::syscall(n, 0, 0, 0, 0, 0, 0) }, libc::ENOSYS, "{name}");
    }
}

fn main() {
    let mut h = Harness::new();
    t_mseal(&mut h);
    t_guard(&mut h);
    t_populate_and_lock(&mut h);
    t_fork_dispositions(&mut h);
    t_dontunmap(&mut h);
    t_process_madvise(&mut h);
    t_pkey(&mut h);
    t_not_configured(&mut h);
    std::process::exit(h.finish());
}
