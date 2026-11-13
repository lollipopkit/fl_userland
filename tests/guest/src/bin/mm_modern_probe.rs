//! The memory calls a 7.x kernel has beyond the classic eleven: `mseal` and
//! what a seal refuses, `process_madvise`, `process_mrelease`, protection
//! keys, `map_shadow_stack`, the NUMA policy family, `memfd_secret`, and the
//! newer `madvise`/`mremap`/`mmap` behaviours (`MADV_GUARD_*`,
//! `MADV_POPULATE_*`, `MADV_DONTNEED_LOCKED`, `MREMAP_DONTUNMAP`,
//! `MAP_FIXED_NOREPLACE`) checked by looking at memory afterwards.
//!
//! **A report, not a check**: one line per case, diffed against an arm64
//! container by `tests/integration/probe_diff.sh`, which runs this one with
//! seccomp off and `CAP_SYS_NICE` added: the guest is root in its own kernel,
//! and the NUMA calls and a remote `process_madvise` are what that capability
//! gates.

use std::io::Write;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<60} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> String {
    match e {
        libc::EPERM => "EPERM",
        libc::ESRCH => "ESRCH",
        libc::EBADF => "EBADF",
        libc::EAGAIN => "EAGAIN",
        libc::EFAULT => "EFAULT",
        libc::EEXIST => "EEXIST",
        libc::EINVAL => "EINVAL",
        libc::ENOMEM => "ENOMEM",
        libc::ENOSYS => "ENOSYS",
        libc::ENOSPC => "ENOSPC",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        libc::EACCES => "EACCES",
        libc::ENODEV => "ENODEV",
        libc::ENOENT => "ENOENT",
        libc::EIO => "EIO",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

fn r(v: i64) -> String {
    if v < 0 { named(errno()) } else { v.to_string() }
}

fn ok(v: i64) -> String {
    if v < 0 { named(errno()) } else { "ok".into() }
}

const PAGE: usize = 4096;
const MADV_POPULATE_READ: i32 = 22;
const MADV_POPULATE_WRITE: i32 = 23;
const MADV_DONTNEED_LOCKED: i32 = 24;
const MADV_COLLAPSE: i32 = 25;
const MADV_GUARD_INSTALL: i32 = 102;
const MADV_GUARD_REMOVE: i32 = 103;
const MREMAP_DONTUNMAP: i32 = 4;
const MAP_FIXED_NOREPLACE: i32 = 0x100000;

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

fn unmap(p: *mut u8, pages: usize) {
    unsafe { libc::munmap(p.cast(), pages * PAGE) };
}

fn mseal(p: *mut u8, len: usize, flags: u64) -> i64 {
    unsafe { libc::syscall(462, p, len, flags) }
}

fn madvise(p: *mut u8, len: usize, adv: i32) -> i64 {
    unsafe { libc::madvise(p.cast(), len, adv) as i64 }
}

/// What a child that touches `p` dies of, or "survived".
fn touch_in_child(p: *mut u8, write: bool) -> String {
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
    if libc::WIFSIGNALED(st) { format!("signal {}", libc::WTERMSIG(st)) } else { "survived".into() }
}

fn smaps_flags_of(p: *mut u8) -> Option<String> {
    let smaps = std::fs::read_to_string("/proc/self/smaps").ok()?;
    let mut inside = false;
    let a = p as usize;
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
                return Some(f.trim().to_owned());
            }
        }
    }
    None
}

fn pidfd_open(pid: i32) -> i32 {
    unsafe { libc::syscall(434, pid, 0) as i32 }
}

fn process_madvise(pidfd: i32, iov: &[libc::iovec], adv: i32, flags: u32) -> i64 {
    unsafe { libc::syscall(440, pidfd, iov.as_ptr(), iov.len(), adv, flags) }
}

fn main() {
    println!("########## mseal: the call ##########");
    {
        let p = anon(4, 0x11);
        line("mseal(1 page, 0)", ok(mseal(p, PAGE, 0)));
        line("mseal(again)", ok(mseal(p, PAGE, 0)));
        line("mseal(flags 1)", ok(mseal(unsafe { p.add(PAGE) }, PAGE, 1)));
        line("mseal(unaligned address)", ok(mseal(unsafe { p.add(PAGE + 1) }, PAGE, 0)));
        line("mseal(len 0)", ok(mseal(unsafe { p.add(PAGE) }, 0, 0)));
        line("mseal(unaligned len)", ok(mseal(unsafe { p.add(3 * PAGE) }, 100, 0)));
        line("mseal(len wraps)", ok(mseal(unsafe { p.add(PAGE) }, usize::MAX - PAGE + 1, 0)));
        // A range with a hole in it.
        let q = anon(3, 0);
        unmap(unsafe { q.add(PAGE) }, 1);
        line("mseal(a range with a hole)", ok(mseal(q, 3 * PAGE, 0)));
        line("  the first page was not sealed", ok(unsafe { libc::munmap(q.cast(), PAGE) } as i64));
        unmap(unsafe { q.add(2 * PAGE) }, 1);
        line("mseal(a range that is not mapped)", ok(mseal(q, PAGE, 0)));
    }

    println!("\n########## mseal: what a seal refuses ##########");
    {
        let p = anon(3, 0x22);
        // Seal the middle page; the neighbours stay free.
        let m = unsafe { p.add(PAGE) };
        line("mseal(middle page)", ok(mseal(m, PAGE, 0)));
        line("smaps VmFlags of the sealed page has sl",
            smaps_flags_of(m).is_some_and(|f| f.split(' ').any(|w| w == "sl")));
        line("smaps VmFlags of its neighbour has sl",
            smaps_flags_of(p).is_some_and(|f| f.split(' ').any(|w| w == "sl")));
        line("mprotect(sealed, R)", ok(unsafe { libc::mprotect(m.cast(), PAGE, libc::PROT_READ) } as i64));
        line("mprotect(sealed, RW), the same protection", ok(unsafe { libc::mprotect(m.cast(), PAGE, libc::PROT_READ | libc::PROT_WRITE) } as i64));
        line("mprotect(all three pages, R)", ok(unsafe { libc::mprotect(p.cast(), 3 * PAGE, libc::PROT_READ) } as i64));
        line("  the first page is still writable", touch_in_child(p, true));
        line("munmap(sealed)", ok(unsafe { libc::munmap(m.cast(), PAGE) } as i64));
        line("munmap(all three)", ok(unsafe { libc::munmap(p.cast(), 3 * PAGE) } as i64));
        line("  the first page is still mapped", touch_in_child(p, false));
        let v = unsafe { libc::mremap(m.cast(), PAGE, 2 * PAGE, libc::MREMAP_MAYMOVE) };
        line("mremap(sealed, grow, MAYMOVE)", if v == libc::MAP_FAILED { named(errno()) } else { "moved".into() });
        let v = unsafe { libc::mremap(m.cast(), PAGE, PAGE / 2, 0) };
        line("mremap(sealed, shrink)", if v == libc::MAP_FAILED { named(errno()) } else { "ok".into() });
        let dst = anon(1, 0);
        let v = unsafe { libc::mremap(dst.cast(), PAGE, PAGE, libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED, m) };
        line("mremap(another page onto the sealed one)", if v == libc::MAP_FAILED { named(errno()) } else { "ok".into() });
        let v = unsafe {
            libc::mmap(m.cast(), PAGE, libc::PROT_READ, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED, -1, 0)
        };
        line("mmap(MAP_FIXED over the sealed page)", if v == libc::MAP_FAILED { named(errno()) } else { "ok".into() });
        line("madvise(sealed RW anon, DONTNEED)", ok(madvise(m, PAGE, libc::MADV_DONTNEED)));
        line("  the sealed page now reads", unsafe { *m });
        line("madvise(sealed RW anon, FREE)", ok(madvise(m, PAGE, libc::MADV_FREE)));
        line("madvise(sealed, WILLNEED)", ok(madvise(m, PAGE, libc::MADV_WILLNEED)));
        line("  the sealed page is still writable", touch_in_child(m, true));
        line("in a child: munmap(sealed)", {
            let c = unsafe { libc::fork() };
            if c == 0 {
                let v = unsafe { libc::munmap(m.cast(), PAGE) };
                unsafe { libc::_exit(if v == 0 { 0 } else { errno() }) };
            }
            let mut st = 0;
            unsafe { libc::waitpid(c, &mut st, 0) };
            let e = libc::WEXITSTATUS(st);
            if e == 0 { "ok".to_string() } else { named(e) }
        });
        // Last: a child no longer inherits the page, so it has nothing to
        // unmap and the seal has nothing to refuse.
        line("madvise(sealed, DONTFORK)", ok(madvise(m, PAGE, libc::MADV_DONTFORK)));
        line("  a child touching it", touch_in_child(m, true));
        unmap(dst, 1);

        // Read-only anonymous: the discarding advice is refused there,
        // because discarding is a write to memory the seal says cannot change.
        let q = anon(1, 0x33);
        unsafe { libc::mprotect(q.cast(), PAGE, libc::PROT_READ) };
        line("mseal(read-only anon)", ok(mseal(q, PAGE, 0)));
        for (n, a) in [
            ("DONTNEED", libc::MADV_DONTNEED), ("FREE", libc::MADV_FREE),
            ("DONTNEED_LOCKED", MADV_DONTNEED_LOCKED), ("REMOVE", libc::MADV_REMOVE),
            ("WIPEONFORK", libc::MADV_WIPEONFORK), ("NORMAL", libc::MADV_NORMAL),
            ("COLD", libc::MADV_COLD), ("PAGEOUT", libc::MADV_PAGEOUT),
            ("GUARD_INSTALL", MADV_GUARD_INSTALL), ("POPULATE_READ", MADV_POPULATE_READ),
            ("DONTFORK", libc::MADV_DONTFORK), ("DOFORK", libc::MADV_DOFORK),
        ] {
            line(&format!("madvise(sealed RO anon, {n})"), ok(madvise(q, PAGE, a)));
        }
        line("  the read-only page still reads", unsafe { *q });
        // Shared and file mappings are not "anonymous" for this rule.
        let s = map(1, libc::PROT_READ, libc::MAP_SHARED | libc::MAP_ANONYMOUS);
        line("mseal(read-only shared anon)", ok(mseal(s, PAGE, 0)));
        line("madvise(sealed RO shared, DONTNEED)", ok(madvise(s, PAGE, libc::MADV_DONTNEED)));
    }

    println!("\n########## MADV_GUARD_INSTALL / REMOVE ##########");
    {
        let p = anon(3, 0x44);
        line("GUARD_INSTALL(middle page)", ok(madvise(unsafe { p.add(PAGE) }, PAGE, MADV_GUARD_INSTALL)));
        line("  read the guard page", touch_in_child(unsafe { p.add(PAGE) }, false));
        line("  write the guard page", touch_in_child(unsafe { p.add(PAGE) }, true));
        line("  read its neighbour", touch_in_child(p, false));
        line("  smaps VmFlags unchanged by a guard",
            smaps_flags_of(p) == smaps_flags_of(unsafe { p.add(2 * PAGE) }));
        line("  mincore", {
            let mut v = [9u8; 3];
            let x = unsafe { libc::mincore(p.cast(), 3 * PAGE, v.as_mut_ptr()) };
            format!("{} {:?}", ok(x as i64), v.map(|b| b & 1))
        });
        line("  MADV_POPULATE_READ over it", ok(madvise(p, 3 * PAGE, MADV_POPULATE_READ)));
        line("  process_vm_readv of it", {
            let mut b = [0u8; 8];
            let local = libc::iovec { iov_base: b.as_mut_ptr().cast(), iov_len: 8 };
            let remote = libc::iovec { iov_base: unsafe { p.add(PAGE) }.cast(), iov_len: 8 };
            r(unsafe { libc::process_vm_readv(libc::getpid(), &local, 1, &remote, 1, 0) } as i64)
        });
        line("GUARD_INSTALL again", ok(madvise(unsafe { p.add(PAGE) }, PAGE, MADV_GUARD_INSTALL)));
        line("GUARD_REMOVE", ok(madvise(unsafe { p.add(PAGE) }, PAGE, MADV_GUARD_REMOVE)));
        line("  read it after removal", touch_in_child(unsafe { p.add(PAGE) }, false));
        line("  it reads", unsafe { *p.add(PAGE) });
        line("  the neighbour kept its bytes", unsafe { *p });
        line("GUARD_REMOVE on a page with no guard", ok(madvise(p, PAGE, MADV_GUARD_REMOVE)));
        line("  the page kept its bytes", unsafe { *p });
        let s = map(1, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED | libc::MAP_ANONYMOUS);
        line("GUARD_INSTALL on shared anon", ok(madvise(s, PAGE, MADV_GUARD_INSTALL)));
        unmap(s, 1);
        let l = anon(1, 0);
        unsafe { libc::mlock(l.cast(), PAGE) };
        line("GUARD_INSTALL on locked memory", ok(madvise(l, PAGE, MADV_GUARD_INSTALL)));
        unmap(l, 1);
        // munmap and remap of a guarded range leaves no guard behind.
        let g = unsafe { p.add(PAGE) };
        madvise(g, PAGE, MADV_GUARD_INSTALL);
        let v = unsafe {
            libc::mmap(g.cast(), PAGE, libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED, -1, 0)
        };
        line("MAP_FIXED over a guard", if v == libc::MAP_FAILED { named(errno()) } else { "ok".into() });
        line("  the new page is touchable", touch_in_child(g, true));
        unmap(p, 3);
    }

    println!("\n########## MADV_POPULATE_* ##########");
    {
        let p = anon(2, 0);
        line("POPULATE_READ(RW anon)", ok(madvise(p, 2 * PAGE, MADV_POPULATE_READ)));
        line("POPULATE_WRITE(RW anon)", ok(madvise(p, 2 * PAGE, MADV_POPULATE_WRITE)));
        unsafe { libc::mprotect(p.cast(), PAGE, libc::PROT_READ) };
        line("POPULATE_READ(R anon)", ok(madvise(p, PAGE, MADV_POPULATE_READ)));
        line("POPULATE_WRITE(R anon)", ok(madvise(p, PAGE, MADV_POPULATE_WRITE)));
        unsafe { libc::mprotect(p.cast(), PAGE, libc::PROT_NONE) };
        line("POPULATE_READ(PROT_NONE)", ok(madvise(p, PAGE, MADV_POPULATE_READ)));
        line("POPULATE_WRITE(PROT_NONE)", ok(madvise(p, PAGE, MADV_POPULATE_WRITE)));
        unmap(p, 2);
        line("POPULATE_READ(unmapped)", ok(madvise(p, PAGE, MADV_POPULATE_READ)));
    }

    println!("\n########## MADV_DONTNEED_LOCKED, MADV_COLLAPSE ##########");
    {
        let p = anon(2, 0x55);
        unsafe { libc::mlock(p.cast(), 2 * PAGE) };
        line("DONTNEED(locked)", ok(madvise(p, PAGE, libc::MADV_DONTNEED)));
        line("  reads", unsafe { *p });
        line("DONTNEED_LOCKED(locked)", ok(madvise(p, PAGE, MADV_DONTNEED_LOCKED)));
        line("  reads", unsafe { *p });
        line("  the other page kept its bytes", unsafe { *p.add(PAGE) });
        unsafe { libc::munlock(p.cast(), 2 * PAGE) };
        line("DONTNEED_LOCKED(unlocked)", ok(madvise(unsafe { p.add(PAGE) }, PAGE, MADV_DONTNEED_LOCKED)));
        line("  reads", unsafe { *p.add(PAGE) });
        line("COLLAPSE(two 4K pages)", ok(madvise(p, 2 * PAGE, MADV_COLLAPSE)));
        unmap(p, 2);
    }

    println!("\n########## MAP_FIXED_NOREPLACE ##########");
    {
        let p = anon(2, 0);
        unmap(unsafe { p.add(PAGE) }, 1);
        let rw = libc::PROT_READ | libc::PROT_WRITE;
        let fl = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_FIXED_NOREPLACE;
        let v = unsafe { libc::mmap(p.add(PAGE).cast(), PAGE, rw, fl, -1, 0) };
        line("NOREPLACE into a hole", if v == libc::MAP_FAILED { named(errno()) } else { format!("at the hint: {}", v == unsafe { p.add(PAGE) }.cast()) });
        let v = unsafe { libc::mmap(p.cast(), PAGE, rw, fl, -1, 0) };
        line("NOREPLACE over a mapping", if v == libc::MAP_FAILED { named(errno()) } else { "mapped".into() });
        line("  the old mapping kept its bytes", unsafe { *p });
        let v = unsafe { libc::mmap(p.add(1).cast(), PAGE, rw, fl, -1, 0) };
        line("NOREPLACE at an unaligned hint", if v == libc::MAP_FAILED { named(errno()) } else { "mapped".into() });
        unmap(p, 2);
    }

    println!("\n########## MREMAP_DONTUNMAP ##########");
    {
        let p = anon(2, 0x66);
        let v = unsafe { libc::mremap(p.cast(), 2 * PAGE, 2 * PAGE, libc::MREMAP_MAYMOVE | MREMAP_DONTUNMAP) };
        let ok_ = v != libc::MAP_FAILED;
        line("DONTUNMAP(private anon)", if ok_ { "moved".into() } else { named(errno()) });
        if ok_ {
            let n = v.cast::<u8>();
            line("  the new address has the bytes", unsafe { *n.add(PAGE) });
            line("  the old address is still mapped", touch_in_child(p, false));
            line("  and reads", unsafe { *p });
            line("  a write there", touch_in_child(p, true));
            unmap(n, 2);
        }
        line("DONTUNMAP, old != new size",
            { let v = unsafe { libc::mremap(p.cast(), 2 * PAGE, 3 * PAGE, libc::MREMAP_MAYMOVE | MREMAP_DONTUNMAP) };
              if v == libc::MAP_FAILED { named(errno()) } else { unmap(v.cast(), 3); "moved".into() } });
        let s = map(1, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED | libc::MAP_ANONYMOUS);
        let v = unsafe { libc::mremap(s.cast(), PAGE, PAGE, libc::MREMAP_MAYMOVE | MREMAP_DONTUNMAP) };
        line("DONTUNMAP(shared anon)", if v == libc::MAP_FAILED { named(errno()) } else { unmap(v.cast(), 1); "moved".into() });
        let dst = anon(2, 0);
        let v = unsafe {
            libc::mremap(p.cast(), 2 * PAGE, 2 * PAGE, libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED | MREMAP_DONTUNMAP, dst)
        };
        line("DONTUNMAP|FIXED onto another mapping", if v == libc::MAP_FAILED { named(errno()) } else { format!("at dst: {}", v == dst.cast()) });
        unmap(p, 2);
        unmap(dst, 2);
        unmap(s, 1);
    }

    println!("\n########## process_madvise ##########");
    {
        let me = pidfd_open(unsafe { libc::getpid() });
        let p = anon(4, 0x77);
        let iov = [
            libc::iovec { iov_base: p.cast(), iov_len: PAGE },
            libc::iovec { iov_base: unsafe { p.add(2 * PAGE) }.cast(), iov_len: 2 * PAGE },
        ];
        for (n, a) in [
            ("COLD", libc::MADV_COLD), ("PAGEOUT", libc::MADV_PAGEOUT), ("WILLNEED", libc::MADV_WILLNEED),
            ("COLLAPSE", MADV_COLLAPSE), ("DONTNEED", libc::MADV_DONTNEED), ("NORMAL", libc::MADV_NORMAL),
            ("FREE", libc::MADV_FREE), ("999", 999),
        ] {
            line(&format!("process_madvise(self, 2 iovecs, {n})"), r(process_madvise(me, &iov, a, 0)));
        }
        line("  after DONTNEED, the first page reads", unsafe { *p });
        line("  and the second, not named", unsafe { *p.add(PAGE) });
        line("process_madvise(self, flags 1)", r(process_madvise(me, &iov, libc::MADV_COLD, 1)));
        line("process_madvise(self, no iovecs)", r(process_madvise(me, &[], libc::MADV_COLD, 0)));
        line("process_madvise(PIDFD_SELF_THREAD_GROUP)", r(process_madvise(-10001, &iov, libc::MADV_COLD, 0)));
        line("process_madvise(PIDFD_SELF_THREAD)", r(process_madvise(-10000, &iov, libc::MADV_COLD, 0)));
        let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        line("process_madvise(/dev/null)", r(process_madvise(null, &iov, libc::MADV_COLD, 0)));
        line("process_madvise(-1)", r(process_madvise(-1, &iov, libc::MADV_COLD, 0)));
        line("process_madvise(self, vlen 1025)",
            r(unsafe { libc::syscall(440, me, iov.as_ptr(), 1025usize, libc::MADV_COLD, 0) }));
        line("process_madvise(self, unreadable iovec)",
            r(unsafe { libc::syscall(440, me, 8usize, 1usize, libc::MADV_COLD, 0) }));
        let bad = [libc::iovec { iov_base: unsafe { p.add(1) }.cast(), iov_len: PAGE }];
        line("process_madvise(self, unaligned base)", r(process_madvise(me, &bad, libc::MADV_COLD, 0)));
        unmap(unsafe { p.add(PAGE) }, 1);
        let hole = [libc::iovec { iov_base: p.cast(), iov_len: 3 * PAGE }];
        line("process_madvise(self, a range with a hole)", r(process_madvise(me, &hole, libc::MADV_COLD, 0)));
        // A child's memory, by address.
        let mut fds = [0; 2];
        unsafe { libc::pipe(fds.as_mut_ptr()) };
        let (rp, wp) = (fds[0], fds[1]);
        let c = unsafe { libc::fork() };
        if c == 0 {
            unsafe {
                libc::close(wp);
                let mut b = 0u8;
                libc::read(rp, (&raw mut b).cast(), 1);
                libc::_exit(0);
            }
        }
        unsafe { libc::close(rp) };
        let cfd = pidfd_open(c);
        let civ = [libc::iovec { iov_base: p.cast(), iov_len: PAGE }];
        line("process_madvise(child, COLD)", r(process_madvise(cfd, &civ, libc::MADV_COLD, 0)));
        line("process_madvise(child, WILLNEED)", r(process_madvise(cfd, &civ, libc::MADV_WILLNEED, 0)));
        line("process_madvise(child, DONTNEED)", r(process_madvise(cfd, &civ, libc::MADV_DONTNEED, 0)));
        line("process_mrelease(live child)", r(unsafe { libc::syscall(448, cfd, 0) }));
        line("process_mrelease(child, flags 1)", r(unsafe { libc::syscall(448, cfd, 1) }));
        unsafe { libc::kill(c, libc::SIGKILL) };
        let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
        unsafe { libc::waitid(libc::P_PID, c as u32, &mut si, libc::WEXITED | libc::WNOWAIT) };
        line("process_mrelease(killed child, a zombie)", r(unsafe { libc::syscall(448, cfd, 0) }));
        line("process_madvise(zombie child, COLD)", r(process_madvise(cfd, &civ, libc::MADV_COLD, 0)));
        let mut st = 0;
        unsafe { libc::waitpid(c, &mut st, 0) };
        line("process_mrelease(reaped child)", r(unsafe { libc::syscall(448, cfd, 0) }));
        line("process_madvise(reaped child, COLD)", r(process_madvise(cfd, &civ, libc::MADV_COLD, 0)));
        line("process_mrelease(/dev/null)", r(unsafe { libc::syscall(448, null, 0) }));
        line("process_mrelease(-1)", r(unsafe { libc::syscall(448, -1, 0) }));
        line("process_mrelease(self)", r(unsafe { libc::syscall(448, me, 0) }));
        unsafe { libc::close(wp) };
        unsafe { libc::close(cfd) };
        unsafe { libc::close(null) };
        unsafe { libc::close(me) };
    }

    println!("\n########## protection keys ##########");
    {
        let p = anon(1, 0);
        line("pkey_alloc(0, 0)", r(unsafe { libc::syscall(289, 0, 0) }));
        line("pkey_alloc(1, 0)", r(unsafe { libc::syscall(289, 1, 0) }));
        line("pkey_alloc(0, 1)", r(unsafe { libc::syscall(289, 0, 1) }));
        line("pkey_free(0)", r(unsafe { libc::syscall(290, 0) }));
        line("pkey_free(1)", r(unsafe { libc::syscall(290, 1) }));
        line("pkey_free(-1)", r(unsafe { libc::syscall(290, -1) }));
        line("pkey_mprotect(R, -1)", r(unsafe { libc::syscall(288, p, PAGE, libc::PROT_READ, -1) }));
        line("  a write after it", touch_in_child(p, true));
        line("pkey_mprotect(RW, 0)", r(unsafe { libc::syscall(288, p, PAGE, libc::PROT_READ | libc::PROT_WRITE, 0) }));
        line("pkey_mprotect(RW, 1)", r(unsafe { libc::syscall(288, p, PAGE, libc::PROT_READ | libc::PROT_WRITE, 1) }));
        line("pkey_mprotect(RW, -2)", r(unsafe { libc::syscall(288, p, PAGE, libc::PROT_READ | libc::PROT_WRITE, -2) }));
        line("pkey_mprotect(unaligned, -1)", r(unsafe { libc::syscall(288, p.add(1), PAGE, libc::PROT_READ, -1) }));
        line("pkey_mprotect(prot 0x100, -1)", r(unsafe { libc::syscall(288, p, PAGE, 0x100, -1) }));
        unmap(p, 1);
    }

    println!("\n########## map_shadow_stack ##########");
    for (n, addr, size, flags) in [
        ("(0, 1 page, 0)", 0usize, PAGE, 0u32),
        ("(0, 1 page, SHADOW_STACK_SET_TOKEN)", 0, PAGE, 1),
        ("(0, 0, 0)", 0, 0, 0),
        ("(0, 1 page, 0x100)", 0, PAGE, 0x100),
        ("(unaligned, 1 page, 0)", 1, PAGE, 0),
    ] {
        let v = unsafe { libc::syscall(453, addr, size, flags) };
        line(&format!("map_shadow_stack{n}"), if v < 0 { named(errno()) } else { "mapped".into() });
    }

    println!("\n########## the NUMA policy calls ##########");
    {
        let mut mode: i32 = -1;
        let mut mask: [u64; 2] = [0; 2];
        let g = |mode: &mut i32, mask: &mut [u64; 2], addr: usize, flags: u64| unsafe {
            libc::syscall(236, mode as *mut i32, mask.as_mut_ptr(), 128usize, addr, flags)
        };
        line("get_mempolicy()", format!("{}, mode {mode}", ok(g(&mut mode, &mut mask, 0, 0))));
        let v = g(&mut mode, &mut mask, 0, 0);
        line("  mode, nodemask", format!("{} {mode} {:#x}", ok(v), mask[0]));
        let v = g(&mut mode, &mut mask, 0, 4);
        line("get_mempolicy(MPOL_F_MEMS_ALLOWED)", format!("{} {:#x}", ok(v), mask[0]));
        let p = anon(1, 0);
        let v = g(&mut mode, &mut mask, p as usize, 3);
        line("get_mempolicy(MPOL_F_NODE|MPOL_F_ADDR)", format!("{} node {mode}", ok(v)));
        let v = g(&mut mode, &mut mask, p as usize, 2);
        line("get_mempolicy(MPOL_F_ADDR)", format!("{} mode {mode}", ok(v)));
        let v = g(&mut mode, &mut mask, 0, 2);
        line("get_mempolicy(MPOL_F_ADDR, NULL)", ok(v));
        let v = g(&mut mode, &mut mask, 0, 0x100);
        line("get_mempolicy(flags 0x100)", ok(v));
        let v = unsafe { libc::syscall(236, &mut mode, mask.as_mut_ptr(), 1usize, 0, 0) };
        line("get_mempolicy(maxnode 1)", ok(v));
        let one: [u64; 2] = [1, 0];
        let s = |m: i32, mask: *const u64, max: usize| unsafe { libc::syscall(237, m, mask, max) };
        line("set_mempolicy(MPOL_DEFAULT, NULL)", ok(s(0, std::ptr::null(), 0)));
        line("set_mempolicy(MPOL_BIND, {0})", ok(s(2, one.as_ptr(), 128)));
        let v = g(&mut mode, &mut mask, 0, 0);
        line("  get_mempolicy after", format!("{} {mode} {:#x}", ok(v), mask[0]));
        line("set_mempolicy(MPOL_PREFERRED, {0})", ok(s(1, one.as_ptr(), 128)));
        line("set_mempolicy(MPOL_INTERLEAVE, {0})", ok(s(3, one.as_ptr(), 128)));
        line("set_mempolicy(MPOL_LOCAL)", ok(s(4, std::ptr::null(), 0)));
        line("set_mempolicy(MPOL_PREFERRED_MANY, {0})", ok(s(5, one.as_ptr(), 128)));
        line("set_mempolicy(MPOL_WEIGHTED_INTERLEAVE, {0})", ok(s(6, one.as_ptr(), 128)));
        line("set_mempolicy(7)", ok(s(7, one.as_ptr(), 128)));
        let two: [u64; 2] = [2, 0];
        line("set_mempolicy(MPOL_BIND, {1}), no such node", ok(s(2, two.as_ptr(), 128)));
        line("set_mempolicy(MPOL_BIND, {})", ok(s(2, mask.as_ptr().cast::<u64>().wrapping_add(1).cast(), 64)));
        line("set_mempolicy(MPOL_DEFAULT, {0})", ok(s(0, one.as_ptr(), 128)));
        line("set_mempolicy(MPOL_F_STATIC_NODES|MPOL_BIND)", ok(s(2 | (1 << 15), one.as_ptr(), 128)));
        line("set_mempolicy(MPOL_DEFAULT)", ok(s(0, std::ptr::null(), 0)));
        line("set_mempolicy_home_node(1 page, node 0)", ok(unsafe { libc::syscall(450, p, PAGE, 0, 0) }));
        line("set_mempolicy_home_node(flags 1)", ok(unsafe { libc::syscall(450, p, PAGE, 0, 1) }));
        line("set_mempolicy_home_node(node 1)", ok(unsafe { libc::syscall(450, p, PAGE, 1, 0) }));
        // mbind(MPOL_BIND) first, which is the policy a home node applies to.
        let v = unsafe { libc::syscall(235, p, PAGE, 2, one.as_ptr(), 128usize, 0) };
        line("mbind(MPOL_BIND, {0})", ok(v));
        line("set_mempolicy_home_node after mbind", ok(unsafe { libc::syscall(450, p, PAGE, 0, 0) }));
        line("set_mempolicy_home_node(unmapped)", ok(unsafe { libc::syscall(450, 0x1000usize, PAGE, 0, 0) }));
        line("migrate_pages(self, {0} -> {0})", r(unsafe { libc::syscall(238, 0, 128usize, one.as_ptr(), one.as_ptr()) }));
        line("migrate_pages(999999)", r(unsafe { libc::syscall(238, 999_999, 128usize, one.as_ptr(), one.as_ptr()) }));
        let pages = [p as usize];
        let mut status = [-99i32; 1];
        let v = unsafe { libc::syscall(239, 0, 1usize, pages.as_ptr(), std::ptr::null::<i32>(), status.as_mut_ptr(), 0) };
        line("move_pages(self, query)", format!("{} status {}", ok(v), status[0]));
        let nodes = [0i32];
        let v = unsafe { libc::syscall(239, 0, 1usize, pages.as_ptr(), nodes.as_ptr(), status.as_mut_ptr(), 2) };
        line("move_pages(self, to node 0, MPOL_MF_MOVE)", format!("{} status {}", ok(v), status[0]));
        let nodes = [1i32];
        let v = unsafe { libc::syscall(239, 0, 1usize, pages.as_ptr(), nodes.as_ptr(), status.as_mut_ptr(), 2) };
        line("move_pages(self, to node 1)", ok(v));
        let v = unsafe { libc::syscall(239, 0, 1usize, pages.as_ptr(), std::ptr::null::<i32>(), status.as_mut_ptr(), 0x10) };
        line("move_pages(flags 0x10)", ok(v));
        let unm = [0x1000usize];
        let v = unsafe { libc::syscall(239, 0, 1usize, unm.as_ptr(), std::ptr::null::<i32>(), status.as_mut_ptr(), 0) };
        line("move_pages(an unmapped page)", format!("{} status {}", ok(v), named(-status[0])));
        unmap(p, 1);
    }

    println!("\n########## memfd_secret ##########");
    {
        let v = unsafe { libc::syscall(447, 0) };
        line("memfd_secret(0)", if v < 0 { named(errno()) } else { "a descriptor".into() });
        if v >= 0 {
            unsafe { libc::close(v as i32) };
        }
        line("memfd_secret(O_CLOEXEC)", {
            let v = unsafe { libc::syscall(447, libc::O_CLOEXEC) };
            if v >= 0 { unsafe { libc::close(v as i32) }; "a descriptor".into() } else { named(errno()) }
        });
        line("memfd_secret(1)", r(unsafe { libc::syscall(447, 1) }));
        // What the descriptor is, when there is one.
        let fd = unsafe { libc::syscall(447, 0) } as i32;
        if fd >= 0 {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            unsafe { libc::fstat(fd, &mut st) };
            line("memfd_secret: st_mode, st_size", format!("{:o} {}", st.st_mode, st.st_size));
            let mut buf = [0u8; 64];
            let n = unsafe { libc::readlink(format!("/proc/self/fd/{fd}\0").as_ptr().cast(), buf.as_mut_ptr().cast(), 64) };
            line("memfd_secret: readlink", if n < 0 { named(errno()) } else { String::from_utf8_lossy(&buf[..n as usize]).into_owned() });
            line("memfd_secret: FD_CLOEXEC without the flag", unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC);
            line("memfd_secret: ftruncate(4096)", ok(unsafe { libc::ftruncate(fd, 4096) } as i64));
            let rw = libc::PROT_READ | libc::PROT_WRITE;
            let v = unsafe { libc::mmap(std::ptr::null_mut(), PAGE, rw, libc::MAP_PRIVATE, fd, 0) };
            line("memfd_secret: mmap(MAP_PRIVATE)", if v == libc::MAP_FAILED { named(errno()) } else { "mapped".into() });
            let v = unsafe { libc::mmap(std::ptr::null_mut(), PAGE, rw, libc::MAP_SHARED, fd, 0) };
            line("memfd_secret: mmap(MAP_SHARED)", if v == libc::MAP_FAILED { named(errno()) } else { "mapped".into() });
            if v != libc::MAP_FAILED {
                let m = v.cast::<u8>();
                unsafe { *m = 0x5a };
                line("memfd_secret: a store and a load", unsafe { *m });
                line("memfd_secret: a child reads it", {
                    let c = unsafe { libc::fork() };
                    if c == 0 { unsafe { libc::_exit(i32::from(*m)) } }
                    let mut st = 0;
                    unsafe { libc::waitpid(c, &mut st, 0) };
                    if libc::WIFEXITED(st) { libc::WEXITSTATUS(st).to_string() } else { format!("signal {}", libc::WTERMSIG(st)) }
                });
                line("memfd_secret: process_vm_readv of it", {
                    let mut b = [0u8; 1];
                    let local = libc::iovec { iov_base: b.as_mut_ptr().cast(), iov_len: 1 };
                    let remote = libc::iovec { iov_base: v, iov_len: 1 };
                    r(unsafe { libc::process_vm_readv(libc::getpid(), &local, 1, &remote, 1, 0) } as i64)
                });
                line("memfd_secret: write(1) from it", r(unsafe { libc::write(1, v, 0) } as i64));
                let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY) };
                line("memfd_secret: write(/dev/null) from it", r(unsafe { libc::write(null, v, 1) } as i64));
                unsafe { libc::close(null) };
                let mut vec = [9u8; 1];
                line("memfd_secret: mincore", format!("{} {}", ok(unsafe { libc::mincore(v, PAGE, vec.as_mut_ptr()) } as i64), vec[0] & 1));
                line("memfd_secret: smaps VmFlags has lo", smaps_flags_of(m).is_some_and(|f| f.split(' ').any(|w| w == "lo")));
                line("memfd_secret: MADV_DONTNEED", ok(madvise(m, PAGE, libc::MADV_DONTNEED)));
                line("memfd_secret: reads after it", unsafe { *m });
                unsafe { libc::munmap(v, PAGE) };
            }
            let mut b = [0u8; 4];
            line("memfd_secret: read(fd)", r(unsafe { libc::read(fd, b.as_mut_ptr().cast(), 4) } as i64));
            line("memfd_secret: write(fd)", r(unsafe { libc::write(fd, b.as_ptr().cast(), 4) } as i64));
            line("memfd_secret: pread(fd)", r(unsafe { libc::pread(fd, b.as_mut_ptr().cast(), 4, 0) } as i64));
            line("memfd_secret: lseek(fd, 0, SEEK_END)", r(unsafe { libc::lseek(fd, 0, libc::SEEK_END) }));
            line("memfd_secret: fallocate", ok(unsafe { libc::fallocate(fd, 0, 0, 8192) } as i64));
            line("memfd_secret: F_ADD_SEALS", ok(unsafe { libc::fcntl(fd, 1033, 1) } as i64));
            line("memfd_secret: ftruncate(8192), growing", ok(unsafe { libc::ftruncate(fd, 8192) } as i64));
            line("memfd_secret: fstat st_size after", { let mut st: libc::stat = unsafe { std::mem::zeroed() }; unsafe { libc::fstat(fd, &mut st) }; st.st_size });
            line("memfd_secret: mmap(MAP_SHARED, PROT_EXEC)", {
                let v = unsafe { libc::mmap(std::ptr::null_mut(), PAGE, libc::PROT_READ | libc::PROT_EXEC, libc::MAP_SHARED, fd, 0) };
                if v == libc::MAP_FAILED { named(errno()) } else { "mapped".into() }
            });
            let e = unsafe { libc::syscall(447, 0) } as i32;
            let v = unsafe { libc::mmap(std::ptr::null_mut(), PAGE, rw, libc::MAP_SHARED, e, 0) };
            line("memfd_secret: mmap of an empty one", if v == libc::MAP_FAILED { named(errno()) } else { "mapped".into() });
            if v != libc::MAP_FAILED {
                line("memfd_secret: touching it", {
                    let c = unsafe { libc::fork() };
                    if c == 0 { unsafe { libc::_exit(i32::from(*v.cast::<u8>())) } }
                    let mut st = 0;
                    unsafe { libc::waitpid(c, &mut st, 0) };
                    if libc::WIFSIGNALED(st) { format!("signal {}", libc::WTERMSIG(st)) } else { "survived".into() }
                });
            }
            unsafe { libc::close(fd) };
        } else {
            // The same lines, so both sides print as many: a kernel without
            // it answers each with the errno the call itself gave.
            let e = named(errno());
            for l in ["st_mode, st_size", "readlink", "FD_CLOEXEC without the flag", "ftruncate(4096)", "mmap(MAP_PRIVATE)", "mmap(MAP_SHARED)", "a store and a load", "a child reads it", "process_vm_readv of it", "write(1) from it", "write(/dev/null) from it", "mincore", "smaps VmFlags has lo", "MADV_DONTNEED", "reads after it", "read(fd)", "write(fd)", "pread(fd)", "lseek(fd, 0, SEEK_END)", "fallocate", "F_ADD_SEALS", "ftruncate(8192), growing", "fstat st_size after", "mmap(MAP_SHARED, PROT_EXEC)", "mmap of an empty one", "touching it"] {
                line(&format!("memfd_secret: {l}"), &e);
            }
        }
    }
}
