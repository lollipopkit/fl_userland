//! What the memory syscalls do, as opposed to what they accept.
//!
//! **A report, not a check** — the eighth in the shape `mmap_probe` established.
//! One line per case, never fails, diffed against an arm64 container by
//! `tests/integration/probe_diff.sh`.
//!
//! `mmap_probe` covers `mmap`, `munmap` and `mprotect`'s argument edges. This
//! covers the other eleven memory calls in the syscall table — `brk`,
//! `mremap`, `madvise`, `msync`, the five locking calls and `mincore` — and it
//! asks a different kind of question about them.
//!
//! **Whether a call was accepted is the weaker half.** A memory call that
//! returns 0 and does nothing is the failure mode that costs a program
//! correctness rather than an errno: `MADV_DONTNEED` on anonymous memory is
//! specified to make the next read see zeroes, and every allocator in existence
//! frees memory that way. `mincore` was found in 2026-08-22 answering "mapped"
//! for every address, which is a report a caller cannot tell from a real one.
//! So every case here that can be checked by *looking at the memory afterwards*
//! is, and the value it reports is the finding.

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn name(e: i32) -> String {
    let s = match e {
        libc::EINVAL => "EINVAL",
        libc::ENOMEM => "ENOMEM",
        libc::EFAULT => "EFAULT",
        libc::EAGAIN => "EAGAIN",
        libc::EPERM => "EPERM",
        libc::EACCES => "EACCES",
        libc::EBADF => "EBADF",
        libc::ENOSYS => "ENOSYS",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        libc::EEXIST => "EEXIST",
        libc::ENODEV => "ENODEV",
        _ => return format!("errno {e}"),
    };
    s.into()
}

fn report(what: &str, r: i64) {
    if r < 0 {
        println!("{what:<54} -> {}", name(errno()));
    } else {
        println!("{what:<54} -> ok");
    }
}

fn value(what: &str, v: i64) {
    println!("{what:<54} -> {v}");
}

const PAGE: usize = 4096;

/// An anonymous read-write mapping of `pages`, filled with `fill`.
fn anon(pages: usize, fill: u8) -> *mut u8 {
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            pages * PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert!(p != libc::MAP_FAILED, "mmap failed");
    let p = p as *mut u8;
    unsafe { std::ptr::write_bytes(p, fill, pages * PAGE) };
    p
}

fn unmap(p: *mut u8, pages: usize) {
    unsafe { libc::munmap(p as *mut libc::c_void, pages * PAGE) };
}

const MADV_NORMAL: i32 = 0;
const MADV_RANDOM: i32 = 1;
const MADV_SEQUENTIAL: i32 = 2;
const MADV_WILLNEED: i32 = 3;
const MADV_DONTNEED: i32 = 4;
const MADV_FREE: i32 = 8;
const MADV_DONTFORK: i32 = 10;
const MADV_DOFORK: i32 = 11;
const MADV_WIPEONFORK: i32 = 18;

const MS_ASYNC: i32 = 1;
const MS_INVALIDATE: i32 = 2;
const MS_SYNC: i32 = 4;

const MREMAP_MAYMOVE: i32 = 1;
const MREMAP_FIXED: i32 = 2;
const MREMAP_DONTUNMAP: i32 = 4;

const MCL_CURRENT: i32 = 1;
const MCL_FUTURE: i32 = 2;
const MCL_ONFAULT: i32 = 4;

fn main() {
    println!("## brk");
    {
        // brk reports the *current* break on failure rather than -1, so a
        // caller cannot tell "I moved it" from "I did not" by sign alone --
        // it compares the answer with what it asked for. Every case here is
        // therefore reported as a relationship, not as an address, which
        // would differ between the two kernels for uninteresting reasons.
        let start = unsafe { libc::syscall(libc::SYS_brk, 0usize) };
        value("brk(0) returned something", (start > 0) as i64);
        let grown = unsafe { libc::syscall(libc::SYS_brk, (start + 4096) as usize) };
        value("brk(current + 4096) moved it", (grown == start + 4096) as i64);
        // Writing there is the check on the answer: a break that moved but
        // mapped nothing is the silent version of this failing.
        if grown == start + 4096 {
            unsafe { std::ptr::write_bytes(start as *mut u8, 0xab, 4096) };
            value("  and the new page is writable", unsafe {
                *(start as *const u8) as i64
            });
        }
        let shrunk = unsafe { libc::syscall(libc::SYS_brk, start as usize) };
        value("brk(back to the start) moved it back", (shrunk == start) as i64);
        let low = unsafe { libc::syscall(libc::SYS_brk, 1usize) };
        value("brk(1) left it alone", (low == start) as i64);
        let huge = unsafe { libc::syscall(libc::SYS_brk, usize::MAX) };
        value("brk(~0) left it alone", (huge == start) as i64);
    }

    println!("## mremap");
    {
        let p = anon(2, 0x11);
        // Shrinking never needs to move.
        let r = unsafe { libc::mremap(p as *mut libc::c_void, 2 * PAGE, PAGE, 0) };
        value("mremap(2 pages -> 1, no flags) stayed put", (r == p as *mut libc::c_void) as i64);
        if r != libc::MAP_FAILED {
            value("  the first byte survived", unsafe { *(r as *const u8) as i64 });
            unsafe { libc::munmap(r, PAGE) };
        }
    }
    {
        // Growing without MAYMOVE needs the pages after the mapping to be
        // free, so both answers are asked for deterministically: two pages
        // with the second unmapped first, and two pages with it still there.
        // The first version mapped one page and asked whether it *happened*
        // to have room after it, which reports the allocator and not mremap:
        // Linux places mappings top-down, so the previous one is usually
        // right above, and this kernel's hole search leaves a gap.
        let p = anon(2, 0x22);
        unmap(unsafe { p.add(PAGE) }, 1);
        let r = unsafe { libc::mremap(p as *mut libc::c_void, PAGE, 2 * PAGE, 0) };
        value("mremap(grow without MAYMOVE into a hole) succeeded", (r != libc::MAP_FAILED) as i64);
        if r != libc::MAP_FAILED {
            unsafe { libc::munmap(r, 2 * PAGE) };
        } else {
            unmap(p, 1);
        }

        let p = anon(2, 0x22);
        report("mremap(grow without MAYMOVE into its own next page)", unsafe {
            let r = libc::mremap(p as *mut libc::c_void, PAGE, 2 * PAGE, 0);
            if r == libc::MAP_FAILED { -1 } else { 0 }
        });
        unmap(p, 2);
    }
    {
        let p = anon(1, 0x33);
        let r = unsafe {
            libc::mremap(p as *mut libc::c_void, PAGE, 4 * PAGE, MREMAP_MAYMOVE)
        };
        // Both follow-ups are printed either way. A case that prints fewer
        // lines when it fails makes the two sides disagree about how many
        // lines they have, which probe_diff.sh reports as "one of them died
        // early" -- and hides the difference that caused it.
        let ok = r != libc::MAP_FAILED;
        value("mremap(grow with MAYMOVE) succeeded", ok as i64);
        value("  the contents came with it", if ok {
            unsafe { *(r as *const u8) as i64 }
        } else { -1 });
        // The pages past the old end are new, and must be zero.
        value("  the new pages are zero", if ok {
            unsafe { *((r as *const u8).add(PAGE)) as i64 }
        } else { -1 });
        if ok {
            unsafe { libc::munmap(r, 4 * PAGE) };
        } else {
            unmap(p, 1);
        }
    }
    {
        let p = anon(1, 0x44);
        report("mremap(new_size=0)", unsafe {
            libc::mremap(p as *mut libc::c_void, PAGE, 0, MREMAP_MAYMOVE) as i64
                - libc::MAP_FAILED as i64
        });
        let q = anon(1, 0x55);
        report("mremap(unaligned old address)", unsafe {
            let r = libc::mremap((q as usize + 1) as *mut libc::c_void, PAGE, 2 * PAGE, MREMAP_MAYMOVE);
            if r == libc::MAP_FAILED { -1 } else { 0 }
        });
        report("mremap(an address that is not mapped)", unsafe {
            let r = libc::mremap(0x1000 as *mut libc::c_void, PAGE, 2 * PAGE, MREMAP_MAYMOVE);
            if r == libc::MAP_FAILED { -1 } else { 0 }
        });
        report("mremap(MREMAP_FIXED without MAYMOVE)", unsafe {
            let r = libc::mremap(q as *mut libc::c_void, PAGE, PAGE, MREMAP_FIXED);
            if r == libc::MAP_FAILED { -1 } else { 0 }
        });
        report("mremap(an undefined flag 0x100)", unsafe {
            let r = libc::mremap(q as *mut libc::c_void, PAGE, 2 * PAGE, 0x100);
            if r == libc::MAP_FAILED { -1 } else { 0 }
        });
        report("mremap(MREMAP_DONTUNMAP without MAYMOVE)", unsafe {
            let r = libc::mremap(q as *mut libc::c_void, PAGE, PAGE, MREMAP_DONTUNMAP);
            if r == libc::MAP_FAILED { -1 } else { 0 }
        });
        unmap(p, 1);
        unmap(q, 1);
    }
    {
        // old_size == 0 with MAYMOVE duplicates a shared mapping; for a
        // private one it is EINVAL.
        let p = anon(2, 0x66);
        report("mremap(old_size=0 on a private mapping)", unsafe {
            let r = libc::mremap(p as *mut libc::c_void, 0, PAGE, MREMAP_MAYMOVE);
            if r == libc::MAP_FAILED { -1 } else { 0 }
        });
        unmap(p, 2);
    }

    println!("## mremap of a file-backed mapping");
    // apt's DynamicMMap, step for step: the package cache is a file mapped
    // shared, grown by writing one byte past its end, and the mapping grown
    // over it with mremap. The pages past the old end are **the file's next
    // pages** -- the vma keeps its file and its offset runs on -- and that is
    // what apt writes its cache through. A kernel that puts anonymous pages
    // there answers success and loses the data; one that refuses makes apt
    // print "Dynamic MMap ran out of room" at its first growth, which is what
    // `apt-get update` did here on 2026-09-04. Both the shared and the private
    // form, because the two differ in what a write does and agree on what a
    // read sees.
    for (shared, label) in [(true, "MAP_SHARED"), (false, "MAP_PRIVATE")] {
        let path = if shared {
            c"/tmp/mem_probe_mremap_shared"
        } else {
            c"/tmp/mem_probe_mremap_private"
        };
        let fd = unsafe {
            libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644)
        };
        assert!(fd >= 0, "open: {}", errno());
        // Four pages of 0xaa, then a fifth page the file has and the mapping
        // does not, holding 0xcc.
        let fill = vec![0xaau8; 4 * PAGE];
        unsafe { libc::pwrite(fd, fill.as_ptr().cast(), fill.len(), 0) };
        let tail = vec![0xccu8; PAGE];
        unsafe { libc::pwrite(fd, tail.as_ptr().cast(), tail.len(), (4 * PAGE) as i64) };
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4 * PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                if shared { libc::MAP_SHARED } else { libc::MAP_PRIVATE },
                fd,
                0,
            )
        };
        assert!(base != libc::MAP_FAILED, "mmap: {}", errno());
        let r = unsafe { libc::mremap(base, 4 * PAGE, 5 * PAGE, MREMAP_MAYMOVE) };
        let ok = r != libc::MAP_FAILED;
        report(
            &format!("mremap(grow a {label} file mapping by a page)"),
            if ok { 0 } else { -1 },
        );
        let r = r as *mut u8;
        value("  the first byte came with it", if ok { unsafe { *r as i64 } } else { -1 });
        // The grown page is the file's fifth page, so it reads 0xcc and not
        // zero: anonymous memory there is the wrong answer even before
        // anything is written.
        value("  the grown page reads the file's byte", if ok {
            unsafe { *r.add(4 * PAGE) as i64 }
        } else {
            -1
        });
        // A write through it reaches the file for a shared mapping and does
        // not for a private one.
        let mut back = 0u8;
        if ok {
            unsafe {
                *r.add(4 * PAGE) = 0xbb;
                libc::msync(r.add(4 * PAGE).cast(), PAGE, MS_SYNC);
                libc::pread(fd, (&raw mut back).cast(), 1, (4 * PAGE) as i64);
            }
        }
        value("  a write to the grown page reached the file", if ok { back as i64 } else { -1 });
        if ok {
            unsafe { libc::munmap(r.cast(), 5 * PAGE) };
        } else {
            unsafe { libc::munmap(base, 4 * PAGE) };
        }
        unsafe {
            libc::close(fd);
            libc::unlink(path.as_ptr());
        }
    }
    {
        // And at apt's size: APT::Cache-Start is 24 MB and APT::Cache-Grow is
        // 1 MB, with the mapping shared and something mapped after it so
        // that growing in place is not an option.
        let path = c"/tmp/mem_probe_mremap_apt";
        let fd = unsafe {
            libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644)
        };
        assert!(fd >= 0, "open: {}", errno());
        let start = 24 * 1024 * 1024;
        let grow = 1024 * 1024;
        unsafe { libc::ftruncate(fd, start as i64) };
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                start,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        assert!(base != libc::MAP_FAILED, "mmap: {}", errno());
        let after = anon(1, 0);
        // apt grows the file by seeking to the new end and writing one byte.
        let zero = 0u8;
        unsafe { libc::pwrite(fd, (&raw const zero).cast(), 1, (start + grow - 1) as i64) };
        let r = unsafe { libc::mremap(base, start, start + grow, MREMAP_MAYMOVE) };
        let ok = r != libc::MAP_FAILED;
        report("mremap(24 MB shared file mapping -> 25 MB, MAYMOVE)", if ok { 0 } else { -1 });
        value("  it moved", if ok { (r != base) as i64 } else { -1 });
        if ok {
            unsafe { libc::munmap(r, start + grow) };
        } else {
            unsafe { libc::munmap(base, start) };
        }
        unmap(after, 1);
        unsafe {
            libc::close(fd);
            libc::unlink(path.as_ptr());
        }
    }
    {
        // apt's actual failure, which the size alone did not reproduce: it
        // forks its fetch methods *before* it builds the cache, so the
        // parent's private pages are copy-on-write, and it then writes the
        // cache one page at a time -- so by the first growth some pages have
        // been copied and some have not. That is per-page state, not a
        // mapping boundary, and mremap must not read it as one. This kernel
        // did: "not uniform" was EFAULT, and apt printed "Dynamic MMap ran
        // out of room" at 24 MB with 975 MB of address space free.
        let p = anon(8, 0x11);
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork: {}", errno());
        if child == 0 {
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        unsafe { libc::waitpid(child, &mut status, 0) };
        // Break the copy-on-write on half the pages and not the other half.
        for i in 0..4 {
            unsafe { *p.add(i * PAGE) = 0x22 };
        }
        let r = unsafe { libc::mremap(p as *mut libc::c_void, 8 * PAGE, 12 * PAGE, MREMAP_MAYMOVE) };
        let ok = r != libc::MAP_FAILED;
        report("mremap(grow a private mapping half copied after fork)", if ok { 0 } else { -1 });
        value("  a copied page came with it", if ok { unsafe { *(r as *const u8) as i64 } } else { -1 });
        value("  an uncopied page came with it", if ok {
            unsafe { *(r as *const u8).add(5 * PAGE) as i64 }
        } else {
            -1
        });
        if ok {
            unsafe { libc::munmap(r, 12 * PAGE) };
        } else {
            unmap(p, 8);
        }
    }

    println!("## madvise: what it does, not what it accepts");
    {
        // The one with an observable effect, and the one every allocator
        // relies on: MADV_DONTNEED on anonymous memory makes the next read
        // see zeroes.
        let p = anon(2, 0xcd);
        report("madvise(MADV_DONTNEED)", unsafe {
            libc::madvise(p as *mut libc::c_void, 2 * PAGE, MADV_DONTNEED) as i64
        });
        value("  the byte that was 0xcd now reads", unsafe { *p as i64 });
        value("  ...and one page in", unsafe { *p.add(PAGE) as i64 });
        // Still writable afterwards: DONTNEED drops the pages, it does not
        // unmap them.
        unsafe { *p = 0x77 };
        value("  and it is still writable", unsafe { *p as i64 });
        unmap(p, 2);
    }
    {
        // MADV_FREE is lazy: the kernel may keep the contents until it needs
        // the memory, so reading 0xce back is allowed and so is reading 0.
        // What is *not* allowed is faulting, which is what this checks.
        let p = anon(1, 0xce);
        report("madvise(MADV_FREE)", unsafe {
            libc::madvise(p as *mut libc::c_void, PAGE, MADV_FREE) as i64
        });
        let seen = unsafe { *p };
        value("  the page is still readable", (seen == 0 || seen == 0xce) as i64);
        unmap(p, 1);
    }
    {
        let p = anon(1, 0);
        for (n, adv) in [
            ("MADV_NORMAL", MADV_NORMAL),
            ("MADV_RANDOM", MADV_RANDOM),
            ("MADV_SEQUENTIAL", MADV_SEQUENTIAL),
            ("MADV_WILLNEED", MADV_WILLNEED),
            ("MADV_DONTFORK", MADV_DONTFORK),
            ("MADV_DOFORK", MADV_DOFORK),
            ("MADV_WIPEONFORK", MADV_WIPEONFORK),
            ("9999 (undefined)", 9999),
            ("-1", -1),
        ] {
            report(&format!("madvise({n})"), unsafe {
                libc::madvise(p as *mut libc::c_void, PAGE, adv) as i64
            });
        }
        // Every advice number a kernel might define, swept rather than
        // guessed. Which ones exist is a list that has grown with every
        // release -- MADV_COLD and MADV_PAGEOUT in 5.4, MADV_POPULATE_* in
        // 5.14, MADV_COLLAPSE in 6.1 -- and writing it from memory is how the
        // `clock_nanosleep` flag rule got written wrong.
        for adv in 0..32i32 {
            report(&format!("madvise(advice={adv})"), unsafe {
                libc::madvise(p as *mut libc::c_void, PAGE, adv) as i64
            });
        }
        for adv in [100i32, 101, 102] {
            report(&format!("madvise(advice={adv})"), unsafe {
                libc::madvise(p as *mut libc::c_void, PAGE, adv) as i64
            });
        }
        report("madvise(len=0)", unsafe {
            libc::madvise(p as *mut libc::c_void, 0, MADV_NORMAL) as i64
        });
        report("madvise(unaligned address)", unsafe {
            libc::madvise((p as usize + 1) as *mut libc::c_void, PAGE, MADV_NORMAL) as i64
        });
        report("madvise(a range that is not mapped)", unsafe {
            libc::madvise(0x1000 as *mut libc::c_void, PAGE, MADV_NORMAL) as i64
        });
        report("madvise(DONTNEED on a range that is not mapped)", unsafe {
            libc::madvise(0x1000 as *mut libc::c_void, PAGE, MADV_DONTNEED) as i64
        });
        report("madvise(len rounds past the end)", unsafe {
            libc::madvise(p as *mut libc::c_void, PAGE * 4, MADV_NORMAL) as i64
        });
        unmap(p, 1);
    }

    println!("## msync");
    {
        let p = anon(1, 0x99);
        for (n, f) in [
            ("MS_SYNC", MS_SYNC),
            ("MS_ASYNC", MS_ASYNC),
            ("MS_INVALIDATE", MS_INVALIDATE),
            ("MS_SYNC|MS_INVALIDATE", MS_SYNC | MS_INVALIDATE),
            ("MS_SYNC|MS_ASYNC (contradictory)", MS_SYNC | MS_ASYNC),
            ("0", 0),
            ("an undefined bit (0x8)", 0x8),
        ] {
            report(&format!("msync({n})"), unsafe {
                libc::msync(p as *mut libc::c_void, PAGE, f) as i64
            });
        }
        report("msync(unaligned address)", unsafe {
            libc::msync((p as usize + 1) as *mut libc::c_void, PAGE, MS_SYNC) as i64
        });
        report("msync(a range that is not mapped)", unsafe {
            libc::msync(0x1000 as *mut libc::c_void, PAGE, MS_SYNC) as i64
        });
        report("msync(len=0)", unsafe {
            libc::msync(p as *mut libc::c_void, 0, MS_SYNC) as i64
        });
        unmap(p, 1);
    }

    println!("## mlock and friends");
    {
        let p = anon(1, 0);
        report("mlock", unsafe { libc::mlock(p as *const libc::c_void, PAGE) as i64 });
        report("munlock", unsafe { libc::munlock(p as *const libc::c_void, PAGE) as i64 });
        report("mlock(len=0)", unsafe {
            libc::mlock(p as *const libc::c_void, 0) as i64
        });
        report("mlock(a range that is not mapped)", unsafe {
            libc::mlock(0x1000 as *const libc::c_void, PAGE) as i64
        });
        report("munlock(never locked)", unsafe {
            libc::munlock(p as *const libc::c_void, PAGE) as i64
        });
        // mlock2 takes a flags word; MLOCK_ONFAULT is 1 and nothing else is
        // defined.
        report("mlock2(flags=0)", unsafe {
            libc::syscall(libc::SYS_mlock2, p, PAGE, 0)
        });
        report("mlock2(MLOCK_ONFAULT)", unsafe {
            libc::syscall(libc::SYS_mlock2, p, PAGE, 1)
        });
        report("mlock2(an undefined flag)", unsafe {
            libc::syscall(libc::SYS_mlock2, p, PAGE, 2)
        });
        unsafe { libc::munlock(p as *const libc::c_void, PAGE) };
        unmap(p, 1);
    }
    {
        for (n, f) in [
            ("MCL_CURRENT", MCL_CURRENT),
            ("MCL_FUTURE", MCL_FUTURE),
            ("MCL_CURRENT|MCL_FUTURE", MCL_CURRENT | MCL_FUTURE),
            ("MCL_ONFAULT alone", MCL_ONFAULT),
            ("0", 0),
            ("an undefined bit (0x8)", 8),
        ] {
            report(&format!("mlockall({n})"), unsafe {
                libc::mlockall(f) as i64
            });
            unsafe { libc::munlockall() };
        }
        report("munlockall", unsafe { libc::munlockall() as i64 });
    }

    println!("## mincore");
    {
        let p = anon(2, 0x5a);
        let mut vec = [0u8; 2];
        report("mincore(2 mapped pages)", unsafe {
            libc::mincore(p as *mut libc::c_void, 2 * PAGE, vec.as_mut_ptr()) as i64
        });
        // Bit 0 is "resident". The pages were just written, so both are.
        value("  page 0 is resident", (vec[0] & 1) as i64);
        value("  page 1 is resident", (vec[1] & 1) as i64);
        value("  no bit above bit 0 is set", ((vec[0] & !1) == 0) as i64);

        // A page that has never been touched. Whether it is resident is the
        // kernel's business, but the *answer* must differ from a page that
        // was written -- a kernel that says "resident" for everything is
        // giving a report a caller cannot use.
        let q = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                2 * PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        } as *mut u8;
        let mut v2 = [0xffu8; 2];
        unsafe { libc::mincore(q as *mut libc::c_void, 2 * PAGE, v2.as_mut_ptr()) };
        value("an untouched page reports resident", (v2[0] & 1) as i64);
        unsafe { *q.add(PAGE) = 1 };
        let mut v3 = [0u8; 2];
        unsafe { libc::mincore(q as *mut libc::c_void, 2 * PAGE, v3.as_mut_ptr()) };
        value("after touching page 1, page 1 says", (v3[1] & 1) as i64);
        unmap(q, 2);

        report("mincore(unaligned address)", unsafe {
            libc::mincore((p as usize + 1) as *mut libc::c_void, PAGE, vec.as_mut_ptr()) as i64
        });
        report("mincore(a range that is not mapped)", unsafe {
            libc::mincore(0x1000 as *mut libc::c_void, PAGE, vec.as_mut_ptr()) as i64
        });
        report("mincore(the vector is not writable)", unsafe {
            libc::mincore(p as *mut libc::c_void, 2 * PAGE, 0x1000 as *mut u8) as i64
        });
        report("mincore(len=0)", unsafe {
            libc::mincore(p as *mut libc::c_void, 0, vec.as_mut_ptr()) as i64
        });
        unmap(p, 2);
    }

    println!("## what mprotect actually changes");
    {
        // Dropping write permission and putting it back, checked by writing.
        let p = anon(1, 0x01);
        report("mprotect(PROT_READ)", unsafe {
            libc::mprotect(p as *mut libc::c_void, PAGE, libc::PROT_READ) as i64
        });
        value("  it is still readable", unsafe { *p as i64 });
        report("mprotect(PROT_READ|PROT_WRITE) again", unsafe {
            libc::mprotect(p as *mut libc::c_void, PAGE, libc::PROT_READ | libc::PROT_WRITE) as i64
        });
        unsafe { *p = 0x02 };
        value("  and writable again", unsafe { *p as i64 });
        // Widening past what the mapping was created with. An anonymous
        // mapping has no file behind it, so PROT_EXEC is allowed.
        report("mprotect(PROT_READ|PROT_WRITE|PROT_EXEC)", unsafe {
            libc::mprotect(
                p as *mut libc::c_void,
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            ) as i64
        });
        unmap(p, 1);
    }

    println!("## a mapping that outlives its descriptor");
    {
        // MAP_SHARED of a file, then close it: the mapping keeps the file
        // alive, which is what mmap(2) promises and what a reference count
        // that lives on the descriptor would get wrong.
        let path = c"/tmp/mem_probe.f";
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o600) };
        if fd >= 0 {
            unsafe { libc::ftruncate(fd, PAGE as i64) };
            let p = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    PAGE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    fd,
                    0,
                )
            };
            report("mmap(MAP_SHARED of a file)", if p == libc::MAP_FAILED { -1 } else { 0 });
            if p != libc::MAP_FAILED {
                unsafe { libc::close(fd) };
                unsafe { *(p as *mut u8) = 0x7e };
                value("  writable after the descriptor closed", unsafe {
                    *(p as *const u8) as i64
                });
                report("msync(MS_SYNC) on it", unsafe {
                    libc::msync(p, PAGE, MS_SYNC) as i64
                });
                unsafe { libc::munmap(p, PAGE) };
                // And the byte reached the file.
                let fd2 = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
                let mut b = [0u8; 1];
                unsafe { libc::read(fd2, b.as_mut_ptr() as *mut libc::c_void, 1) };
                value("  and the byte reached the file", b[0] as i64);
                unsafe { libc::close(fd2) };
            } else {
                unsafe { libc::close(fd) };
            }
            unsafe { libc::unlink(path.as_ptr()) };
        }
    }
}
