//! Opening a device node whose major or minor is out of range.
//!
//! A `dev_t` carries a 12-bit major and a 20-bit minor, so `mknod` can name
//! major 4095 and minor 1048575. The tables the kernel dispatches through have
//! 256 entries and the terminal registries fewer than that, and neither the
//! major nor the minor was checked against them.
//!
//! `char_devs[major]` past the end reads whatever follows the array and calls
//! the function pointer it finds. The minor reaches `tty_get`, which asks the
//! registry for a number it does not have, gets a null back and locks it.
//!
//! Both are reachable by an unprivileged guest: a fakefs stores ownership and
//! device numbers in its own database, so the guest is root there and `mknod`
//! works. This runs against `-f`, for that reason.
//!
//! What a correct answer is does not matter much -- `ENXIO`, `ENODEV`, `EPERM`
//! are all defensible for a device that is not there. What matters is that the
//! process comes back.

use guest_tests::{Harness, check, cpath, sys};

/// The kernel's dev_t encoding: 12 bits of major, 20 of minor, interleaved.
fn makedev(major: u32, minor: u32) -> u64 {
    (((minor & 0xfff00) << 12) | ((major & 0xfff) << 8) | (minor & 0xff)) as u64
}

fn mknod(path: &str, major: u32, minor: u32) -> i32 {
    let _ = std::fs::remove_file(path);
    unsafe { libc::mknod(cpath(path).as_ptr(), libc::S_IFCHR | 0o600, makedev(major, minor)) }
}

fn main() {
    let mut h = Harness::new();
    let dir = "/tmp/dev_bounds_dir";
    let _ = std::fs::create_dir_all(dir);

    h.group("major-past-the-table");
    // 256 is the first index past the dispatch tables. 4095 is the largest a
    // dev_t can hold. Everything in between is the same read.
    for major in [256u32, 257, 300, 1000, 4095] {
        let path = format!("{dir}/c{major}");
        let r = mknod(&path, major, 0);
        check!(h, r == 0, "mknod c {major} 0: r={r} errno={}",
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
        if r != 0 {
            continue;
        }
        let fd = unsafe { libc::open(cpath(&path).as_ptr(), libc::O_RDONLY) };
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        check!(h, fd < 0, "opening it is refused rather than dispatched: fd={fd} errno={e}");
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
        let _ = std::fs::remove_file(&path);
    }

    h.group("minor-past-the-registry");
    // Major 136 is the pty slave driver, whose registry is bounded by the
    // number of ptys. A minor past it has no terminal and no slot to make one
    // in, and the lookup answered with a null the caller then locked.
    for minor in [4096u32, 65535, 1048575] {
        let path = format!("{dir}/s{minor}");
        let r = mknod(&path, 136, minor);
        check!(h, r == 0, "mknod c 136 {minor}: r={r}");
        if r != 0 {
            continue;
        }
        let fd = unsafe { libc::open(cpath(&path).as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        check!(h, fd < 0, "opening it is refused: fd={fd} errno={e}");
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
        let _ = std::fs::remove_file(&path);
    }

    h.group("dynamic-minor-past-the-registry");
    // Major 240 is the dynamic character device, whose minors are a 256-entry
    // table an embedder registers into. `dev_open` bounds the *major* against
    // its own table -- there is a paragraph above it about what happens
    // otherwise -- and hands the minor straight through to `dyn_open`, which
    // indexes with it and calls the function pointer it finds.
    //
    // A `dev_t` carries a 20-bit minor, so `mknod c 240 1048575` reads about
    // eight megabytes past a 256-pointer array and calls whatever is there.
    for minor in [256u32, 4096, 65535, 1048575] {
        let path = format!("{dir}/d{minor}");
        let r = mknod(&path, 240, minor);
        check!(h, r == 0, "mknod c 240 {minor}: r={r} errno={}",
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
        if r != 0 {
            continue;
        }
        let fd = unsafe { libc::open(cpath(&path).as_ptr(), libc::O_RDONLY) };
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
        check!(
            h,
            fd < 0,
            "opening it is refused rather than dispatched: fd={fd} errno={e}"
        );
    }

    h.group("master-minor-past-the-registry");
    // The same for major 128, the pty master. Its registry is the same size,
    // and reaching it through a device node skips the allocation in
    // /dev/ptmx that is the only other way in.
    for minor in [4096u32, 1048575] {
        let path = format!("{dir}/m{minor}");
        let r = mknod(&path, 128, minor);
        check!(h, r == 0, "mknod c 128 {minor}: r={r}");
        if r != 0 {
            continue;
        }
        let fd = unsafe { libc::open(cpath(&path).as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        check!(h, fd < 0, "opening it is refused: fd={fd} errno={e}");
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
        let _ = std::fs::remove_file(&path);
    }

    h.group("block-major-past-the-table");
    // The block table is empty, so every major in it is already ENXIO -- but
    // it is the same unbounded index, and an out-of-range one read past it
    // just the same.
    for major in [256u32, 4095] {
        let path = format!("{dir}/b{major}");
        let _ = std::fs::remove_file(&path);
        let r = unsafe {
            libc::mknod(cpath(&path).as_ptr(), libc::S_IFBLK | 0o600, makedev(major, 0))
        };
        check!(h, r == 0, "mknod b {major} 0: r={r}");
        if r != 0 {
            continue;
        }
        let fd = unsafe { libc::open(cpath(&path).as_ptr(), libc::O_RDONLY) };
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        check!(h, fd < 0, "opening it is refused: fd={fd} errno={e}");
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
        let _ = std::fs::remove_file(&path);
    }

    h.group("the-devices-that-do-exist-still-work");
    // The control. None of the above is satisfied by a dispatch that refuses
    // everything.
    let path = format!("{dir}/null");
    let r = mknod(&path, 1, 3);
    check!(h, r == 0, "mknod c 1 3: r={r}");
    if r == 0 {
        let fd = unsafe { libc::open(cpath(&path).as_ptr(), libc::O_WRONLY) };
        check!(h, fd >= 0, "/dev/null opens: fd={fd}");
        if fd >= 0 {
            let n = unsafe { libc::write(fd, b"x".as_ptr().cast(), 1) };
            check!(h, n == 1, "and swallows a write: n={n}");
            unsafe { libc::close(fd) };
        }
    }
    let path = format!("{dir}/zero");
    let r = mknod(&path, 1, 5);
    check!(h, r == 0, "mknod c 1 5: r={r}");
    if r == 0 {
        let fd = unsafe { libc::open(cpath(&path).as_ptr(), libc::O_RDONLY) };
        check!(h, fd >= 0, "/dev/zero opens: fd={fd}");
        if fd >= 0 {
            let mut b = [0xABu8; 8];
            let n = unsafe { libc::read(fd, b.as_mut_ptr().cast(), 8) };
            check!(h, n == 8 && b == [0u8; 8], "and reads zeroes: n={n}");
            unsafe { libc::close(fd) };
        }
    }
    // Major 255 is the last index the table has. It is empty, so this is
    // ENXIO -- and it is the check that the bound is not off by one the other
    // way, refusing a number the table does have.
    let path = format!("{dir}/c255");
    let r = mknod(&path, 255, 0);
    check!(h, r == 0, "mknod c 255 0: r={r}");
    if r == 0 {
        let fd = unsafe { libc::open(cpath(&path).as_ptr(), libc::O_RDONLY) };
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        check!(h, fd < 0 && e == libc::ENXIO,
            "the last entry in the table is ENXIO, not a bounds refusal: fd={fd} errno={e}");
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }

    // ---- the memory devices, which are only a rule each --------------
    //
    // Every one of these is a few lines with no state, and the ones with a
    // rule are worth stating: /dev/full refuses every write with ENOSPC, which
    // is what it exists for, and /dev/null accepts one and keeps nothing.
    h.group("dev-mem");

    for (name, minor, want_read) in [("null", 3u32, 0usize), ("zero", 5, 8), ("full", 7, 8)] {
        let path = format!("{dir}/{name}");
        if mknod(&path, 1, minor) != 0 {
            continue;
        }
        let fd = unsafe { libc::open(cpath(&path).as_ptr(), libc::O_RDWR) };
        check!(h, fd >= 0, "/dev/{name} opens: fd={fd}");
        if fd < 0 {
            continue;
        }
        let mut b = [0xABu8; 8];
        let n = unsafe { libc::read(fd, b.as_mut_ptr().cast(), 8) };
        check!(h, n == want_read as isize, "/dev/{name} reads {n}, wanted {want_read}");
        if want_read == 8 {
            check!(h, b == [0u8; 8], "/dev/{name} reads zeroes");
        }

        sys::clear_errno();
        let w = unsafe { libc::write(fd, b.as_ptr().cast(), 8) };
        let e = sys::errno();
        if name == "full" {
            check!(h, w < 0 && e == libc::ENOSPC, "/dev/full refuses a write: w={w} errno={e}");
        } else {
            check!(h, w == 8, "/dev/{name} takes a write: w={w} errno={e}");
        }
        unsafe { libc::close(fd) };
    }

    // RNDGETENTCNT on /dev/random. It answered ENOTTY: the driver had an ioctl
    // handler and no ioctl_size, and the VFS asks for the size first and
    // refuses a negative before it calls anything -- so the handler was dead
    // code that read as working.
    //
    // The count is compared against zero rather than a number, because it is a
    // pool estimate: a real kernel answered 256 in a container and this one
    // reports a full pool. What a program reads it for is whether it has to
    // wait.
    let path = format!("{dir}/random");
    if mknod(&path, 1, 8) == 0 {
        let fd = unsafe { libc::open(cpath(&path).as_ptr(), libc::O_RDONLY) };
        check!(h, fd >= 0, "/dev/random opens: fd={fd}");
        if fd >= 0 {
            let mut count: i32 = -1;
            sys::clear_errno();
            let r = unsafe { libc::ioctl(fd, RNDGETENTCNT, &mut count) };
            check!(h, r == 0, "RNDGETENTCNT is answered: r={r} errno={}", sys::errno());
            check!(h, count > 0, "and reports entropy available: {count}");

            // An ioctl the driver does not have is ENOTTY, which is how a
            // program tells "not this device" from "this device said no".
            sys::clear_errno();
            let r = unsafe { libc::ioctl(fd, 0x5401 as _, &mut count) };
            check!(h, r < 0 && sys::errno() == libc::ENOTTY,
                "TCGETS on /dev/random is ENOTTY: r={r} errno={}", sys::errno());
            unsafe { libc::close(fd) };
        }
    }

    let _ = std::fs::remove_dir_all(dir);
    std::process::exit(h.finish());
}

/// `RNDGETENTCNT`: how many bits of entropy the pool holds.
const RNDGETENTCNT: libc::c_int = 0x80045200u32 as libc::c_int;
