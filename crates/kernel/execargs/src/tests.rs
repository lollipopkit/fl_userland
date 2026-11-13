use super::*;

use std::collections::BTreeMap;
use std::sync::Mutex;

/// A stand-in address space, one byte at a time.
///
/// `crates/kernel/usercopy`'s `GuestMem` exists so that a test can
/// substitute the C entry points rather than the whole call, and this is
/// that: a map from guest address to byte, which makes "an address that is
/// not there" something a test can write down.
static MEM: Mutex<BTreeMap<u64, u8>> = Mutex::new(BTreeMap::new());

fn map(addr: u64, bytes: &[u8]) {
    let mut m = MEM.lock().unwrap();
    for (i, b) in bytes.iter().enumerate() {
        m.insert(addr + i as u64, *b);
    }
}

/// A pointer array at `at`, pointing at strings laid out from `strings_at`.
///
/// **Every test uses its own base address.** The map is one global, because
/// the C entry points it stands in for are, and the tests run in parallel —
/// so clearing it between them is a test wiping another's memory, which is
/// what the first version of these did.
fn map_argv(at: u64, strings_at: u64, args: &[&[u8]]) {
    let mut p = strings_at;
    let mut slot = at;
    for a in args {
        map(slot, &p.to_le_bytes());
        let mut s = a.to_vec();
        s.push(0);
        map(p, &s);
        p += s.len() as u64;
        slot += 8;
    }
    map(slot, &0u64.to_le_bytes());
}

/// The stand-in address space, as a [`usercopy::GuestIo`].
///
/// It used to replace the usercopy entry points with linker symbols. The
/// test now supplies a [`usercopy::GuestIo`] implementation directly, so
/// the test measures the memory model declared by its source.
///
/// The trait costs the product nothing: [`read_array`] is generic, so the
/// real call monomorphises to `GuestMem` and is direct.
struct Fake;

impl usercopy::GuestIo for Fake {
    fn read(&self, addr: u64, bytes: &mut [u8]) -> c_int {
        let m = MEM.lock().unwrap();
        for (i, d) in bytes.iter_mut().enumerate() {
            match m.get(&(addr + i as u64)) {
                Some(b) => *d = *b,
                None => return EFAULT,
            }
        }
        0
    }

    fn read_u64(&self, addr: u64) -> Result<u64, c_int> {
        let mut word = [0u8; 8];
        match self.read(addr, &mut word) {
            0 => Ok(u64::from_le_bytes(word)),
            e => Err(e),
        }
    }

    /// Nothing here writes to the guest.
    fn write(&self, _addr: u64, _bytes: &[u8]) -> c_int {
        EFAULT
    }

    fn write_u64(&self, _addr: u64, _value: u64) -> c_int {
        EFAULT
    }

    fn read_string(&self, addr: u64, buf: &mut [u8]) -> Result<usize, c_int> {
        let m = MEM.lock().unwrap();
        for (i, byte) in buf.iter_mut().enumerate() {
            match m.get(&(addr + i as u64)) {
                Some(0) => {
                    *byte = 0;
                    return Ok(i);
                }
                Some(b) => *byte = *b,
                None => return Err(EFAULT),
            }
        }
        Err(ENAMETOOLONG)
    }
}

/// An `argv` out of guest memory, into the flat buffer.
#[test]
fn an_argv_array_becomes_a_flat_list() {
    map_argv(0x1_0000, 0x1_8000, &[b"one", b"two", b"three"]);
    let (buf, n) = read_array(&Fake, 0x1_0000, 64).expect("fits");
    assert_eq!(n, 3);
    assert_eq!(size(&buf, n), Some(15));
    assert_eq!(&buf[..15], b"one\0two\0three\0\0");
}

/// A string longer than the first window is reread into a bigger one until it
/// fits, and the list is exactly the strings: the windows leave nothing behind.
#[test]
fn a_string_longer_than_a_page_is_read_whole() {
    let long = vec![b'x'; 10_000];
    map_argv(0x8_0000, 0x9_0000, &[&long, b"y"]);
    let (buf, n) = read_array(&Fake, 0x8_0000, 64 * 1024).expect("fits");
    assert_eq!(n, 2);
    assert_eq!(buf.len(), 10_000 + 1 + 2 + 1);
    assert!(buf[..10_000].iter().all(|&b| b == b'x'));
    assert_eq!(&buf[10_000..], b"\0y\0\0");
    // And one past the bound is the array being too big, however the windows
    // fall.
    assert_eq!(read_array(&Fake, 0x8_0000, 10_003), Err(E2BIG));
}

/// An empty array is a terminator and nothing else, which is exactly what
/// `shebang` has to cope with.
#[test]
fn an_empty_argv_array_is_a_list_of_none() {
    map_argv(0x2_0000, 0x2_8000, &[]);
    let (buf, n) = read_array(&Fake, 0x2_0000, 8).expect("fits");
    assert_eq!(n, 0);
    assert_eq!(buf[0], 0);
    assert_eq!(size(&buf, 0), Some(1));
}

/// The bound counts the terminator that ends the list, so a buffer that the
/// strings exactly fill is `E2BIG` rather than a list with no end.
#[test]
fn the_bound_leaves_room_for_the_list_terminator() {
    map_argv(0x3_0000, 0x3_8000, &[b"abc"]);
    // "abc\0" is four, plus the list terminator is five.
    let (five, n) = read_array(&Fake, 0x3_0000, 5).expect("fits");
    assert_eq!((n, &five[..]), (1, &b"abc\0\0"[..]));

    assert_eq!(read_array(&Fake, 0x3_0000, 4), Err(E2BIG));
}

/// A string too long for what is left is the *array* being too big, which
/// is what `execve` answers.
#[test]
fn a_string_that_does_not_fit_is_e2big_and_not_enametoolong() {
    map_argv(0x4_0000, 0x4_8000, &[b"aaaaaaaa", b"bbbbbbbb"]);
    assert_eq!(read_array(&Fake, 0x4_0000, 12), Err(E2BIG));
}

/// An address that is not there is `EFAULT`, whether it is the array or a
/// string it points at.
#[test]
fn an_unmapped_address_is_a_fault() {
    // Nothing is mapped here at all.
    assert_eq!(read_array(&Fake, 0x5_0000, 64), Err(EFAULT));

    // And a pointer array whose one entry points nowhere.
    map(0x6_0000, &0xdead_0000u64.to_le_bytes());
    map(0x6_0008, &0u64.to_le_bytes());
    assert_eq!(read_array(&Fake, 0x6_0000, 64), Err(EFAULT));
}

/// An entry that is not there is appended.
#[test]
fn setting_an_absent_variable_appends_it() {
    let (out, n) = set_env(b"A=1\0\0", 1, b"B=2", 2, false, 64).expect("fits");
    assert_eq!(n, 2);
    assert_eq!(out, b"A=1\0B=2\0\0");
    assert_eq!(size(&out, n), Some(out.len()));
}

/// One that is there is left alone, unless the caller says to replace it —
/// and the match is on the *name*, not on the whole entry.
#[test]
fn a_present_variable_is_kept_or_replaced_by_name() {
    // "NO_COLOR=" is nine bytes; the value after it does not matter.
    assert_eq!(
        set_env(b"NO_COLOR=0\0\0", 1, b"NO_COLOR=1", 9, false, 64),
        None
    );

    let (out, n) = set_env(b"NO_COLOR=0\0\0", 1, b"NO_COLOR=1", 9, true, 64).expect("fits");
    assert_eq!(n, 1);
    assert_eq!(out, b"NO_COLOR=1\0\0", "the old one is gone, not shadowed");

    // A replacement goes to the end, and everything else keeps its order.
    let (out, n) = set_env(b"A=1\0P=old\0B=2\0\0", 3, b"P=new", 2, true, 64).expect("fits");
    assert_eq!(n, 3);
    assert_eq!(out, b"A=1\0B=2\0P=new\0\0");
}

/// A prefix that is not a whole name does not match a longer one.
///
/// `PATH=` must not match `PATHEXT=`, which is what a prefix compare gets
/// wrong when the prefix is the name without its `=`.
#[test]
fn the_name_match_includes_the_equals_sign() {
    let (out, n) = set_env(b"PATHEXT=x\0\0", 1, b"PATH=/bin", 5, false, 64).expect("fits");
    assert_eq!(n, 2);
    assert_eq!(out, b"PATHEXT=x\0PATH=/bin\0\0");
}

/// Not fitting is the same answer as already being there: the list is
/// unchanged and the `execve` goes ahead.
#[test]
fn an_injection_that_does_not_fit_leaves_the_list_alone() {
    // "A=1\0" + "B=2\0" + "\0" is 9.
    assert!(set_env(b"A=1\0\0", 1, b"B=2", 2, false, 9).is_some());
    assert_eq!(set_env(b"A=1\0\0", 1, b"B=2", 2, false, 8), None);
}

/// A flag goes after `argv[0]`, which is where an interpreter's own
/// options belong: before the script's arguments, not after them.
#[test]
fn an_argument_is_inserted_after_argv0() {
    let (out, n) = insert_arg(b"node\0app.js\0\0", 2, b"--jitless", 64).expect("fits");
    assert_eq!(n, 3);
    assert_eq!(out, b"node\0--jitless\0app.js\0\0");
    assert_eq!(size(&out, n), Some(out.len()));
}

/// An identical argument anywhere is enough: the caller asked for it and
/// it is there.
#[test]
fn an_argument_that_is_already_present_is_not_repeated() {
    assert_eq!(
        insert_arg(b"node\0--jitless\0\0", 2, b"--jitless", 64),
        None
    );
    assert_eq!(
        insert_arg(b"node\0a\0--jitless\0\0", 3, b"--jitless", 64),
        None
    );
    // A different flag with the same start is a different flag.
    assert!(insert_arg(b"node\0--jit\0\0", 2, b"--jitless", 64).is_some());
}

/// An empty argv has no `argv[0]` to insert after, and no program to pass
/// a flag to either.
#[test]
fn an_empty_argv_takes_no_inserted_argument() {
    assert_eq!(insert_arg(b"\0", 0, b"--jitless", 64), None);
}

/// Both refuse a list whose count and bytes disagree, rather than walking.
#[test]
fn a_broken_list_is_left_alone_by_both() {
    assert_eq!(set_env(b"A=1\0", 2, b"B=2", 2, false, 64), None);
    assert_eq!(insert_arg(b"a\0", 2, b"x", 64), None);
    assert_eq!(set_env(b"", 0, b"B=2", 2, false, 64), None);
}

/// Whatever they do, the result is a list the rest of this crate reads.
#[test]
fn every_injection_leaves_a_well_formed_list() {
    let (out, n) = set_env(b"A=1\0B=2\0\0", 2, b"C=3", 2, false, 64).expect("fits");
    assert_eq!(size(&out, n), Some(out.len()));
    let (out, n) = insert_arg(&out, n, b"D", 64).expect("fits");
    assert_eq!(size(&out, n), Some(out.len()));
    assert_eq!(out, b"A=1\0D\0B=2\0C=3\0\0");
}

/// Counting walks to the terminator, and stops at the buffer if there is
/// none.
#[test]
fn counting_is_bounded_by_the_buffer() {
    assert_eq!(count(b"\0"), Some(0));
    assert_eq!(count(b"a\0\0"), Some(1));
    assert_eq!(count(b"a\0bb\0\0"), Some(2));
    assert_eq!(count(b"a\0\0trailing"), Some(1), "past the end is not ours");
    // No terminator at all: the walk the C did would have run off it.
    assert_eq!(count(b""), None);
    assert_eq!(count(b"a\0b"), None);
    assert_eq!(count(b"abc"), None);
}

/// Indexing answers `None` past the end rather than a pointer into
/// whatever follows.
#[test]
fn indexing_stops_at_the_end_of_the_list() {
    let l = b"one\0two\0\0";
    assert_eq!(at(l, 2, 0), Some(&b"one"[..]));
    assert_eq!(at(l, 2, 1), Some(&b"two"[..]));
    assert_eq!(at(l, 2, 2), None);
    assert_eq!(at(l, 2, usize::MAX), None);
    // And a count that disagrees with the bytes answers nothing at all,
    // rather than the entries that happen to be there.
    assert_eq!(at(l, 3, 0), None);
}

/// What `execve` actually does: read the array, then rewrite it for a `#!`.
/// The two halves have to agree about the format.
#[test]
fn a_list_read_from_the_guest_can_be_rewritten() {
    map_argv(0x7_0000, 0x7_8000, &[b"argv0", b"x"]);
    let (buf, n) = read_array(&Fake, 0x7_0000, 64).expect("fits");
    let (out, m) = shebang(b"/bin/sh", None, b"/tmp/s", &buf, n, 4096).expect("fits");
    assert_eq!(m, 3);
    assert_eq!(out, b"/bin/sh\0/tmp/s\0x\0\0");
}

/// A list is its strings and then one more NUL, and the size counts it.
#[test]
fn the_size_of_a_list_includes_the_terminator_after_the_last_one() {
    assert_eq!(size(b"\0", 0), Some(1), "an empty list is one byte");
    assert_eq!(size(b"a\0\0", 1), Some(3));
    assert_eq!(size(b"a\0bb\0\0", 2), Some(6));
    assert_eq!(size(b"\0\0", 1), Some(2), "an empty string is a string");
    // Trailing bytes past the terminator belong to whoever put them there.
    assert_eq!(size(b"a\0\0junk", 1), Some(3));
}

/// A count that does not match its buffer is an answer, not an assertion.
///
/// The C walked `count` strings and then `assert`ed the terminator was
/// there — which a release build does not check at all.
#[test]
fn a_count_that_disagrees_with_its_buffer_is_refused() {
    assert_eq!(size(b"a\0\0", 2), None, "more strings than there are");
    assert_eq!(size(b"a\0b\0", 2), None, "no terminator after the last");
    assert_eq!(size(b"", 0), None, "not even the terminator");
    assert_eq!(size(b"abc", 1), None, "an unterminated string");
    // The count the empty-argv bug produced: 2^64 - 1. It stops at the
    // buffer rather than walking off it.
    assert_eq!(size(b"a\0\0", usize::MAX), None);
}

#[test]
fn dropping_the_first_leaves_the_rest() {
    assert_eq!(
        rules::without_first(b"a\0bb\0\0", 2),
        Some((&b"bb\0\0"[..], 1))
    );
    assert_eq!(rules::without_first(b"a\0\0", 1), Some((&b"\0"[..], 0)));
    assert_eq!(rules::without_first(b"\0", 0), None, "nothing to drop");
}

/// The ordinary rewrite: `#!/bin/sh` running `script` with two arguments.
#[test]
fn a_shebang_replaces_argv0_with_the_script() {
    let (out, n) =
        shebang(b"/bin/sh", None, b"/tmp/s", b"argv0\0one\0two\0\0", 3, 4096).expect("fits");
    // Four: the interpreter, the script's path in place of argv[0], and
    // the two arguments the caller passed after its own argv[0].
    assert_eq!(n, 4);
    assert_eq!(out, b"/bin/sh\0/tmp/s\0one\0two\0\0");
    assert_eq!(size(&out, n), Some(out.len()));
}

/// With the single argument a `#!` line may carry.
#[test]
fn the_shebang_argument_comes_between_the_interpreter_and_the_script() {
    let (out, n) = shebang(
        b"/bin/awk",
        Some(b"-f"),
        b"/tmp/p",
        b"argv0\0x\0\0",
        2,
        4096,
    )
    .expect("fits");
    assert_eq!(n, 4);
    assert_eq!(out, b"/bin/awk\0-f\0/tmp/p\0x\0\0");
    assert_eq!(size(&out, n), Some(out.len()));
}

/// **An empty `argv` has no `argv[0]` to drop.**
///
/// `count - 1` on a `size_t` zero is about 2^64, and the C then walked that
/// many strings off the end of a 128 KB buffer. `argc` 0 is legal and Linux
/// runs the script.
#[test]
fn an_empty_argv_is_run_rather_than_walked_off_the_end() {
    let (out, n) = shebang(b"/bin/sh", None, b"/tmp/s", b"\0", 0, 4096).expect("fits");
    assert_eq!(n, 2, "the interpreter and the script, and nothing else");
    assert_eq!(out, b"/bin/sh\0/tmp/s\0\0");
    assert_eq!(size(&out, n), Some(out.len()));
}

/// The bound is checked before anything is written, and it is `>=`.
#[test]
fn a_list_that_does_not_fit_is_e2big() {
    // "/bin/sh\0" + "/tmp/s\0" + "\0" = 8 + 7 + 1 = 16.
    assert!(shebang(b"/bin/sh", None, b"/tmp/s", b"\0", 0, 17).is_ok());
    assert_eq!(
        shebang(b"/bin/sh", None, b"/tmp/s", b"\0", 0, 16),
        Err(E2BIG),
        "exactly filling the buffer is refused, as Linux refuses it"
    );
    assert_eq!(
        shebang(b"/bin/sh", None, b"/tmp/s", b"\0", 0, 1),
        Err(E2BIG)
    );
    // A long tail, refused for the tail rather than the head.
    let mut rest = b"argv0\0".to_vec();
    rest.extend(std::iter::repeat_n(b'x', 4096));
    rest.push(0);
    rest.push(0);
    assert_eq!(
        shebang(b"/bin/sh", None, b"/tmp/s", &rest, 2, 1024),
        Err(E2BIG)
    );
}

/// A rest whose count does not match its bytes is `EINVAL`, not a walk.
#[test]
fn a_rewrite_over_a_broken_list_is_refused() {
    assert_eq!(
        shebang(b"/bin/sh", None, b"/tmp/s", b"argv0\0one\0", 3, 4096),
        Err(EINVAL)
    );
}

/// The result is always a well-formed list, whatever went in — which is
/// what the next `execve` in a `#!` chain reads.
#[test]
fn the_result_of_a_rewrite_is_a_list_again() {
    for (rest, count) in [
        (&b"\0"[..], 0usize),
        (&b"a\0\0"[..], 1),
        (&b"a\0b\0c\0\0"[..], 3),
    ] {
        let (out, n) = shebang(b"/i", Some(b"-a"), b"/f", rest, count, 4096).expect("fits");
        assert_eq!(size(&out, n), Some(out.len()), "{rest:?} {count}");
        assert_eq!(*out.last().unwrap(), 0);
    }
}
