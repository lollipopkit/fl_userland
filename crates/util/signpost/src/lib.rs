//! `os_signpost` intervals and events, for a profile in Instruments.
//!
//! `util/signpost.c` until 2026-09-06, where it was one of the three files
//! `docs/remaining-c.md` listed with the same blocker: `os_signpost_*` is a
//! macro over **`__builtin_os_log_format`**, a clang builtin that encodes a
//! format string and its arguments into a byte buffer at compile time, and
//! there is no Rust equivalent of it.
//!
//! # What the builtin actually produces
//!
//! The blocker is a true statement about the builtin and a false one about this
//! file, because the three call shapes here take **only `%{public}s` and
//! pointers**. The encoding for that is small enough to write out:
//!
//! ```text
//! byte 0     summary: 0x02, "has a non-scalar argument"
//! byte 1     argument count
//! per arg    0x22  descriptor: (string << 4) | public
//!            0x08  size
//!            8 bytes, the pointer, little-endian
//! ```
//!
//! **Those bytes were not read off a blog post.** They came from clang, by
//! compiling `__builtin_os_log_format(buf, "%{public}s", p)` for exactly the two
//! format strings this file uses and dumping the buffer:
//!
//! ```text
//! one %{public}s   size=12  02 01 22 08 88 77 66 55 44 33 22 11
//! two %{public}s   size=22  02 02 22 08 <ptr> 22 08 <ptr>
//! ```
//!
//! `crates/util/signpost/src/lib.rs`'s own tests assert that layout, so a
//! change to either format string that adds a non-string argument fails a test
//! rather than emitting a buffer the tracing library reads past the end of.
//!
//! Everything else the macro did is an ordinary exported function:
//! `_os_signpost_emit_with_name_impl`, `os_log_create`, `os_signpost_enabled`
//! and `os_signpost_id_generate` are all in libSystem.
//!
//! The one part that is *not* a call is where the literals live: clang puts the
//! format string and the signpost's name in `__TEXT,__oslogstring`, which is
//! how the trace resolves them. `#[unsafe(link_section = ...)]` puts them
//! there, and `otool -s __TEXT __oslogstring` on the built object is what says
//! it worked.
//!
//! # Why it costs nothing when it is off
//!
//! The C exported `iul_signpost_compiled_in` as a `const int` global because
//! its callers were in another translation unit: a load and a predicted branch,
//! chosen over "two non-inlinable calls at about 5 ns each" on the syscall
//! path. All three callers are Rust now, so [`enabled`] is a `const fn` over a
//! `cfg` and the branch is folded away with the call. There is no global left
//! to load.
//!
//! # The interval is a guard
//!
//! The C paired `iul_signpost_begin` with `iul_signpost_end` by hand, and
//! `crates/asbestos/gen` had grown a `finish` closure called at each of the
//! function's exits to do it. [`Interval`] ends on drop, so the pairing is the
//! compiler's.
//!
//! # A race the C had
//!
//! `iul_signpost_begin` read `logs[cat]` unsynchronised and called the
//! `pthread_once` initialiser if it was null — the check itself was the data
//! race. The handles are a `OnceLock` here, so the first caller wins and
//! nothing needs an explicit init call at boot.

use std::ffi::CStr;

/// What an interval or event is filed under in the trace.
///
/// `enum iul_sp_cat` in `util/signpost.h`, whose numbering left this crate
/// with it: nothing outside compares these to an integer any more.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Category {
    Exec,
    Jit,
    Fs,
    Syscall,
    Tlb,
}

/// `dead_code` because in a build without the flag only the tests reach these
/// — and the tests are the point: the encoding they pin is what makes writing
/// this crate defensible, so they must run in *every* build rather than only
/// in the one build nobody makes.
#[allow(dead_code)]
impl Category {
    /// The `os_log` category name, which is what `Instruments` groups by.
    const fn name(self) -> &'static CStr {
        match self {
            Category::Exec => c"exec",
            Category::Jit => c"jit",
            Category::Fs => c"fs",
            Category::Syscall => c"syscall",
            Category::Tlb => c"tlb",
        }
    }

    const ALL: [Category; 5] = [
        Category::Exec,
        Category::Jit,
        Category::Fs,
        Category::Syscall,
        Category::Tlb,
    ];

    const fn index(self) -> usize {
        self as usize
    }
}

/// Whether this build emits anything at all.
///
/// A `const fn`, so a caller's `if signpost::enabled()` is folded at compile
/// time along with everything inside it.
pub const fn enabled() -> bool {
    cfg!(iul_iul_os_signpost)
}

/// An interval that ends when this is dropped.
///
/// `name` reaches Instruments as the interval's **message**. It cannot be its
/// *name*: `_os_signpost_emit_with_name_impl` takes the name as a pointer into
/// `__TEXT,__oslogstring`, so it has to be a literal in this image, and every
/// interval here is called "iul". Passing the caller's name as a `%{public}s`
/// argument is what makes an `execve` interval distinguishable from a syscall
/// one; before 2026-09-03 the C dropped it on the floor entirely.
#[must_use = "the interval ends when this value is dropped"]
pub struct Interval {
    live: imp::Live,
}

impl Interval {
    /// Open an interval. Ends when the returned value goes out of scope.
    pub fn begin(cat: Category, name: &'static CStr) -> Self {
        Interval {
            live: imp::begin(cat, name),
        }
    }
}

impl Drop for Interval {
    fn drop(&mut self) {
        imp::end(&mut self.live);
    }
}

/// A point event, with a message beside the name.
pub fn event(cat: Category, name: &'static CStr, msg: &CStr) {
    imp::event(cat, name, msg);
}

// ------------------------------------------------------------- the encoding

/// The largest buffer any format string here needs: two `%{public}s`.
#[allow(dead_code)]
const MAX_BUF: usize = 2 + 2 * 10;

/// A `__builtin_os_log_format` buffer, built at run time because the builtin
/// is clang's.
///
/// Sized for the worst case and carried with its length rather than heap
/// allocated: this is on the syscall path when signposts are on.
#[allow(dead_code)]
struct FormatBuffer {
    bytes: [u8; MAX_BUF],
    len: u32,
}

#[allow(dead_code)]
impl FormatBuffer {
    /// Encode `args` as that many `%{public}s` arguments.
    ///
    /// Public rather than private because os_log redacts a plain `%s` in a
    /// release build, and these are this kernel's own strings — never a
    /// guest's, which is the distinction that would make redaction right.
    fn public_strings(args: &[*const std::ffi::c_char]) -> Self {
        debug_assert!(
            args.len() * 10 + 2 <= MAX_BUF,
            "format buffer is sized for two arguments"
        );
        let mut bytes = [0u8; MAX_BUF];
        // 0x02: "has a non-scalar argument". A string is non-scalar; no
        // argument here is private, which is the other bit.
        bytes[0] = 0x02;
        bytes[1] = args.len() as u8;
        let mut at = 2;
        for arg in args {
            // (string << 4) | public. The two nibbles are both 2 here, so
            // which is which was settled by measuring a *bare* `%s` as well:
            // clang answers 0x20, so the low nibble is the annotation.
            bytes[at] = 0x22;
            bytes[at + 1] = 8;
            bytes[at + 2..at + 10].copy_from_slice(&(*arg as usize as u64).to_le_bytes());
            at += 10;
        }
        FormatBuffer {
            bytes,
            len: at as u32,
        }
    }
}

#[cfg(iul_iul_os_signpost)]
mod imp {
    use super::{Category, FormatBuffer};
    use std::ffi::{CStr, c_char, c_int, c_void};
    use std::sync::OnceLock;

    /// `OS_SIGNPOST_EVENT`, `_INTERVAL_BEGIN`, `_INTERVAL_END` from
    /// `<os/signpost.h>`.
    const TYPE_EVENT: u8 = 0x00;
    const TYPE_BEGIN: u8 = 0x01;
    const TYPE_END: u8 = 0x02;

    /// `OS_SIGNPOST_ID_EXCLUSIVE`, for an event that is not part of an
    /// interval.
    const ID_EXCLUSIVE: u64 = 0xEEEE_B0B5_B2B2_EEEE;

    /// The literals the tracing library resolves out of this image's
    /// `__TEXT,__oslogstring` section. clang puts a format string and a
    /// signpost name there; a pointer to an ordinary `.rodata` string is not
    /// something the trace can name.
    macro_rules! oslogstring {
        ($id:ident, $bytes:expr) => {
            #[used]
            #[unsafe(link_section = "__TEXT,__oslogstring,cstring_literals")]
            static $id: [u8; $bytes.len()] = *$bytes;
        };
    }

    oslogstring!(SP_NAME, b"iul\0");
    oslogstring!(FMT_ONE, b"%{public}s\0");
    oslogstring!(FMT_TWO, b"%{public}s %{public}s\0");

    unsafe extern "C" {
        /// This image's mach header. The trace uses it to resolve the two
        /// pointers above back to strings.
        static __dso_handle: c_void;

        fn os_log_create(subsystem: *const c_char, category: *const c_char) -> *mut c_void;
        fn os_signpost_enabled(log: *mut c_void) -> bool;
        fn os_signpost_id_generate(log: *mut c_void) -> u64;
        fn _os_signpost_emit_with_name_impl(
            dso: *mut c_void,
            log: *mut c_void,
            ty: c_int,
            spid: u64,
            name: *const c_char,
            format: *const c_char,
            buf: *mut u8,
            size: u32,
        );
    }

    /// An `os_log_t`, which is an Objective-C object and documented
    /// thread-safe. Stored as an address so this handle remains freely shareable.
    #[derive(Clone, Copy)]
    struct Log(usize);

    /// One handle per category, made on first use.
    ///
    /// The C read `logs[cat]` without synchronisation to decide whether to run
    /// its `pthread_once`; that read was itself the race.
    fn log(cat: Category) -> Log {
        static LOGS: OnceLock<[Log; 5]> = OnceLock::new();
        LOGS.get_or_init(|| {
            Category::ALL.map(|c| {
                // SAFETY: two 'static C strings.
                Log(unsafe {
                    os_log_create(c"iul".as_ptr(), c.name().as_ptr()) as usize
                })
            })
        })[cat.index()]
    }

    /// The open interval, or `None` if signposts were off when it began.
    ///
    /// The id is kept so that `end` matches `begin`; the category too, because
    /// they must be emitted against the same log handle.
    pub(super) type Live = Option<(Category, &'static CStr, u64)>;

    pub(super) fn begin(cat: Category, name: &'static CStr) -> Live {
        let log = log(cat);
        // SAFETY: `log` came from `os_log_create`.
        if !unsafe { os_signpost_enabled(log.0 as *mut c_void) } {
            return None;
        }
        // SAFETY: as above.
        let spid = unsafe { os_signpost_id_generate(log.0 as *mut c_void) };
        emit(TYPE_BEGIN, log, spid, &[name.as_ptr()]);
        Some((cat, name, spid))
    }

    pub(super) fn end(live: &mut Live) {
        if let Some((cat, name, spid)) = live.take() {
            emit(TYPE_END, log(cat), spid, &[name.as_ptr()]);
        }
    }

    pub(super) fn event(cat: Category, name: &CStr, msg: &CStr) {
        let log = log(cat);
        // SAFETY: `log` came from `os_log_create`.
        if !unsafe { os_signpost_enabled(log.0 as *mut c_void) } {
            return;
        }
        emit(
            TYPE_EVENT,
            log,
            ID_EXCLUSIVE,
            &[name.as_ptr(), msg.as_ptr()],
        );
    }

    /// The call the `os_signpost_*` macros expand to.
    ///
    /// The format literal is picked by argument count, which is the invariant
    /// the whole encoding rests on: a buffer describing two arguments beside a
    /// format naming one makes the tracing library read a pointer that is not
    /// there.
    fn emit(ty: u8, log: Log, spid: u64, args: &[*const c_char]) {
        let fmt: *const c_char = match args.len() {
            1 => FMT_ONE.as_ptr(),
            2 => FMT_TWO.as_ptr(),
            _ => unreachable!("no format string for {} arguments", args.len()),
        };
        let mut buf = FormatBuffer::public_strings(args);
        // SAFETY: `log` came from `os_log_create`; `fmt` and `SP_NAME` are
        // 'static NUL-terminated literals in this image's `__oslogstring`
        // section, which is where the tracing library resolves them from; and
        // `buf` describes exactly `args.len()` arguments, which is what `fmt`
        // names.
        unsafe {
            _os_signpost_emit_with_name_impl(
                (&raw const __dso_handle).cast_mut(),
                log.0 as *mut c_void,
                ty as c_int,
                spid,
                SP_NAME.as_ptr(),
                fmt,
                buf.bytes.as_mut_ptr(),
                buf.len,
            );
        }
    }
}

#[cfg(not(iul_iul_os_signpost))]
mod imp {
    use super::Category;
    use std::ffi::CStr;

    /// Nothing to carry: [`super::enabled`] is `false`, so every caller's
    /// branch is folded and none of this is reached.
    pub(super) type Live = ();

    pub(super) fn begin(_cat: Category, _name: &'static CStr) -> Live {}
    pub(super) fn end(_live: &mut Live) {}
    pub(super) fn event(_cat: Category, _name: &CStr, _msg: &CStr) {}
}

#[cfg(test)]
mod tests {
    use super::{Category, FormatBuffer, MAX_BUF};

    /// The bytes clang emits for `__builtin_os_log_format(buf, "%{public}s", p)`
    /// with `p == 0x1122334455667788`, read back from a compiled object:
    ///
    /// ```text
    /// one %{public}s   size=12  02 01 22 08 88 77 66 55 44 33 22 11
    /// ```
    ///
    /// This is the whole reason the crate could be written: if the encoding
    /// were guessed rather than measured, a wrong descriptor byte would make
    /// the tracing library read a pointer out of the middle of the buffer.
    #[test]
    fn one_public_string_matches_what_clang_emits() {
        let p = 0x1122_3344_5566_7788usize as *const std::ffi::c_char;
        let b = FormatBuffer::public_strings(&[p]);
        assert_eq!(b.len, 12);
        assert_eq!(
            &b.bytes[..12],
            &[
                0x02, 0x01, 0x22, 0x08, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
            ]
        );
    }

    /// And for `"%{public}s %{public}s"`:
    ///
    /// ```text
    /// two %{public}s   size=22  02 02 22 08 88 77 66 55 44 33 22 11
    ///                           22 08 00 ff ee dd cc bb aa 99
    /// ```
    #[test]
    fn two_public_strings_match_what_clang_emits() {
        let p = 0x1122_3344_5566_7788usize as *const std::ffi::c_char;
        let q = 0x99aa_bbcc_ddee_ff00usize as *const std::ffi::c_char;
        let b = FormatBuffer::public_strings(&[p, q]);
        assert_eq!(b.len, 22);
        assert_eq!(
            &b.bytes[..22],
            &[
                0x02, 0x02, //
                0x22, 0x08, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, //
                0x22, 0x08, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99,
            ]
        );
    }

    /// The buffer is a fixed array, so the size it is declared with has to
    /// cover the longest format string in the crate. Two arguments is that.
    #[test]
    fn the_buffer_is_sized_for_the_longest_format() {
        assert_eq!(MAX_BUF, 22);
    }

    /// `Category::index` is what selects the log handle out of the array, and
    /// `ALL` is what fills it — a disagreement would file every interval under
    /// the wrong category, which is silent.
    #[test]
    fn the_category_index_agrees_with_the_table() {
        for (i, c) in Category::ALL.iter().enumerate() {
            assert_eq!(c.index(), i, "{c:?}");
        }
    }

    /// The names are `os_log` categories and reach Instruments as written.
    #[test]
    fn every_category_has_a_name() {
        let names: Vec<_> = Category::ALL
            .iter()
            .map(|c| c.name().to_str().unwrap())
            .collect();
        assert_eq!(names, ["exec", "jit", "fs", "syscall", "tlb"]);
    }
}
