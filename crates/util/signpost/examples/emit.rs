//! Link and emit, which is what `util/signpost.c` never got.
//!
//! The C it replaced was verified "only that it compiles, with
//! `cc -c -DIUL_OS_SIGNPOST=1`".
//! Compiling says nothing about the four libSystem symbols resolving or about
//! `_os_signpost_emit_with_name_impl` accepting the hand-built format buffer,
//! and this crate builds that buffer itself rather than getting it from a
//! compiler builtin, so the question matters more here than it did there.
//!
//! Not a `#[test]`: the interesting build is the one with the flag on, and a
//! test that compiles to nothing in every build the tree makes would be a test
//! that asserts nothing. Run it deliberately:
//!
//! ```sh
//! RUSTFLAGS='--cfg iul_iul_os_signpost' cargo run -p util-signpost --example emit
//! ```
//!
//! It prints and exits 0 whether or not a trace is being recorded —
//! `os_signpost_enabled` is false with no `Instruments` attached, which is the
//! path that returns early. What it proves is the link.

fn main() {
    println!("signposts compiled in: {}", signpost::enabled());

    {
        let _interval = signpost::Interval::begin(signpost::Category::Syscall, c"example");
        signpost::event(signpost::Category::Exec, c"example_event", c"a message");
    }

    // Nested, and out of order with the categories, because the id belongs to
    // the interval rather than to a per-category slot -- which is what an
    // `os_signpost_id_generate` per begin buys and what a global "current
    // interval" would not.
    let outer = signpost::Interval::begin(signpost::Category::Jit, c"outer");
    let inner = signpost::Interval::begin(signpost::Category::Fs, c"inner");
    drop(outer);
    drop(inner);

    println!("emitted");
}
