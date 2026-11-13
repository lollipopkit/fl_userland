//! Prints `cpu-offsets.h`, for reading it by hand or diffing it against a
//! change. The generator is the library beside this, which
//! `crates/asbestos/gadgets` calls from its `build.rs`; nothing in the build
//! runs this binary since 2026-09-11, when meson's generator target went.

fn main() {
    print!("{}", cpuoffsets::text());
}
