//! Find `libvdso.so.elf` and pad it to the size the guest is shown.
//!
//! # It builds its own, since 2026-09-09
//!
//! `kernel/vdso.c` was five lines of `__asm__(".incbin \"libvdso.so.elf\"")`,
//! and the blocker written beside it was that the *path* is meson's — so
//! passing it to cargo would be a second build-time channel beside
//! `TMPFS_RS_CLANG_ARGS`, with no check on it.
//!
//! That was answered by reading `-I` out of the channel that already exists,
//! and it is moot now. The vDSO is Rust built by `vdso/arm64/build.sh`, which
//! takes no configuration and needs nothing installed beyond the target — so
//! this script runs it, and there is one image rather than a search over places
//! one might be. What went with the search is a `cargo:warning` that said the
//! embedded image "may not be the one this build produced", which was true and
//! is the shape a fallback takes when it cannot be made unnecessary.

use std::path::{Path, PathBuf};

/// Pages of image the guest is shown. The C `.skip`ped to this; the padding is
/// here now.
///
/// `crates/kernel/taskview` also defines it, because `crates/kernel/execcalls`
/// sizes the guest's mapping from it — so this is a **second rendering of one
/// number**, which is the shape that has cost this tree a `siginfo_` with three
/// copies and a `timeval_` with four. `src/lib.rs` asserts the two agree, in a
/// `const` block; `check_header_agrees` parsed `kernel/vdso.h` for the same
/// purpose until 2026-09-08, when the last crate stopped reading a header.
const VDSO_PAGES: usize = 2;
const PAGE: usize = 1 << 12;
const IMAGE_LEN: usize = VDSO_PAGES * PAGE;

const IMAGE_NAME: &str = "libvdso.so.elf";

/// Build the image, which is what `vdso/arm64/build.sh` does: `rustc --emit=obj`
/// for an aarch64 Linux object and `rust-lld` to link it against `vdso.lds`.
///
/// **Always, rather than looking for meson's first.** That order was the other
/// way round until 2026-09-09, when the vDSO was C and building it needed a
/// clang that could target `aarch64-linux-gnu` — so the script preferred an
/// image meson had already made, fell back to guessing a build directory, and
/// warned that the image might not be the one this build produced. None of that
/// applies now: `build.sh` takes no configuration, `rust-lld` ships with the
/// toolchain, and two invocations of it on the same sources cannot differ. So
/// there is one image, and this invocation made it.
fn build_image(root: &Path, out: &Path) -> PathBuf {
    let src = root.join("vdso").join("arm64");
    for f in ["src/lib.rs", "vdso.lds", "build.sh"] {
        println!("cargo:rerun-if-changed={}", src.join(f).display());
    }
    let image = out.join(IMAGE_NAME);
    let status = std::process::Command::new(src.join("build.sh"))
        .arg(&image)
        .status()
        .unwrap_or_else(|e| panic!("running {}: {e}", src.join("build.sh").display()));
    // No cause named here. The script has two steps that fail for unrelated
    // reasons and each prints its own; repeating one of them at this level made
    // a broken toolchain linker read as a missing target.
    assert!(
        status.success(),
        "vdso/arm64/build.sh failed; its own message above says which step."
    );
    image
}

fn main() {
    let root = buildcfg::repo_root();
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let path = build_image(&root, &out);

    let image = std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));

    // An empty file was what vdso/arm64/meson.build's stub target produced when
    // it found no aarch64 cross-compiler, and this was a `cargo:warning` for
    // that reason -- a state the build could reach on purpose. It cannot since
    // 2026-09-09: the vDSO is Rust built by rustc and `rust-lld`, `build.sh`
    // runs under `set -eu`, and there is no fallback. So an empty file means
    // something went wrong upstream of here.
    //
    // Worth failing on because **nothing downstream notices**: this script pads
    // to two pages, so `map_vdso`'s `debug_assert_eq!(vdso_pages, VDSO_PAGES)`
    // compares 2 with 2 either way, and every binary in the test rootfs is
    // static musl and never reads the image. Replacing it with zero bytes
    // changed no test's answer until
    // `tests/guest/src/bin/vdso_symbols.rs` was written.
    assert!(
        !image.is_empty(),
        "{} is empty: vdso/arm64/build.sh produced nothing",
        path.display()
    );

    assert!(
        image.len() <= IMAGE_LEN,
        "{} is {} bytes and the guest is shown {IMAGE_LEN}. VDSO_PAGES in \
         crates/kernel/taskview and this build script have to agree.",
        path.display(),
        image.len()
    );

    let mut padded = image;
    padded.resize(IMAGE_LEN, 0);

    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("vdso_image.bin");
    std::fs::write(&out, &padded).unwrap_or_else(|e| panic!("writing {}: {e}", out.display()));
}
