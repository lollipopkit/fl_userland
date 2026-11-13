//! A guest cannot reach outside the fakefs `data/` directory.
//!
//! This is the security boundary of the mount that actually ships. A fakefs is
//! `data/` plus `meta.db`, and a guest path becomes a host path by stripping
//! the leading `/` (`fs/fix_path.h`) and opening it relative to `data/`.
//!
//! The runner puts bait beside `data/` and outside the fakefs directory
//! entirely. Everything here asserts the bait is unreachable — by `..`, by a
//! symlink, and by a symlink chain.
//!
//! There are two layers, and the second is the load-bearing one.
//!
//! The first is path normalisation, which is **subtractive**: it only ever
//! removes components and never emits a `..`, so `fix_path` cannot be handed
//! one. The root clamp in `crates/fs/path` is a refinement of that, not the
//! mechanism — removing it does not produce an escape.
//!
//! The second is that a fakefs is a **database-backed namespace**.
//! `fakefs_open` looks the guest path up in `meta.db` and returns `ENOENT` when
//! there is no row, whatever the host filesystem holds under `data/`. That is
//! what the `ghost` group below tests directly, and it holds even when
//! normalisation is broken: `..` emitted literally still cannot reach the bait.
//!
//! A symlink in a fakefs is stored as a host *regular file* holding the target
//! text, with the type in `meta.db`, so a target is always resolved inside the
//! guest namespace and never handed to the host as a path.

use guest_tests::{Harness, check, cpath};

const BAIT: &str = "SHELLBOX-BAIT";

/// Whatever `path` reads as, or None.
fn read(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

fn leaked(h: &mut Harness, what: &str, got: Option<String>) {
    let leak = got.as_deref().map(|s| s.contains(BAIT)).unwrap_or(false);
    check!(h, !leak, "{what} did not reach the host: got {got:?}");
}

fn main() {
    let mut h = Harness::new();

    h.group("dotdot");
    for p in [
        "/../secret_sibling",
        "/../../secret_outside",
        "/tmp/../../secret_sibling",
        "/./../secret_sibling",
        "//../secret_sibling",
        "/tmp/../../../../../../secret_sibling",
    ] {
        leaked(&mut h, p, read(p));
    }

    h.group("symlink");
    let dir = "/tmp/containment";
    let _ = std::fs::create_dir_all(dir);
    for (name, target) in [
        ("rel", "../secret_sibling"),
        ("abs", "/../secret_sibling"),
        ("up2", "../../secret_outside"),
        ("deep", "../../../../../../secret_sibling"),
    ] {
        let link = format!("{dir}/{name}");
        let _ = std::fs::remove_file(&link);
        unsafe {
            libc::symlink(cpath(target).as_ptr(), cpath(&link).as_ptr());
        }
        leaked(&mut h, &format!("a symlink to {target}"), read(&link));
    }

    // A chain: a link to a link to the bait. Each hop is resolved in the guest
    // namespace, so the chain cannot get further than one hop could.
    let a = format!("{dir}/chain_a");
    let b = format!("{dir}/chain_b");
    let _ = std::fs::remove_file(&a);
    let _ = std::fs::remove_file(&b);
    unsafe {
        libc::symlink(cpath("../secret_sibling").as_ptr(), cpath(&b).as_ptr());
        libc::symlink(cpath("chain_b").as_ptr(), cpath(&a).as_ptr());
    }
    leaked(&mut h, "a symlink chain", read(&a));

    h.group("ghost");
    // The runner puts a file in `data/tmp/` *after* meta.db was built, so it
    // exists on the host and has no row. This is the layer that actually
    // contains a guest: a path with no row does not exist, whatever is under
    // data/. Nothing the guest can do creates this situation, which is why the
    // runner has to.
    leaked(&mut h, "a host file with no meta.db row", read("/tmp/ghost"));
    check!(
        h,
        std::fs::metadata("/tmp/ghost").is_err(),
        "and it does not stat either"
    );

    h.group("still-works");
    // The controls. Containment must not be "nothing resolves": ordinary paths,
    // `..` that stays inside, and a symlink to something real all still work.
    let inside = format!("{dir}/real");
    let _ = std::fs::write(&inside, b"inside");
    check!(h, read(&inside).as_deref() == Some("inside"), "an ordinary file reads");
    check!(
        h,
        read(&format!("{dir}/../containment/real")).as_deref() == Some("inside"),
        "a .. that stays inside resolves"
    );
    let good = format!("{dir}/good_link");
    let _ = std::fs::remove_file(&good);
    unsafe { libc::symlink(cpath("real").as_ptr(), cpath(&good).as_ptr()) };
    check!(h, read(&good).as_deref() == Some("inside"), "a symlink to something real resolves");
    // And `..` from the root is the root, not an error.
    check!(h, std::fs::metadata("/../").is_ok(), "/.. is the root");

    std::process::exit(h.finish());
}
