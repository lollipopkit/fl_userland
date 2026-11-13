//! macOS support helpers for native process spawning.

use super::*;
use std::ffi::{OsStr, OsString};

/// The guest's environment, minus what must not cross, plus what the redirect
/// dylib needs.
///
/// Every prefix ends with `=`, which is what makes a prefix compare a **name**
/// compare: `PATH=` must not match `PATHEXT=`.
#[cfg(target_os = "macos")]
pub(super) fn build_native_env(envp: &[Vec<u8>]) -> Vec<(OsString, OsString)> {
    const SKIP: &[&[u8]] = &[
        b"OPENSSL_armcap=",
        b"PYTHONMALLOC=",
        b"PYTHONDONTWRITEBYTECODE=",
        // Never the guest's values: these are this kernel's to set.
        b"DYLD_INSERT_LIBRARIES=",
        b"FAKEFS_ROOT=",
    ];
    // An entry with no `=`, or an empty name, is not a variable; `execve`
    // passes such strings through and a host program cannot read them as one.
    let split = |e: &[u8]| {
        let eq = e.iter().position(|&b| b == b'=').filter(|&i| i > 0)?;
        Some((OsStr::from_bytes(&e[..eq]).to_owned(), OsStr::from_bytes(&e[eq + 1..]).to_owned()))
    };
    let mut out: Vec<(OsString, OsString)> = envp
        .iter()
        .filter(|e| !SKIP.iter().any(|p| e.starts_with(p)))
        .filter_map(|e| split(e))
        .collect();

    // Path redirection, which fakefs and realfs both need: a guest absolute
    // path has to reach the rootfs directory on the host.
    if let (Some(root), Some(dylib)) = (root_source(), dylib_path()) {
        out.push(("DYLD_INSERT_LIBRARIES".into(), dylib.as_os_str().to_owned()));
        out.push(("FAKEFS_ROOT".into(), root.into_os_string()));
    }
    out
}
