//! Accounting for host mappings rejected by the operating system.

use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

static HOST_MAP_FAILURES: AtomicU64 = AtomicU64::new(0);
static HOST_MAP_LAST_ERRNO: AtomicI32 = AtomicI32::new(0);
static HOST_MAP_LAST_BYTES: AtomicU64 = AtomicU64::new(0);

/// Record a rejected host mapping while its `errno` is still available.
pub(crate) fn note_host_map_failure(bytes: usize) {
    HOST_MAP_FAILURES.fetch_add(1, Ordering::Relaxed);
    HOST_MAP_LAST_ERRNO.store(
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        Ordering::Relaxed,
    );
    HOST_MAP_LAST_BYTES.store(bytes as u64, Ordering::Relaxed);
}

/// Return the number of failures, the last host `errno`, and the last size.
pub fn host_map_failures() -> (u64, i32, u64) {
    (
        HOST_MAP_FAILURES.load(Ordering::Relaxed),
        HOST_MAP_LAST_ERRNO.load(Ordering::Relaxed),
        HOST_MAP_LAST_BYTES.load(Ordering::Relaxed),
    )
}
