//! Notifications for mappings whose lifetime is also tracked by a descriptor.

use std::sync::OnceLock;

use taskview::ffi;

/// Called when the last page of a shared mapping disappears.
///
/// A safe `fn` since 2026-10-01: it was `unsafe fn(&fd)`, whose only
/// implementation takes the same reference safely.
pub type SharedMappingGoneFn = fn(fd: &ffi::fd);

/// Installed by `kernel-memfdcalls`, which owns the descriptors that count
/// shared mappings. Keeping the callback here avoids a dependency cycle from
/// the page table back to the descriptor implementation.
static SHARED_MAPPING_GONE: OnceLock<SharedMappingGoneFn> = OnceLock::new();

/// Install the notification. The first call wins, so every `memfd_create` can
/// safely call this during initialization.
pub fn set_shared_mapping_gone_hook(f: SharedMappingGoneFn) {
    let _ = SHARED_MAPPING_GONE.set(f);
}

/// The caller must not be holding a lock the descriptor's own operations take:
/// a deadlock, which is why it is said here rather than as a `# Safety`.
pub(crate) fn shared_mapping_gone(fd: &ffi::fd) {
    if let Some(tell) = SHARED_MAPPING_GONE.get() {
        tell(fd);
    }
}
