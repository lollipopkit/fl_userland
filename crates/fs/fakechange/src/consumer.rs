//! Waking whoever drains the queue: the last of `fs/fake.c`, which is gone.
//!
//! An embedder installs a handler and the engine calls it, on a serial queue of
//! its own, with a batch of events whenever a producer has recorded one. On
//! Apple that is a `dispatch_source` of type `DATA_ADD`, which coalesces any
//! number of producer signals into one wakeup, and the handler is a **Clang
//! block** -- `fs/fake.h` publishes `void (^)(const struct fakefs_change_event *,
//! int)` and ServerBox passes one.
//!
//! # The blocker that was not one
//!
//! This stayed C on the grounds that "a block is not a function pointer,
//! `Block_copy` is a compiler runtime call on an object with a hidden layout,
//! and stable Rust can neither call one nor hold one". Two of those three are
//! not so. The engine never *creates* a block: libdispatch has a function-pointer
//! form of every call the C made with a block literal -- `dispatch_async_f`,
//! `dispatch_source_set_event_handler_f` -- and holding one is `_Block_copy`
//! and `_Block_release`, which are plain C functions in libSystem. What is left
//! is *invoking* the embedder's block, and a block's layout is not hidden: it is
//! Apple's published Block ABI, whose header is `isa`, `flags`, `reserved`,
//! `invoke`, `descriptor`, and whose `invoke` takes the block itself as its
//! first argument. Five fields, one of which is read.
//!
//! # Order: the source exists before anything can wake it
//!
//! The C claimed the listener slot first and built the queue and source after,
//! so a producer that saw the listener in between woke a source that did not
//! exist yet. Here the wake tolerates no source, and the installer merges one
//! signal after resuming, so an event recorded in that window is drained at
//! once rather than at the next unrelated wakeup.

use std::ffi::{c_int, c_void};

use std::sync::atomic::{AtomicPtr, Ordering};

use crate::Event;

/// Wake the consumer, if one has been installed. Cheap, and safe to call from
/// any thread: a `dispatch_source_merge_data`, which libdispatch serialises.
pub(crate) fn wake_consumer() {
    {
        let source = SOURCE.load(Ordering::Acquire);
        if !source.is_null() {
            // SAFETY: a resumed source this module created and never releases.
            unsafe { apple::dispatch_source_merge_data(source, 1) };
        }
    }
}

mod apple {
    use std::ffi::{c_char, c_int, c_ulong, c_void};

    use crate::Event;

    /// The start of every block: Apple's Block ABI (`Block_literal`). Only
    /// `invoke` is read, and it is called with the block itself first, the way
    /// the compiler calls it.
    #[repr(C)]
    pub struct BlockHeader {
        pub isa: *const c_void,
        pub flags: c_int,
        pub reserved: c_int,
        pub invoke: unsafe extern "C" fn(*mut c_void, *const Event, c_int),
        pub descriptor: *const c_void,
    }

    unsafe extern "C" {
        /// `DISPATCH_SOURCE_TYPE_DATA_ADD` is `&_dispatch_source_type_data_add`.
        pub static _dispatch_source_type_data_add: [u8; 0];
        pub fn dispatch_queue_create(label: *const c_char, attr: *const c_void) -> *mut c_void;
        pub fn dispatch_source_create(
            type_: *const c_void,
            handle: usize,
            mask: c_ulong,
            queue: *mut c_void,
        ) -> *mut c_void;
        pub fn dispatch_source_set_event_handler_f(
            source: *mut c_void,
            handler: unsafe extern "C" fn(*mut c_void),
        );
        pub fn dispatch_resume(object: *mut c_void);
        pub fn dispatch_source_merge_data(source: *mut c_void, value: c_ulong);
        pub fn dispatch_async_f(
            queue: *mut c_void,
            context: *mut c_void,
            work: unsafe extern "C" fn(*mut c_void),
        );
        /// `Block_copy` and `Block_release` are macros over these.
        pub fn _Block_copy(block: *const c_void) -> *mut c_void;
        pub fn _Block_release(block: *const c_void);
    }
}

/// The installed handler, a copied block. Written only on the consumer's
/// serial queue, which is what serialises a replacement against a batch in
/// flight -- the same discipline the C had, with `dispatch_async` -- and read
/// only there, so the atomic is for the compiler rather than for a race.
static HANDLER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static QUEUE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static SOURCE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// How many events one call to the handler carries at most. Sixty-four is what
/// the C handed over; the batch lives on the queue thread's stack.
const BATCH: usize = 64;

const NO_EVENT: Event = Event {
    linux_path: [0; crate::PATH_MAX],
    op: 0,
    timestamp_ns: 0,
    fs_context: 0,
};

/// The source fired: drain the queue into batches and hand each to the handler.
unsafe extern "C" fn on_events(_context: *mut c_void) {
    let handler = HANDLER.load(Ordering::Acquire);
    let mut batch = [NO_EVENT; BATCH];
    loop {
        let n = crate::drain(&mut batch);
        if n == 0 {
            break;
        }
        if !handler.is_null() {
            // SAFETY: `handler` is a block this module copied and has not
            // released; its header is the Block ABI's, and `invoke` takes the
            // block, then the arguments the embedder's signature names.
            unsafe {
                let header = &*handler.cast::<apple::BlockHeader>();
                (header.invoke)(handler, batch.as_ptr(), n as c_int);
            }
        }
        if n < BATCH {
            break; // drained everything
        }
    }
}

/// A replacement handler, applied on the queue so that it cannot land in the
/// middle of a batch.
unsafe extern "C" fn replace_handler(copied: *mut c_void) {
    let old = HANDLER.swap(copied, Ordering::AcqRel);
    if !old.is_null() {
        // SAFETY: `old` came from `_Block_copy` in `fakefs_install_change_consumer`.
        unsafe { apple::_Block_release(old) };
    }
}

/// The embedder's registration: `fs/fake.h`'s `fakefs_install_change_consumer`.
///
/// `handler` is a block on Apple. Replacing an installed consumer is allowed
/// and happens on the consumer's own queue.
///
/// # Safety
/// `handler` is a block of the type `fs/fake.h` declares, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fakefs_install_change_consumer(handler: *mut c_void) {
    if handler.is_null() {
        return;
    }
    // SAFETY: the caller's contract. A copy is what outlives the caller's
    // frame, which a stack block does not.
    let copied = unsafe { apple::_Block_copy(handler) };
    if !crate::claim_listener() {
        // SAFETY: a queue exists once the listener has been claimed.
        unsafe { apple::dispatch_async_f(QUEUE.load(Ordering::Acquire), copied, replace_handler) };
        return;
    }
    HANDLER.store(copied, Ordering::Release);
    unsafe {
        let queue = apple::dispatch_queue_create(
            c"com.openminis.iul.fakechange".as_ptr(),
            std::ptr::null(),
        );
        let source = apple::dispatch_source_create(
            (&raw const apple::_dispatch_source_type_data_add).cast(),
            0,
            0,
            queue,
        );
        apple::dispatch_source_set_event_handler_f(source, on_events);
        QUEUE.store(queue, Ordering::Release);
        SOURCE.store(source, Ordering::Release);
        apple::dispatch_resume(source);
        // Whatever was recorded between the claim and this line.
        apple::dispatch_source_merge_data(source, 1);
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    /// The batch a handler is handed is the C's sixty-four, and an empty
    /// event is all zeroes -- what the array is built from before a drain
    /// fills it.
    #[test]
    fn the_batch_is_sixty_four_zeroed_events() {
        let batch = [NO_EVENT; BATCH];
        assert_eq!(batch.len(), 64);
        assert!(batch[0].linux_path.iter().all(|&c| c == 0));
        assert_eq!(batch[0].op, 0);
    }

    /// The block header this reads `invoke` from is the Block ABI's: `isa`,
    /// `flags`, `reserved`, `invoke` at sixteen bytes.
    #[test]
    fn invoke_is_at_the_block_abis_offset() {
        assert_eq!(std::mem::offset_of!(apple::BlockHeader, invoke), 16);
        assert_eq!(std::mem::offset_of!(apple::BlockHeader, descriptor), 24);
    }
}
