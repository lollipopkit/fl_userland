//! C-layout data types shared by the emulator, JIT, and assembly.

use super::{addr_t, cpu_state, page_t};

#[repr(C)]
#[derive(Debug, Default)]
pub struct mmu {
    pub asbestos: *mut asbestos,
    /// Every mapping change, counted. Written by the thread that changes the
    /// mapping and read by every thread's TLB, so atomic -- an `AtomicU64`
    /// since 2026-10-16, where it was a `u64` that every Rust access reached
    /// through `AtomicU64::from_ptr`. The gadgets read it with a plain `ldr`.
    pub changes: std::sync::atomic::AtomicU64,
    /// Whether something is waiting to change this address space, from the
    /// write lock that guards it. Null until the owner sets it.
    ///
    /// The JIT holds that lock for **reading** while it runs, and the writer
    /// cannot block — `crates/util/locks`'s `wrlock` explains the deadlock — so
    /// the only way a writer gets in is for the reader to let go. Reading this
    /// in the dispatch loop is what tells it when to bother: with nobody
    /// waiting it keeps the lock and runs, and when somebody is it ends its
    /// quantum at the next block. One shared, almost-never-written word against
    /// a lock release and re-acquire on every quantum.
    pub writers_waiting: *const std::sync::atomic::AtomicI32,
}
const _: () = {
    assert!(std::mem::size_of::<mmu>() == 24, "Size of mmu");
    assert!(std::mem::align_of::<mmu>() == 8, "Alignment of mmu");
    assert!(
        std::mem::offset_of!(mmu, asbestos) == 0,
        "Offset of field: mmu::asbestos"
    );
    assert!(
        std::mem::offset_of!(mmu, changes) == 8,
        "Offset of field: mmu::changes"
    );
    assert!(
        std::mem::offset_of!(mmu, writers_waiting) == 16,
        "Offset of field: mmu::writers_waiting"
    );
};
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct tlb_entry {
    pub page: page_t,
    pub page_if_writable: page_t,
    pub data_minus_addr: usize,
    /// The coherence generation: a snapshot of `mmu.changes` when this entry
    /// was populated, which is how a stale entry is detected — a page remapped
    /// by copy-on-write, `mmap` or `munmap` on another thread while this one
    /// was mid-block.
    ///
    /// It sits in what used to be the 32-byte padding slot, because the
    /// assembly indexes entries by `lsl #5`.
    pub gen_: usize,
}
const _: () = {
    assert!(std::mem::size_of::<tlb_entry>() == 32, "Size of tlb_entry");
    assert!(
        std::mem::align_of::<tlb_entry>() == 8,
        "Alignment of tlb_entry"
    );
    assert!(
        std::mem::offset_of!(tlb_entry, page) == 0,
        "Offset of field: tlb_entry::page"
    );
    assert!(
        std::mem::offset_of!(tlb_entry, page_if_writable) == 8,
        "Offset of field: tlb_entry::page_if_writable"
    );
    assert!(
        std::mem::offset_of!(tlb_entry, data_minus_addr) == 16,
        "Offset of field: tlb_entry::data_minus_addr"
    );
    assert!(
        std::mem::offset_of!(tlb_entry, gen_) == 24,
        "Offset of field: tlb_entry::gen_"
    );
};
/// No `Copy` since 2026-10-01: it owns its frame, and a 288 KB `Copy` was
/// never a thing to want.
#[repr(C)]
pub struct tlb {
    pub mmu: *mut mmu,
    pub dirty_page: page_t,
    pub mem_changes: std::ffi::c_uint,
    /// One of the return values of `tlb_handle_miss`, `tlb_read`/`tlb_write`
    /// and the two cross-page helpers, carried in the struct because the
    /// assembly's calling convention has nowhere else to put it. `emu/tlb.h`
    /// said "yes, this sucks" and it is still true.
    pub segfault_addr: addr_t,
    pub entries: [tlb_entry; 8192usize],
    /// A block cache that survives a syscall, so the dispatch loop does not
    /// look a block up again after every interrupt. Its size must match
    /// `FIBER_CACHE_SIZE`.
    pub block_cache: [*mut fiber_block; 4096usize],
    /// Tracks `asbestos.invalidate_gen`, which is how [`tlb::block_cache`] is
    /// invalidated.
    pub block_cache_gen: std::ffi::c_uint,
    /// A frame that survives a syscall, which is what stops a `malloc`, a
    /// `free` and a 48 KB zeroing of the return cache on every one.
    ///
    /// Owned since 2026-10-01: a `*mut` from `libc::calloc` that `tlb_free`
    /// and `tlb_refresh` each `libc::free`d by hand. `None` is the all-zero
    /// bit pattern, which is what `tlb_new`'s zeroed allocation relies on.
    pub frame: Option<Box<fiber_frame>>,
}
const _: () = {
    assert!(std::mem::size_of::<tlb>() == 294960, "Size of tlb");
    assert!(std::mem::align_of::<tlb>() == 8, "Alignment of tlb");
    assert!(
        std::mem::offset_of!(tlb, mmu) == 0,
        "Offset of field: tlb::mmu"
    );
    assert!(
        std::mem::offset_of!(tlb, dirty_page) == 8,
        "Offset of field: tlb::dirty_page"
    );
    assert!(
        std::mem::offset_of!(tlb, mem_changes) == 16,
        "Offset of field: tlb::mem_changes"
    );
    assert!(
        std::mem::offset_of!(tlb, segfault_addr) == 24,
        "Offset of field: tlb::segfault_addr"
    );
    assert!(
        std::mem::offset_of!(tlb, entries) == 32,
        "Offset of field: tlb::entries"
    );
    assert!(
        std::mem::offset_of!(tlb, block_cache) == 262176,
        "Offset of field: tlb::block_cache"
    );
    assert!(
        std::mem::offset_of!(tlb, block_cache_gen) == 294944,
        "Offset of field: tlb::block_cache_gen"
    );
    assert!(
        std::mem::offset_of!(tlb, frame) == 294952,
        "Offset of field: tlb::frame"
    );
};
impl Default for tlb {
    fn default() -> Self {
        let mut s = std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}

pub const INT_MAX: u32 = 2147483647;

pub const INT_MIN: i32 = -2147483648;

pub const PREBUILT_SENTINEL: u64 = 281474976706560;

pub const FIBER_INITIAL_HASH_SIZE: u32 = 1024;

pub const FIBER_CACHE_SIZE: u32 = 4096;

pub const FIBER_PAGE_HASH_SIZE: u32 = 1024;


pub const FIBER_RETURN_CACHE_SIZE: u32 = 4096;

pub const INT_NONE: i32 = -1;

pub const INT_DIV: u32 = 0;

pub const INT_DEBUG: u32 = 1;

pub const INT_NMI: u32 = 2;

pub const INT_BREAKPOINT: u32 = 3;

pub const INT_OVERFLOW: u32 = 4;

pub const INT_BOUND: u32 = 5;

pub const INT_UNDEFINED: u32 = 6;

pub const INT_FPU: u32 = 7;

pub const INT_DOUBLE: u32 = 8;

pub const INT_GPF: u32 = 13;

pub const INT_TIMER: u32 = 32;

pub const INT_SYSCALL: u32 = 128;

pub const INT_JIT_CRASH: u32 = 256;

pub const INT_PREBUILT_RET: u32 = 512;

pub type sqword_t = i64;

pub type qword_t = u64;

pub type dword_t = u32;

pub type sdword_t = i32;

pub type word_t = u16;

pub type byte_t = u8;

pub type uint_t = dword_t;

pub type int_t = sdword_t;

/// What `struct mmu` points at: `asbestos_blockcache::Asbestos`, opaque here.
///
/// A placeholder since 2026-10-17. It was the struct itself, `#[repr(C)]` with
/// the cache behind a `*mut c_void` and its lock a separate field, because
/// `struct mmu` -- this crate's -- has to name it and `crates/asbestos/blockcache`
/// is above this crate. Nothing in the assembly reads it, so the layout was
/// never a contract; `Asbestos::of` is the one cast back.
#[repr(C)]
pub struct asbestos {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct fiber_block {
    pub addr: addr_t,
    pub end_addr: addr_t,
    pub used: usize,
    pub jump_ip: [*mut std::ffi::c_ulong; 2usize],
    pub old_jump_ip: [std::ffi::c_ulong; 2usize],
    pub hash_next: *mut fiber_block,
    /// Set under the cache lock when the block is invalidated, and read
    /// **without** it by the dispatch loop before it tries to chain -- so an
    /// atomic since 2026-10-17. It was a `bool`, and that read raced the
    /// write: undefined behaviour however harmless the hint it reads.
    pub is_jetsam: std::sync::atomic::AtomicBool,
    pub code: [std::ffi::c_ulong; 0],
}
const _: () = {
    assert!(
        std::mem::size_of::<fiber_block>() == 72,
        "Size of fiber_block"
    );
    assert!(
        std::mem::align_of::<fiber_block>() == 8,
        "Alignment of fiber_block"
    );
    assert!(
        std::mem::offset_of!(fiber_block, addr) == 0,
        "Offset of field: fiber_block::addr"
    );
    assert!(
        std::mem::offset_of!(fiber_block, end_addr) == 8,
        "Offset of field: fiber_block::end_addr"
    );
    assert!(
        std::mem::offset_of!(fiber_block, used) == 16,
        "Offset of field: fiber_block::used"
    );
    assert!(
        std::mem::offset_of!(fiber_block, jump_ip) == 24,
        "Offset of field: fiber_block::jump_ip"
    );
    assert!(
        std::mem::offset_of!(fiber_block, old_jump_ip) == 40,
        "Offset of field: fiber_block::old_jump_ip"
    );
    assert!(
        std::mem::offset_of!(fiber_block, hash_next) == 56,
        "Offset of field: fiber_block::hash_next"
    );
    assert!(
        std::mem::offset_of!(fiber_block, is_jetsam) == 64,
        "Offset of field: fiber_block::is_jetsam"
    );
    assert!(
        std::mem::offset_of!(fiber_block, code) == 72,
        "Offset of field: fiber_block::code"
    );
    // The code follows the header with no padding, which `fiber_block::layout`
    // relies on.
    assert!(std::mem::offset_of!(fiber_block, code) == std::mem::size_of::<fiber_block>());
};

/// A block is one allocation: the header, then `used` code words. Made here
/// and freed here, so the two agree on the layout; `used` is what `free`
/// recovers it from, and nothing writes it after `alloc`.
///
/// Not a `Box`: the code's length is not in the type, and a `Box<[u64]>`
/// beside the header would be a second allocation the gadgets follow on every
/// instruction. So `free` runs no destructor, and this is the tripwire for a
/// header field that grows one.
const _: () = assert!(
    !std::mem::needs_drop::<fiber_block>(),
    "a field of `struct fiber_block` has grown a destructor, and \
     `fiber_block::free` runs none: the field has to release itself, or move \
     out of the header."
);

impl fiber_block {
    fn layout(words: usize) -> std::alloc::Layout {
        let code = std::alloc::Layout::array::<std::ffi::c_ulong>(words).expect("block size");
        std::alloc::Layout::new::<Self>().extend(code).expect("block size").0
    }

    /// `header` followed by `code`, with `used` set to `code.len()`. `None` if
    /// the allocation fails.
    pub fn alloc(mut header: Self, code: &[std::ffi::c_ulong]) -> Option<std::ptr::NonNull<Self>> {
        header.used = code.len();
        // SAFETY: the layout is never zero-sized: the header is 72 bytes.
        let b = std::ptr::NonNull::new(unsafe { std::alloc::alloc(Self::layout(code.len())) }.cast::<Self>())?;
        // SAFETY: `b` is fresh, sized for the header and `code.len()` words.
        unsafe {
            b.write(header);
            std::ptr::copy_nonoverlapping(code.as_ptr(), Self::code(b.as_ptr()), code.len());
        }
        Some(b)
    }

    /// The first code word of `b`.
    pub fn code(b: *mut Self) -> *mut std::ffi::c_ulong {
        b.wrapping_byte_add(std::mem::offset_of!(Self, code)).cast()
    }

    /// # Safety
    /// `b` came from [`fiber_block::alloc`], and nothing executes or refers to
    /// it any more.
    pub unsafe fn free(b: *mut Self) {
        // SAFETY: the caller's contract; `used` is what `alloc` sized it by.
        unsafe { std::alloc::dealloc(b.cast(), Self::layout((*b).used)) }
    }
}

#[repr(C)]
#[repr(align(16))]
pub struct fiber_frame {
    pub cpu: cpu_state,
    pub bp: *mut std::ffi::c_void,
    pub value_addr: addr_t,
    pub value: [u64; 4usize],
    pub last_block: *mut fiber_block,
    pub jit_exit_sp: u64,
    pub ret_cache: [std::ffi::c_long; 4096usize],
}

impl fiber_frame {
    /// A zeroed frame on the heap: 33 KB, too large to build on a guest
    /// thread's stack and move. All-zero is a valid frame -- every field is an
    /// integer, a raw pointer, a `bool` or an array or union of those -- which
    /// is what the `libc::calloc` this replaced relied on too.
    pub fn new_boxed() -> Box<fiber_frame> {
        // SAFETY: as above.
        unsafe { Box::<fiber_frame>::new_zeroed().assume_init() }
    }
}
const _: () = {
    assert!(
        std::mem::size_of::<fiber_frame>() == 33728,
        "Size of fiber_frame"
    );
    assert!(
        std::mem::align_of::<fiber_frame>() == 16,
        "Alignment of fiber_frame"
    );
    assert!(
        std::mem::offset_of!(fiber_frame, cpu) == 0,
        "Offset of field: fiber_frame::cpu"
    );
    assert!(
        std::mem::offset_of!(fiber_frame, bp) == 896,
        "Offset of field: fiber_frame::bp"
    );
    assert!(
        std::mem::offset_of!(fiber_frame, value_addr) == 904,
        "Offset of field: fiber_frame::value_addr"
    );
    assert!(
        std::mem::offset_of!(fiber_frame, value) == 912,
        "Offset of field: fiber_frame::value"
    );
    assert!(
        std::mem::offset_of!(fiber_frame, last_block) == 944,
        "Offset of field: fiber_frame::last_block"
    );
    assert!(
        std::mem::offset_of!(fiber_frame, jit_exit_sp) == 952,
        "Offset of field: fiber_frame::jit_exit_sp"
    );
    assert!(
        std::mem::offset_of!(fiber_frame, ret_cache) == 960,
        "Offset of field: fiber_frame::ret_cache"
    );
};
impl Default for fiber_frame {
    fn default() -> Self {
        let mut s = std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}


