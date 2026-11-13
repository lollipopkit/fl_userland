//! Starting a block, ending one, and the two ways to end one early.
//!
//! A `struct fiber_block` is a header followed by a flat array of `unsigned
//! long`: gadget addresses and the operands each reads after itself. It is one
//! allocation, `fiber_block::alloc`, made by `gen_end` once the code is known,
//! and freed by `fiber_block::free`.
//!
//! # The jump slots are recorded as indices and become pointers here
//!
//! A block that ends in a branch emits the destination as a *value* with bit
//! 63 set, and the block cache overwrites that word with a pointer to the
//! next block's code when it chains the two. To find the word again it needs a
//! pointer to it, and it cannot have one while the block is still being built:
//! the block does not exist yet. So the decoder records an **index** and this
//! turns it into a pointer once it does.

use crate::ffi;
use crate::gadgets::*;
use offloadprebuilt::SpecFn;

/// Make the block: one allocation of the header and the code, the jump slots
/// resolved, the block's own address filled in where a call gadget needs it,
/// and the address range it covers recorded. `None` if the allocation fails.
pub(crate) fn gen_end(st: &crate::State) -> Option<std::ptr::NonNull<ffi::fiber_block>> {
    let header = ffi::fiber_block {
        addr: st.addr,
        // A block that compiled nothing covers one address; otherwise it ends
        // at the last byte it consumed, which is one before where the decoder
        // stopped.
        end_addr: if st.addr != st.ip { st.ip - 1 } else { st.addr },
        used: 0,
        jump_ip: [std::ptr::null_mut(); 2],
        old_jump_ip: [0; 2],
        hash_next: std::ptr::null_mut(),
        is_jetsam: false.into(),
        code: [],
    };
    let block = ffi::fiber_block::alloc(header, &st.code)?;
    let b = block.as_ptr();
    let code = ffi::fiber_block::code(b);
    // SAFETY: `b` is fresh and nothing else has it; every index below is one
    // the decoder recorded into `st.code`, so inside the block.
    unsafe {
        for (i, &at) in st.jump_ip.iter().enumerate() {
            if at != 0 {
                (*b).jump_ip[i] = code.add(at as usize);
                (*b).old_jump_ip[i] = st.code[at as usize];
            }
        }
        if st.block_patch_ip != 0 {
            *code.add(st.block_patch_ip as usize) = b as usize as u64;
        }
    }
    Some(block)
}

/// End the block by leaving the interpreter, at whatever address the decoder
/// stopped on.
pub(crate) fn gen_exit(b: &mut crate::Builder) {
    let mut g = b.decoder();
    let ip = g.ip();
    g.gadget(gadget_exit);
    g.emit(ip);
}

/// Emit a block that is one gadget: run a host implementation of a whole guest
/// function and resume at the guest's link register.
///
/// The layout is what `gadget_prebuilt_entry` in `control.S` reads:
/// the gadget, then the function. See `crates/asbestos/offloadsym`.
///
/// `spec_fn` is a `void (*)(cpu, tlb)` that stays valid for as long as the
/// block does -- the registry leaks its entries for that reason. Emitting it
/// is a word; the gadget is what calls it.
pub(crate) fn gen_prebuilt_block(b: &mut crate::Builder, spec_fn: SpecFn) {
    let mut g = b.decoder();
    g.gadget(gadget_prebuilt_entry);
    g.emit(spec_fn as usize as u64);
}
