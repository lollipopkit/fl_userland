//! The guest's `siginfo_t` and `sigval`: a wire format, 128 bytes.
//!
//! **A crate of its own since 2026-09-29**, for the reason
//! `crates/util/identity` is one. It was `crates/kernel/abi`'s
//! `signal_types.rs`, and `crates/kernel/sigqueue` depended on that whole
//! crate for this one type. That edge is what kept three of `struct fd`'s state
//! pointers opaque: `kernel-eventfd`, `fs-pipe` and `fs-tty` each run their
//! tests against the real `wait_for`, which reaches `kernel-sigqueue`, so
//! `kernel-abi` naming any of them would have been a cycle through a
//! dev-dependency. `kernel-abi` re-exports everything here, so no caller moved.

#![allow(non_camel_case_types)]

use emu_abi::{addr_t, dword_t, int_t, sdword_t, sqword_t};

/// `pid_t`, as `crates/kernel/abi` spells it. The same `i32`.
type pid_t_ = sdword_t;
/// `uid_t`, as `crates/kernel/abi` spells it. The same `u32`.
type uid_t_ = dword_t;

/* `sighand` and `sigqueue_state` were field-less `#[repr(C)]` placeholders
 * here until 2026-09-11. They are `kernel_sighand::SigHand` and
 * `kernel_sigqueue::Signals`, re-exported under those names by
 * `crates/kernel/taskview`'s `task_types.rs` — which is *above* this crate,
 * because both owning crates depend on it for `siginfo_`. So neither
 * placeholder could be replaced by a re-export in place; each had to be deleted
 * here in the same commit that added the one there, or `taskview::ffi`'s two
 * glob re-exports would make the name ambiguous rather than shadowed. */
#[repr(C)]
#[derive(Copy, Clone)]
pub union sigval_ {
    pub sv_int: int_t,
    pub sv_ptr: addr_t,
}
const _: () = {
    assert!(std::mem::size_of::<sigval_>() == 8, "Size of sigval_");
    assert!(std::mem::align_of::<sigval_>() == 8, "Alignment of sigval_");
    assert!(
        std::mem::offset_of!(sigval_, sv_int) == 0,
        "Offset of field: sigval_::sv_int"
    );
    assert!(
        std::mem::offset_of!(sigval_, sv_ptr) == 0,
        "Offset of field: sigval_::sv_ptr"
    );
};
impl Default for sigval_ {
    fn default() -> Self {
        Self { sv_ptr: 0 }
    }
}
#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct siginfo_ {
    pub sig: int_t,
    pub sig_errno: int_t,
    pub code: int_t,
    /// Bytes 12..16, which a guest reads as zero.
    ///
    /// The union is 8-aligned, so these four bytes were **padding** until
    /// 2026-09-30, and padding is not part of a value: `SigInfo { code, ..
    /// SigInfo::default() }` zeroed the fields and left these four bytes
    /// whatever the stack held, and every move of a `siginfo_` is free to do
    /// the same. `as_bytes` then handed them to the guest -- `sigtimedwait`,
    /// `waitid` and the signal frame copy all 128 bytes -- so a guest read four
    /// bytes of host stack where Linux's `clear_siginfo` gives it zeros, and
    /// reading them at all was undefined behaviour. A field is part of the
    /// value, so every construction and every move carries it.
    pub _pad0: int_t,
    pub __bindgen_anon_1: siginfo___bindgen_ty_1,
}
impl siginfo_ {
    /// The guest's 128 bytes, as the struct -- the header's four words and
    /// the union as its padding member, which every other member overlays.
    ///
    /// Safe, and a copy. It was the buffer's address cast to
    /// `*const siginfo_` and read through, which needed the buffer to be
    /// 8-aligned and a wrapper type to say so; decoding field by field needs
    /// neither.
    pub fn from_le_bytes(bytes: &[u8; 128]) -> siginfo_ {
        let word = |at: usize| int_t::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let mut pad = [0 as std::ffi::c_char; 112];
        for (to, from) in pad.iter_mut().zip(&bytes[16..]) {
            *to = *from as std::ffi::c_char;
        }
        siginfo_ {
            sig: word(0),
            sig_errno: word(4),
            code: word(8),
            _pad0: word(12),
            __bindgen_anon_1: siginfo___bindgen_ty_1 { _pad: pad },
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union siginfo___bindgen_ty_1 {
    pub kill: siginfo___bindgen_ty_1__bindgen_ty_1,
    pub child: siginfo___bindgen_ty_1__bindgen_ty_2,
    pub fault: siginfo___bindgen_ty_1__bindgen_ty_3,
    pub sigsys: siginfo___bindgen_ty_1__bindgen_ty_4,
    pub timer: siginfo___bindgen_ty_1__bindgen_ty_5,
    pub _pad: [std::ffi::c_char; 112usize],
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct siginfo___bindgen_ty_1__bindgen_ty_1 {
    pub pid: pid_t_,
    pub uid: uid_t_,
}
const _: () = {
    assert!(
        std::mem::size_of::<siginfo___bindgen_ty_1__bindgen_ty_1>() == 8,
        "Size of siginfo___bindgen_ty_1__bindgen_ty_1"
    );
    assert!(
        std::mem::align_of::<siginfo___bindgen_ty_1__bindgen_ty_1>() == 4,
        "Alignment of siginfo___bindgen_ty_1__bindgen_ty_1"
    );
    assert!(
        std::mem::offset_of!(siginfo___bindgen_ty_1__bindgen_ty_1, pid) == 0,
        "Offset of field: siginfo___bindgen_ty_1__bindgen_ty_1::pid"
    );
    assert!(
        std::mem::offset_of!(siginfo___bindgen_ty_1__bindgen_ty_1, uid) == 4,
        "Offset of field: siginfo___bindgen_ty_1__bindgen_ty_1::uid"
    );
};
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct siginfo___bindgen_ty_1__bindgen_ty_2 {
    pub pid: pid_t_,
    pub uid: uid_t_,
    pub status: int_t,
    pub utime: sqword_t,
    pub stime: sqword_t,
}
const _: () = {
    assert!(
        std::mem::size_of::<siginfo___bindgen_ty_1__bindgen_ty_2>() == 32,
        "Size of siginfo___bindgen_ty_1__bindgen_ty_2"
    );
    assert!(
        std::mem::align_of::<siginfo___bindgen_ty_1__bindgen_ty_2>() == 8,
        "Alignment of siginfo___bindgen_ty_1__bindgen_ty_2"
    );
    assert!(
        std::mem::offset_of!(siginfo___bindgen_ty_1__bindgen_ty_2, pid) == 0,
        "Offset of field: siginfo___bindgen_ty_1__bindgen_ty_2::pid"
    );
    assert!(
        std::mem::offset_of!(siginfo___bindgen_ty_1__bindgen_ty_2, uid) == 4,
        "Offset of field: siginfo___bindgen_ty_1__bindgen_ty_2::uid"
    );
    assert!(
        std::mem::offset_of!(siginfo___bindgen_ty_1__bindgen_ty_2, status) == 8,
        "Offset of field: siginfo___bindgen_ty_1__bindgen_ty_2::status"
    );
    assert!(
        std::mem::offset_of!(siginfo___bindgen_ty_1__bindgen_ty_2, utime) == 16,
        "Offset of field: siginfo___bindgen_ty_1__bindgen_ty_2::utime"
    );
    assert!(
        std::mem::offset_of!(siginfo___bindgen_ty_1__bindgen_ty_2, stime) == 24,
        "Offset of field: siginfo___bindgen_ty_1__bindgen_ty_2::stime"
    );
};
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct siginfo___bindgen_ty_1__bindgen_ty_3 {
    pub addr: addr_t,
}
const _: () = {
    assert!(
        std::mem::size_of::<siginfo___bindgen_ty_1__bindgen_ty_3>() == 8,
        "Size of siginfo___bindgen_ty_1__bindgen_ty_3"
    );
    assert!(
        std::mem::align_of::<siginfo___bindgen_ty_1__bindgen_ty_3>() == 8,
        "Alignment of siginfo___bindgen_ty_1__bindgen_ty_3"
    );
    assert!(
        std::mem::offset_of!(siginfo___bindgen_ty_1__bindgen_ty_3, addr) == 0,
        "Offset of field: siginfo___bindgen_ty_1__bindgen_ty_3::addr"
    );
};
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct siginfo___bindgen_ty_1__bindgen_ty_4 {
    pub addr: addr_t,
    pub syscall: int_t,
}
const _: () = {
    assert!(
        std::mem::size_of::<siginfo___bindgen_ty_1__bindgen_ty_4>() == 16,
        "Size of siginfo___bindgen_ty_1__bindgen_ty_4"
    );
    assert!(
        std::mem::align_of::<siginfo___bindgen_ty_1__bindgen_ty_4>() == 8,
        "Alignment of siginfo___bindgen_ty_1__bindgen_ty_4"
    );
    assert!(
        std::mem::offset_of!(siginfo___bindgen_ty_1__bindgen_ty_4, addr) == 0,
        "Offset of field: siginfo___bindgen_ty_1__bindgen_ty_4::addr"
    );
    assert!(
        std::mem::offset_of!(siginfo___bindgen_ty_1__bindgen_ty_4, syscall) == 8,
        "Offset of field: siginfo___bindgen_ty_1__bindgen_ty_4::syscall"
    );
};
#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct siginfo___bindgen_ty_1__bindgen_ty_5 {
    pub timer: int_t,
    pub overrun: int_t,
    pub value: sigval_,
    pub _private: int_t,
}
const _: () = {
    assert!(
        std::mem::size_of::<siginfo___bindgen_ty_1__bindgen_ty_5>() == 24,
        "Size of siginfo___bindgen_ty_1__bindgen_ty_5"
    );
    assert!(
        std::mem::align_of::<siginfo___bindgen_ty_1__bindgen_ty_5>() == 8,
        "Alignment of siginfo___bindgen_ty_1__bindgen_ty_5"
    );
    assert!(
        std::mem::offset_of!(siginfo___bindgen_ty_1__bindgen_ty_5, timer) == 0,
        "Offset of field: siginfo___bindgen_ty_1__bindgen_ty_5::timer"
    );
    assert!(
        std::mem::offset_of!(siginfo___bindgen_ty_1__bindgen_ty_5, overrun) == 4,
        "Offset of field: siginfo___bindgen_ty_1__bindgen_ty_5::overrun"
    );
    assert!(
        std::mem::offset_of!(siginfo___bindgen_ty_1__bindgen_ty_5, value) == 8,
        "Offset of field: siginfo___bindgen_ty_1__bindgen_ty_5::value"
    );
    assert!(
        std::mem::offset_of!(siginfo___bindgen_ty_1__bindgen_ty_5, _private) == 16,
        "Offset of field: siginfo___bindgen_ty_1__bindgen_ty_5::_private"
    );
};
const _: () = {
    assert!(
        std::mem::size_of::<siginfo___bindgen_ty_1>() == 112,
        "Size of siginfo___bindgen_ty_1"
    );
    assert!(
        std::mem::align_of::<siginfo___bindgen_ty_1>() == 8,
        "Alignment of siginfo___bindgen_ty_1"
    );
    assert!(
        std::mem::offset_of!(siginfo___bindgen_ty_1, kill) == 0,
        "Offset of field: siginfo___bindgen_ty_1::kill"
    );
    assert!(
        std::mem::offset_of!(siginfo___bindgen_ty_1, child) == 0,
        "Offset of field: siginfo___bindgen_ty_1::child"
    );
    assert!(
        std::mem::offset_of!(siginfo___bindgen_ty_1, fault) == 0,
        "Offset of field: siginfo___bindgen_ty_1::fault"
    );
    assert!(
        std::mem::offset_of!(siginfo___bindgen_ty_1, sigsys) == 0,
        "Offset of field: siginfo___bindgen_ty_1::sigsys"
    );
    assert!(
        std::mem::offset_of!(siginfo___bindgen_ty_1, timer) == 0,
        "Offset of field: siginfo___bindgen_ty_1::timer"
    );
    assert!(
        std::mem::offset_of!(siginfo___bindgen_ty_1, _pad) == 0,
        "Offset of field: siginfo___bindgen_ty_1::_pad"
    );
};
impl Default for siginfo___bindgen_ty_1 {
    fn default() -> Self {
        Self { _pad: [0; 112] }
    }
}
const _: () = {
    assert!(std::mem::size_of::<siginfo_>() == 128, "Size of siginfo_");
    assert!(
        std::mem::align_of::<siginfo_>() == 8,
        "Alignment of siginfo_"
    );
    assert!(
        std::mem::offset_of!(siginfo_, sig) == 0,
        "Offset of field: siginfo_::sig"
    );
    assert!(
        std::mem::offset_of!(siginfo_, sig_errno) == 4,
        "Offset of field: siginfo_::sig_errno"
    );
    assert!(
        std::mem::offset_of!(siginfo_, code) == 8,
        "Offset of field: siginfo_::code"
    );
    assert!(
        std::mem::offset_of!(siginfo_, _pad0) == 12,
        "Offset of field: siginfo_::_pad0"
    );
    assert!(
        std::mem::offset_of!(siginfo_, __bindgen_anon_1) == 16,
        "Offset of field: siginfo_::__bindgen_anon_1"
    );
    // Every byte is a field's: the sum of the parts is the whole, so there is
    // no padding for a move to leave uninitialised.
    assert!(
        std::mem::size_of::<siginfo_>()
            == 4 * std::mem::size_of::<int_t>() + std::mem::size_of::<siginfo___bindgen_ty_1>(),
        "siginfo_ has padding"
    );
};
