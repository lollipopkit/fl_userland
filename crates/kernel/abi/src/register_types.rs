//! Guest register layouts used by ptrace and process execution.

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct user_regs_struct_ {
    pub regs: [u64; 31usize],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}
const _: () = {
    assert!(
        std::mem::size_of::<user_regs_struct_>() == 272,
        "Size of user_regs_struct_"
    );
    assert!(
        std::mem::align_of::<user_regs_struct_>() == 8,
        "Alignment of user_regs_struct_"
    );
    assert!(
        std::mem::offset_of!(user_regs_struct_, regs) == 0,
        "Offset of field: user_regs_struct_::regs"
    );
    assert!(
        std::mem::offset_of!(user_regs_struct_, sp) == 248,
        "Offset of field: user_regs_struct_::sp"
    );
    assert!(
        std::mem::offset_of!(user_regs_struct_, pc) == 256,
        "Offset of field: user_regs_struct_::pc"
    );
    assert!(
        std::mem::offset_of!(user_regs_struct_, pstate) == 264,
        "Offset of field: user_regs_struct_::pstate"
    );
};
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct user_fpsimd_state_ {
    pub vregs: [[u64; 2usize]; 32usize],
    pub fpsr: u32,
    pub fpcr: u32,
    pub __reserved: [u32; 2usize],
}
const _: () = {
    assert!(
        std::mem::size_of::<user_fpsimd_state_>() == 528,
        "Size of user_fpsimd_state_"
    );
    assert!(
        std::mem::align_of::<user_fpsimd_state_>() == 8,
        "Alignment of user_fpsimd_state_"
    );
    assert!(
        std::mem::offset_of!(user_fpsimd_state_, vregs) == 0,
        "Offset of field: user_fpsimd_state_::vregs"
    );
    assert!(
        std::mem::offset_of!(user_fpsimd_state_, fpsr) == 512,
        "Offset of field: user_fpsimd_state_::fpsr"
    );
    assert!(
        std::mem::offset_of!(user_fpsimd_state_, fpcr) == 516,
        "Offset of field: user_fpsimd_state_::fpcr"
    );
    assert!(
        std::mem::offset_of!(user_fpsimd_state_, __reserved) == 520,
        "Offset of field: user_fpsimd_state_::__reserved"
    );
};

plain::plain! {
    user_regs_struct_ { regs, sp, pc, pstate }
    user_fpsimd_state_ { vregs, fpsr, fpcr, __reserved }
}
