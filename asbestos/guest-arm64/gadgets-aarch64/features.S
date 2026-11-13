/*
 * Guest CPU features beyond ARMv8.0: LRCPC's neighbours, DotProd, I8MM, RDM,
 * FCMA, FlagM, FJCVTZS and the helpers that call into
 * `crates/asbestos/features`.
 *
 * The **host** these run on is an iPhone from the iOS 13 floor, an A9:
 * ARMv8.0-A, AdvSIMD and crypto, and none of LSE, RDM, dotprod, FP16, JSCVT,
 * LRCPC, FCMA, FlagM, I8MM or BF16. Every gadget here is therefore built out of
 * ARMv8.0 instructions, and the directive below makes the assembler refuse
 * anything newer, so that a sequence that only works on the machine it was
 * written on is a build error instead of a SIGILL on a phone.
 *
 * Code stream: every gadget reads the guest instruction word as its first
 * operand and picks the fields out itself, so the decoder does not repack them.
 */

.arch armv8-a+crypto

#include "gadgets.h"

.text

/*
 * MRS Xt, <ID register>: a constant from `asbestos_features::caps`.
 * Code stream: [gadget addr][rt][value]
 */
.gadget mrs_const
    ldr x8, [_pc]
    ldr x10, [_pc, #8]
    add _pc, _pc, #16
    and x8, x8, #0x1f
    cmp x8, #31
    b.eq 1f
    add x9, _cpu, #CPU_x0
    str x10, [x9, x8, lsl #3]
1:  gret

/*
 * DotProd: SDOT and UDOT, vector and by element.
 *
 * Each 32-bit lane of Vd gains the sum of four products of the corresponding
 * four bytes of Vn and Vm. ARMv8.0 has no dot product, so: widening multiply of
 * the low and high eight bytes (a product of two int8 or two uint8 fits 16
 * bits, but the sum of *two* of them may not, hence the widening pairwise add
 * to 32 bits), one more pairwise add to reach four terms, and an add into Vd.
 * That is 7 instructions for 16 multiplies; a scalar loop is 16 mul + 15 add.
 *
 * Q = 0 is the 64-bit form. The registers are loaded with `ldr d`, which zeroes
 * the upper half, so the products there are 0 and Vd's upper half stays 0 when
 * the result is stored whole (which is also what the instruction does to it).
 *
 * Code stream: [gadget addr][insn]
 */
.macro dot_load_vd_vn rdreg=w9
    // x9 = &Vd, x10 = &Vn, x11 = &Vm; w8 = insn
    and w9, w8, #0x1f
    ubfx w10, w8, #5, #5
    ubfx w11, w8, #16, #5
    add x12, _cpu, #CPU_fp
    add x9, x12, x9, lsl #4
    add x10, x12, x10, lsl #4
    add x11, x12, x11, lsl #4
.endm

.macro dot_reduce mul, mul2, padd
    \mul  v3.8h, v0.8b, v1.8b
    \mul2 v4.8h, v0.16b, v1.16b
    \padd v3.4s, v3.8h
    \padd v4.4s, v4.8h
    addp v3.4s, v3.4s, v4.4s
    add v2.4s, v2.4s, v3.4s
    str q2, [x9]
.endm

.macro dot_vec name, mul, mul2, padd
.gadget \name
    ldr w8, [_pc]
    add _pc, _pc, #8
    dot_load_vd_vn
    tbz w8, #30, 1f
    ldr q0, [x10]
    ldr q1, [x11]
    ldr q2, [x9]
    b 2f
1:  ldr d0, [x10]
    ldr d1, [x11]
    ldr d2, [x9]
2:  dot_reduce \mul, \mul2, \padd
    gret
.endm

.macro dot_elem name, mul, mul2, padd
.gadget \name
    ldr w8, [_pc]
    add _pc, _pc, #8
    dot_load_vd_vn
    // The element is a group of four bytes: index H:L, replicated to all lanes.
    ubfx w13, w8, #21, #1
    ubfx w14, w8, #11, #1
    orr w13, w13, w14, lsl #1
    add x11, x11, x13, lsl #2
    ld1r {v1.4s}, [x11]
    tbz w8, #30, 1f
    ldr q0, [x10]
    ldr q2, [x9]
    b 2f
1:  ldr d0, [x10]
    ldr d2, [x9]
2:  dot_reduce \mul, \mul2, \padd
    gret
.endm

dot_vec sdot_vec, smull, smull2, saddlp
dot_vec udot_vec, umull, umull2, uaddlp
dot_elem sdot_elem, smull, smull2, saddlp
dot_elem udot_elem, umull, umull2, uaddlp

/*
 * RDM: SQRDMLAH and SQRDMLSH, vector, scalar and by element, on 16- and 32-bit
 * elements.
 *
 * The result is `sat(acc + ((2ab + 2^(e-1)) >> e))` for the add and
 * `sat(acc + ((-2ab + 2^(e-1)) >> e))` for the subtract, rounded ONCE. Not
 * `sqrdmulh` then `sqadd`: that rounds the product to e bits and saturates it
 * (a = b = -2^(e-1) gives 2^(e-1) - 1 and raises QC) before adding, and for the
 * subtract `-sqrdmulh(a, b)` rounds half the other way. So the product is
 * formed exactly (`smull`, 2e bits), rounded and shifted by e-1 (`srshr`,
 * which is (p + 2^(e-2)) >> (e-1), exactly half of the doubled form), widened
 * accumulator added without overflow (`saddw`), and only then narrowed with
 * saturation (`sqxtn`, the one place QC is set).
 *
 * Code stream: [gadget addr][insn | mode << 32]
 * mode: bit 0 subtract, bit 1 by element, bit 2 scalar.
 */
.macro rdm_gadget name, esz
.gadget \name
    ldr x8, [_pc]
    add _pc, _pc, #8
    lsr x13, x8, #32
    dot_load_vd_vn
    tbnz w13, #2, 10f
    tbz w8, #30, 11f
    ldr q0, [x10]
    ldr q1, [x11]
    ldr q2, [x9]
    b 12f
11: ldr d0, [x10]
    ldr d1, [x11]
    ldr d2, [x9]
    b 12f
10:
  .if \esz == 16
    ldr h0, [x10]
    ldr h1, [x11]
    ldr h2, [x9]
  .else
    ldr s0, [x10]
    ldr s1, [x11]
    ldr s2, [x9]
  .endif
12: tbz w13, #1, 13f
  .if \esz == 16
    // Rm is four bits; the index is H:L:M.
    ubfx w11, w8, #16, #4
    add x11, x12, x11, lsl #4
    ubfx w14, w8, #20, #1
    ubfx w15, w8, #21, #1
    orr w14, w14, w15, lsl #1
    ubfx w15, w8, #11, #1
    orr w14, w14, w15, lsl #2
    add x11, x11, x14, lsl #1
    ld1r {v1.8h}, [x11]
  .else
    // Rm is five bits (M is its top bit); the index is H:L.
    ubfx w14, w8, #21, #1
    ubfx w15, w8, #11, #1
    orr w14, w14, w15, lsl #1
    add x11, x11, x14, lsl #2
    ld1r {v1.4s}, [x11]
  .endif
13:
  .if \esz == 16
    smull  v3.4s, v0.4h, v1.4h
    smull2 v4.4s, v0.8h, v1.8h
    tbz w13, #0, 14f
    neg v3.4s, v3.4s
    neg v4.4s, v4.4s
14: srshr v3.4s, v3.4s, #15
    srshr v4.4s, v4.4s, #15
    saddw  v3.4s, v3.4s, v2.4h
    saddw2 v4.4s, v4.4s, v2.8h
    sqxtn  v5.4h, v3.4s
    sqxtn2 v5.8h, v4.4s
  .else
    smull  v3.2d, v0.2s, v1.2s
    smull2 v4.2d, v0.4s, v1.4s
    tbz w13, #0, 14f
    neg v3.2d, v3.2d
    neg v4.2d, v4.2d
14: srshr v3.2d, v3.2d, #31
    srshr v4.2d, v4.2d, #31
    saddw  v3.2d, v3.2d, v2.2s
    saddw2 v4.2d, v4.2d, v2.4s
    sqxtn  v5.2s, v3.2d
    sqxtn2 v5.4s, v4.2d
  .endif
    str q5, [x9]
    gret
.endm

rdm_gadget rdm_h, 16
rdm_gadget rdm_s, 32

/*
 * FCMA: FCMLA (vector and by element) and FCADD on single and double
 * precision complex numbers, the real part in the even lane.
 *
 * FCMLA is one fused multiply-add per lane, so ARMv8.0's `fmla` does it once the
 * operands are arranged: the multiplicand is the real (trn1) or imaginary (trn2)
 * part of Vn duplicated across the pair, and the multiplier is Vm, or Vm with
 * its pair swapped for the odd rotations, sign-flipped where the rotation says
 * so. The flip is on **Vm**, as the pseudocode has it (`FPNeg(operand2[..])`),
 * and it is an exclusive-or with the sign bit, so a NaN in Vm comes out with
 * its sign flipped: negating Vn's side instead gave the right numbers and the
 * wrong NaN sign, which the differential against a real kernel caught. The FPCR
 * modes and the exception flags are `fmla`'s own.
 *
 *   rot 0    n' = [n.re, n.re]  m' = [ m.re,  m.im]
 *   rot 90   n' = [n.im, n.im]  m' = [-m.im,  m.re]
 *   rot 180  n' = [n.re, n.re]  m' = [-m.re, -m.im]
 *   rot 270  n' = [n.im, n.im]  m' = [ m.im, -m.re]
 *
 * FCADD rotates Vm by 90 or 270 and adds Vn: m'' = [-m.im, m.re] or
 * [m.im, -m.re], then `fadd`. Negation then add, not subtract: FPSub returns a
 * NaN operand unnegated and FPAdd(x, FPNeg(y)) does not.
 *
 * The 64-bit forms (Q = 0, single precision only) compute on zeroed upper lanes,
 * where a round-toward-minus-infinity `0 + -0` is -0, so the upper half is
 * cleared before the store.
 *
 * Code stream: [gadget addr][insn]
 */
.macro complex_load elem
    ldr w8, [_pc]
    add _pc, _pc, #8
    dot_load_vd_vn
    tbz w8, #30, 1f
    ldr q0, [x10]
    ldr q2, [x9]
  .if \elem
    // The multiplier is one complex number, the H'th pair of Vm, replicated.
    ubfx w14, w8, #11, #1
    add x11, x11, x14, lsl #3
    ld1r {v1.2d}, [x11]
  .else
    ldr q1, [x11]
  .endif
    b 2f
1:  ldr d0, [x10]
    ldr d2, [x9]
  .if \elem
    ubfx w14, w8, #11, #1
    add x11, x11, x14, lsl #3
    ld1r {v1.2d}, [x11]
  .else
    ldr d1, [x11]
  .endif
2:
.endm

.macro complex_store
    tbnz w8, #30, 3f
    fmov d2, d2
3:  str q2, [x9]
.endm

.gadget fcmla_s
    complex_load 0
    ubfx w14, w8, #11, #2
    b fcmla_s_compute
.gadget fcmla_elem_s
    complex_load 1
    ubfx w14, w8, #13, #2
fcmla_s_compute:
    tbz w14, #0, 4f
    trn2 v3.4s, v0.4s, v0.4s
    rev64 v1.4s, v1.4s
    movi v6.2d, #0xffffffff
    movi v7.4s, #0x80, lsl #24
    and v6.16b, v6.16b, v7.16b
    tbz w14, #1, 5f
    shl v6.2d, v6.2d, #32
5:  eor v1.16b, v1.16b, v6.16b
    b 6f
4:  trn1 v3.4s, v0.4s, v0.4s
    tbz w14, #1, 6f
    fneg v1.4s, v1.4s
6:  fmla v2.4s, v3.4s, v1.4s
    complex_store
    gret

.gadget fcmla_d
    complex_load 0
    ubfx w14, w8, #11, #2
    tbz w14, #0, 4f
    trn2 v3.2d, v0.2d, v0.2d
    ext v1.16b, v1.16b, v1.16b, #8
    movz x15, #0x8000, lsl #48
    movi v6.2d, #0
    tbz w14, #1, 5f
    mov v6.d[1], x15
    b 7f
5:  mov v6.d[0], x15
7:  eor v1.16b, v1.16b, v6.16b
    b 6f
4:  trn1 v3.2d, v0.2d, v0.2d
    tbz w14, #1, 6f
    fneg v1.2d, v1.2d
6:  fmla v2.2d, v3.2d, v1.2d
    complex_store
    gret

/* FCADD: rotation 90 (bit 12 clear) or 270. */
.gadget fcadd_s
    complex_load 0
    ubfx w14, w8, #12, #1
    rev64 v1.4s, v1.4s
    movi v6.2d, #0xffffffff
    movi v7.4s, #0x80, lsl #24
    and v6.16b, v6.16b, v7.16b
    cbz w14, 1f
    shl v6.2d, v6.2d, #32
1:  eor v1.16b, v1.16b, v6.16b
    fadd v2.4s, v0.4s, v1.4s
    complex_store
    gret

.gadget fcadd_d
    complex_load 0
    ubfx w14, w8, #12, #1
    ext v1.16b, v1.16b, v1.16b, #8
    movz x15, #0x8000, lsl #48
    movi v6.2d, #0
    cbz w14, 1f
    mov v6.d[1], x15
    b 2f
1:  mov v6.d[0], x15
2:  eor v1.16b, v1.16b, v6.16b
    fadd v2.2d, v0.2d, v1.2d
    complex_store
    gret

/*
 * FlagM and FlagM2: CFINV, AXFLAG, XAFLAG, SETF8/SETF16 and RMIF.
 *
 * The guest's flags live in `cpu->nzcv` (bits 31:28 = N Z C V) between gadgets,
 * so each of these is integer work on that word. Code stream: [gadget addr]
 * and, for SETF and RMIF, [operands].
 */
.gadget flagm_cfinv
    ldr w9, [_cpu, #CPU_nzcv]
    eor w9, w9, #0x20000000
    str w9, [_cpu, #CPU_nzcv]
    gret

// AXFLAG: Z' = Z | V, C' = C & ~V, N' = V' = 0. Arm's float compare encoding
// to the "external" one.
.gadget flagm_axflag
    ldr w9, [_cpu, #CPU_nzcv]
    ubfx w10, w9, #30, #1
    ubfx w11, w9, #28, #1
    orr w10, w10, w11
    ubfx w12, w9, #29, #1
    bic w12, w12, w11
    lsl w10, w10, #30
    orr w10, w10, w12, lsl #29
    str w10, [_cpu, #CPU_nzcv]
    gret

// XAFLAG: N' = ~C & ~Z, Z' = Z & C, C' = C | Z, V' = ~C & Z.
.gadget flagm_xaflag
    ldr w9, [_cpu, #CPU_nzcv]
    ubfx w10, w9, #30, #1       // Z
    ubfx w11, w9, #29, #1       // C
    eor w12, w10, #1
    bic w12, w12, w11           // ~C & ~Z ... (Z^1) & ~C
    and w13, w10, w11           // Z & C
    orr w14, w10, w11           // C | Z
    bic w15, w10, w11           // Z & ~C
    lsl w12, w12, #31
    orr w12, w12, w13, lsl #30
    orr w12, w12, w14, lsl #29
    orr w12, w12, w15, lsl #28
    str w12, [_cpu, #CPU_nzcv]
    gret

// SETF8/SETF16 Wn. Code stream: [gadget addr][rn | size << 8], size 0 = 8 bits.
// N = the top bit of the low byte or halfword, Z = that part is zero,
// V = the bit above it differs from it, C is unchanged.
.gadget flagm_setf
    ldr x8, [_pc]
    add _pc, _pc, #8
    and x9, x8, #0x1f
    lsr x8, x8, #8
    mov w10, #0
    cmp x9, #31
    b.eq 1f
    add x11, _cpu, #CPU_x0
    ldr x11, [x11, x9, lsl #3]
    mov w10, w11
1:  ldr w9, [_cpu, #CPU_nzcv]
    and w9, w9, #0x20000000
    cbnz x8, 2f
    ubfx w11, w10, #7, #1       // N
    ubfx w12, w10, #8, #1
    ands w13, w10, #0xff
    b 3f
2:  ubfx w11, w10, #15, #1
    ubfx w12, w10, #16, #1
    ands w13, w10, #0xffff
3:  cset w13, eq                // Z
    eor w12, w12, w11           // V
    orr w9, w9, w11, lsl #31
    orr w9, w9, w13, lsl #30
    orr w9, w9, w12, lsl #28
    str w9, [_cpu, #CPU_nzcv]
    gret

// RMIF Xn, #shift, #mask. Code stream: [gadget addr][rn | shift << 8 | mask << 16].
// The flags named by the mask take the low four bits of Xn rotated right by shift.
.gadget flagm_rmif
    ldr x8, [_pc]
    add _pc, _pc, #8
    and x9, x8, #0x1f
    ubfx x10, x8, #8, #6
    ubfx x11, x8, #16, #4
    mov x12, #0
    cmp x9, #31
    b.eq 1f
    add x13, _cpu, #CPU_x0
    ldr x12, [x13, x9, lsl #3]
1:  ror x12, x12, x10
    and w12, w12, #0xf
    lsl w12, w12, #28
    lsl w11, w11, #28
    ldr w9, [_cpu, #CPU_nzcv]
    bic w9, w9, w11
    and w12, w12, w11
    orr w9, w9, w12
    str w9, [_cpu, #CPU_nzcv]
    gret

/*
 * DIT: `PSTATE.DIT` is one byte of state, `cpu->dit`. Nothing here has
 * data-dependent timing to switch off, so setting it changes what is read back
 * and what a signal frame carries, and no more.
 */

// MSR DIT, #imm. Code stream: [gadget addr][imm]
.gadget dit_set
    ldr x8, [_pc]
    add _pc, _pc, #8
    strb w8, [_cpu, #CPU_dit]
    gret

// MSR DIT, Xt takes bit 24 of the register. Code stream: [gadget addr][rt]
.gadget dit_msr
    ldr x8, [_pc]
    add _pc, _pc, #8
    mov x10, #0
    cmp x8, #31
    b.eq 1f
    add x9, _cpu, #CPU_x0
    ldr x10, [x9, x8, lsl #3]
1:  ubfx x10, x10, #24, #1
    strb w10, [_cpu, #CPU_dit]
    gret

// MRS Xt, DIT reads bit 24, everything else zero. Code stream: [gadget addr][rt]
.gadget dit_mrs
    ldr x8, [_pc]
    add _pc, _pc, #8
    ldrb w10, [_cpu, #CPU_dit]
    lsl x10, x10, #24
    cmp x8, #31
    b.eq 1f
    add x9, _cpu, #CPU_x0
    str x10, [x9, x8, lsl #3]
1:  gret

/*
 * I8MM: USDOT and SUDOT (mixed-sign dot products) and SMMLA, UMMLA, USMMLA
 * (2x2 integer matrix multiply-accumulate).
 *
 * A product of an unsigned and a signed byte is in -32640..32385, which fits 16
 * bits but which `smull` and `umull` cannot form (they widen both operands the
 * same way), so the operands are widened to 16 bits separately (`uxtl`, `sxtl`)
 * and multiplied with `mul`, whose low 16 bits are then the whole product. The
 * rest is the DotProd reduction: pairwise widening add, then `addp`.
 *
 * MMLA: Vn and Vm are each two rows of eight bytes and Vd is the 2x2 result,
 * lane 2i+j += row i of Vn . row j of Vm. Four eight-byte dot products, each
 * reduced to a partial sum per 32-bit lane by `saddlp`, then three `addp` to
 * bring the four totals into one vector in that lane order.
 */
.macro mixed_dot name, elem, next, mext
.gadget \name
    ldr w8, [_pc]
    add _pc, _pc, #8
    dot_load_vd_vn
  .if \elem
    ubfx w13, w8, #21, #1
    ubfx w14, w8, #11, #1
    orr w13, w13, w14, lsl #1
    add x11, x11, x13, lsl #2
    ld1r {v1.4s}, [x11]
    tbz w8, #30, 1f
    ldr q0, [x10]
    ldr q2, [x9]
    b 2f
1:  ldr d0, [x10]
    ldr d2, [x9]
2:
  .else
    tbz w8, #30, 1f
    ldr q0, [x10]
    ldr q1, [x11]
    ldr q2, [x9]
    b 2f
1:  ldr d0, [x10]
    ldr d1, [x11]
    ldr d2, [x9]
2:
  .endif
    \next\()xtl  v3.8h, v0.8b
    \mext\()xtl  v4.8h, v1.8b
    mul v3.8h, v3.8h, v4.8h
    \next\()xtl2 v5.8h, v0.16b
    \mext\()xtl2 v6.8h, v1.16b
    mul v5.8h, v5.8h, v6.8h
    saddlp v3.4s, v3.8h
    saddlp v5.4s, v5.8h
    addp v3.4s, v3.4s, v5.4s
    add v2.4s, v2.4s, v3.4s
    str q2, [x9]
    gret
.endm

mixed_dot usdot_vec, 0, u, s
mixed_dot usdot_elem, 1, u, s
mixed_dot sudot_elem, 1, s, u

// Reduce four int16x8 product vectors (v3 = n0.m0, v4 = n0.m1, v5 = n1.m0,
// v6 = n1.m1) into the four totals and add them to v2.
.macro mmla_reduce
    saddlp v3.4s, v3.8h
    saddlp v4.4s, v4.8h
    saddlp v5.4s, v5.8h
    saddlp v6.4s, v6.8h
    addp v3.4s, v3.4s, v4.4s
    addp v5.4s, v5.4s, v6.4s
    addp v3.4s, v3.4s, v5.4s
    add v2.4s, v2.4s, v3.4s
    str q2, [x9]
.endm

.macro mmla name, mul, mul2, padd
.gadget \name
    ldr w8, [_pc]
    add _pc, _pc, #8
    dot_load_vd_vn
    ldr q0, [x10]
    ldr q1, [x11]
    ldr q2, [x9]
    ext v7.16b, v1.16b, v1.16b, #8      // Vm's rows swapped
    \mul  v3.8h, v0.8b, v1.8b
    \mul  v4.8h, v0.8b, v7.8b
    \mul2 v5.8h, v0.16b, v7.16b
    \mul2 v6.8h, v0.16b, v1.16b
    \padd v3.4s, v3.8h
    \padd v4.4s, v4.8h
    \padd v5.4s, v5.8h
    \padd v6.4s, v6.8h
    addp v3.4s, v3.4s, v4.4s
    addp v5.4s, v5.4s, v6.4s
    addp v3.4s, v3.4s, v5.4s
    add v2.4s, v2.4s, v3.4s
    str q2, [x9]
    gret
.endm

mmla smmla, smull, smull2, saddlp
mmla ummla, umull, umull2, uaddlp

// USMMLA: Vn unsigned, Vm signed, so the products go through 16-bit `mul`.
.gadget usmmla
    ldr w8, [_pc]
    add _pc, _pc, #8
    dot_load_vd_vn
    ldr q0, [x10]
    ldr q1, [x11]
    ldr q2, [x9]
    uxtl  v16.8h, v0.8b
    uxtl2 v17.8h, v0.16b
    sxtl  v18.8h, v1.8b
    sxtl2 v19.8h, v1.16b
    mul v3.8h, v16.8h, v18.8h           // n0.m0
    mul v4.8h, v16.8h, v19.8h           // n0.m1
    mul v5.8h, v17.8h, v18.8h           // n1.m0
    mul v6.8h, v17.8h, v19.8h           // n1.m1
    mmla_reduce
    gret

/*
 * SB: the speculation barrier. The host is ARMv8.0 and has no `sb`, and the
 * architecture defines `dsb` then `isb` as its equivalent: nothing after the
 * `isb` executes, speculatively or not, until everything before the `dsb` has
 * completed. It is what a guest asks for when it uses SB to bound a
 * Spectre-style speculation window, and the host's own speculation is what
 * matters here, since the guest's instructions are data to the gadgets.
 */
.gadget sb
    dsb sy
    isb
    gret

/*
 * MSR FPCR, Xt with FZ16 kept.
 *
 * `msr_fpcr` in math.S stores what the *host* reads back, which is right for
 * every bit the host's arithmetic honours and wrong for FPCR.FZ16 (bit 19):
 * half-precision arithmetic is done in software here (`crates/asbestos/
 * features::fp16`), so the bit has to be the guest's whether or not the host
 * has it -- an A9 reads it back clear, an M-series reads it back set. It is
 * ORed into the stored copy from the value written.
 * Code stream: [gadget addr][rt]
 */
.gadget msr_fpcr_fz16
    ldr x8, [_pc]
    add _pc, _pc, #8
    and x8, x8, #0x1f
    add x9, _cpu, #CPU_x0
    mov x10, #0
    cmp x8, #31
    b.eq 1f
    ldr x10, [x9, x8, lsl #3]
1:  and x11, x10, #0x80000
    msr fpcr, x10
    mrs x10, fpcr
    orr x10, x10, x11
    str w10, [_cpu, #CPU_fpcr]
    gret

