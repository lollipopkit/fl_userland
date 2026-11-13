#!/usr/bin/env python3
"""AArch64 disassembly -> an equivalent Rust spec_fn.

Input is objdump output for one function; output is the body of a
`crates/kernel/offloadtestprebuilt` module, written against that crate's `spec`
module: registers through `Regs`, guest memory through the TLB, arithmetic
through named wrapping helpers.

An unsupported instruction is an error, never a silent approximation: a spec_fn
*replaces* a guest function, so a wrong one is a miscompile with no symptom at
the point of the mistake.

It emitted C until 2026-09-09. Two things changed beyond the syntax:

  * **Arithmetic is named.** C's `+` on `uint64_t` wraps and Rust's panics in a
    debug build, so every operation is a call into `spec` -- which also makes
    the output say which AArch64 semantics it meant, where `sar` and `shr` were
    both `>>`.

  * **`goto` becomes a state machine.** A translated body is a list of labelled
    blocks, so it is `loop { match label { .. } }` with `goto L` written
    `label = N; continue`. Nothing else about the control flow changes: the
    blocks and the edges between them are the ones the disassembly has.
"""
import re, sys

_ic_counter = [0]
def _next_ic_id():
    _ic_counter[0] += 1
    return _ic_counter[0]

# name → file-offset symbol map (optional). Loaded from a "name 0xoffset" file
# passed as argv[2]; used to resolve `X@plt` calls (and tail-call `b`s) to the
# real function body so the inline cache can hit a registered spec_fn. Symbols
# not in the map (e.g. libc frexp/__stack_chk_fail) fall through to prebuilt_call.
_symmap = {}
def _load_symmap(path):
    for ln in open(path):
        p = ln.split()
        if len(p) == 2:
            try: _symmap[p[0]] = int(p[1], 16)
            except ValueError: pass

def _resolve_plt(args_str):
    """If a branch target is `<name@plt>` or `<name>`, and `name` is in the
    symbol map, return the body's *file offset* (int); else None."""
    m = re.search(r'<([A-Za-z_][\w.]*?)(@plt)?>', args_str)
    if not m: return None
    return _symmap.get(m.group(1))

def reg(r):
    """x0/w0 -> a register index; wzr/xzr -> -1; sp -> 32."""
    r = r.strip().rstrip(',')
    if r in ('xzr','wzr'): return -1
    if r in ('sp','wsp'): return 32   # sp 特殊
    m = re.match(r'[wx](\d+)', r)
    return int(m.group(1)) if m else None

def R(r):
    """A register as a Rust rvalue."""
    i = reg(r)
    if i == -1: return "0u64"
    return f"r.get({i})"

def RSET(dst, expr):
    """A register assignment. Writing to the zero register discards."""
    i = reg(dst)
    if i == -1: return "/* discarded to the zero register */"
    return f"r.set({i}, {expr});"

def is_w(r):  # a 32-bit register?
    return r.strip().rstrip(',').startswith('w')

def w32(expr):  # truncate to 32 bits, which is what writing a `w` register does
    return f"w32({expr})"

def freg(r):
    """s0/d0/q0 → float register index (a separate 32-entry file `fr[]`)."""
    r = r.strip().rstrip(',')
    m = re.match(r'[sdq](\d+)', r)
    return int(m.group(1)) if m else None

def FR(r):
    """A float register. Values are `f64` in a local `fr` array; the op's width
    controls rounding."""
    i = freg(r)
    return f"fr[{i}]"

def is_s(r):  # single-precision (32-bit float) register?
    return r.strip().rstrip(',').startswith('s')

def translate(lines):
    _ic_counter[0] = 0
    out = []
    labels = {}   # addr → C label (only for IN-FUNCTION targets)
    body = []
    insns = []
    for ln in lines:
        m = re.match(r'\s*([0-9a-f]+):\s+[0-9a-f]+\s+(\S+)\s*(.*)', ln)
        if not m: continue
        addr, op, args = int(m.group(1),16), m.group(2), m.group(3).strip()
        insns.append((addr, op, args))
    # Function address range = [first insn, last insn + 4). A branch to a target
    # inside this range is a local jump (goto); a target OUTSIDE it is a tail
    # call to another function (set guest PC, return — the dispatch loop runs
    # the callee, which returns to our guest LR).
    lo = insns[0][0] if insns else 0
    hi = insns[-1][0] + 4 if insns else 0
    for addr, op, args in insns:
        bm = re.search(r'([0-9a-f]+)\s+<', args)
        if bm and (op.startswith('b') or op in ('cbz','cbnz','tbz','tbnz')):
            t = int(bm.group(1), 16)
            if lo <= t < hi:                 # only label in-function targets
                labels[t] = f"L_{bm.group(1)}"
    # Jump-table support: JUMPTABLE_TARGETS env = comma-separated in-function target
    # addresses (hex) that a computed `br` dispatches to. Force a label at each so
    # the dispatch can `goto` them. The emit() for the `br` idiom reads the same env
    # + JUMPTABLE_MAP to emit the switch. Resolving the table is done by the caller
    # (gen.sh reads the .rodata bytes); translate.py just needs the target labels.
    import os as _os
    _jt = _os.environ.get('JUMPTABLE_TARGETS', '')
    for _ts in _jt.split(','):
        _ts = _ts.strip()
        if not _ts: continue
        t = int(_ts, 16)
        if lo <= t < hi:
            labels[t] = f"L_{t:x}"

    # JUMPTABLE_SUPPRESS: comma-separated addresses whose instructions are dropped
    # (the jump-table-building prologue: adrp/add/ldrb/adr/add). With them gone the
    # index register stays intact for the switch emitted at the `br`.
    import os as _os2
    _suppress = set()
    for _s in _os2.environ.get('JUMPTABLE_SUPPRESS', '').split(','):
        _s = _s.strip()
        if _s: _suppress.add(int(_s, 16))

    # Label -> block index, which is what a `goto` becomes. Block 0 is the
    # entry, whether or not an instruction there is also a branch target.
    order = sorted(labels)
    block_of = {addr: i + 1 for i, addr in enumerate(order)}

    for i, (addr, op, args) in enumerate(insns):
        if addr in labels:
            body.append(f"@BLOCK {block_of[addr]}")
        if addr in _suppress:
            continue
        # Strip objdump trailing "// ..." comments (e.g. "csel ..., ne  // ne = any")
        # so operands like the condition code aren't polluted. Branch targets use
        # the pre-comment hex + "<sym>" annotation, which this leaves intact.
        args_clean = args.split('//')[0].rstrip() if args else args
        a = [x.strip() for x in args_clean.split(',')] if args_clean else []
        next_pc = insns[i+1][0] if i+1 < len(insns) else addr+4  # for bl return addr
        c = emit(addr, op, a, labels, next_pc, block_of)
        if c is None:
            sys.stderr.write(f"UNSUPPORTED @ {addr:#x}: {op} {args}\n")
            return None
        body.append(c)
    return as_state_machine(body)


def as_state_machine(body):
    """The labelled blocks, as `loop { match label { .. } }`.

    A block that runs off its end falls through to the next one, which is what
    a label does in the original -- written as an explicit `label = N` so there
    is no fallthrough to read. The last block's fallthrough is a `return`,
    since a function's last instruction is a `ret` or an unconditional branch
    and anything after it is unreachable.
    """
    blocks = [[]]
    for line in body:
        if line.startswith("@BLOCK "):
            blocks.append([])
        else:
            blocks[-1].append(line)

    out = ["let mut label = 0usize;", "'body: loop {", "    match label {"]
    for i, stmts in enumerate(blocks):
        out.append(f"        {i} => {{")
        for st in stmts:
            for sub in st.split("\n"):
                out.append("            " + sub)
        # A block that already ends in a `return` or an unconditional jump
        # needs no fallthrough; adding one would be unreachable code.
        last = stmts[-1].strip() if stmts else ""
        ends = last == "return;" or last.endswith("return; }") or last.startswith("{ label = ")
        if not ends:
            if i + 1 < len(blocks):
                out.append(f"            label = {i + 1};")
            else:
                out.append("            return;")
        out.append("        }")
    out.append("        _ => return,")
    out.append("    }")
    out.append("}")
    return out

def emit(addr, op, a, labels, next_pc=None, block_of=None):
    """One instruction -> one Rust statement (or None = unsupported)."""
    block_of = block_of or {}
    # ldur/stur are unscaled-offset ldr/str; identical semantics here. ldar/stlr
    # (load-acquire / store-release) and ldapr act as plain ldr/str in our model —
    # iul issues real host barriers separately (gadget_dmb), so ordering is handled.
    _unscaled = {'ldur':'ldr','stur':'str','ldurb':'ldrb','sturb':'strb',
                 'ldurh':'ldrh','sturh':'strh',
                 'ldar':'ldr','stlr':'str','ldapr':'ldr',
                 'ldarb':'ldrb','stlrb':'strb','ldarh':'ldrh','stlrh':'strh'}
    op = _unscaled.get(op, op)

    def goto(tgt_hex):
        """A jump to a block of this function."""
        return f"{{ label = {block_of[int(tgt_hex, 16)]}; continue 'body; }}"

    def branch_to(tgt_hex, args_str=""):
        """In-function target -> a jump; out-of-function -> a tail call.

        A tail-call `b` to a *known* function body becomes an inline-cache call
        followed by a return: the same net effect as jumping there and letting
        it return to our caller, without leaving host code."""
        t = int(tgt_hex, 16)
        if t in labels:
            return goto(tgt_hex)
        body = _resolve_plt(args_str)
        dst = f"0x{body:x}" if body is not None else f"0x{tgt_hex}"
        ic = _next_ic_id()
        return (f"{{ unsafe {{ call(&IC{ic}, cpu, tlb, base() + {dst}) }}; return; }}")

    def imm(s):
        s = s.strip().lstrip('#')
        s = s.split()[0].split('//')[0].strip()   # drop a trailing comment
        return int(s, 0)

    def u64(v):
        """An integer literal, as Rust reads it.

        A negative offset -- a pre-index writeback is the common one -- is
        written as the wrapped unsigned value rather than a cast, so it reads
        the same as every other literal and needs no parentheses."""
        return f"0x{v & 0xffffffffffffffff:x}u64"

    # AArch64 condition codes -> the `Flags` predicates the generated body reads.
    COND = {'eq':'f.eq()','ne':'f.ne()','gt':'f.gt()','le':'f.le()',
            'ge':'f.ge()','lt':'f.lt()','hi':'f.hi()','lo':'f.lo()',
            'hs':'f.hs()','ls':'f.ls()','cs':'f.hs()','cc':'f.lo()',
            # N flag (sign of result): after subs/adds we compare the result
            # against 0, so mi (negative) == signed <, pl == signed >=.
            'mi':'f.lt()','pl':'f.ge()'}

    def sel(cond, yes, no):
        return f"if {COND[cond]} {{ {yes} }} else {{ {no} }}"

    # ── adrp xD, <target>  (PC-relative page address of a global) ──
    #   objdump prints the file-absolute target; at runtime it is the load base
    #   plus that target, which `base()` supplies.
    if op == 'adrp' and len(a) == 2:
        tgt = re.match(r'(?:0x)?([0-9a-f]+)', a[1].split()[0])
        if tgt:
            return RSET(a[0], f"base() + 0x{tgt.group(1)}")
    # ── adr xD, <target>  (PC-relative byte address) ──
    if op == 'adr' and len(a) == 2:
        tgt = re.match(r'(?:0x)?([0-9a-f]+)', a[1].split()[0])
        if tgt:
            return RSET(a[0], f"base() + 0x{tgt.group(1)}")
    # ── sign/zero extension: sxtw/sxth/sxtb, uxtw/uxth/uxtb ──
    if op in ('sxtw','sxth','sxtb','uxtw','uxth','uxtb') and len(a)==2:
        bits={'w':32,'h':16,'b':8}[op[3]]
        src=R(a[1])
        res = f"sx({bits}, {src})" if op[0]=='s' else f"zx({bits}, {src})"
        return RSET(a[0], res)
    # ── mov / movz / movk ──
    if op == 'mov' and len(a)==2:
        if a[1].startswith('#'):
            return RSET(a[0], u64(imm(a[1])))
        return RSET(a[0], R(a[1]))
    # ── neg rd, rm (= -rm) and mvn rd, rm (= ~rm) ──
    if op == 'neg' and len(a)==2:
        e = f"neg({R(a[1])})"
        return RSET(a[0], w32(e) if is_w(a[0]) else e)
    if op == 'mvn' and len(a)==2:
        e = f"!{R(a[1])}"
        return RSET(a[0], w32(e) if is_w(a[0]) else e)
    # ── negs rd, rm (= -rm, sets flags) ──
    if op == 'negs' and len(a)==2:
        return RSET(a[0], f"neg({R(a[1])})") + f" f.cmp({R(a[0])}, 0);"
    if op == 'movk' and len(a)>=2:
        # movk xD, #imm, lsl #sh
        sh = 0
        val = imm(a[1])
        shm = re.search(r'#(\d+)', a[2]) if len(a)>2 else None
        if shm: sh = int(shm.group(1))
        keep = ~(0xffff << sh) & 0xffffffffffffffff
        return RSET(a[0], f"({R(a[0])} & {u64(keep)}) | {u64((val & 0xffff) << sh)}")
    # ── arithmetic. The *s forms (adds/subs/ands) also set flags; bic clears
    #    bits. A shifted or extended register operand is supported. ──
    #    `add`/`sub`/`mul` are calls because they wrap; the bitwise ones are
    #    operators because they cannot.
    ARI = {'add':'add','sub':'sub','eor':'^','orr':'|','and':'&','mul':'mul',
           'adds':'add','subs':'sub','ands':'&','bic':'&!','eon':'^!','bics':'&!'}
    if op in ARI and len(a) in (3,4):
        cop = ARI[op]
        if a[2].startswith('#'):
            rhs = u64(imm(a[2]))
        else:
            rhs = R(a[2])
        if len(a) == 4:                       # shifted or extended register operand
            sm = re.match(r'(lsl|lsr|asr|ror)\s*#(\d+)', a[3])
            em = re.match(r'(uxtw|sxtw|uxtx|sxtx|uxtb|sxtb|uxth|sxth)(?:\s*#(\d+))?', a[3])
            if sm:
                sop, sh = sm.group(1), int(sm.group(2))
                rhs = {'lsl':'shl','lsr':'shr','asr':'sar','ror':'ror'}[sop] + f"({rhs}, {sh})"
            elif em:                          # extend: {u,s}xt{b,h,w,x} #shift
                ext, sh = em.group(1), int(em.group(2)) if em.group(2) else 0
                bits = {'b':8,'h':16,'w':32,'x':64}[ext[3]]
                if bits < 64:
                    rhs = (f"sx({bits}, {rhs})" if ext[0]=='s' else f"zx({bits}, {rhs})")
                if sh: rhs = f"shl({rhs}, {sh})"
            else: return None
        lhs = R(a[1])
        if cop in ('add','sub','mul'): expr = f"{cop}({lhs}, {rhs})"
        elif cop == '&!': expr = f"{lhs} & !({rhs})"
        elif cop == '^!': expr = f"{lhs} ^ !({rhs})"
        else: expr = f"{lhs} {cop} ({rhs})"
        if is_w(a[0]): expr = w32(expr)
        # Writing to the zero register discards the result -- only the flags
        # matter (`ands wzr, x, y` is `tst`; `bics xzr, ...`).
        if reg(a[0]) == -1:
            if op in ('adds','subs','ands','bics'):
                return f"f.cmp({expr}, 0);"
            return "// the result is discarded to the zero register"
        code = RSET(a[0], expr)
        if op in ('adds','subs','ands','bics'):  # set flags from the result
            code += f" f.cmp({R(a[0])}, 0);"
        return code
    # ── ror ──
    if op == 'ror' and len(a)==3:
        return RSET(a[0], f"ror({R(a[1])}, {imm(a[2])})")
    # ── lsl / lsr / asr  (register or immediate shift) ──
    if op in ('lsl','lsr','asr') and len(a)==3:
        n = R(a[1])
        amt = f"{imm(a[2])}" if a[2].startswith('#') else R(a[2])
        res = {'lsl':'shl','lsr':'shr','asr':'sar'}[op] + f"({n}, {amt})"
        if is_w(a[0]): res = w32(res)
        return RSET(a[0], res)
    # ── csel wD, wN, wM/wzr, cond  (D = cond ? N : M) ──
    if op == 'csel' and len(a)==4:
        if a[3] not in COND: return None
        return RSET(a[0], sel(a[3], R(a[1]), R(a[2])))
    # ── csinc wD, wN, wM, cond  (D = cond ? N : M+1) ──
    if op == 'csinc' and len(a)==4:
        if a[3] not in COND: return None
        return RSET(a[0], sel(a[3], R(a[1]), f"add({R(a[2])}, 1)"))
    # ── csinv wD, wN, wM, cond  (D = cond ? N : ~M) ──
    if op == 'csinv' and len(a)==4 and a[3] in COND:
        res = sel(a[3], R(a[1]), f"!{R(a[2])}")
        if is_w(a[0]): res = w32(res)
        return RSET(a[0], res)
    # ── csneg wD, wN, wM, cond  (D = cond ? N : -M) ──
    if op == 'csneg' and len(a)==4 and a[3] in COND:
        res = sel(a[3], R(a[1]), f"neg({R(a[2])})")
        if is_w(a[0]): res = w32(res)
        return RSET(a[0], res)
    # ── madd rd,rn,rm,ra = rn*rm+ra ──
    if op == 'madd' and len(a)==4:
        return RSET(a[0], f"add(mul({R(a[1])}, {R(a[2])}), {R(a[3])})")
    # ── msub rd,rn,rm,ra = ra - rn*rm ──
    if op == 'msub' and len(a)==4:
        expr = f"sub({R(a[3])}, mul({R(a[1])}, {R(a[2])}))"
        if is_w(a[0]): expr = w32(expr)
        return RSET(a[0], expr)
    # ── umaddl xD, wN, wM, xA = xA + (u32)wN * (u32)wM ──
    if op == 'umaddl' and len(a)==4:
        return RSET(a[0], f"add({R(a[3])}, mul(zx(32, {R(a[1])}), zx(32, {R(a[2])})))")
    # ── umsubl xD, wN, wM, xA = xA - (u32)wN * (u32)wM ──
    if op == 'umsubl' and len(a)==4:
        return RSET(a[0], f"sub({R(a[3])}, mul(zx(32, {R(a[1])}), zx(32, {R(a[2])})))")
    # ── smaddl xD, wN, wM, xA = xA + (i32)wN * (i32)wM ──
    if op == 'smaddl' and len(a)==4:
        return RSET(a[0], f"add({R(a[3])}, mul(sx(32, {R(a[1])}), sx(32, {R(a[2])})))")
    # ── umull/smull xD, wN, wM  (alias of {u,s}maddl ..., xzr) ──
    if op == 'umull' and len(a)==3:
        return RSET(a[0], f"mul(zx(32, {R(a[1])}), zx(32, {R(a[2])}))")
    if op == 'smull' and len(a)==3:
        return RSET(a[0], f"mul(sx(32, {R(a[1])}), sx(32, {R(a[2])}))")
    # ── umulh/smulh xD, xN, xM = the high 64 bits of a 128-bit product ──
    if op == 'umulh' and len(a)==3:
        return RSET(a[0], f"umulh({R(a[1])}, {R(a[2])})")
    if op == 'smulh' and len(a)==3:
        return RSET(a[0], f"smulh({R(a[1])}, {R(a[2])})")
    # ── sdiv/udiv rd,rn,rm  (division by zero answers 0, per AArch64) ──
    if op == 'udiv' and len(a)==3:
        e = f"udiv({R(a[1])}, {R(a[2])})"
        return RSET(a[0], w32(e) if is_w(a[0]) else e)
    if op == 'sdiv' and len(a)==3:
        e = f"sdiv({R(a[1])}, {R(a[2])})"
        return RSET(a[0], w32(e) if is_w(a[0]) else e)
    # ── sbfiz wD, wN, #lsb, #width  (signed bitfield insert in zero) ──
    #   Wd = sign_extend(Wn[0+:width]) << lsb
    if op == 'sbfiz' and len(a)==4:
        lsb, width = imm(a[2]), imm(a[3])
        res = f"shl(zx({width}, sx({width}, {R(a[1])})), {lsb})"
        if is_w(a[0]): res = w32(res)
        return RSET(a[0], res)
    # ── cinc wD, wN, cond  (D = cond ? N+1 : N) ──
    if op == 'cinc' and len(a)==3 and a[2] in COND:
        res = sel(a[2], f"add({R(a[1])}, 1)", R(a[1]))
        if is_w(a[0]): res = w32(res)
        return RSET(a[0], res)
    # ── cneg wD, wN, cond  (D = cond ? -N : N) ──
    if op == 'cneg' and len(a)==3 and a[2] in COND:
        res = sel(a[2], f"neg({R(a[1])})", R(a[1]))
        if is_w(a[0]): res = w32(res)
        return RSET(a[0], res)
    # ── cinv wD, wN, cond  (D = cond ? ~N : N) ──
    if op == 'cinv' and len(a)==3 and a[2] in COND:
        res = sel(a[2], f"!{R(a[1])}", R(a[1]))
        if is_w(a[0]): res = w32(res)
        return RSET(a[0], res)
    # ── ldrb/strb (byte) and ldrh/strh (halfword). Two forms: [Xn, Xm{,lsl#s}]
    #    (register offset, e.g. a table lookup) and [Xn, #imm] (imm/pre/post). ──
    if op in ('ldrb','strb','ldrh','strh'):
        ld  = op.startswith('ldr')
        LD, ST = ('ld1','st1') if op[-1]=='b' else ('ld2','st2')
        m = re.match(r'\[(\w+),\s*([wx]\w+)(?:,\s*(lsl|uxtw|sxtw|uxtx|sxtx)\s*#?(\d+)?)?\]', args_join(a[1:]))
        if m:
            base = R(m.group(1)); ext = m.group(3); sh = int(m.group(4)) if m.group(4) else 0
            raw = R(m.group(2))
            if ext == 'sxtw':   idx = f"sx(32, {raw})"
            elif ext == 'uxtw': idx = f"zx(32, {raw})"
            else:               idx = raw
            ea = f"add({base}, shl({idx}, {sh}))" if sh else f"add({base}, {idx})"
            return (RSET(a[0], f"unsafe {{ {LD}(tlb, {ea}) }}") if ld
                    else f"unsafe {{ {ST}(tlb, {ea}, {R(a[0])}) }};")
        r = _memop(a[1:])
        if r:
            base, off, pre, post = r
            code = f"{RSET_EXPR(base, f'add({base}, {u64(off)})')} " if pre else ""
            ea = base if (pre or post) else f"add({base}, {u64(off)})"
            code += (RSET(a[0], f"unsafe {{ {LD}(tlb, {ea}) }}") if ld
                     else f"unsafe {{ {ST}(tlb, {ea}, {R(a[0])}) }};")
            if post: code += f" {RSET_EXPR(base, f'add({base}, {u64(off)})')}"
            return code
    # ── Vector-register ldr/str (q/v/s/d/h/b) are SIMD and are not modelled.
    #    Bail rather than emit a wrong access. ──
    if op in ('ldr','str','ldur','stur') and a and re.match(r'[qvsdhb]\d', a[0].strip()):
        return None
    # ── ldr/str Xt/Wt, [Xn, Rm{, lsl|sxtw|uxtw #sh}]  (register offset) ──
    #   The index may be 64-bit (lsl) or a 32-bit register sign/zero-extended,
    #   which is what `array[i]` with a 32-bit `i` compiles to.
    if op in ('ldr','str') and len(a) >= 2:
        mem = args_join(a[1:]).strip()
        m = re.match(r'\[(\w+),\s*(\w+)(?:,\s*(lsl|sxtw|uxtw|sxtx|uxtx)\s*#?(\d+)?)?\]', mem)
        if m and not m.group(2).startswith('#'):
            base = R(m.group(1)); ext = m.group(3); sh = int(m.group(4)) if m.group(4) else 0
            raw = R(m.group(2))
            if ext == 'sxtw':   idx = f"sx(32, {raw})"
            elif ext == 'uxtw': idx = f"zx(32, {raw})"
            else:               idx = raw
            ea = f"add({base}, shl({idx}, {sh}))" if sh else f"add({base}, {idx})"
            LD, ST = ('ld4','st4') if is_w(a[0]) else ('ld8','st8')
            return (RSET(a[0], f"unsafe {{ {LD}(tlb, {ea}) }}") if op == 'ldr'
                    else f"unsafe {{ {ST}(tlb, {ea}, {R(a[0])}) }};")
    # ── ldr/str Xt/Wt, [Xn, #imm]  (64/32-bit access through the TLB) ──
    if op in ('ldr','str') and len(a) >= 2:
        r = _memop(a[1:])
        if r:
            base, off, wb_pre, wb_post = r
            code = ""
            if wb_pre: code += f"{RSET_EXPR(base, f'add({base}, {u64(off)})')} "
            ea = base if (wb_pre or wb_post) else f"add({base}, {u64(off)})"
            LD, ST = ('ld4','st4') if is_w(a[0]) else ('ld8','st8')
            code += (RSET(a[0], f"unsafe {{ {LD}(tlb, {ea}) }}") if op == 'ldr'
                     else f"unsafe {{ {ST}(tlb, {ea}, {R(a[0])}) }};")
            if wb_post: code += f" {RSET_EXPR(base, f'add({base}, {u64(off)})')}"
            return code
    # ── stp/ldp Wt1/Xt1, Wt2/Xt2, [Xn, #imm]  (pair, pre/post-index).
    #   The element size follows the register width: w-regs are 4-byte elements
    #   (the second at +4), x-regs 8-byte. Using the wrong width silently
    #   corrupts adjacent fields -- observed: `ldp w3,w4` read as two 8-byte
    #   loads. ──
    if op in ('stp','ldp') and len(a) >= 3:
        if re.match(r'[qvsdhb]\d', a[0].strip()) or re.match(r'[qvsdhb]\d', a[1].strip()):
            return None                       # SIMD pairs are not modelled
        r = _memop(a[2:])
        if r:
            base, off, wb_pre, wb_post = r
            code = ""
            if wb_pre: code += f"{RSET_EXPR(base, f'add({base}, {u64(off)})')} "
            ea = base if (wb_pre or wb_post) else f"add({base}, {u64(off)})"
            w = is_w(a[0])
            esz = 4 if w else 8
            LD, ST = ('ld4','st4') if w else ('ld8','st8')
            if op == 'ldp':
                code += (RSET(a[0], f"unsafe {{ {LD}(tlb, {ea}) }}") + " " +
                         RSET(a[1], f"unsafe {{ {LD}(tlb, add({ea}, {esz})) }}"))
            else:
                code += (f"unsafe {{ {ST}(tlb, {ea}, {R(a[0])}) }}; "
                         f"unsafe {{ {ST}(tlb, add({ea}, {esz}), {R(a[1])}) }};")
            if wb_post: code += f" {RSET_EXPR(base, f'add({base}, {u64(off)})')}"
            return code
    # ── cmp (sets the flags). Both operands are kept, so every condition
    #    resolves; a w-register comparison is unsigned 32-bit. ──
    if op == 'cmp' and len(a) >= 2:
        if a[1].startswith('#'):
            v = imm(a[1])
            if len(a) >= 3:                       # an optional lsl #sh
                shm = re.search(r'lsl\s*#(\d+)', args_join(a[2:]))
                if shm: v <<= int(shm.group(1))
            rhs = u64(v)
        else:
            rhs = R(a[1])
        lhs = R(a[0])
        if is_w(a[0]): lhs, rhs = w32(lhs), w32(rhs)
        return f"f.cmp({lhs}, {rhs});"
    # ── cmn Rn, #imm  (compare negative: the flags of Rn + imm) ──
    if op == 'cmn' and len(a) == 2:
        rhs = u64(imm(a[1])) if a[1].startswith('#') else R(a[1])
        return f"f.cmp({R(a[0])}, neg({rhs}));"
    # ── tst Rn, Rm/#imm  (the flags of Rn & op2; only Z and N are meaningful) ──
    if op == 'tst' and len(a) >= 2:
        rhs = u64(imm(a[1])) if a[1].startswith('#') else R(a[1])
        lhs = R(a[0])
        if is_w(a[0]): lhs, rhs = w32(lhs), w32(rhs)
        return f"f.cmp({lhs} & {rhs}, 0);"
    # ── conditional branch b.<cond> ──
    if op.startswith('b.') and op[2:] in COND:
        tgt = re.search(r'([0-9a-f]+)\s+<', args_join(a))
        if tgt: return f"if {COND[op[2:]]} " + branch_to(tgt.group(1), args_join(a))
    # ── tbnz/tbz Rn, #bit, tgt  (test one bit and branch) ──
    if op in ('tbnz','tbz') and len(a) >= 3:
        bit = imm(a[1])
        tgt = re.search(r'([0-9a-f]+)\s+<', args_join(a[2:]))
        if tgt:
            cond = f"(shr({R(a[0])}, {bit}) & 1) != 0"
            if op == 'tbz': cond = f"(shr({R(a[0])}, {bit}) & 1) == 0"
            return f"if {cond} " + branch_to(tgt.group(1), args_join(a))
    # ── cset wD, <cond> (D = cond ? 1 : 0) ──
    if op == 'cset' and len(a)==2 and a[1] in COND:
        return RSET(a[0], sel(a[1], "1", "0"))
    # ── csetm wD, <cond> (D = cond ? all-ones : 0) ──
    if op == 'csetm' and len(a)==2 and a[1] in COND:
        mask = "0xffff_ffffu64" if is_w(a[0]) else "u64::MAX"
        return RSET(a[0], sel(a[1], mask, "0"))
    # ── ubfx/ubfiz  (unsigned bitfield extract / insert-in-zero) ──
    if op in ('ubfx','ubfiz') and len(a) == 4:
        lsb, width = imm(a[2]), imm(a[3])
        if op == 'ubfx':
            res = f"zx({width}, shr({R(a[1])}, {lsb}))"
        else:
            res = f"shl(zx({width}, {R(a[1])}), {lsb})"
        if is_w(a[0]): res = w32(res)
        return RSET(a[0], res)
    # ── sbfx Wd, Wn, #lsb, #width  (signed bitfield extract) ──
    if op == 'sbfx' and len(a) == 4:
        lsb, width = imm(a[2]), imm(a[3])
        res = f"sx({width}, shr({R(a[1])}, {lsb}))"
        if is_w(a[0]): res = w32(res)
        return RSET(a[0], res)
    # ── bfxil Wd, Wn, #lsb, #width  (insert Wn[lsb+:width] into Wd's low bits) ──
    if op == 'bfxil' and len(a) == 4:
        lsb, width = imm(a[2]), imm(a[3])
        mask = (1 << width) - 1
        field = f"zx({width}, shr({R(a[1])}, {lsb}))"
        res = f"({R(a[0])} & !{u64(mask)}) | {field}"
        if is_w(a[0]): res = w32(res)
        return RSET(a[0], res)
    # ── bfi Wd, Wn, #lsb, #width  (insert Wn[0+:width] into Wd[lsb+:width]) ──
    if op == 'bfi' and len(a) == 4:
        lsb, width = imm(a[2]), imm(a[3])
        mask = ((1 << width) - 1) << lsb
        field = f"shl(zx({width}, {R(a[1])}), {lsb})"
        res = f"({R(a[0])} & !{u64(mask)}) | {field}"
        if is_w(a[0]): res = w32(res)
        return RSET(a[0], res)
    if op == 'cbz' and len(a)>=2:
        tgt = re.search(r'([0-9a-f]+)\s+<', args_join(a))
        v = w32(R(a[0])) if is_w(a[0]) else R(a[0])
        if tgt: return f"if {v} == 0 " + branch_to(tgt.group(1), args_join(a))
    if op == 'cbnz' and len(a)>=2:
        tgt = re.search(r'([0-9a-f]+)\s+<', args_join(a))
        v = w32(R(a[0])) if is_w(a[0]) else R(a[0])
        if tgt: return f"if {v} != 0 " + branch_to(tgt.group(1), args_join(a))
    if op == 'b':
        tgt = re.search(r'([0-9a-f]+)\s+<', args_join(a))
        if tgt: return branch_to(tgt.group(1), args_join(a))
    # ── bl <target>  (a direct call). `call` does inline-cache dispatch: if the
    #   callee has a spec_fn of its own, call it and stay in host code;
    #   otherwise hand it to the interpreter. Each site has its own cache. ──
    if op == 'bl':
        tgt = re.search(r'([0-9a-f]+)\s+<', args_join(a))
        if tgt and next_pc is not None:
            ic = _next_ic_id()
            # Prefer the real body offset when the target is a PLT stub whose
            # symbol we know; otherwise the literal branch target. Both become
            # base() + offset, so the cache keys on the address we register.
            body = _resolve_plt(args_join(a))
            dst = f"0x{body:x}" if body is not None else f"0x{tgt.group(1)}"
            return (f"r.set(30, base() + 0x{next_pc:x}); "
                    f"unsafe {{ call(&IC{ic}, cpu, tlb, base() + {dst}) }};")
    # ── blr xN  (an indirect call). The cache is worth most here: the target is
    #    usually monomorphic, so it hits and skips the interpreter. ──
    if op == 'blr' and len(a) == 1 and next_pc is not None:
        ic = _next_ic_id()
        return (f"r.set(30, base() + 0x{next_pc:x}); "
                f"unsafe {{ call(&IC{ic}, cpu, tlb, {R(a[0])}) }};")
    # ── br xN  (an indirect branch: a tail call, which does not return here) ──
    if op == 'br' and len(a) == 1:
        # A jump table: JUMPTABLE_MAP = "idxreg;key0:tgt0,...,default:tgtd",
        # where idxreg is the guest register holding the switch index and each
        # target is an in-function address (labelled above). Emitting the match
        # keeps the whole function in host code, where the tail call below would
        # clobber the link register -- which is wrong for an *intra*-function
        # table.
        import os as _os
        jm = _os.environ.get('JUMPTABLE_MAP', '')
        if jm:
            idxreg, _, rest = jm.partition(';')
            cases = []
            default = None
            for pair in rest.split(','):
                k, _, v = pair.partition(':')
                k = k.strip(); v = v.strip()
                if k == 'default': default = int(v, 16)
                elif k: cases.append((int(k, 0), int(v, 16)))
            lines = [f"match w32(r.get({idxreg})) {{"]
            for k, t in cases:
                lines.append(f"    {k} => {{ label = {block_of[t]}; continue 'body; }}")
            if default is not None:
                lines.append(f"    _ => {{ label = {block_of[default]}; continue 'body; }}")
            else:
                lines.append("    _ => return,")
            lines.append("}")
            return "\n".join(lines)
        # An indirect `br xN` is a tail call to regs[N]. The callee returns to
        # the *current* guest link register, which our caller set up. Running it
        # through the interpreter preserves that: it executes to completion and
        # comes back, and the `return` below lets the prebuilt entry resume at
        # the real lr. Setting regs[30] = regs[N] would clobber the return
        # address and the callee's `ret` would loop on itself.
        return f"unsafe {{ tail(cpu, tlb, {R(a[0])}) }}; return;"
    # ── ret ──
    if op == 'ret':
        return "return;"
    # ── ldrsb/ldrsh/ldrsw: sign-extending loads ──
    if op in ('ldrsb','ldrsh','ldrsw'):
        LD = {'ldrsb':'lds1','ldrsh':'lds2','ldrsw':'lds4'}[op]
        s = args_join(a[1:]).strip()
        im = re.match(r'\[(\w+)(?:,\s*#(-?\w+))?\]$', s)
        if im:
            base = R(im.group(1)); off = int(im.group(2), 0) if im.group(2) else 0
            ea = f"add({base}, {u64(off)})" if off else base
            return RSET(a[0], f"unsafe {{ {LD}(tlb, {ea}) }}")
        m = re.match(r'\[(\w+),\s*(\w+)(?:,\s*(lsl|uxtw|sxtw|uxtx|sxtx)\s*#?(\d+)?)?\]', s)
        if m and not m.group(2).startswith('#'):
            base = R(m.group(1)); ext = m.group(3); sh = int(m.group(4)) if m.group(4) else 0
            raw = R(m.group(2))
            if ext == 'sxtw':   idx = f"sx(32, {raw})"
            elif ext == 'uxtw': idx = f"zx(32, {raw})"
            else:               idx = raw
            ea = f"add({base}, shl({idx}, {sh}))" if sh else f"add({base}, {idx})"
            return RSET(a[0], f"unsafe {{ {LD}(tlb, {ea}) }}")
    # ── ccmp Rn, Rm/#imm, #nzcv, cond  (a conditional compare) ──
    #   If cond holds, the flags come from (Rn - op2); otherwise from #nzcv.
    #   The flag pair models Z (eq/ne) and C (hi/ls/lo/hs), which are the only
    #   bits a downstream condition reads. Pick the pair that reproduces the
    #   fallback's C (bit 1) and Z (bit 2):
    #     Z=1      -> (0, 0): eq, hs, ls
    #     Z=0, C=1 -> (1, 0): ne, hi, hs
    #     Z=0, C=0 -> (0, 1): ne, lo, ls
    if op == 'ccmp' and len(a) == 4 and a[3] in COND:
        rhs = u64(imm(a[1])) if a[1].startswith('#') else R(a[1])
        nzcv = imm(a[2])
        Z = bool(nzcv & 0x4); C = bool(nzcv & 0x2)
        pair = "0, 0" if Z else ("1, 0" if C else "0, 1")
        return (f"if {COND[a[3]]} {{ f.cmp({R(a[0])}, {rhs}); }} "
                f"else {{ f.cmp({pair}); }}")
    # ── ccmn Rn, #imm/Rm, #nzcv, cond  (a conditional compare against -op2) ──
    if op == 'ccmn' and len(a) == 4 and a[3] in COND:
        rhs = f"neg({u64(imm(a[1]))})" if a[1].startswith('#') else f"neg({R(a[1])})"
        nzcv = imm(a[2])
        Z = bool(nzcv & 0x4); C = bool(nzcv & 0x2)
        pair = "0, 0" if Z else ("1, 0" if C else "0, 1")
        return (f"if {COND[a[3]]} {{ f.cmp({R(a[0])}, {rhs}); }} "
                f"else {{ f.cmp({pair}); }}")
    # ── mrs/msr TPIDR_EL0: the guest's thread pointer. objdump prints the
    #    sysreg name in lower case. ──
    if op == 'mrs' and len(a) == 2 and 'tpidr_el0' in a[1].lower():
        return RSET(a[0], "r.tls()")
    if op == 'msr' and len(a) == 2 and 'tpidr_el0' in a[0].lower():
        return f"r.set_tls({R(a[1])});"
    # ── clz rd, rn  (count leading zeros; the width follows the register) ──
    if op == 'clz' and len(a) == 2:
        bits = 32 if is_w(a[0]) else 64
        return RSET(a[0], f"clz({bits}, {R(a[1])})")
    # ── rev / rev16 / rev32  (byte reverse) ──
    if op in ('rev','rev32') and len(a) == 2:
        return RSET(a[0], f"rev32({R(a[1])})" if is_w(a[0]) else f"rev64({R(a[1])})")
    if op == 'rev16' and len(a) == 2:
        return RSET(a[0], f"rev16({R(a[1])})")
    # ── ldpsw xt1, xt2, [xn, #imm]  (a pair of 32-bit loads, sign-extended) ──
    if op == 'ldpsw' and len(a) >= 3:
        s = args_join(a[2:]).strip()
        im = re.match(r'\[(\w+)(?:,\s*#(-?\w+))?\]', s)
        if im:
            base = R(im.group(1)); off = int(im.group(2), 0) if im.group(2) else 0
            e1 = f"add({base}, {u64(off)})" if off else base
            e2 = f"add({base}, {u64(off+4)})"
            return (RSET(a[0], f"unsafe {{ lds4(tlb, {e1}) }}") + " " +
                    RSET(a[1], f"unsafe {{ lds4(tlb, {e2}) }}"))
    # ── brk: a breakpoint. Real code reaches it only on an assertion failure,
    #    so make any surprise loud rather than silent. ──
    if op == 'brk':
        return 'unreachable!("the guest executed brk");'
    if op == 'nop':
        return "// nop"
    # ── Minimal floating point. Values live in a local `fr` array of f64;
    #    enough for the hashtable load-factor idiom: ucvtf, fmov #imm, fdiv,
    #    fcmp/fcmpe. ──
    if op in ('ucvtf','scvtf') and len(a) == 2 and freg(a[0]) is not None:
        src = R(a[1])
        if op == 'ucvtf':
            v = f"zx(32, {src})" if is_w(a[1]) else src
            return f"{FR(a[0])} = {v} as f64;"
        v = f"sx(32, {src})" if is_w(a[1]) else src
        return f"{FR(a[0])} = ({v} as i64) as f64;"
    if op == 'fmov' and len(a) == 2 and freg(a[0]) is not None and a[1].startswith('#'):
        return f"{FR(a[0])} = {float(a[1].lstrip('#'))}f64;"
    if op == 'fmov' and len(a) == 2 and freg(a[0]) is not None and freg(a[1]) is None:
        # A value move rather than a bit-cast, which is all this is used for
        # after a conversion.
        return f"{FR(a[0])} = {R(a[1])} as f64;"
    FBIN = {'fdiv':'/','fmul':'*','fadd':'+','fsub':'-'}
    if op in FBIN and len(a) == 3 and freg(a[0]) is not None:
        return f"{FR(a[0])} = {FR(a[1])} {FBIN[op]} {FR(a[2])};"
    if op in ('fcmp','fcmpe') and len(a) == 2 and freg(a[0]) is not None:
        rhs = "0.0" if a[1].startswith('#') else FR(a[1])
        return f"f.fcmp({FR(a[0])}, {rhs});"
    # Everything else is not safely translatable. Reject rather than emit a
    # silently wrong spec_fn.
    return None

def RSET_EXPR(lvalue, expr):
    """A write-back to a base register, whose lvalue is already `r.get(N)`."""
    m = re.match(r'r\.get\((\d+)\)', lvalue)
    if not m:
        raise ValueError(f"not a register lvalue: {lvalue}")
    return f"r.set({m.group(1)}, {expr});"

def args_join(a): return ', '.join(a)

def _memop(mem_args):
    """Parse a memory operand from the args after the value register(s).
    Returns (base_expr, offset_int, writeback_pre, writeback_post) or None.
    Forms:  [Xn]            [Xn, #imm]       [Xn, #imm]!   (pre-index)
            [Xn], #imm  (post-index)"""
    s = args_join(mem_args).strip()
    # post-index:  [Xn], #imm
    m = re.match(r'\[(\w+)\],\s*#(-?\w+)', s)
    if m: return (R(m.group(1)), int(m.group(2), 0), False, True)
    # pre-index:   [Xn, #imm]!
    m = re.match(r'\[(\w+),\s*#(-?\w+)\]!', s)
    if m: return (R(m.group(1)), int(m.group(2), 0), True, False)
    # offset:      [Xn, #imm]   or   [Xn]
    m = re.match(r'\[(\w+),\s*#(-?\w+)\]', s)
    if m: return (R(m.group(1)), int(m.group(2), 0), False, False)
    m = re.match(r'\[(\w+)\]', s)
    if m: return (R(m.group(1)), 0, False, False)
    return None

if __name__ == '__main__':
    lines = open(sys.argv[1]).readlines()
    if len(sys.argv) > 2 and sys.argv[2]:   # optional symbol map for @plt resolve
        _load_symmap(sys.argv[2])
    body = translate(lines)
    if body is None:
        sys.stderr.write("转译失败 (有不支持的指令)\n"); sys.exit(1)
    for l in body: print(l)
