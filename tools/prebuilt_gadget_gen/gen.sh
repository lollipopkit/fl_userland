#!/bin/bash
# prebuilt_gadget_gen — generate a prebuilt-gadget spec_fn from a guest binary.
#
# Given a guest AArch64 binary and a function name, this:
#   1. resolves the symbol's address and whether the binary is a PIE (nm, file)
#   2. disassembles the function (objdump)
#   3. translates it to an equivalent Rust spec_fn (translate.py)
#   4. writes crates/kernel/offloadtestprebuilt/src/<fn>.rs and prints the two
#      lines to add to that crate's `register`
#
# A spec_fn stays entirely in guest semantics — it reads and writes
# `cpu_state`'s registers and reaches guest memory through the TLB — so it works
# for any function and is fork- and copy-on-write-safe. It is compiled only with
# `-Doffload_test_prebuilt=true`, which is a cargo feature of `crates/iul`.
#
# It wrote C into kernel/offload_tests/prebuilt/ until 2026-09-09. That
# directory is gone, and so is every header the generated file included: this is
# what kept `emu/arch/arm64/cpu.h`, `emu/tlb.h`, `emu/mmu.h`, `misc.h`,
# `debug.h`, `util/ish_env.h` and `kernel/native_offload.h` alive.
#
# Usage:  tools/prebuilt_gadget_gen/gen.sh <guest-binary> <function> [runtime-addr]
#   <guest-binary>  path to the ELF (e.g. a libpython in a rootfs)
#   <function>      symbol name
#   [runtime-addr]  optional 0x… guest runtime address (default: the symbol
#                   offset, which is right for a non-PIE; for a PIE or a shared
#                   library pass the load base + offset you observed in
#                   /proc/self/maps).
#
# **What it generates is a translation of one build.** The addresses are handled
# — `base()` is the bias between where it was disassembled and where it loaded —
# but the *register allocation* is not and cannot be: a spec_fn has to leave the
# CPU as the guest's own instructions would. Rebuild the guest binary with a
# different compiler and the generated file is wrong in a way the bit-identical
# check does not necessarily catch, because that compares the program's output
# and a scratch register the caller never reads is not in it.
set -u
cd "$(dirname "$0")/../.."                       # repo root
HERE="tools/prebuilt_gadget_gen"
OUT="crates/kernel/offloadtestprebuilt/src"

BIN="${1:?usage: gen.sh <guest-binary> <function> [runtime-addr]}"
FN="${2:?usage: gen.sh <guest-binary> <function> [runtime-addr]}"
[ -f "$BIN" ] || { echo "no such binary: $BIN" >&2; exit 2; }

# 1. Resolve the symbol offset and whether the binary is a PIE.
OFF=$(nm "$BIN" 2>/dev/null | awk -v f="$FN" '$3==f && $2 ~ /[Tt]/ {print $1; exit}')
[ -n "$OFF" ] || OFF=$(nm -D "$BIN" 2>/dev/null | awk -v f="$FN" '$3==f && $2 ~ /[Tt]/ {print $1; exit}')
[ -n "$OFF" ] || { echo "symbol '$FN' not found (T/t) in $BIN" >&2; exit 2; }
PIE=no; file "$BIN" | grep -qiE 'pie|shared object' && PIE=yes
ADDR="${3:-0x$OFF}"
echo "== $FN in $BIN =="
echo "  symbol offset: 0x$OFF   PIE: $PIE   runtime addr: $ADDR"
[ "$PIE" = yes ] && [ $# -lt 3 ] && \
  echo "  WARNING: the binary is a PIE — 0x$OFF is a file offset, not a runtime" \
       "address; pass the observed load base + offset as the third argument."

# 2. Disassemble the whole function. A function can have several return paths,
#    so stopping at the first `ret` would drop later branch targets. A stripped
#    library does not label the *next* function, so stop at the function
#    boundary heuristically: the last `ret` whose following instruction is a
#    prologue (`sub sp, sp` / `stp x29, x30`). Also stop at an explicit next
#    `<symbol>:` when there is one.
ASM="$HERE/$FN.asm"
objdump -d "$BIN" 2>/dev/null | awk -v f="<$FN>:" '
  $0 ~ f {p=1; print; next}
  !p {next}
  /^[0-9a-f]+ </ {exit}                 # an explicit next symbol -> stop
  # the prologue of the following (unlabelled) function -> stop before it
  prev_ret && ($0 ~ /\tsub\tsp, sp,/ || $0 ~ /\tstp\tx29, x30,/) {exit}
  {print; prev_ret = ($0 ~ /\tret$/)}
' > "$ASM"
[ -s "$ASM" ] || { echo "failed to disassemble $FN" >&2; exit 2; }

# 3. Translate. translate.py exits non-zero and prints UNSUPPORTED for any
#    instruction it cannot safely handle, so a silently wrong spec is never
#    emitted.
BODY=$(python3 "$HERE/translate.py" "$ASM" 2>"$HERE/$FN.err")
if [ $? -ne 0 ]; then
    echo "  TRANSLATION FAILED — an unsupported instruction:" >&2
    sed 's/^/    /' "$HERE/$FN.err" >&2
    exit 1
fi

# How many inline caches the body needs: one per call site, numbered by
# translate.py in the order it emitted them.
ICS=$(printf '%s\n' "$BODY" | grep -o 'IC[0-9]*' | sort -u | sed 's/IC//' | sort -n)

# 4. Write the module.
MOD=$(printf '%s' "$FN" | tr -c 'a-zA-Z0-9' '_')
SPEC="$OUT/$MOD.rs"
BASE_BIAS=$(printf '%#x' $(( ADDR - 0x$OFF )))
{
  echo "//! AUTO-GENERATED from guest \`$FN\` — DO NOT EDIT."
  echo "//!"
  echo "//! Source: \`$BIN\`, symbol at 0x$OFF, registered at $ADDR."
  echo "//! Produced by \`tools/prebuilt_gadget_gen/gen.sh\`."
  echo "//!"
  echo "//! It is a translation of **one build**: the addresses are absorbed by"
  echo "//! [\`base\`], and the register allocation is not. Regenerate it when the"
  echo "//! guest binary is rebuilt."
  echo ""
  [ -n "$ICS" ] && echo "use std::sync::atomic::AtomicU64;"
  [ -n "$ICS" ] && echo ""
  echo "use crate::spec::*;"
  echo "use crate::{Cpu, Tlb};"
  echo ""
  echo "/// The bias between the address this was disassembled at and the one it"
  echo "/// loaded at. Set by the crate's \`register\`."
  echo "pub static BASE: Base = Base::new();"
  echo ""
  echo "/// Where \`$FN\` sat in the binary this was translated against."
  echo "pub const ANCHOR: u64 = 0x$(printf '%x' 0x$OFF);"
  echo ""
  echo "#[inline]"
  echo "pub fn base() -> u64 {"
  echo "    BASE.get()"
  echo "}"
  if [ -n "$ICS" ]; then
    echo ""
    echo "// One inline cache per call site. See \`spec::call\`."
    for n in $ICS; do
      echo "static IC$n: AtomicU64 = AtomicU64::new(0);"
    done
  fi
  echo ""
  echo "/// # Safety"
  echo "/// \`cpu\` and \`tlb\` are the running guest's, and this is entered from"
  echo "/// the interpreter in place of the guest's own \`$FN\`."
  echo "#[allow(unused_variables, unused_mut, unused_assignments)]"
  echo "pub unsafe extern \"C\" fn spec(cpu: *mut Cpu, tlb: *mut Tlb) {"
  echo "    let r = Regs(cpu);"
  echo "    let mut f = Flags::default();"
  echo "    let mut fr = [0.0f64; 32];"
  printf '%s\n' "$BODY" | sed 's/^/    /'
  echo "}"
} > "$SPEC"
echo "  wrote $SPEC   (load-base bias would be $BASE_BIAS)"

# 5. Print what to add to the crate's registration.
BASENAME=$(basename "$BIN")
echo ""
echo "== add to crates/kernel/offloadtestprebuilt/src/lib.rs =="
echo "    mod $MOD;"
echo ""
echo "    // inside register():"
echo "    let at = env_addr(\"IUL_${MOD}_ADDR\", $ADDR);"
echo "    $MOD::BASE.set(at, $MOD::ANCHOR);"
echo "    add(c\"$BASENAME\", c\"$FN\", at, $MOD::spec);"
echo ""
echo "then: tools/build-cli.sh --features offload-test-prebuilt -o <build>"
