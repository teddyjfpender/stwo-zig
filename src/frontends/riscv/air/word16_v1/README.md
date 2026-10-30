# Word16 semantic specifications, version 1

**Experimental local algebra only.** The full-block baseline imports none of
this namespace. These files are not a working alternative prover, verification
key, range-admission receipt or performance result. The focused ReleaseSafe
gate passed all 16 tests on 2026-10-30 after the full-block campaign was stopped.
No tests or formatter ran while that proof occupied the host.

```sh
python3 scripts/zig_protocol_test.py --lock /tmp/stwo-zig-integration-build.lock \
  src/frontends/riscv/air/word16_v1/test_root.zig \
  -OReleaseSafe --test-filter word16 -j1
```

This tests M31 equations, fixed-table diagnostic predicates, request censuses,
compact residual/event equivalence and hostile local mutations. It does not
qualify a complete range/clock/ROM/CPU provider, original proof, recursive
proof, global closure, compiled circuit scalar adapter or inferred degree
audit. Some dormant host helpers have not yet been instantiated by this gate.

`root.zig` exports the generic equations, canonical two-halfword value ABI,
new tuple domains, bounded honest writers, natural lookup counters and finite
request manifest. Scalar and recursive circuit backends are intended to call
the same equations through the existing `S.splat(QM31)` scalar interface.

The operation coverage is ADD, SUB, ADDI, XOR, OR, AND, XORI, ORI, ANDI, LW,
LB, LBU, LH, LHU, SW, SB and SH. The load/store equations preserve canonical
base addresses below 2^30, bounded effective-address addition, alignment,
partial-word preservation, sign extension, x0 and every-access first-halt
semantics. All rows enforce canonical inactive padding. The writer has fixed
capacity and byte bounds; it does not silently grow or assert proof authority.

An expression sink implements `add(residual, total_degree)`. A relation sink
implements `access`, `clock`, `cpu`, `rom`, `range16`, `range8_8` and `bitwise`.
Provider sinks additionally implement the four `provide*` methods documented
in `range_plan.zig`. Request methods denote negative requests; the provider
methods denote positive fractions. Every physical fraction and integer-count
claim still needs a genuine committed interaction AIR and transcript binding.

Quarter-low address limbs require BOTH unscaled R16 membership and scaled
R16(4*q) membership: the scaled constraint alone admits q=4^{-1} in M31.
This adds one R16 request to every LS row. Quarter-high is separately bounded
by its equality to canonical base.hi plus a ternary carry before its scaled
check. The legacy signed-immediate conversion similarly has three explicit
R16 requests, including an unscaled low12 bound. New immediate kernels instead
derive their pre-scaling bound from the signed-ROM equality and Boolean sign.

The new ROM schema uses signed [-2048,2047] immediate field values. Released
immediate-ALU u12 ROM keys cannot be reused. Distinct register/RAM four-field
tuples contain address, access clock, low16 and high16. Legacy native/caller
bytes can be packed as affine expressions over the same authenticated wires;
this does not create range authority for arbitrary replacement cells. Initial
and final public tuple values must come from independent ELF/snapshot/CPU
admission with bounded addresses/clocks and explicit x0.

Clock-order, fixed-ROM and bitwise-table semantics are OPEN relation obligations
until the corresponding independently keyed providers and all producers close.
The range helpers similarly do not admit host counter arrays. Canonical R16
and byte-pair provider tables each require all 65,536 fixed rows. Natural
request counts must remain below M31's modulus and be tied to physical count
claims. This namespace deliberately exposes no key factory or proof codec.

The semantic row structures retain explicit redundant byte views where that
makes the specification complete. `projection.zig` now provides explicit
committed arrays for a finite subset: ADD/SUB20, ADDI17, LW22 and SW18. LW/SW
include two HALT auxiliaries. Each component additionally reserves THREE fixed
columns (canonical activity prefix and domain first/last). Its finite opcode
is key/geometry-owned, with no hidden committed opcode selector. The generic
expander derives only affine aliases and zeros, then replays the SAME semantic
equations and events. The final column-major writer stores only compact cells;
it does not retain a semantic-width intermediate matrix. No PCS is implemented.

The host packer rejects inconsistent discarded semantic fields as hygiene;
the proof authority must come from `projection.evaluate` over committed cells.
Dormant hostile tests mutate those cells directly, bypassing the packer.
The inverse-quarter mutant reaches the emitted R16 obligation, and x0/HALT
mutants reach the polynomial equations. These are not full original proofs.

Additional local cases cover `rs1=rs2=rd` with ordered predecessor clocks,
ADDI/LW destination aliases and SW source aliases, LW into x0, native terminal
HALT permission at the exact cycle versus the wrong cycle, and nonzero padding
in EVERY compact slot of all five profiles. These remain local-algebra tests.

`load_store.Halt` must be independently admitted as a key parameter. A future
receiver must derive its address from the pinned ELF, validate alignment and
platform bounds, and bind permitted native cycles to the exact terminal local
frame and full completion/output policy. Nonterminal and caller accesses have
no final-cycle exemption. Checking only writer inputs is not authority: choosing
the wrong halt address can make an actual halt write have hit=0 locally. The
local terminal guard merely permits that cycle; it does not prove the final
halt value is one or the expected output is correct.

The local diagnostic sink deliberately leaves register/RAM/ROM/CPU closure
OPEN. In particular, an LW with a noncanonical incoming RAM limb can satisfy
the local arithmetic while copying it into RD: canonical input bounds require
the complete well-founded clock/access graph and authenticated bounded
initial/write producers. The test sink is not that proof and must never be
presented as establishing canonical input limbs or a complete original.

Remaining operation lowering, actual interaction/provider and clock-gap witness
cost, typed degree auditing and total padded/LDE accounting are future work;
a declaration of degree4 for the dominant kernels is not a
completed compiler audit. Affine legacy/caller conversion inherits the actual
source polynomial and activation degrees; it cannot relabel a nonlinear
authenticated source expression as a degree1 main cell.

Before activation: finish all remaining ISA affine adapters and their full
register/RAM/ROM/lookup/clock/public boundary roster, implement the original
and generic recursive adapters, generate new semantic/layout/key identities,
and qualify q70/26 source-to-single-root proofs from serialized artifacts.
Negative gates must cover field-wrap and signed carries, x0 and operand aliases,
all load signs/offsets/partial stores, inactive pads, missing producers,
compensated physical claims, transient halt writes, terminal output and
current/+27 caller authentication. Preserve old codecs, schemas and keys under
their existing versions. See
`design/riscv-proving-stack/performance/native-and-caller-encoding-next-architecture-20261030.md`
for source census and carefully scoped projections.
