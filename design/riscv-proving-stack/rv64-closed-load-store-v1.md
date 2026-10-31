# Closed Word16 load/store foundation v1

This experimental eight-component STARK proves independently expected load/store
requests against a complete finite word image, immutable word-uniform R/W policy
and terminal values/times. It does not prove CPU execution, a service bridge,
general sparse initialization, an aggregate, recursion or Ethereum execution.
There is no accepting open-LS or open-RAM verifier. Existing runtime/proof
profiles never select this namespace.

The contract matches the current RV64 memory facade: widths 1/2/4/8 are naturally
aligned, little endian, and remain inside one aligned eight-byte word.
Misaligned/crossword accesses are rejected. LB/LH/LW sign extend; LBU/LHU/LWU zero
extend; LD preserves all 64 bits. Stores replace only the addressed bytes and have
architectural C=0. Loads have normalized unused B=0. Write-only stores are valid;
only reads require readable, only writes require writable.

## Physical ownership and arithmetic

The typed owner tuple has 21 coordinates:

`(ownerID, opcode, A_base[4], decoded_imm[4], B_store[4], C_load[4], epoch16, tick16, tick8)`.

A, immediate, B and C are full four-limb u64 values. Four Boolean carries prove
EA=A+imm modulo 2^64; the final carry is permitted, not discarded implicitly.
Raw independently expected instructions supply opcode/width/sign/immediate through
the existing RV64 decoder and the legacy AIR's decode-derived access metadata.
The ISA switch and arithmetic recipes are not copied into a host acceptor.

Expected after ticks are nonzero multiples of four, explicitly bound by the LS
schema and public owner authority. Future CPU joins must physically authenticate
`after_tick=4*CPU_row+4`; modulo-four admission alone is not a CPU-origin proof.
The CPU load destination is written at `4*CPU_row+3`. A prior RAM producer at
a multiple of four strictly below the current RAM tick is therefore from an
earlier instruction, not a same-instruction slot-three alias. This separation is
needed by any future joint REG/RAM value-canonicality induction. Before times
remain grounded in INIT/previous owners by the closed RAM ledger; no CPU join
or canonicality pruning is activated here.

The aligned RAM word address is distinct from EA. Eight one-hot offset selectors
connect them; a ranged quotient proves alignedLow=8*q without a modular
inverse-of-eight compensation. Opcode-specific selector exclusions enforce
natural alignment. The same Boolean active coordinate weights the LS owner query
and its RAM before-minus-after query. Each row owns the real RAM transition;
there is no detached unbound before-word advice for store byte preservation.

The first 28 coordinates reuse the qualified closed RAM prefix. Its pure local
activity/order/permission/read-preservation and RAM/range authorities were
extracted without changing the closed RAM residual sequence; the retained
365,312-byte `1141f98a…b937583` proof remains exact with a fresh receiver.
Address addition uses the neutral `word_add.limbResidualFor` shared with ALU.
Domain and OODS use one arithmetic-lane authority. Full arbitrary-QM31 residual
and packed-base/secure lane comparisons retain all unconstrained selector values.

## Byte selection and measured geometry

The semantic table has 131,072 exact facts:

`(u16, parity, selectedByte, selectedByteBit7, u16Bit15)`.

Both parities occupy one physical row at log16. Fixed columns are
`(u16, hiByte, signLo, signHi, first, last)`; two main multiplicities and one
strict product inverse plus cyclic prefix use eight interaction columns. The
parity-zero selected byte is `u16−256*hiByte`; parity one selects `hiByte`.
Both tuples are affine. The weighted numerator `(m0*d1+m1*d0)*inverse` is cubic.
Strict inversion checks both poles even at zero multiplicity. Opposite-signed
weight changes preserving total count do not preserve the physical relation.

| Role | Log | Fixed | Main | Interaction | Residuals |
|---|---:|---:|---:|---:|---:|
| LS A | 6 | 3 | 79 | 116 | 280 |
| LS B | 7 | 3 | 79 | 116 | 280 |
| Sorted INIT | 5 | 34 | 23 | 48 | 51 |
| Sorted TERMINAL | 5 | 34 | 23 | 48 | 51 |
| Expected owner | 6 | 66 | 22 | 8 | 26 |
| U16 | 16 | 3 | 1 | 8 | 3 |
| U8 | 8 | 3 | 1 | 8 | 3 |
| Paired selection | 16 | 6 | 2 | 8 | 3 |

All residuals have degree at most three; the table and LS have genuine cubic
residuals. Quotient expansion is 2n. The fixture source is 597,568 fixed + 214,912
main + 1,076,480 interaction = 1,888,960 fields / 7,555,840 bytes, with 832 masks.
The initial naive log17 provider passed an actual q70 proof, but its table cost
was a rejected geometry control: 2,097,152 table cells instead of 1,048,576.
Packing removes 4,194,304 raw source bytes and lowers the largest source domain
without adding masks. This is a source-geometry result, not a complete-job
speedup claim; no Ethereum throughput is predicted from the small fixture.

## Conservative range ledger

All current queries remain present, including padding. No induction-based pruning
has been activated.

| U16 coordinates per LS row | Count | Current reason / future obligation |
|---|---:|---|
| Aligned RAM address | 4 | Full-u64 key and alignment/output-add canonicality |
| Before/after epoch | 2 | Local integer strict-order proof |
| Before/after tick low | 2 | Local two-limb clock proof |
| Epoch gap/tick-gap low | 2 | Nonnegative strict-order differences |
| Before/after RAM value | 8 | Canonical state without assuming a global value-induction lemma |
| A_base | 4 | Canonical address-add operand; eventual prior REG-write authority |
| Decoded immediate | 4 | Canonical operand; eventual immutable ROM authority |
| B_store | 4 | Canonical store input; eventual prior REG-write authority |
| C_load | 4 | Canonical output; eventual LS write-output lemma |
| Aligned-address quotient | 1 | Excludes modular inverse-of-eight alignment aliases |
| Total | 35 | 18 inverse pairs + prefix = 76 interaction columns |

U8 has five queries: before/after tick high, tick-gap high, B0 low and B0 high
bytes. The last two plus B0=low+256*high prove actual byte decomposition; a
canonical B0 alone does not justify removing either byte range. One unconditional
selection query authenticates the selected byte and sign bits. RAM and owner each
use eight columns; U8 uses sixteen, selection eight: total interaction 116.

A future **joint**, well-founded REG/RAM chronology may discharge 24 U16 value
queries: A4/B4 from prior canonical register writes, imm4 from ROM, RAM-before4
from INIT/earlier stores, RAM-after4 from the merge/write lemma and C4 from the
load lemma. A deliberately conservative hypothetical remainder is eleven U16
queries, reducing that group's 76 columns to 28 (total LS interaction 68), with
no claimed implementation or measured removal. This depends on authenticated
CPU/service origins, strict read-before-write order, complete unit-flow coverage
and canonical genesis/INIT. It cannot be assumed independently by each open chip;
REG loads and RAM stores require a single mutual-induction argument.

All range closures in this prototype are local to one PCS. The pinned whole-job
census model in `vectors/reports/rv64-guest-lean-20261031/round5/global-u16-mass-review-v1.json` counts 2,408,579,072 padded
U16 queries for a hypothetical shared global ledger, exceeding M31's
characteristic. A future execution-wide reuse needs explicit scoped provider
partitions and mass admission; this local proof does not activate such a ledger.

## Authority, tests and limits

Forty-nine expected requests cover every legal offset of all eleven opcodes,
negative signed values, high-u64 addressing, positive wrapping address addition and a negative immediate,
write-only stores, a no-op store, readonly clock advancement, three epochs and a
same-epoch high-clock carry. Native memory observations construct untrusted
witness only. The receiver derives public coefficients from expected raw
instructions/operands and derives immutable geometry without executing memory
operations. INIT/TERMINAL remain sorted-unique, complete finite public image
bindings, not a permission-only zero fallback.

All main columns and multiplicities seal before five distinct typed challenge
families. Every physical claim enters the local transcript before interaction
commitment and constraint coefficients. Each family closes separately; unused
claim tails must be zero. Padded positive masses are RAM67, owner49, U16 7,616,
U8 1,024 and selection192, all below the characteristic.

The twelve-test Safe/Fast suite includes actual q70/P26 closed proofs and nineteen
malicious physical proof attempts, exhaustive two-parity truth comparison against
independent little-endian bytes, strict paired poles at zero weights, dense degree
bounds, secure lane parity, locally valid INIT-fork and unused-store-B-high witnesses with distinct nonzero RAM/owner debt,
claim/root/image/raw-instruction/count attacks and exhaustive source allocation
failures. The dedicated durable tool produces and verifies in different
processes; the qualification report pins the final physical protocol and proof.
CPU/service joins, general image initialization, distributed inventory/epochs and
whole-block qualification remain explicit future obligations.
