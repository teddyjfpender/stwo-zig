# Arithmetization and memory engineering program

Branch: `codex/rv64-arith-memory`. Started from `a06c0992f`, reconciled
with the qualified frontend/recursion merge `caeb185e1` in `9aae4fe3f`.
The interrupted attempt left two design documents and no implementation.
This document describes the resumed engineering, rather than retaining its
unqualified width estimates as implementation budgets.

The requested **3–5× arithmetization** and **1.5–2× memory** improvements
remain acceptance targets. A faster diagnostic or fewer CPU columns does
not establish either result. Compare the complete joined proof, including
independent component padding, tables, composition domains, setup, receiver,
peak memory and total time, against the same legacy packet.

## Architecture implemented in the new namespace

`air/word16_execution/` is a concrete protocol, not another runtime profile.
It retains full 64-bit values and program counters. Program-only immutable
ROM/features are separate from request counts, register endpoints, memory
boundaries and fresh transcript challenges.

| Physical component | Main / interaction columns | Qualification boundary |
| --- | ---: | --- |
| CPU | 53 / 40 | 55 residuals, degree ≤3, 2n; native and actual circuit-point tests |
| ROM | 1 / 8 | 32 fixed columns; full-ISA normalized semantics and branch edges |
| ALU | 52 / 52 | Existing independently sized provider; exact-fact grouping |
| BINARY | 42 / 28 | Existing AND-backed provider |
| SHIFT | 53 / 48 | Existing packed provider plus independent shared table |
| Nonzero-immediate JALR | 18 / 12 | Unit-weight composite, ADD and AND supports must close |
| MUL / DIV | Existing separate providers | Exact 13-limb to 25-byte challenge basis; no extra bridge rows |
| Load/store | 79 / 116 | Typed OWNER19; RAM14; 281 residuals including epoch/tick binding |
| INIT / TEARDOWN | 23 / 48 each | Scalable expected-image/public-list binding; no one-hot table |

Zero-immediate JALR uses the direct AND provider. LUI, AUIPC, JAL and FENCE
use normalized ROM flags and existing ALU operations. Branches emit a
predicate rather than a fabricated register write. No CONTROL table is needed.
CPU clocks use u16/u8 range lookups rather than Boolean decompositions.
All component dimensions come from the complete seventeen-role physical roster.
MUL/DIV use a higher local quotient bound without widening CPU constraint
evaluation. The existing accumulator lifts by evaluation height, so mixing
native 2n and 4n contributions needs an explicit common composition format:
split 2, with reviewed one-log polynomial extension for every native-2n
component's weighted quotient. CPU constraints are still evaluated at 2n;
the global composition and FRI geometry is not uniformly 2n. Both dimensions
must be reported. A split-only override fails OODS consistency because it
changes the canonical lifting map; matching native residuals is insufficient.

The OWNER relation includes operation, architectural base, immediate, store
value, loaded result, epoch and tick. Keeping the immediate is essential:
operation and operand values alone do not identify a load/store request.
The RAM collector consumes compact memory advice without executing a VM,
constructing a Poseidon tree or retaining a second wide Retirement journal.

## Soundness decisions

A merged accumulator does not make every inverse pair cheap. REG already
has quadratic denominator products; pairing those again would exceed degree
three. The interrupted CPU28/ALU28/LS60 interaction estimates were therefore
withdrawn. Actual widths above take priority over a narrower drawing.

A composite JALR provider cannot accept arbitrary field-valued multiplicities.
Signed rows can make all marginal ADD/AND request sums close while carrying
invalid JALR outputs. Its multiplicity is constrained to unit activity. Base
ALU/BINARY truth providers may still group identical locally constrained facts.

All 33 physical claims enter the transcript before interaction commitment.
The receiver checks closure and rejects nonzero fields with no physical
columns. INIT values and permissions come from a separately loaded pristine
image. Expected boundary claims are recomputed after main columns are sealed.
MAIN buffers can then be released while narrow relation obligations survive.

The current memory admission is **genesis-only, epoch 1**. It deliberately
rejects later batches; independently reinitializing those from the ELF would
be unsound. Service owners are also rejected until their bridges are joined.
A proof admitted here establishes an execution prefix, not final block output.

## Measured transport evidence

The direct reader admitted real round-5 packet 0: 4,194,303 retirements,
343,445,435 packet bytes and 211,004,104 compact-tape bytes. Its planning
probe used approximately 857 MB peak RSS. This is transport evidence, not a
proving-memory result. It classified 1,202,034 loads/stores, 995,056 shifts,
5,051 multiplication requests and no service calls, plus ALU/BINARY/JALR.
See `vectors/reports/rv64-word16-execution-20261031/` for pinned scope/receipts.

## Remaining acceptance gates, in dependency order

1. Qualify one joined mixed-instruction proof and fresh receiver, including
   arithmetic, strict registers, loads/stores, trusted initialization and all
   physical claims. Add mutation cases and main-release lifecycle tests.
2. Prove and freshly verify real packet 0. Report independently padded cells,
   stages, setup amortization and RSS; compare identical work with legacy.
3. Integrate constrained Keccak/secp service owners and their RAM effects.
   Refusing service packets remains mandatory until this closes physically.
4. Qualify the two-phase global-memory manifest and aggregate receiver before
   admitting non-genesis shards. Stage-one roots must all be sealed before
   shared challenges; check exact coverage, adjacency and total RAM closure.
5. Route new fixed proof shapes into the independently pinned recursion path,
   and benchmark complete real-block production and receiving.
6. Move delegations into their planned directories after active source/build
   work freezes. Preserve public imports and actual layout-derived budgets.

No claimed cell/time/RSS improvement may be extrapolated solely from CPU53/40.
Load/store width, shared tables and per-family padding can dominate the joined
result and must guide the next optimization.
