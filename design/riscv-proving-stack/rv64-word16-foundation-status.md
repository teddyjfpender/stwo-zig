# Word16 frontend qualification status

This inventory separates accepting experimental proofs from the unchanged
full-block Ethereum route. Source counts and timings belong to the named
fixtures; they are not forecasts for arbitrary blocks.

## Accepted full-block reference

The round-five guest executes 104,253,913 instructions for Ethereum block
24,628,607. The retained CPU run produced 25 batch proofs plus a terminal
certificate in 716.99 seconds, with 41,862,758,400 bytes peak RSS. A separate
receiver accepted them in 7.16 seconds with approximately 6.09 GB peak RSS.
This route uses the existing wide CPU, batch RAM root chain and crypto
services. It has no recursive proof or GPU execution.

See [the pinned block receipt](../../vectors/reports/rv64-guest-lean-20261031/round5/complete-block-isolated-v1.json)
and [per-batch profiles](../../vectors/reports/rv64-guest-lean-20261031/round5/batch-bottlenecks-v1.json).

## Qualified experimental foundations

| Foundation | Physical evidence | Integration boundary |
| --- | --- | --- |
| Raw Word16 CPU with independently sized ALU/BINARY | Closed CPU, ROM, local register, boundary and range relations; branch and immediate requests; degree-three constraints on 2n; one-shot 4,194,300-instruction loop with fresh verification | Limited opcode set, register-only execution; no Ethereum, services or RAM |
| Indexed Word16 CPU | 40 main / 56 interaction CPU columns; full-u64 ROM address map, immutable static exits, authenticated program IDs, real padding tuple | Static control only; no dynamic JALR or full ISA |
| Immutable setup | Program, geometry and encoding determine fixed polynomials and a retained shared committed tree; public steps, PCs, register values/clocks and fresh transcript stay request-specific | Thin diagnostics only; the accepted legacy block receiver still has substantial setup and memory cost |
| Native witness pipeline | Physical-order projection once, transactional worker histograms, bounded native interaction prefix waves, committed matrices released while narrow relation metadata survives | Complete scalar/packed and serial/parallel parity on qualified fixtures |
| Composition | Packed M31 domain evaluation and secure random-coefficient accumulation; QM31 OODS; shared bounded column FFT and row workers | Tests cover arbitrary field points, degree bounds, worker errors and small stacks |
| Closed finite RAM | Physical operation, image, policy, terminal and range closure in an actual STARK | Explicit finite expected image; no general sparse image or CPU link |
| Word16 load/store | 79 main / 116 interaction columns; 280 degree-three residuals, paired byte-selection table, full base/immediate/store/load operands, strict aligned RAM transition | Closed finite-image proof with public expected operations; CPU time and operand joins are not yet present |
| Narrow ALU encoding | 52 main / 52 interaction columns and 69 degree-three constraints; SUM-zero equality hints retain mandatory external U16 authority | Composed with weighted source; isolated paired-loop RSS fell about101 MB, no runtime win observed |
| Weighted BINARY source | 31 independently expected Boolean requests close against three truth facts with weights7/11/13; physical AND queries remain unweighted | Optional native source; all three historical BINARY proofs remain exact |
| Weighted ALU source | Existing FUNCTION multiplicities, canonical native mass, owned 70-byte metadata; a fresh closed proof binds 1,048,575 native BEQ instructions to one truth fact | Optional prover witness choice; same receiver and caller-selected independent geometry; no full-block activation |
| SHIFT providers and native source | Byte and two Word16 encodings; strict table/range/FUNCTION closure; native main released before challenges, retained 26-byte payload per row | No CPU SHIFT join; full table, dictionary and count costs remain charged |

Qualification reports:

- [Execution, native sources and bounded composition](../../vectors/reports/rv64-ethereum-20261030/word16-execution-foundation-v1-qualification.json).
- [Indexed control](../../vectors/reports/rv64-ethereum-20261030/indexed-control-diagnostic-v1.json).
- [Physical CPU projection](../../vectors/reports/rv64-ethereum-20261030/word16-native-physical-projection-v1.json) and [contiguous ROM lookup](../../vectors/reports/rv64-ethereum-20261030/immutable-contiguous-lookup-v1.json).
- [Closed load/store](../../vectors/reports/rv64-ethereum-20261030/closed-load-store-v1-qualification.json).
- [Composed narrow and weighted ALU](../../vectors/reports/rv64-ethereum-20261030/alu-sumzero-weighted-composed-v1.json) and [paired loop observations](../../vectors/reports/rv64-ethereum-20261030/alu-sumzero-v2-paired-loop-v1.json).
- [Weighted BINARY source](../../vectors/reports/rv64-ethereum-20261030/word16-binary-weighted-source-v1-qualification.json).
- [Register and transcript soundness review](rv64-word16-register-soundness-review.md).
- [Weighted ALU source](../../vectors/reports/rv64-ethereum-20261030/word16-alu-weighted-source-v1-qualification.json).
- [Load/store SIMD and bounded domain workers](../../vectors/reports/rv64-ethereum-20261030/load-store-domain-simd-v1-qualification.json).
- [SHIFT source lifecycle](../../vectors/reports/rv64-ethereum-20261030/word16-shift-source-v1-qualification.json).

The contiguous lookup benchmark measures the native lookup operation only.
The legacy full-ISA route already has that fast path; it is not an Ethereum
speedup. The 4.19M loop is a capacity and correctness qualification, with
9,564,782,592 bytes peak RSS in its retained run. It has no RAM or services
and was not an isolated whole-block performance comparison.

## Measured opportunity: pure function reuse

The read-only census covers all 25 admitted block packets and all 104,253,913
instructions. Exact `(operation,A,B,C)` tuples retain ordered operands and all
64-bit values, including W-operation high bits and branch predicates.

| Family | Requests | Distinct tuples across the block | Sum of distinct tuples within each batch |
| --- | ---: | ---: | ---: |
| ALU, including branches | 38,032,275 | 9,348,047 | 10,367,981 |
| BINARY | 13,582,670 | 6,515,889 | 7,142,615 |
| SHIFT | 12,715,792 | 5,219,439 | 5,515,478 |

Existing arithmetic authorities already support committed multiplicities. A
weighted source can choose fewer physical truth rows without adding a new
instruction profile or arithmetic equation. Range/table queries remain per
physical truth row, while FUNCTION counts repeated CPU requests. The actual
padded roster still determines the cost; this is not a measured full-block
saving. Register and RAM events retain their individual time and ownership.

See [the exact census and capacity models](../../vectors/reports/rv64-ethereum-20261030/round5-exact-function-reuse-census-v1.json).
The [range mass review](../../vectors/reports/rv64-guest-lean-20261031/round5/global-u16-mass-review-v1.json)
also shows why a proposed global provider must admit its entire padded query
inventory below the characteristic, including other chips. Its conservative
unit-fact counterexample is not a lower bound after deduplication.

## Native batch recursion integration

The native-protocol circuit verifier wraps the existing wide Ethereum batch
proofs. Fresh two- and four-batch runs produce one circuit root, while the
receiver checks digest-bound statement adjacency natively. This does not yet
wrap the new Word16 CPU or prove adjacency inside the fold circuit. It also
does not replace the full-block terminal certificate.

Integration hardening binds the native fixed commitment inside the circuit;
requires independently trusted per-position circuit and layout pins; checks
every internal fold topology; binds each packed leaf digest to the revealed
statement; and applies the native public admission rules before chain use.
The trusted admission JSON is an explicit receiver input, not an authority
inferred from the proof directory. See [the recursion admission review](rv64-recursion-root-admission-review.md) and [the merge qualification report](../../vectors/reports/rv64-ethereum-20261030/recursion-merged-v1-qualification.json).

## Gates before replacing the Ethereum CPU

1. Finish one concrete full-ISA CPU/request contract, with store B, immediate,
   JALR target and service operands bound physically. Independently size chips
   and count fixed providers, padding, interactions and openings in the roster.
2. Join LOAD/STORE and each crypto service to CPU-issued requests and their
   actual REG/RAM event times. Prove the canonicality induction before removing
   inherited read ranges. A native witness check is not a replacement.
3. Qualify all RV64IM operations and supported services against independent
   execution oracles, semantic statements, adversarial proofs and fresh
   receivers. Representation changes deliberately require new proof fixtures.
4. Keep each RAM batch closed until the two-phase global challenge protocol and
   an aggregate receiver authenticate all stage-one roots, every physical
   claim, INIT/TEARDOWN ownership, exact coverage and execution adjacency.
5. Run retained CSP workloads and the entire pinned Ethereum block on the new
   route, recording end-to-end witness/proving/receiver time and peak memory.
   Compare committed cells, quotient points, padding and immutable setup costs.
6. Integrate recursion work separately when supplied and qualified. The current
   experimental foundations make no recursive acceptance claim. Port the
   qualified base-field lane authority to accelerators after its roster and
   resource lifetimes are fixed.

The [result advice proposal](rv64-result-advice-tape-proposal.md) addresses the
48-byte per-instruction capture separately. Its modeled storage reduction is
not a proof-memory reduction or an activated packet format.
