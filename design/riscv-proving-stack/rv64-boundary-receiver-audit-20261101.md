# Boundary receiver authority audit, 2026-11-01

Source baseline: `9ded605ae`, including boundary `39c1c0e58`, affine trims
`f8d35c0a6`, DIV `0025cd686` and LS7. This change adds qualification fixtures;
it does not remove more constraints, change transcripts or assign a new schema.

## Authority checked at each accepting endpoint

`Cell` uses address/value u64, epoch u16, tick u24 and rights u2
(`air/memory/closed_ram/types.zig:5`). Its projection into four u16 limbs and
u16+u8 clock limbs is canonical by type, including decoding into these types.
The fixed-width sidecar also checks raw tick <2^24 and rights <=3 before
casting (`word16_execution/cells_wire.zig:74`); existing decode tests exercise
both failures and preserve high address/value limbs. Services and global wire
receivers use this same decoder, so noncanonical raw bytes cannot exploit a
narrowing conversion. That does not prove image authority, sorting or unique
addresses. Those are
checked separately, before statement/key/proof acceptance.

Paths below are relative to `src/integrations/riscv_cpu/`.

| Receiver | Public admission authority | Physical claim authority | Qualification coverage |
|---|---|---|---|
| Genesis per-execution | `word16_execution/execution.zig:178` -> `Admission.validateGeometry:41` -> `memory/statement.zig:40` | `execution.zig:200` -> exact INIT and TERM `expectedClaim` | Genuine malformed-list physical proofs; duplicate, unsorted, unaligned, unauthorized image value. Existing noncanonical limb/value ghosts, rebinding and physical row permutation tests retained. |
| Global RAM execution | `word16_global_execution/execution.zig:143` -> `protocol.validateRequests:96` -> `validateInventory:103` | `execution.zig:177` | Existing genuine two-shard proofs plus explicit top-receiver admission routing checks; shares the same global admission used by the production malformed-list fixtures. |
| Mixed services | `services/execution.zig:61` -> `services/protocol.zig:69` -> global `validateMaterials` | `services/execution.zig:102` | Hostile low-level worker constructs physical proof with malformed list, MAIN, retained metadata, claims and transcript in agreement; independent polynomial verification succeeds, top receiver rejects. |
| Ethereum complete/prefix | `ethereum/receiver.zig:40` calls mixed services after independently deriving program identity and CPU coverage | Mixed-service claim check, then independent terminal ABI checks for completed mode | Same genuine malformed-list physical proofs pass through the actual Ethereum prefix endpoint. Completion uses the same service gate before its additional terminal checks. |
| Per-shard Keccak | `keccak/execution.zig:213` -> local `validate:69` -> global `validateMaterials:89` | `keccak/execution.zig:247` | Existing genuine CPU/K/bridge proofs plus top-receiver routing checks. |
| Shared/bounded Keccak | `keccak/shared/execution.zig:316` -> `protocol.admitBounded` -> `admitCpu:24` -> global `validateMaterials:48` | `keccak/shared/execution.zig:364` | Existing genuine shared truth proof plus top-receiver routing checks; the single-truth entrypoint delegates to bounded acceptance. |
| Secp | `secp/execution.zig:312` -> `secp/protocol.zig:52` -> global `validateMaterials` | `secp/execution.zig:351` | Existing genuine CPU/ADD/DOUBLE proofs plus top-receiver routing checks. |
| Diagnostic two-PCS boundary | `word16_execution/memory/global_boundary_proof.zig:242` -> `specs:99` | `global_boundary_proof.zig:230` | Genuine baseline physical aggregate plus duplicate/unsorted/unaligned/wrong-image receiver input checks. Diagnostic certifies boundary proofs only, not CPU coverage. |

The genesis statement validator rejects unequal boundary lengths, unaligned
addresses, non-strict initial order, position-mismatched terminal addresses,
untrusted initial epoch/tick/value/rights, changed terminal rights and terminal
epoch beyond the execution. Global `validateInventory` establishes the same
properties for the sole INIT and final TEARDOWN, prohibits repeated intermediate
INIT/TERM, binds CPU adjacency and endpoints, and bounds RAM mass. Strict initial
order plus positional equality also establishes terminal sorting/uniqueness.
There is no accepting route that relies on `expectedClaim` alone for sorting.

Native residual diagnostics (`word16_execution/native_diagnostic.zig`) are not
accepting proof receivers. Its header explicitly disclaims degree/off-domain
correctness; no diagnostic success is promoted to an execution certificate.

## Genuine malformed-list physical proofs

`memory/boundary_anchor_test.zig` now extends the hostile genesis prover. Its
public lists and committed boundary tuples deliberately agree on a duplicate,
unsorted address, unaligned address or unauthorized initial value. Retained
metadata is rebuilt to agree as well: leaving it canonical would merely test
honest-producer rejection before proving. Each full physical proof is freshly
verified independently before the real endpoint must reject public admission.

`services/boundary_receiver_test.zig` repeats that construction under the actual
production mixed-service transcript and shared-challenge worker protocol. It
bypasses only the coordinator's native producer admission by directly using its
low-level worker. Fixed/MAIN roots, manifest, interaction generation, commitment,
FRI, openings and independently recomputed boundary claims remain real. An
independent physical verifier checks the proof and closed RAM debt; both actual
services and Ethereum receivers then reject the malformed public statement.

The positive control leaves the public list strictly canonical but permutes
physical boundary rows and their retained metadata. Both receivers must accept:
RAM14 is a multiset argument, and physical sorting is intentionally unnecessary.
Existing noncanonical-field-limb attacks and public-debt rebinding tests remain.

The specialized global/K/shared-K/secp tests mutate public headers on already
valid baseline proofs to lock the top endpoint's routing to the common native
admission guard. Those are not represented as independently re-proved malformed
transcripts for each specialized protocol. The genuine malformed-transcript
qualification is on genesis and the production services/Ethereum lane.

## Small affine and DIV review

The affine trim is a substitution, not an omitted assertion: ALU op/C are
derived by the same expression authority used in FUNCTION; packed SHIFT derives
opcode from selectors; JALR uses Boolean ACTIVE as its sole weight; LS still
queries the affine `b_low = B0 - 256*b_high` expression in U8. Existing physical
forgeries and their exact rejected obligations are recorded in
`rv64-word16-small-air-trims-v1.md:223`. The later CPU/LS read-range inheritance
has its own joint REG/RAM write qualification and is not justified by this
boundary audit alone.

DIV high-product support is the actual MULHU tuple with constant-zero result,
not an unchecked removed field. DIV's remaining nonlocal QUOTIENT, ABS_B and
PRODUCT_LOW ranges still depend on independently byte-ranged MUL inputs/results.
The recovered review added all24 actual degree-three MUL A/B/RESULT byte-query
coordinates and physical FUNCTION closure gates (`0c79e958c`, integrated by the
parent). Existing full DIV local-proof attacks and closed low/high support
fixtures remain the authority; no second DIV trim is applied here.

## Gate status

Source audit and expanded ReleaseSafe/ReleaseFast qualification passed for all
seven suites: memory, combined services, global execution, per-shard Keccak,
shared Keccak, secp and diagnostic global memory. Gate logs and exact source
hashes are recorded in
`vectors/reports/rv64-word16-execution-20261101/boundary-receiver-audit-v1.json`. An initial engineering run exposed three hostile-fixture metadata
mismatches; those were honest producer rejections, not accepting receiver bugs.
The corrected fixture rewrites MAIN and retained metadata together.

This qualification neither establishes128-bit whole-protocol security nor
qualifies device proving or recursion. Those remain separate gates.
