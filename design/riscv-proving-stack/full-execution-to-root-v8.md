# Complete RISC-V execution to one recursive root

The qualification target is the retained Ethereum guest's complete execution,
including instruction one, the real halt store and its expected 43-byte output.
Native nonterminal windows are calibration evidence, not substitutes for this
statement. The implementation remains experimental until the complete campaign
and its independent receiver pass.

## Proof structure

```text
Pinned ELF + input bytes + expected output + security + exact coverage
       |
       +--> independently reconstructed initial CPU and RAM snapshot
       +--> terminal halt/output policy
       |
       v
One bounded execution prepares adjacent checkpoint inputs
       |                 (preparation, not proof authority)
       v
Ordered windows, independently sized for native and caller work
       |
       +--> native OR mixed original
       |      native instruction/state/register equations
       |      exact ROM + shared lookup providers
       |      caller arithmetic, program/state/table and RAM equations
       |      every-access halt guards
       |      authenticated narrow RAM endpoint main tree
       |             |
       |             +--> release wide execution witness
       |             v
       +--> late bridge over the SAME endpoint commitment
       +--> compact global RAM over full pinned snapshot boundaries
       |      includes every changed address
       |      terminal window also includes halt, length and output words
       v
ONE recursive window proof verifies all original proof families
       |
       v
Bounded ordered folds: independently admitted child keys + physical claims
       |      public-supply closure, not aggregate-zero substitution
       |      exact CPU and snapshot adjacency
       |      contiguous cycle coverage, ELF and security agreement
       |      carry an odd frontier unchanged; never duplicate a leaf
       v
ONE full-execution root
       |
       v
Fresh receiver rebuilds keys from external policy and saved metadata
Checks exact initial/terminal policy identities and complete coverage
Verifies the serialized final proof independently
```

## Authority and lifetime rules

Checkpoint SHA-256 identities bind complete canonical CPU/RAM snapshots; file
transport hashes are separate. A checkpoint manifest authenticates no execution.
Window proof keys must be independently reconstructed with those external
snapshot identities and their derived boundary constants. An upper fold must
verify the child STARK and its public lookup supply, then compare the ordered
statement coordinates. Accepting a producer-nominated key or a host verification
receipt would break this chain.

This receiver is **statement-specific**: it needs the complete intermediate
snapshots to reconstruct instance-dependent fixed boundary keys. The current
retained schedule shares approximately 2.7 GB of checkpoint data. These values
may be supplied untrusted: initialization is independently derived, each window
proves its actual RAM transition and all snapshot changes, and the root binds
adjacency and terminal output. However, a small final proof does **not** imply a
universal verifier needing only ELF/input/output digests. Bounded public inputs,
universal key admission and eliminating intermediate snapshot dependence are
remaining architectural work beyond this profiling path. Final key reconstruction
time belongs inside the reported receiving cost.

The mixed producer builds and proves its wide witness once. It retains only the
endpoint matrix and the corresponding PCS tree lease, never a reconstructed
endpoint commitment. The bridge consumes that same root. After bridge generation,
the narrow lease is released before global memory proving. Every original is
serialized, its producer destroyed, and the durable bundle freshly received.

Wide native shard geometry is separate from direct RAM-clock selection. Mixed
execution retains its independently constrained caller/native memory clocks;
selecting larger opcode shards cannot silently select a different memory argument.
Each geometry extension is serialized and bound into admission and transcript
identity. Resource limits bound allocation and decoding; they do not waive AIR,
lookup or completion checks.

Initial admission reconstructs the loader's entry PC, SP, GP, zero registers and
input-overlay RAM. Terminal admission permits the actual final native halt store
only at its final instruction cycle. The corresponding completion access clock
is `4 * cycles - 1`. Caller writes remain guarded throughout. Expected output
words enter the compact RAM boundary argument; matching a host snapshot alone
does not certify output.

## Execution preparation

`scripts/v8_full_block_campaign.py plan` validates the retained census and emits
an exact window schedule, a checkpoint schedule and a reduction DAG. The existing
execution census accepts `STWO_B8_CENSUS_CHECKPOINT_PLAN`, producing all requested
states in one bounded run. `publish-capsules` checks transport hashes, canonical
snapshot identities, execution coverage and caller/native counts before emitting
the existing source-producer inputs. No skipped prefix is replayed per window.

The current qualification schedule has 107 windows and 106 folds under explicit
8M-native/1M-mixed/4,096-caller bounds. This is a complete resource-bounded schedule,
not the final throughput architecture or an extrapolation of the earlier
nine-native-window cost model. Larger mixed cohorts and shared physical openings
remain structural optimization targets after full closure.

## Measurement boundary

The complete driver is `prover/block_v8_full_block_pipeline_v1.zig`. It persists
thin, schema-framed receiving metadata separately from proofs; complete snapshots
are shared external inputs and are not copied into every ancestor packet. Each
fold loads and releases its two child proof captures/profiles. The final receiver
reloads the catalog and proof bytes and derives a new full boundary policy.

Explicit `resume_saved` mode independently reconstructs and verifies each saved
window root before reuse. File presence, prior reports and successful status flags
are never admission evidence. An incomplete leaf packet fails closed. Retained
original bundles are reusable only through the ordinary fresh original verifier
and root producer. All upper folds are rebuilt from the admitted ordered leaves.
Previous final reports/catalogs/proofs are archived, and resumed timing explicitly
excludes prior proving work; it cannot be presented as a fresh full-block latency.

Record input preparation and execution separately, then source loading, witness
construction, original proving, late memory closure, recursive compilation/setup,
recursive witness/proving, publication and fresh final verification. Report whole
request wall time and peak live memory as well. Concurrent stage times may overlap
and must not be added as if they were serial. Preserve failed attempts and label
contended diagnostics. The primary optimization benchmark is a complete block
whose final serialized root has independently verified.

Campaign evidence and current qualification status live in
`vectors/reports/riscv-cpu-architecture-20261029/full-block-assembly-v1/`.
