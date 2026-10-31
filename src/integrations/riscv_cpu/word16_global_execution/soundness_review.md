# Independent review: global execution prefix v1

This manual review covers `protocol.zig`, `execution.zig`, `collector.zig`, the
additive global witness path in `word16_execution/sources.zig` and
`memory/prepared.zig`, and the reused CPU/LS/boundary authorities. It is not a
formal proof or a claim of whole-block, service or recursion qualification.

The accepting statement is an execution prefix with independently supplied
program/image authority, genesis PC/registers, step budget, and public final
PC/register values. It does not establish the guest halt flag or Ethereum's
43-byte output certificate. Services remain unsupported by this source path.
The epoch16/tick24 representation retains its explicit finite bounds.

## Authority and transcript obligations checked

`protocol.validateRequests` checks the caller's `Expected.program_identity`,
not agreement with a producer-chosen first key. Receiver setup owners must be
reconstructed from the pristine expected program and geometry. Each shard's
fixed root is checked against that independent key in `execution.verify`.
The per-shard budget and global total-step budget are enforced before proof
decoding. Program pin and local-budget checks were added following this review.

`checkStage1` obtains actual fixed/main PCS roots and checks the exact geometry.
The ordered manifest seals every statement digest and actual root pair before
`Manifest.ram` derives shared RAM14 randomness. Receivers reconstruct the
statement digests, check the complete inventory, and compare actual proof roots
to the manifest. Resumed stage-two workers recheck their retained stage-one
roots. Native value roots and transport hashes never substitute for PCS roots.

Every local challenge channel binds its own public request, ordinal, first
step, expected context, and complete manifest. All core physical claims (including optional LS tail) enter the
local transcript before interaction commitment and constraint coefficients.
`Source.validateOpenForGlobalRam` checks a zero sum EXCLUDING only LS/INIT/TERM
RAM claims from head LS, optional tail LS, INIT and TERM through the canonical core ramClaim helper. Thus non-RAM debts cannot cancel across shards.
Within a shard this is a joint typed rational identity, not an independently
closed certificate for each individual family. The receiver repeats that check,
fresh-verifies every physical proof, and closes the remaining shared RAM debt.

## Continuation and RAM argument checked

Epochs equal ordinal+1. PC and all 32 register VALUES are adjacent across shards;
local register clocks deliberately reset to zero and are checked within each
CPU proof. Summed physical CPU step counts must equal the expected total, with
independently admitted genesis and claimed final endpoints.

Only shard0 may contain INIT and only the last shard may contain TEARDOWN.
Boundary addresses are sorted and unique both in public admission and the
reused ranged strict-address AIR. INIT values and permissions are read from the
independent pristine image/policy. The receiver checks actual boundary claims
against `boundary_source.expectedClaim`, including zero claims for empty
boundaries; constructor checks or receipt assertions alone are insufficient.

Every RAM event is unit-active, with the same OWNER weight as its CPU request.
The OWNER19 tuple authenticates after-epoch and after-tick=4*CPUrow+4, so there
is no independently chosen producer timestamp. Reused LS equations/ranges prove
strict lexicographic epoch/tick predecessor ordering, canonical words and
permissions, read preservation and store semantics. Bounded integer limb sums
are below M31 and cannot hide field wrap. INIT stamp is zero. Sorted unique
INIT, unique owner-produced address/time states, and the admitted total unit
mass below the characteristic rule out forked histories and orphan cycles in
the shared multiset argument. Canonical range checks have not been pruned.
Unrelated byte/U16/register relations remain locally scoped.

## Actual adversarial checks

The strongest fixture uses SDx1=7 in shard0 followed by LDx0 in shard1. Its
forged advice makes shard1 read pristine zero instead of the stored7, while
all public register/PC endpoints stay unchanged because the load discards its
result. Both actual local CPU/LS STARK proofs can be produced and their local
non-RAM debts close. After verifying those proofs, the aggregate receiver must
reject `UnclosedGlobalExecutionRam`. The honest control is accepted. This test
bypasses the native collector intentionally, so host predecessor checks are not
the authority.

Additional tests reseal manifests with wrong actual fixed/main roots, swap root
positions, omit inventory, balance RAM-claim mutations across shards, attempt
cross-shard local-debt cancellation, set omitted physical claim tails, change
program/image/permissions, repeat INIT, end RAM early, duplicate addresses, and
break epoch/PC/register/step adjacency. The old closed/genesis receiver still
rejects these open fragments, including the epoch2 scope after rebasing its
claimed local CPU initial endpoint. These tests supplement the existing dense-Q
degree, SIMD, local clock, permission and range qualifications.

## Worker ownership seam and security accounting

The concrete `Stage1Worker` consumes one Source and owns its PCS scheme. `seal`
commits fixed/MAIN, checks actual roots and geometry, retires MAIN, and only then
returns an ordinal/spec/two-root descriptor. `manifestFromSeals` needs no witness
or PCS pointer. `complete` remeasures the retained roots and matches its own
statement before deriving randomness internally from the complete manifest.
Failed pre-draw context checks preserve the sealed state; post-draw errors move
to a terminal failed state. Partial seal failures publish no descriptor. Source
and scheme owners drain on every error, and successful completion retires both.

This is an ownership API, not a proof of bounded aggregate memory: PCS
coefficients and narrow metadata remain worker-owned across the barrier. The
central qualification helper still retains all worker owners in one process;
production fanout needs explicit per-process/spill/resource budgets.

The unchanged q70/P26/log-blowup1 configuration has nominal PCS config score96.
This is not a fixed whole-protocol96-bit or128-bit security claim. Lookup degree,
actual positive/absolute masses, identity checks and unions across relations and
proofs require separate accounting. The real two-packet RAM absolute mass is
4,974,878, below M31. The hard characteristic guard prevents multiplicity
cancellation modulo p; it does not by itself establish a fixed security-bit
bound for every admitted near-characteristic roster.
