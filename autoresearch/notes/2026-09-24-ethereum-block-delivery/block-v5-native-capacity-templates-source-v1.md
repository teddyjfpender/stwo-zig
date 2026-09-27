Native capacity templates v1 — source handoff, unqualified

This is a real, distinct producer and CPU receiver protocol. It remains off
the canonical driver/fused/recursive/transport route. No build, test, proof,
guest, device, segment or benchmark was run by this batch. `zig fmt` completed.
This does not complete roadmap ID12 or demonstrate a speedup.

The existing native-v3 template protocol binds total_steps, external retirements
and every exact n_rows into geometryDigest; `blake3_execution_protocol.flags`
commits that exact activity prefix as fixed data. Its CPU receiver reconstructs
those selectors. The statement validator also requires the minimal capacity
log and canonical opcode shard roster. Those identities genuinely prevent
fixed-template reuse across changing row counts, even within one power bucket.
The existing native_recursive_admission_v3.Prepared and native roots circuit
remain tied to that protocol. They have not been weakened or relabeled.

New files are `block_v5_native_capacity_{protocol,activity,component,proof}_v1`,
`block_v5_native_capacity_unit_test`, and its named frontend root. The explicit
B5CT/v1 template binds ordered family/log/width/recipe, local-zero ABI, relation
registry, execution profile, PCS config and capacity-only fixed root. It never
accepts a different roster or a nonminimal capacity as equivalent. All exact
counts, total steps, external retirements, public admission, ordinal and both
first roots are bound by the new instance ID and linear PCS transcript.

For each ordinary opcode or auxiliary-clock shard, the main commitment appends
two cells: activity and cumulative count. Four equations prove activity boolean,
no interior 0→1 transition, cumulative reset/recurrence, and previous count at
the independently reconstructed first row equal to public n_rows. These have
degrees 2,3,2,2. Capacities ≤2^24 are below the M31 modulus, so summing boolean
activity cannot wrap. The prefix and count obligations therefore authenticate
exact activity; padded main values are never authority. No extra lookup request
or range-provider claim is invented for the count columns.

One composite AIR owns the complete native inventory. Its old component view
contains precisely the original native main prefix and current selector sample.
Every old selector reads the same main activity cell checked by the companion;
all other masks and interaction shifts are preserved. The old opcode, clock,
local-zero and LogUp equations run before the companion equations. There is
one interaction/composition/FRI proof. Genuinely caller-only native shapes keep
the existing proved frame AIR; they do not acquire a fake empty STARK or zero
receipt. The companion algebra permits zero activity, but a nonempty native
descriptor cannot claim zero rows under the independent statement validator.

The producer APIs are `ForBackend.collect` (bounded owned plain proposal;
physical PCS immediately released), `commitPhysical` (warm actual PCS lease),
`PhysicalFirstRound.bind` (late admission transfer), `commitFirstRound`, and
`prove`. The receiver is `verifyOwned`, taking the independently pinned exact
shape, external count, public admission, capacity template/ID, seal/pins/roster
and resource limits. It reconstructs capacity fixed rows, checks exact roster
and instance IDs, then freshly verifies the original and activity equations.
Its distinct OpenReceipt retains native universal claims plus the existing
PC/clock compensation; global ROM, lookup, register/RAM, caller and endpoints
still must close. The legacy native receiver cannot consume this receipt.

Limits independently cap shards, log24, main cells, public words and retained
proposal metadata. Owned proposals clone public input/output arrays; per-source
and late-binding ownership is explicit. The first fixed commitment is currently
regenerated/recommitted per instance. Actual cached fixed-PCS/setup leases are
the next integration slice; an identity-only reuse claim is not a throughput
improvement. Companion proving adds two main columns and four equations per
shard, and the composite initially forfeits specialized parallel/device handles.

The nonproving root is
`src/frontends/riscv/block_v5_native_capacity_unit_test_root.zig`, safe filter
`native capacity`. Ten named tests cover prefix counts/power edges/odd tails,
count/selector holes, public exact-count and shape/config/fixed-root mutations,
old template/transcript downgrade, allocation failure for column and mask
ownership, nonzero off-domain original-equation parity, mixed opcode/clock
capacity domain parity, explicit degree accounting and legal caller-only frame
geometry. Concrete collect/physical/bind/prove/fresh-receiver bodies are retained
without executing their commitment or STARK callbacks.

Still required: a genuine fresh capacity proof gate;
immutable capacity fixed-commitment leases; independently versioned varied
capacity catalog and owned wire codec; fused projection/access remapping and
metadata; a recursive public activity/count bus with explicit capacity-native
equations rather than instance-specific setup constants; and canonical
collector/driver/Global integration. Old v3 and qualified direct-source files
are untouched. Segment and proof runs remain stopped.

Source correction after root qualification attempt: root found the prefix
fixture failing its first positive equation check (12/13 other checks passed).
The producer count column and fixture reader had incorrectly used natural
circle bit reversal; existing opcode selectors use coset-to-circle mapping
before bit reversal. Both now use the canonical mapping. The prefix fixture
also checks independently generated infra.BitReversalTable destinations and
actual previousBitReversedCircleDomainIndex, plus exact selector/count values
at every row. Equations, point shifts and domain recovery are unchanged.
Root also corrected explicit Shard array typing and the concrete PCS verifier/
prover namespace calls before the body gate. Updated source hashes are frozen;
this corrected batch remains unqualified until root reruns the source gate.
No runs were launched by this agent.

Root qualification of the corrected batch now passes13/13, including ten named
contracts and actual producer/fresh receiver body compilation without invocation.
All six frozen source hashes match. Evidence is retained in
`cpu-performance-gates-v1/native-capacity-production-v4.log` and
`native-capacity-templates-qualified-v1.json`. The previous failed gate is retained
for diagnosis; the corrected source passes. No STARK or segment was run.
