# Explicit-rate immutable fixed keys

`word16_execution/fixed_setup.zig` adds a field-neutral retained-key/cache seam
for the OM candidate's β2 fixed tree. It does not select a protocol, extend the
legacy Suite enum, modify CPU/truth workers, or certify 128-bit security. Existing
β1 defaults and keys remain untouched.

## Construction and authority

CPU and service truth setups already own the same legacy Key type and retain
native M31 circle coefficients. The helper consumes borrowed coefficient views
synchronously through the existing `Scheme.commitPolys` authority. It performs
no fixed-row reconstruction and no interpolation. Forward extension and Merkle
construction run once when the explicit-rate key is first sealed. The existing
commit API makes one retained coefficient copy at sealing; this implementation
does **not** claim zero-copy coefficient sharing with the original β1 key.
Whole-key cache hits reuse the sealed tree and do not extend/hash it again.

A Profile explicitly contains receiver-owned protocol identity and log blowup.
Only β1/β2 are admitted, with no default. The cache hashes protocol identity,
rate, ordered coefficient logs and canonical coefficient bytes. Each hit also
compares the actual coefficient values/logs, so a caller-supplied digest or an
independently reconstructed key is not blindly trusted. Column order and native
heights are part of identity. Request state, execution witness and transcript
are absent from this cache.

`WideFixedKey.append` checks independently expected profile, identity and root,
the empty PCS phase, matching blowup and absence of revision/lifting overrides.
It appends the same field-neutral tree into Q or OM PCS. A stale β1 root, wrong
protocol identity or β1 destination refuses before changing the destination.
The embedding receiver must still derive its expected key independently and
bind the candidate protocol and target root before dependent MAIN commitments.

## Bounded ownership

Cache construction requires a finite requested-byte cap. A SharedHostBudget
covers cache state, entry/header arrays, native coefficient copies, Merkle data
and temporary sealing scratch. Its own control-object size is explicitly
included in the declared limit/snapshot. Original source keys and allocator
metadata/RSS/stacks are outside that cap. There is no process-global cache or
eviction. Cache insertion is serialized; the immutable keys may be leased to
parallel proof workers afterwards. Acquire hashes/compares source coefficients;
retain and reuse its returned lease across workers to avoid doing that scan per
batch.

A key lease retains the cache state. After the cache handle and all key leases
are released, unused entries are freed. A PCS may still retain an appended tree:
its backing token holds a separate allocator-budget lease, so it survives cache
state destruction. The existing committed-tree final-release guard keeps that
allocator alive through SharedOwner teardown. Scheme destruction finally frees
its tree and budget. Raw struct copies do not acquire ownership; use Lease.retain
or the explicit tree append operation. Backing allocators must support the
thread that performs final release.

All allocation-failure exits release partial trees/leases. A failed insertion
may retain already grown cache-header capacity within the same hard cap; it
never publishes a half-built key. Hard-cap refusal is OutOfMemory, observable
through the snapshot's sticky refused flag. No invalid-proof normalization or
request for more memory is hidden in the helper.

## Integration seam

```
var cache = try Fixed.Cache.init(allocator, fixed_setup_byte_cap);
defer cache.deinit();
const profile = Fixed.Profile{ .protocol = receiver_protocol_identity, .log_blowup = 2 };
var cpu = try cache.acquireFromKey(&cpu_setup.key, profile);
defer cpu.deinit();
var truth = try cache.acquireFromKey(truth_spec.key(), profile);
defer truth.deinit();
try cpu.key.append(allocator, &om_scheme, &raw_om_channel,
    profile, independently_expected_key_identity, independently_expected_fixed_root);
```

Call both acquisitions before retiring the source key itself; original fixed
witness rows may already be retired. Root needs to wire this explicit key seam
into CPU/truth worker admission and manifest fixed roots. The existing β1
worker profile remains separate. Actual β2 native proof/fresh verification,
receiver setup authority, fixed geometry and candidate configuration admission
are subsequent integration gates. A helper root test is not that milestone.

## Qualification

Five reachable tests pass in ReleaseSafe and ReleaseFast. They cover native
fixed heights 5/6, cache hits across independently sealed source keys, independently
rebuilt β2 roots, protocol/order-sensitive identity, wrong-profile/stale-root/rate
refusal, exact β1 legacy root and root-mix transcript parity, source release,
cache/key teardown before final OM PCS destruction, hard caps and exhaustive
allocation-failure injection over the complete construction/append lifecycle.

The fixture β1 root is
`c2eb2765ea8e37e118efdc02ec69db837d938cc1c121b335186bf1f76f6b1bcd`;
the β2 root is
`96f81de73ee85f8d04b79fbb609a43259679be9f0015d439a3813b24c3244fda`.
The report directory includes the exact module-aware test command and logs.
There is no throughput, RSS, GPU or whole-protocol security claim.
