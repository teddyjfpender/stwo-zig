# Supplemental recursive worker and capture lifetimes

This source batch extends the existing typed setup-worker path to ROM/program
 tables, native lookup tables, caller arithmetic, caller fused, and native
 capacity fused publication. It preserves each original capture, verifier
 equation, transcript, public statement, producer fixed-root admission, and
 mandatory fresh recursive receiver. No new proof format or acceptance rule is
 introduced.

Each `Stage.ForBackend(Backend).Options.cache` still borrows the existing
 `Stage.SetupCache`. The CPU publication session supplies one persistent cache
 per active family and the same borrowed driver pool. The cache, pool,
 independently owned original Prepared policy, template callback context and
 allocator backing must outlive the synchronous stage call. The callback now
 runs on the joined coordinator thread while the actual exclusive worker lease
 is held. Its Store operations retain their original mutex protection; it must
 not reenter the same cache. The new cache method is:

```
provePreparedConsumingWithPreflight(
    prepared: *Bus.Prepared,
    context: *anyopaque,
    preflight: *const fn (*anyopaque, Protocol.Key, [32]u8,
                        []const Bus.Wire) anyerror!void,
) !Proved
```

Cache construction also validates the original worker-count geometry before
 metadata allocation; the shared session enforces the same worker/scratch
 policy for all seven cache specializations. CPU result statistics expose
 per-family hits/misses, joined request starts/completions, retained-entry
 status and live/peak scoped bytes for later measurement. These counters do
 not establish warm proof success or throughput improvement.

It uses the original Request/acquire path, including expected-ID admission,
 before calling the preflight and consuming producer. Rejection stops before
 STARK proving and retains original errors and consuming-row cleanup. These
 five supplemental families currently derive their keys from genuine original
 verifier rows or the actual cached worker. Preflight is a producer template
 notification, not a new proof-independent expected-key factory. Existing fresh
 hierarchy receiving/source policy and all-family detached checks remain
 required.

`block_v5_supplemental_recursive_proving_v1.ForModules` shares the cold and warm
 lifetime body. Cold fixed geometry/key derivation occurs solely in the cold
 branch. The cold plan and workspace end immediately after the original
 consuming producer returns, before proof encoding or fresh receiving. This is
 supported by `blake3_native_parent_producer.PlanForProtocol`: output uses the
 caller's allocator, `outputAliasesScratch` is rejected, and the producer
 returns `artifact.Owned.init(a, extended.proof, ..., claims)`. The artifact owns
 the core proof and fixed-array claims, without borrowing plan, input rows or
 workspace. The temporary proof is destroyed after encoding and before this
 helper returns bytes. Persistent warm workers stay in their cache.

The capture's last reader is successful `Bus.prepare`: the original State
 plans and all verifier witness columns/public values have then been copied
 into owned rows. ROM/lookup receipts and caller arithmetic claims are fixed
 value data and survive capture teardown by value. Fused claims and range
 exports already required deep copies for Artifact custody; those same copies
 now occur before capture teardown, rather than after recursive proving.
 `block_v5_supplemental_recursive_exports_v1` performs these atomic copies with
 failure cleanup. Native absent access stays null; an empty present range
 vector remains distinct. Cloning proposal arrays grants no verification
 authority.

Caller arithmetic and caller fused expose
 `publishConsumingVerifiedCapture`, which consumes a genuine capture on every
 return, including option/capture validation, allocation, callback, producer,
 receiver or sink errors. Existing `publishFromVerifiedCapture` keeps its
 borrowing semantics. The actual caller pipeline copies the freshly verified
 arithmetic receipt, then uses the consuming methods. It releases the
 arithmetic capture before recursive setup/proving and the fused capture after
 its final row reader. Original arithmetic/fused proof bytes and warm producer
 tree leases still belong to the original producer/pending transport; they
 remain available for the unchanged base sinks. This batch does not release a
 caller-owned proof or change that transport order.

Artifact success still transfers bytes, schedules, public values and owned
 fused claim/range exports exactly once. Sink failure consumes none. Independent
 original admission must remain stable for the callback and fresh verifier;
 early capture release never releases that policy.

## Qualification boundary

The isolated lifetime root includes claim-copy mutation/custody and exhaustive
 allocation-failure fixtures, five-family profile/cache mismatch checks, the
 seven empty-worker/partial-OOM fixtures, rejected consuming-preflight cleanup,
 and original caller pending/admission regression fixtures. Metadata fixtures
 never construct a successful capture or receipt. A marker retains actual
 cold/warm publish bodies, both caller borrowing/consuming APIs and real staged
 caller integration; it never invokes them. Both original caller recipes have
 separate retained roots. Root owns all semantic, Debug and body qualification.

No compiler, test, commitment, proof, segment, device or benchmark was run by
 this source author. No successful warm proof, all-family runtime parity,
 standalone block authority or speed improvement is claimed by these fixtures.
