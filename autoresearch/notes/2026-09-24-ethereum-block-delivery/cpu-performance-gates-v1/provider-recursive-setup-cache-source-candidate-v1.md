# Provider recursive setup reuse: source candidate v1

Status: source-only and unqualified. No compiler, test, commitment, STARK/FRI,
segment, guest, device or benchmark job was run for this candidate. The JSON
pins four owned files and nine unchanged dependencies. Existing qualification
receipts describe their original source snapshots, not this change.

`block_v5_native_recursive_setup_cache_v1.ForModules(Backend, Bus, Protocol)` is
now public. Legacy native and capacity native wrappers still select that exact
body; `ForRangeBackend` selects the genuine range bus and reusable range parent
protocol. Protocol/receipt types remain distinct. RAM and ROM can specialize
this factory without a second cache kernel.

Range Stage exports `SetupCache` and `Options.cache: ?*SetupCache = null`.
An optional producer-owned cache must outlive the synchronous publish call and
match the stage profile. Cached publication invokes `provePreparedConsuming`;
uncached publication still derives real key geometry and initializes the
original actual Plan. It uses that Plan's consuming workspace API, preserving
all original equations and releasing source storage after its last interaction
reader. Wires/values/context retain separate ownership for encoding and receipt
verification. Both branches share the original codec, fresh range leaf verifier
and sink publication. Sink failure releases stage-owned bytes/schedule/proof;
sink success moves independently owned bytes and schedule into the sink.

Reuse authenticates child context, profile/config, wire digest and every exact
wire field, then validates all actual fixed rows, row counts, column inventories
and logs against the persistent Plan before returning a lease. A fresh typed
Admission replaces ALL public values on every hit. Worker.proveAdmitted still
validates/rebinds admission; neither cached public values nor transcript state
are reused. One-entry eviction happens before miss construction. Existing
aggregate heap budget, worker sub-budget, retained scratch limit, joined request
thread and borrowed driver pool behavior remain unchanged. An output proof must
be destroyed before its cache; Stage handles this synchronously before return.

Six named `range cache:` fixtures exercise metadata substitution, the real
fixed-row validator, exhaustive allocation cleanup, cache-cap admission and
consuming request rejection. The early rejection fixture starts no request
thread and executes no setup. Actual cold/warm stage and cache bodies are kept
through exported function-pointer retention without invoking them. A matching
metadata fixture is never reported as a cache-hit proof.

Root-only focused command:

```sh
python3 autoresearch/notes/2026-09-24-ethereum-block-delivery/test_sha_memory_proof.py --root src/frontends/riscv/block_v5_range16_recursive_cache_unit_test_root.zig 'range cache:'
```

Remaining qualification: the serial nonproving source gate, followed separately
by any authorized genuine two-instance cached proof/publication comparison.
Canonical Driver provider-cache selection is not activated here. Routed heap
limits do not claim an RSS bound or absorb unrelated preparation, encoding,
verification, stack and framework overhead.
