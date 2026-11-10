# Hierarchical OP execution: source-only capacity gate

Status: descriptor validation only. No page circuit, supermanifest transcript,
receiver, wire decoder, protocol profile or execution admission is implemented.
The new module does not change any existing 256-worker cap. Its `Pending` result
always has `execution_verified=false` and `production_admission=false`.

## Why the current flat frame cannot just get a larger count

The retained anchored replay is at least 3.072 billion retirements: at a maximum
2^22 instructions per CPU shard it already needs at least 733 CPU workers,
before detached sponge, Keccak, SHA or pairing providers. Existing count bounds
are independent of the work-pool thread count:

* `pure_p2_manifest.zig:12` defines `MAX_WORKERS=256`; it also has a bounded
  legacy roster scratch array. Ordinal fields are u32, not an 8-bit wire limit.
* `word16_global_execution/services/protocol.zig:183` bounds CPU setups to256;
  this admission path also binds genesis, adjacent CPU PC/register state, program
  image, expected endpoints, independently sized boundaries and service coverage.
* `sponge_cpu/inventory.zig` bounds the complete CPU/detached/catalog/Miller
  roster, reconstructs first IDs and exact service coverage, and derives its
  source/security bounds. `sponge_cpu/manifest.zig` validates epoch=ordinal+1,
  presence masks, MAIN/local-receipt framing and relation mass before challenges.
* `sponge_cpu/wire.zig:59,97`, `pure_p2_root_sidecar.zig:47`, and
  `native_group/plan.zig:5` independently cap native fragments, decoded metadata
  and canonical tree planning at256. Custody/planning arrays and source/security
  preflights also need an explicit new owner rather than larger stack arrays.
* Most importantly, manifest validation and
  `services/gkr_local/source_bounds.zig:42,737` require signed relation masses
  strictly below p=2^31-1. `services/protocol.zig:269` checks the RAM characteristic
  bound. Larger OM31 challenge entropy does NOT change the base characteristic.
  At billions of instructions a single shared RAM/lookup relation may wrap even
  when each proof is individually sound. The security ledger must union all new
  pages and recursive arguments; the old 256-proof envelope is not automatically
  a bound for the larger execution.

Thus changing parser/array limits alone neither establishes continuity nor
preserves the existing rational multiset argument. A larger count also does not
solve retaining hundreds of leaf keys, boundaries, claims or advice under32GiB.

## Proposed explicit hierarchy

Keep independently source-planned pages with at most256 **total** native workers
and a source-derived signed RAM/KIO/Wire mass below p on each side. A page may
need fewer than256 workers because of its relation mass. Each page retains the
existing physical local proof semantics and commits ALL MAIN roots/local receipts
before deriving that page's global relation challenges. Local scope ordinals and
epochs remain locally valid; the new frame binds page index and global CPU range
separately. Native proofs cannot be transplanted between pages or old manifests.
There is no proposal to sum claims drawn under different page challenges.

A new supermanifest must bind program, input and immutable policy/profile,
ordered page count/ranges, independently reconstructed per-page inventory,
per-page MAIN manifest, exact page proof output, global first-ID spans and source
security envelope. It must be fixed before any cross-page continuity challenge.
The source planner owns partitioning; a producer cannot choose independent page
endpoints or omit a provider to make an inconvenient debt disappear.

CPU continuity binds all32 registers and PC at every seam, exact retirement and
CPU ranges, initial program/image/genesis, and the final independently pinned
terminal policy/output. A digest equality alone is NOT proof of that state:
the corresponding page circuit must constrain its own full state to that digest.
The descriptor currently holds opaque candidate commitments to make this pending
obligation explicit; it has no producer-declared `authenticated` flag.

RAM requires a real cross-page argument. Independently closed page LogUp proofs
must consume INIT and produce TEARDOWN at each seam, with canonical sorted unique
addresses and complete values. The superroot must prove that the next INIT is
exactly the preceding complete memory state: unchanged cells cannot be dropped,
address aliases cannot be collapsed, and a touched-set digest is insufficient.
A full snapshot multiset/streaming merge or another reviewed boundary argument
must be costed. **This design does not select sparse Poseidon trees per page**:
that would recreate the earlier hash-heavy RAM bottleneck without evidence.
Boundary rows, snapshot retention, extra lookups, recursive openings and
state-transfer work are separate mandatory cost gates.

Initial service policy: no outstanding service obligations cross a seam. Every
CPU-produced OWNER/Wire/KIO tuple must have its corresponding detached/truth
consumer in the same page. Complete calls can be assigned to that page before
MAIN generation; call IDs, byte/word tuples, times and namespaces stay exact.
Cross-page calls or asynchronous providers require explicit typed carried
obligations, not a Boolean flag or a summed claim under a different challenge.
Current descriptor validation rejects nonzero pending-services counts.

## Bounded foundation in descriptor.zig

`validate(Expected, []Page)` checks version,1..4096 pages,1..256 workers/page,
exact contiguous CPU and retirement spans, exact beginning/end boundary
commitments, canonical full nine-limb roots, zero carried services, and both
signed masses of each distinct relation below p. It permits the *sum* of
independently closed page masses to exceed p; it never asserts a flat global
relation over that sum. The4-page fixture covers733 CPUs/813 total workers.
It rejects gaps, duplicate/order errors, omitted tail pages, mismatched RAM/CPU
seams, unclosed services, count257, characteristic aliases and ninth-limb aliases.

The bookkeeping SHA256 fingerprint encodes every typed field with fixed widths
and a distinct source-descriptor domain. It is NOT a proposed in-circuit hash or
admitted FS transcript and is never sufficient for acceptance. Existing32-byte
program/input identities and36-byte native P2 roots remain separate exact types.

## Gates before integration

1. Source-derived page planner, total mass and service-span allocator; reject a
   single call/page that cannot fit; prove exact coverage with bounded ownership.
2. Cost and independently review complete RAM boundary transfer and CPU seam
   framing; source/circuit/native parity and coherent adversarial proofs.
3. Versioned per-page/supermanifest transcript and frames; page/root key identities
   bind new semantics without modifying old R5/R6/R7 identities or defaults.
4. Page proof and superroot physical verification: missing/duplicate/reordered
   pages, balanced forged debts, changed full seam state, dropped/duplicate RAM
   addresses, namespace/ID/call carry and terminal controls.
5. Streaming sidecars/planning/online folds with bounded live keys/advice; disk
   quotas, exact EOF/canonical integers, allocation-failure cleanup and fixed
   work/memory caps before source-key construction.
6. Full conditional security ledger over every native/page/superroot argument,
   rational/pole/tuple errors, GKR/FRI and hash/FS assumptions. Label remains
   **128-bit security target under documented assumptions**, not certification.

No long replay or proof was run for this source-only gate.
