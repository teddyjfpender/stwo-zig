# 2026-08-12 — R-009 authenticated pair-node shadow substrate

## Result

The first canonical `2 -> 1` record now has an allocation-free native shadow
authority. It fixes the data and checks that a future recursive verifier must
constrain: two ordered expected child-verifier results; the complete
session-bound authority context; relation closure; exact session cardinality;
and the parent aggregator verification-key identity.

This is protocol substrate, not recursive proving. It does not inspect child
STARK proof bytes, execute the 36-row recursion AIR, build a recursive circuit,
produce a parent proof, or verify one. R-009 and the full outer proof therefore
remain active and open.

## Fixed record

`recursion/pair_node.zig` defines `PairNodeRecordV1` and a canonical
little-endian encoding with no variable-length fields:

- 96-byte header;
- two 328-byte child records; and
- exactly 752 encoded bytes in total.

The codec is allocation-free, rejects overlapping source/destination buffers,
and publishes no partial output on validation or decode failure. Its format
identity is a domain-separated Poseidon2-M31 digest over the protocol and
relation-domain identities, explicit wire/authority/fold/node schema versions,
wire constants, roles, bounds, and identity domains. The recursion protocol ID
also binds its identity-domain-suite version and the statement, proof,
transcript, summary, challenge, empty-call, pair-statement, and relation-domain
tags. Tests pin the format identity and SHA-256 of the complete canonical wire.

The format is deliberately the first pair layer. Child zero is the left
`core_request` leaf and child one is the right `poseidon2_provider` leaf. Both
must have leaf count one, consecutive indexes, the same pair index, distinct
statement/proof/transcript identity tuples, and nonempty summary identities. A
claimed subtree in either slot is rejected as count padding rather than
silently treated as an extension point.

## Verifier-supplied authority

`VerifierAuthorityV1` combines an admitted verifier context with the exact
expected public outputs that the production caller must obtain from two
successful child verifications. It binds:

- session and job identities;
- execution-statement identity;
- ordered public-call commitment and canonical event count;
- exact power-of-two session leaf count and pair index; and
- canonical aggregator verification-key identity.

The challenge context is re-derived from the verifier-owned session. A second
authority-context digest rebinds the format, protocol, relation domain,
session-derived challenge, job, execution statement, public-call commitment,
event count, session leaf count, pair index, and aggregator VK. Agreement
between two encoded children is not accepted as authority: every encoded child
field, including its four identities and signed relation total, must equal the
corresponding externally supplied `VerifiedChildV1` result.

This native shadow can compare expected results but cannot prove their
provenance. Its eventual production seam must accept the actual child-verifier
result type; constructing `VerifiedChildV1` by copying the record's own claims
would provide no authentication. This limitation is one reason the substrate
is not recursive-proof evidence.

## A2 and A3 borrowing now represented

The Zisk comparison's A2/A3 ideas now have concrete native substrate:

- **A2 — VK injection and root pinning.** The aggregator VK identity is injected
  into both child public records, rebound by the verifier authority, folded
  into every parent identity, and checked against an explicit root pin. Root
  authentication returns a distinct `RootAuthenticatedPairV1`, so an unpinned
  pair cannot be confused with root-authorized output. The eventual recursive
  root must replace the supplied development pin with the reviewed aggregator
  VK constant.
- **A3 — derivation and cardinality checks.** Session and challenge context are
  re-derived rather than trusted; the complete authority context is rebound at
  the pair; signed child relation totals must cancel exactly; and the folded
  leaf count is limited by `protocol.MAX_LEAVES = 1024`. The admitted session
  count must be a power of two from 2 through 1,024, and the pair must fall
  inside it. Checked arithmetic, exact first-layer child counts, pair-index
  limits, and canonical zero-event totals reject overflow and multiset/count
  padding.

This adopts the shape of those safeguards without adopting Zisk's LtHash or
claiming its security argument. ADR-0030's ordered, session-bound protocol
remains the local basis.

## Canonical identities

Successful authentication derives separate ordered folds for child statement,
proof, transcript, and relation-summary identities. The final node identity
binds all four folds, the authority context, aggregator VK, pair position,
folded leaf count, and exact session leaf count. All M31 words are checked for
canonical representation before hashing.

Keeping the identity classes separate matters: a statement mutation changes
the statement fold without being mislabeled as a proof-byte mutation, while
the final node identity commits to the recursive meaning of the authenticated
pair. A separately pinned record hash remains available for wire diagnostics,
but is intentionally absent from `AuthenticatedPairV1` and the mandatory node
identity path; recursive semantics do not depend on a redundant encoding hash.

## Validation evidence

The current focused pair-node build passes 259/260 in Debug, ReleaseSafe, and
ReleaseFast: 259 pass and the environment-gated wall benchmark is the sole
intentional skip. That includes 18/18 directly declared, non-benchmark R-009
tests. Its adversarial corpus rejects:

- swapped, omitted, duplicated, mis-positioned, or mis-role children;
- foreign sessions, locally self-consistent but verifier-foreign challenge or
  authority contexts, protocol drift, exact-child-output drift, and event-count
  mismatch;
- child, record, authority, or root aggregator-VK substitution;
- unclosed relation totals, noncanonical field limbs, zero identities, and
  malformed flags, padding, empty-call commitments, or zero-event totals;
- zero, padded, overflowing, non-power-of-two, or over-1,024 leaf/session
  counts, pair indexes outside the admitted session, and the exact M31 event
  boundary; and
- malformed, aliased, or failure-partial wire encoding.

Golden tests pin the 752-byte encoding, format identity, diagnostic record
identity, four ordered evidence folds, and final node identity. Compile-time
capability flags keep protocol-substrate, proof-verification, proof-production,
and production-activation states explicit. The hot authentication and codec
paths allocate nothing.

## Prepared authentication result

Preparation now has two explicit lifetimes. `prepareProtocolSuite()` validates
and seals the immutable format, protocol, relation-domain, and Poseidon
parameter identities once per aggregation tree. `prepareRootContext()` then
performs the context-dependent validation and hashing once per admitted
verifier authority, snapshots that authority and root pin by value, and caches
only the derived challenge and authority-context identities. The hot
`authenticateRootWithPreparedContext()` call requires the original
verifier-owned authority and pin, rejects mutation of either input or the
snapshot, and performs only the four protocol-preserving evidence folds and
the final node identity.

The original convenience and suite-prepared APIs remain unchanged. An
executable 13-entry call-tree ledger derives each count from the actual byte or
word preimage length, and compile-time assertions pin those lengths and totals:

| Path | Permutations |
| --- | ---: |
| Independent audit's conservative original call tree | 229 |
| Convenience root, including suite preparation | 94 |
| Suite-prepared root; immutable pre-context-cache RED baseline | 55 |
| Authority-context preparation, amortized across hot calls | 17 |
| Context-prepared hot root | 38 |

The exact context-prepared reduction is therefore 17 scalar permutations, or
30.9% of the 55-permutation RED baseline. This is a hash-work result, not a
wall-time speedup claim. The earlier focused ReleaseFast ABBA observation is
preserved for the 94-versus-55 change: with 16 warmups and 2,000 operations per
half-order it reported 61,152 ns per convenience root and 32,219 ns per
suite-prepared root, or 1.898x, on the 2026-08-13 development host.

The benchmark now uses ABCCBA ordering and reports all three paths. A wall-time
observation for 55 versus 38 remains pending a quiet, AC-powered capture; no
speedup is claimed for that change yet. Exact authenticated outputs remain
bit-for-bit equal to the golden V1 folds and node identity. Independent
authority, pin, prepared-snapshot, challenge, context, VK, proof, event-count,
and balanced-relation mutations reject. The checked cold/hot heap-allocation
ledger is zero throughout, the prepared snapshot is compile-time pointer-free,
and no preparation or authentication API accepts an allocator.

Any wall result remains a focused observation, not a whole-recursion throughput
receipt or portable speed guarantee. The test is explicitly environment gated,
bounds its requested iteration count, reports stable machine-readable fields,
and deliberately has no timing threshold:

```text
STWO_PAIR_NODE_BENCH_ITERATIONS=2000 zig build \
  --build-file src/frontends/riscv/build.zig \
  test-recursion-pair-node -Doptimize=ReleaseFast
```

## Remaining R-009 production work

The substrate becomes a recursive node only after all of the following land:

1. independently verify each child's real proof bytes and obtain its public
   identities from that verifier;
2. constrain the same reconstruction, ordered folds, relation closure, VK
   binding, and count checks inside the typed recursion AIR;
3. assemble and prove the complete sealed 36-row outer verifier, expanding the
   current 3/36 real proof-byte gates;
4. fix the reviewed aggregator VK at the recursive root and close the protocol
   and security review; and
5. produce and independently verify the parent proof, extend the first pair to
   a complete aggregation tree, and measure proof size, verifier time, memory,
   total work, wall time, and security. The native prepared-root measurement
   above is not a substitute for this whole-proof evidence.

Until those gates close, `PROTOCOL_SUBSTRATE_ONLY` remains true and the module's
recursive-proof verification, recursive-proof production, and production
activation capabilities remain false.
