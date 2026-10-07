# Two private Bitcoin headers in one circuit plus SHA proof

The [focused test](../../../src/frontends/s31/sha/tests/sha_joint_batch2_prover_test.zig)
uses the existing [two-header relation](../../../src/frontends/s31/examples/bitcoin/bitcoin_header_pair.s31.json).
Its private inputs are the 80-byte genesis and block-one headers. The source
asserts that the parent hash is genesis, that the child's previous-hash bytes
equal the parent's SHA256d digest, that both headers satisfy their decoded
targets, and that the child's timestamp is later. Its eight public M31 words
are a Poseidon2 commitment to the ordered pair of block hashes.

The `sha-joint-batch2-v1` proof keeps one circuit and one PCS/FRI instance:

| Component positions | AIR | Role |
| --- | --- | --- |
| 0–3 | Sparse-wide circuit Eq, QM31, M31-to-u32, range16 | Link, PoW, time, Poseidon2, and public root |
| 4–7 | SHA source, schedule, round, feed-forward | Six SHA-256 compression calls, IDs 1–6 |
| 8–9 | Private callers 0 and 1 | Constrain each header/digest to its three SHA calls |
| 10–11 | Bitwise and byte-range tables | Close the SHA internal lookups |

Each header contributes forty `u16` header limbs and sixteen `u16` digest
limbs. The circuit's preprocessed Gate multiplicities include **112 extra
uses**, exactly one for each of those private values across the two headers.
The caller AIR for header 0 uses SHA call IDs 1–3; header 1 uses IDs 4–6.
Their 56 Gate addresses are individually validated, and the two address sets
must be disjoint. Both callers commit their limb/byte equations before the
lookup challenges are sampled.

The proof envelope contains fourteen claimed sums in a pinned order. The
native verifier requires both closures over independently drawn lookup
challenges:

```text
Gate: circuit_lookup_sum + caller_0_gate + caller_1_gate = 0
SHA:  sha_source + sha_schedule + sha_round + sha_feed_forward
    + caller_0_wire + caller_1_wire + bitwise_table + byte_range_table = 0
```

The focused test derives verifier admission from a value-free compilation of
the source and both private Gate-address lists. The batch profile has a
distinct transcript domain, key digest, component roster, and `S31NAT7S`
envelope from the one-header `S31NAT6S` proof. The native verifier reconstructs all twelve
AIR components and verifies the single STARK proof. The proof cannot nominate
its own key or omit one caller.

Run the focused test with:

```sh
zig build --build-file src/frontends/s31/build.zig test-sha-joint-batch2 -Doptimize=ReleaseSafe -j2
```

It checks native acceptance, changed public root, changed second caller key,
proof corruption, and committed header/digest substitutions at **both**
private boundaries. A substituted caller value fails the joint SHA lookup
closure; changing either private header while keeping the circuit witness
fixed fails the Gate lookup closure. The test also verifies that the source
and witness compilations select identical Gate addresses.

The [matched three-run record](../measurements/sha/bitcoin-sha-joint-batch2-v1-2026-10-07.json)
uses the same source, assignment, public root, and FRI schedule. The generic
package proved in a median 323 ms excluding proof of work with a 382,425-byte
proof. The joined profile took 646 ms excluding FRI proof of work and produced
889,412 bytes. The joined figure still includes an unmeasured small
interaction grind. Both proofs passed native verification. Sharing the SHA
tables across two headers has **not** yet amortized their cost; the generic
lowering remains the default.

The [table-free round AIR plan](SHA_ROUND_AIR_PLAN.md) spells out the next
implementation milestone, the Boolean and carry relations, the private
caller custody requirements, and the cost gate for adoption.

The two-header proof is an opt-in research profile. It is not yet a generated
`s31 build` package or an automatically chosen lowering. A separate
cryptographic review of the multiset collision bound and AIR constraints
remains open. Its focused verifier and tests establish this profile's local
integration behavior; they do not establish full Bitcoin consensus validity.
