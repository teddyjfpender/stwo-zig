# Outer circuit lookup repetition: construction checkpoint

Status: **construction primitive, production receiver closed**. This is a new
candidate for a **128-bit security target under documented assumptions**, not a
qualified end-to-end outer proof or a whole-protocol security certificate.
Legacy circuit provers, AIR recordings, proof codecs, registries and receivers
are unchanged. No legacy proof-byte comparison or GPU proof was run for this
checkpoint.

## Implemented

`frontends/circuit/witness/lookup_repeat2.zig` builds both independent native
interaction traces against the same existing MAIN columns. It never rebuilds
or copies MAIN. It checks each lane's public lookup sum separately, allocates
the final column-header list, transfers the two INTER owners, and only then
retires MAIN. Allocation failure, a zero denominator, malformed shape, reused
challenge pair or failed closure leaves the MAIN owner intact; constructed
INTER owners unwind normally. Output values remain available for framing.
The output is lane0's eleven component blocks followed by lane1's eleven
blocks, with two claimed-sum vectors. A sum of the two closure equations is
not an acceptable replacement: the tests reject balanced +delta/-delta debt.

This first implementation retains MAIN until both complete INTER lanes exist.
Its value-plane footprint is one MAIN plus two INTERs, not two MAINs. A later
streaming implementation may retire each MAIN component after both associated
lanes exist, but must define and test ownership on every failure. It must not
call the legacy releasing generator twice: the first call frees columns that
the second still needs.

`frontends/circuit/common/lookup_repeat2.zig` specifies two successive,
receiver-derived `(z, alpha)` draws after MAIN. A temporary channel makes the
combined draw failure atomic. Both claim vectors mix in one lane-major field
list. The candidate fixes q108, FRI PoW20, interaction PoW20 and fold4, with a
distinct domain-separated registry identity bound to the original topology
identity. That identity is not a verifier key and is never a substitute for
receiver-owned setup. `requireProductionReceiver` rejects unconditionally;
there is no environment flag that admits a two-lane proof through the current
one-lane decoder.

## Conditional security accounting

Let `F = (2^31-1)^4`. A source-derived LogUp error analysis must bound tuple
compression, numerator degree/support, poles, multiplicities and the actual
challenge sampler. For a fixed incorrect MAIN, suppose that analysis establishes
an error bound `epsilon_lookup` for each independently drawn lookup pair.
Under the corresponding conditional independence and random-oracle assumptions,
requiring both independently closed identities bounds this lookup event by
`epsilon_lookup^2`. This is not a proof that arbitrary prover-supplied distinct
pairs are independent: the receiver must derive both from the bound transcript.

For orientation only, a uniform-field illustration `D/F` with `D <= 2^27`
gives about97 bits for one pair and about194 for two. **This is not the
concrete bound of this implementation.** The internal circuit channel reduces
Blake words to M31 before drawing QM31 coordinates; the existing whole-protocol
policy records the sampler-density and reduced-state review obligations.
Those losses, adversarial grinding, all lookup tuples, poles and all recursive
nodes must enter the actual bound. Characteristic/multiplicity limits remain
unchanged by repetition.

The composed ledger still has the form

```
epsilon_execution
+ sum_over_outer_nodes(epsilon_lookup_repeat2
                      + epsilon_composition + epsilon_oods
                      + epsilon_deep + epsilon_fri)
+ epsilon_commitments_and_fiat_shamir
+ epsilon_statement_and_topology_binding.
```

Repeating lookup lanes does not independently repeat composition, OODS, DEEP or
FRI. Batching two INTER lanes into one QM31 composition still has its own
single-field algebraic error. Raising queries or late query PoW alone does not
remove those terms. q108/P20 is the nominal query/PoW engineering target under
the previously documented assumptions; it is not an automatically composed
2^-128 statistical bound. A strict per-node2^-128 probability claim also loses
bits under a union over many nodes unless the budget includes that node count.
See `rv64-whole-protocol-security-policy.md` and
`rv64-native-128-assumptions-review.md`; this checkpoint does not change their
certificate policy or extend the native review to the circuit wrapper.

## Remaining accepting integration

1. **Captured AIR and geometry.** Bind both challenge pairs and both INTER
   offsets to one MAIN span. The current recorded circuit AIR has one lookup
   pair and one component claimed sum. A first correct implementation can
   instantiate each component authority twice while sharing MAIN. That repeats
   arithmetic constraint evaluation too; separating lookup-only roots is a
   later optimization requiring the same authority/parity tests.
2. **Proof shape and codec.** Add an explicit new circuit protocol/profile
   identity. Update `component_list`, `circuit_statement` shapes and
   `circuit_cpu/verifier_proof` for two lane-major claim and interaction blocks.
   Reject a missing lane, trailing claims, mutated widths/logs, wrong profile
   identity and a mixed legacy/new proof. Legacy eleven-component proofs keep
   their old shape and default receiver.
3. **Prover and native receiver.** `circuit_cpu/prove` must commit MAIN once,
   draw the repeated challenges, call the new witness primitive, commit INTER
   once and bind the two AIR authorities. The receiver independently rederives
   all geometry, challenges and both public lookup sums.
4. **Recursive receiver and registry.** Update
   `stark_verifier/verify`, the statement public-lookup calculation and the
   circuit-verifier shape. Rebuild and independently admit repeat-aware leaf,
   fold and root topology/key identities. A root cannot erase an unqualified
   inner argument. Test profile/claim mutation, lane swapping/cancellation,
   malformed offsets, wrong registry keys and actual accepted proof parity.
5. **Device circuit paths.** Adapt CUDA/Metal transcript prefixes, lookup
   generation and captured composition to both lanes, preserving a single MAIN
   commitment. Measure peak residency and real proof times; no device support
   or speedup is claimed here.
6. **Composed review.** Close the remaining QM31 algebraic/sampler and
   Fiat-Shamir assumptions, node-count budget and hash authority before
   claiming the complete outer target. Lookup repetition by itself is not that
   review.

## Validation

```
zig build --build-file src/frontends/circuit/build.zig test \
  -Doptimize=ReleaseFast -Dtest-filter=repeat2 -j4 --summary all
```

45 tests passed. The new tests cover independent closure versus balanced debt,
reused pairs, two-owner allocation failure and zero-copy transfer, malformed
MAIN ownership, deterministic independent transcript draws, failure-atomic
transcript state, both-claim binding, candidate configuration/identity and
closed production admission. They do not produce an accepted repeat2 circuit
proof, exercise a complete valid large witness, or qualify recursion/GPU paths.
