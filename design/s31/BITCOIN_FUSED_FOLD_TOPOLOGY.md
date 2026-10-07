# Fused SHA inside the Bitcoin chain fold

The existing Bitcoin fold circuit verifies its child proof, checks a fresh
80-byte mainnet header, and emits an eight-word Blake2s digest of the new
chain state. Its original header step computes SHA256d in ordinary circuit
gates. The fused variant keeps the same child and public chain-state digest
semantics while replacing that one SHA256d calculation with a private
header/digest boundary. A joined SHA AIR must authenticate both sides of this
boundary in the **same** STARK proof through the Gate lookup. The fold circuit
still checks the prior hash link, exact genesis-epoch `nBits`, target
comparison, median time past, and Poseidon root of the digest.

The value-free builder is `bitcoin_chain_fold.zig:fusedTopology`; the matching
value builder is `buildFusedCircuit`. Both return the same 40 header and 16
digest producer wires, ordered as little-endian u16 limbs. The full circuit
preprocessed commitment increments the Gate multiplicity once for each of
those 56 addresses. The verifier must derive the addresses and fixed root
from the value-free topology; a witness cannot choose them. The external
digest step alone is deliberately insufficient: without the joined SHA Gate
closure, a prover could substitute a low digest that passes PoW.
The joined key also pins a digest of the trusted fold builder source. Native
admission must use a key independently derived from that topology; proof bytes
cannot select a different source digest or fixed root.

## Reproduce the topology record

```sh
python3 src/frontends/s31/record_bitcoin_chain_fold_fused.py
```

The [machine-readable record](measurements/bitcoin-chain-fold-fused-topology-v1-2026-10-07.json)
contains the command, source hashes, value-free fixed root, 56-address roster
hash, and raw row counts at steps 0 and 1. The inspector confirms the boundary
and fixed root are identical at both steps, and rejects duplicate or public
output addresses. Its child shape is the existing self-recursive anchor
geometry; the fused fold pads to that geometry.

| Component | Generic raw rows | Fused raw rows | Difference |
| --- | ---: | ---: | ---: |
| Eq | 32,455 | 28,797 | −3,658 |
| QM31 operations | 1,152,060 | 804,740 | −347,320 |
| M31 to u32 | 205,456 | 203,600 | −1,856 |
| XOR | 112,600 | 112,600 | 0 |
| Blake-G | 1,126,000 | 1,126,000 | 0 |

Raw circuit variables fall from 5,955,496 to 5,606,320. The padded fold
still uses 32,768 Eq, 2,097,152 QM31, 262,144 conversion, 131,072 XOR,
and 2,097,152 Blake-G rows because the recursive child verifier requires
that fixed geometry. The extra SHA AIR has its own smaller trace. These are
**topology counts**, not a proof-time speed measurement. The full joined
profile contains 11 circuit components and 10 SHA components; its public
output is the same packed raw-u32 chain-state digest as the generic fold.

## Matched one-step proof measurement

```sh
python3 src/frontends/s31/record_sha_fused_fold_matched.py
```

This proves and natively verifies one generic fold and one joined fused-SHA
fold at step 0. Both consume the *same* independently verified child-anchor
proof, Bitcoin header, prior hash, and child row geometry. Each uses its own
value-free fixed root, so their eight-word public chain-state digests differ
even though the represented chain step is the same. The timer starts after
building the witness, topology, and native verifier key; it includes each
outer proof's fixed commitment. The first proof and circuit are released
before timing the second. The record lists proof bytes, exact prover and
verifier times, six measured stage timings, machine details, and the hash of
the executed benchmark source. The harness now also emits base witness and
interaction stage timings for future runs; the recorded run predates that
reporting change and does not invent those measurements.

The outer proofs deliberately use **test-only FRI0/12/fold1**, while the
shared child uses production FRI26/70/fold4. Proof sizes compare only under
the test configuration. Timings are a single sequential sample and make no
production speed or security claim. A separately reported production-parameter
joined proof appears in the record solely as a single-path observation; there
is no matched production generic result yet.
