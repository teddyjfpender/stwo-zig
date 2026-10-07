# Bitcoin first-retarget recursive fold

The [v4 fold circuit](../../../src/frontends/s31/bitcoin/fold/bitcoin_chain_fold.zig) and
[sealed verifier](../../../src/frontends/s31/bitcoin/verification/bitcoin_chain_retarget_verifier.zig)
extend the genesis-anchored profile through Bitcoin block height 2016.
Step `k` appends block height `k+1`; a v4 key accepts at most step `2015`.
The earlier v3 profile remains capped at step `2014` and has a different AIR
root and key schema. The new profile has native proofs for steps zero and one;
**no height-2016 chain proof has yet been generated**.

## Authenticated state and first-retarget boundary

The public fold statement is an eight-word personalized Blake2s digest of
the v4 AIR root, exact `u32` step, genesis checkpoint root, current Bitcoin
hash root, and eleven most recent header timestamps. The timestamps are in
newest-first order. The base branch forces the genesis timestamp in slot
zero and sentinel values in the ten remaining slots. At every header step,
the circuit shifts the old window and puts the new header's constrained
`nTime` into slot zero.

At step `2015`, the verified child must be a v4 proof for step `2014`.
Its public digest is recomputed inside the outer circuit from the guessed
prior root and timestamp window. The in-circuit STARK verifier checks this
digest and the fixed v4 child AIR root. Consequently `prior_times[0]` is
the timestamp of block 2015 in the authenticated chain. Changing this value
while keeping the same child proof invalidates the outer circuit.

The [header kernel](../../../src/frontends/s31/bitcoin/fold/bitcoin_fold_step.zig) computes
the exact first-retarget nBits from that timestamp with the
[integer-sound retarget gadget](../../../src/frontends/s31/bitcoin/consensus/bitcoin_retarget.zig).
It constrains a selector `s` such that `s = 1` exactly when the range-checked
step is `2015`; otherwise `s = 0`. The two `u16` nBits limbs in the header
must then satisfy, limb by limb,

```text
header_nBits = genesis_nBits + s × (first_retarget_nBits - genesis_nBits)
```

Every v4 step includes the same retarget arithmetic and selector gates, so
value-bearing circuits at steps zero and 2015 have one witness-free AIR root.
The key's maximum step is an essential consensus limit: a step after 2015
would select genesis bits again and is rejected by the sealed verifier.
The rest of the header circuit still checks the previous-hash link,
byte-exact SHA256d, canonical compact target, PoW inequality, and strict
median-time-past before committing the next root and timestamps.

## Evidence and cost

The selector tests accept genesis bits at steps zero and 2014 and the exact
retarget bits at step 2015. They reject the wrong epoch, adjacent mantissa,
and altered exponent. Value-bearing step-2014 and step-2015 circuits have
the same gate lists as the value-free circuit. The key test derives the
first-retarget topology at both steps zero and 2015 and checks identical
preprocessed roots; it checks that v3 and v4 roots differ and that a key
above step 2015 is rejected.

The opt-in `test-bitcoin-retarget-fold-proof` step proves and natively verifies
real Bitcoin blocks one and two under one v4 key. It verifies the generated
statements with the standalone sealed verifier. It rejects changed public
timestamps and a circuit with the same valid child proof and header but a
forged `prior_times[0]`. The
[CLI acceptance script](../../../src/frontends/s31/tests/acceptance/acceptance_bitcoin_retarget_chain_cli.py)
also checks key and statement regeneration, v3/v4 profile separation,
replay, changed claims, over-limit keys, and damaged proofs.

The [measurement record](../measurements/bitcoin/bitcoin-first-retarget-fold-v4-2026-10-07.json)
lists exact row counts and one local ReleaseSafe native-proof run. Raw
Eq/QM31/u32 rows move from `32455/1152060/205456` in v3 to
`33844/1158056/205659` in v4, each with its own fixed child layout. The
extra 1389
Eq rows cross the 32768-row power-of-two boundary, so v4 reserves 65536
Eq rows. Other padded component counts stay the same. This makes the v4
AIR costlier on early steps even though the retarget is selected only once.
Proof times are single runs and do not support a speed claim.

Repeated fold proving now compares every ordered preprocessed column and the
structural metadata of each value-bearing circuit against the already sealed
witness-free circuit. The prover uses that sealed circuit after the check. An
earlier guard rebuilt its FFT/Merkle root for each step just to compare it
with the root already in the key. In one local ReleaseSafe two-step run, the
exact comparison took 11 ms per step; redundant recomputation took 898 and
914 ms. This change leaves the AIR, key, transcript and proof encoding
untouched. The [guard measurement](../measurements/bitcoin/bitcoin-fold-preprocessed-guard-v4-2026-10-07.json)
records the method and proof compatibility checks. These times are for this
setup guard alone; the prover times above exclude it.

## Remaining chain proof and profile work

The tested steps zero and one show that v4 recursively verifies its own
key. They do not substitute for the 2015 preceding header proofs required
to reach height 2016. A v3 step-2014 proof cannot be directly used as a v4
child: the child AIR root and the root included in its statement digest are
different. A sound v3-to-v4 bridge would have to verify the v3 proof,
reconstruct its authenticated state, and produce a child statement with an
explicitly verified transition accepted by a new v4 boundary relation.
The current straightforward path is to prove the historical chain from
genesis under v4. Its cost reinforces the need for a faster SHA AIR before
claiming a practical Bitcoin light client.

Later retarget periods require the first timestamp and previous nBits of
each period in authenticated state. Accumulated work, best-chain selection,
contextual future-time policy, and full Bitcoin consensus validation are
additional work beyond this fold.
