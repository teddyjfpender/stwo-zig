# Authenticated native FRI layers

`NativeFriVerifier` verifies the b2/q108/p20/fold4 OM31 FRI profile. A
surrounding verifier calls `beginFri` with its reconstructed OODS transcript
prefix, domain and sample count. The returned state contains the DEEP
challenge, folding challenges and the sorted distinct positions derived
from the verified proof-of-work nonce. The surrounding verifier uses
those positions and the DEEP challenge to compute the first-layer
values from authenticated trace openings and OODS samples.

The surrounding verifier passes those computed values to
`verifyFriLayers`. At every layer the verifier derives all the leaves
needed for the complete folding groups. It authenticates those leaves
against that layer's transcript commitment, checks every query value,
then folds each distinct group once. The outputs become the expected
query values in the next layer. Final query values on the two-point
domain are checked against the single constant polynomial coefficient
in the transcript.
The checker has no public entry point that accepts purported DEEP
answers.

The proof carries each layer's opened rows, compressed Merkle siblings,
and coordinate inverses. Rows contain four consecutive OM31 values
per leaf for fold steps of two to four, or one OM31 value per leaf for
a single fold. Each value is eight canonical little-endian M31 words
in native basis order. Rows and siblings use the same order as the
lifted Merkle opening format. Inverses are ordered by group, then
folding round, then butterfly index, and checked against the canonical
circle or line domain. Positions, step lengths and row widths are
derived in the contract.

The tests use a nonconstant circle polynomial, independent Node
BLAKE2s, and a direct field multiplication to build the complete
three-layer chain. They also construct separately committed invalid
chains with valid proof of work and Merkle paths to exercise rejection
at the inner-layer and terminal checks. The synthetic log-10 fixture
opens 105 distinct queries. A Shanghai Anvil transaction used
27,165,386 gas with solc 0.8.30 at the package settings, including the
transcript, proof of work, calldata and all layer checks. This exceeds
the Osaka transaction cap and is not a deployment benchmark.

The checked-in OP Mainnet block 121057303 `truth-4.bin` fixtures verify
that the Solidity transcript derives all 99 expected distinct queries.
They do not include its FRI opening rows. To replay those openings if
the accepted worker bundle is available, apply
`tools/native-fri-capture.patch` in a disposable native receiver checkout.
Set `STWO_EXPORT_FRI_LAYERS=1` and use one proof worker for contiguous
capture records. Run the receiver against the bundle to produce
`fri.log` and an accepted `receive.json`, then run from this directory:

```sh
python3 tools/export_fri_layers.py fri.log receive.json \
  fixtures/native-queries-121057303.json fixtures/native-pcs-121057303-truth-4.json \
  fixtures/native-fri-121057303-truth-4.json
npm test
```

The exporter checks the recorded transcript and nonce, deduplicates
the captured groups, and independently reconstructs their Merkle roots
before writing the witness. When the witness file is present, the
test harness uses its native-captured DEEP answers for the full
layer replay. In production those answers must come from the
surrounding verifier's DEEP calculation.
