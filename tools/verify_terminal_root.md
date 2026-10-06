# Terminal circuit root verification

`fold-tree` publishes a Cairo felt stream as `root.proof`. The Zig `verify`
command accepts a different, internal `CircuitSerialize` format and must not
be used on this file. `verify_terminal_root.py` runs the actual
`stwo_circuit_verifier` Cairo executable from StarkWare
[`proving@5a7c5ed`](https://github.com/starkware-libs/proving/tree/5a7c5ede4299c91a61df19a07cba4f7502c14230/stwo_cairo_verifier/crates/circuit_verifier),
then checks its eight-word public result against the declared root.
This is a focused validation tool for the production pairwise tree, not a
general verifier API for arbitrary circuit registries.

The checker requires a clean checkout of that exact revision and Scarb 2.18.
It rebuilds the verifier before each run, then reads four files: the felt
stream, `root_outputs.json`, `root_packed.json`, and the circuit registry.
For a production pairwise root:

```sh
python3 tools/verify_terminal_root.py \
  --proof "$ARTIFACTS/root.proof" \
  --outputs "$ARTIFACTS/root_outputs.json" \
  --packed "$ARTIFACTS/root_packed.json" \
  --registry vectors/circuit/official/registries/production.json \
  --pinned-proving "$PINNED_PROVING"
```

The checker binds the eight proof-public output words to `root_outputs.json`;
the first STARK commitment to the registry's preprocessed root; and the
Blake2s circuit hash recomputed from that root and the eleven component log
sizes to the registry's multiverifier hash. It hashes each packed leaf's
canonical felt preimage and the pairwise tree bottom-up, requiring each leaf
circuit hash to be registered and the final digest to equal the output claim.
The pinned Cairo verifier checks the full circuit AIR, transcript, interaction
sum, Merkle openings, FRI, and PoW under its compiled production geometry
(70 queries, 26 PoW bits). Its published output must equal
`Blake2s(circuit_hash words || root output words)`.

The saved QEC two-leaf root with SHA-256
`84ce57c46b8ba0e832bad666e7b44e567873ccfd468a53ac8726e55497ea671d`
passed this check. The Cairo verifier executed 9,747,576 steps and published
`[2556026839,4199023084,1184413043,572087286,4291030969,2593195461,2790601923,2040688564]`.
Changing an interior proof felt or an output felt made the Cairo verifier
reject with an assertion failure; changing one declared output word made the
wrapper reject before execution. This check verifies the terminal proof and
its exposed packed tree; it does not establish any separate SHAKE/source-file
binding that the leaf program itself did not prove.
