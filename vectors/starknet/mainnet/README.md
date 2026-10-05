# Starknet mainnet leaf and aggregator PIEs

Contiguous Starknet mainnet (0.14.3) block ranges run through the Starknet OS
with SNOS (`full_output=1`, `use_kzg_da=0`, layout `all_cairo`). These are the
leaf PIEs of the proving pipeline described in
`design/starknet-proving-pipeline/README.md`. They were produced with
`tools/starknet-block-collector`. `manifest.json` lists every file with its
sha256, block range, exact `n_steps`, memory holes, builtins and OS state roots.

| PIE | Blocks | Cairo steps |
|---|---|---:|
| `pies/leaves/15627902-15627904.zip` | 15,627,902–904 (3) | 1,224,007 |
| `pies/leaves/15627905-15627907.zip` | 15,627,905–907 (3) | 785,807 |
| `pies/leaves/15627902-15627907.zip` | 15,627,902–907 (6) | 1,580,295 |
| `pies/leaves/15630654-15630683.zip` | 15,630,654–683 (30) | 13,370,386 |
| `pies/aggregator/aggregator-15627902-15627907_x1.zip` | aggregator over the 6-block leaf | 17,325 |
| `pipeline/15627902-15627907_x2/aggregator-15627902-15627907.zip` | aggregator over the two 3-block leaves | 18,816 |

Checks:

- **Chain.** Every leaf's OS `initial_root` equals the chain's `old_root` at its
  first block, and its `final_root` equals the chain's `new_root` at its last
  block.
- **Chaining.** The aggregator accepted `15627902-15627904` + `15627905-15627907`,
  so the second leaf starts at the first leaf's final root, block number and
  block hash.

`pipeline/15627902-15627907_x2/` is one run of
`tools/starknet-block-collector/prove_pipeline.py`. It contains:

- the stwo-zig CPU proofs (binary format) of both leaves and of the aggregator
  PIE, with their product reports;
- the official Rust verifier's verdicts (all `verified: true`);
- `results.json` with timings.

Those timings come from an Apple M4 Max (36 GB, macOS 15.3) while other work
was running. They are indicative, not benchmarks.

The same directory now also holds `root.proof`, `root_outputs.json`,
`root_packed.json`, and `root_verification.json` for the two contiguous PIEs,
generated under the production circuit registry (70 queries and 26 PoW bits)
on an M5 Max. The independent Cairo `stwo_circuit_verifier` accepted the root
proof, and the packed tree's ordered public preimages produce its exact output
digest. `starknet-aggregator --packed-output root_packed.json` rebuilt the
committed aggregator PIE byte for byte from the two source PIEs; mutating a
preimage caused an admission failure. These artifacts establish the real
handoff inputs, not a final applicative proof.

`blocks.jsonl` holds one line per block the collector processed: status, tx
count, single-block OS steps, and chain roots. Only rows with `status: "ok"`
have single-block OS runs whose roots matched the chain. The full RPC
recording (~4 GB) is not committed. The leaves can be rebuilt from the archive
RPC as described in `tools/starknet-block-collector/README.md`.
