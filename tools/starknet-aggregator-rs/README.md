# starknet-aggregator-rs

Development tool. It runs the Starknet aggregator program
(`core/aggregator/main.cairo`, sequencer tag `APOLLO-0.14.3-RC.15`) over
ordered Starknet OS public outputs via `starknet_os::runner::run_aggregator`
and writes the aggregator's CairoPie. The recursive root's packed tree already
contains the full ordered public preimages, so a matching aggregator PIE can
be built without downloading each source PIE ZIP again:

```sh
starknet-aggregator --packed-output root_packed.json --output aggregator.zip \
    --program-output aggregator_output.json
```

This construction is a data-preparation step, not a proof that the outputs are
authentic. The circuit-applicative Cairo proof verifies the root and asserts
that these exact outputs are what the aggregator consumed. The root's leaf
proofs bind each preimage to its proved OS execution.

The ordered public preimages are available as soon as the PIEs enter a
campaign, before their circuit proofs and folds finish. To construct the
aggregator concurrently with proving, write a JSON array of leaf preimage
arrays in block order, then run:

```sh
starknet-aggregator --preimages ordered_preimages.json --output aggregator.zip
```

The Go proving service prepares that bounded package from admitted,
SHA-256-checked objects. On the committed two-PIE fixture, this mode wrote
the same aggregator ZIP bytes as `--packed-output`. The final applicative
proof remains responsible for proving that the resulting aggregator consumed
the root's verified preimages.

The pinned Starknet OS aggregator also has a blob data-availability branch.
The existing 128/512 fixtures use the default `calldata` branch. To exercise
the blob branch and publish its DA segment, pass:

```sh
starknet-aggregator --preimages ordered_preimages.json \
    --da-mode blob --da-output aggregator.da.json --output aggregator.zip
```

The DA segment is a separate, hashed output artifact; this tool does not
package or submit an L1 blob. On the two-PIE fixture, the blob-mode ZIP and
DA segment were byte-identical whether built from ordered preimages or the
packed tree. The blob-mode applicative Cairo execution was proved on Metal and
accepted by the pinned independent Rust verifier at 70 FRI queries and 26
PoW bits. Calldata and blob outputs differ, so their proof hashes and timing
results must be compared within the same DA mode.
The saved 128-PIE root also passed blob-mode applicative proving on Metal:
27.456 seconds from published root to independently verified final receipt
with a release aggregator. The [service evidence](https://github.com/teddyjfpender/proving-service/tree/feature/circuit-applicative-campaign-final/data/h200-api-128-512/h200-api-128-001/applicative-blob-final)
contains the proof, DA segment, and digest-bound receipts. Blob mode has not
been measured on the saved 512-PIE root.

To cross-check against original ZIPs during qualification:

```sh
starknet-aggregator --leaves leaf1.zip leaf2.zip ... --output aggregator.zip \
    [--packed-output root_packed.json] [--program-output out.json] \
    [--full-output] [--chain-id SN_MAIN] [--layout all_cairo]
```

Leaves must be given in block order. The aggregator asserts that each leaf's
initial root, block number and block hash equal the previous leaf's final values.
When both sources are supplied, each ZIP's OS output must equal the
corresponding packed public preimage. The runner limits packed trees to 4,096
leaves, checks each leaf's OS program hash, and lets the aggregator enforce
the contiguous block/state-root sequence.

## Build

The dependencies are pinned to match SNOS `feature/0.14.3` (`38cabc9`).
Apollo's build script needs `cairo-compile` from Cairo 0.14.3a3:

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install cairo-lang==0.14.3a3
PATH="$PWD/.venv/bin:$PATH" cargo build --locked --release
```

## Measured

One 6-block mainnet leaf (15627902–15627907) produces an aggregator PIE of
17,325 Cairo steps with 312 output felts.
