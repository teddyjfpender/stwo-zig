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
