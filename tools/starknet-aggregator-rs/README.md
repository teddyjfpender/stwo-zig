# starknet-aggregator-rs

Development tool. It runs the Starknet aggregator program
(`core/aggregator/main.cairo`, sequencer tag `APOLLO-0.14.3-RC.15`) over
contiguous Starknet OS leaf PIEs via `starknet_os::runner::run_aggregator`
and writes the aggregator's CairoPie, which can then be proved like any other
PIE.

```sh
starknet-aggregator --leaves leaf1.zip leaf2.zip ... --output aggregator.zip \
    [--packed-output root_packed.json] [--program-output out.json] \
    [--full-output] [--chain-id SN_MAIN] [--layout all_cairo]
```

Leaves must be given in block order. The aggregator asserts that each leaf's
initial root, block number and block hash equal the previous leaf's final values.
When `--packed-output` is supplied, the runner also requires each OS output it
actually passes to the aggregator to equal the corresponding ordered public
preimage in the recursive circuit root. This is an input admission check; the
final Cairo applicative proof must still enforce the relationship.

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
