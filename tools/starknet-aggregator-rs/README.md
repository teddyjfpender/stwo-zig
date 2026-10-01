# starknet-aggregator-rs

Development tool. It runs the Starknet aggregator program
(`core/aggregator/main.cairo`, sequencer tag `APOLLO-0.14.3-RC.15`) over
contiguous Starknet OS leaf PIEs via `starknet_os::runner::run_aggregator`
and writes the aggregator's CairoPie, which can then be proved like any other
PIE.

```sh
starknet-aggregator --leaves leaf1.zip leaf2.zip ... --output aggregator.zip \
    [--program-output out.json] [--full-output] [--chain-id SN_MAIN] [--layout all_cairo]
```

Leaves must be given in block order. The aggregator asserts that each leaf's
initial root, block number and block hash equal the previous leaf's final values.

## Build

The dependencies are pinned to match SNOS `feature/0.14.3` (`38cabc9`), so you
can reuse SNOS's target directory instead of building from scratch:

```sh
source ~/Coding/snos/sequencer_venv/bin/activate   # cairo-lang 0.14.3a3
export MLIR_SYS_190_PREFIX=/opt/homebrew/opt/llvm@19
export LLVM_SYS_191_PREFIX=/opt/homebrew/opt/llvm@19
export TABLEGEN_190_PREFIX=/opt/homebrew/opt/llvm@19
export LIBRARY_PATH=/opt/homebrew/lib
CARGO_TARGET_DIR=~/Coding/snos/target cargo build --release
```

## Measured

One 6-block mainnet leaf (15627902–15627907) produces an aggregator PIE of
17,325 Cairo steps with 312 output felts.
