# rv64-m9-prep / m9-fewer-leaves receipts

- `model.json`: output of `scripts/rv64_m9_leaf_fanin_model.py` [D/E]. It holds the self-check against the M7 D2 receipts, the bench15 calibration, and per-block, per-option nodes, cells, GPU-s, windows, tails and node memory for all 15 basket blocks.
- `tests.json`: the CPU unit-test receipt [M]. The Zig planner tests and the Python mirror tests both pass, and the receipt records the source hashes.

Design and numbers: `design/riscv-proving-stack/rv64-m9-fewer-leaves.md`. No GPU was used, and no raw artifacts were produced.
