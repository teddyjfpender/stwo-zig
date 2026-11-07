# m9-proof-params receipts (branch codex/rv64-m9-proof-params)

Doc: `design/riscv-proving-stack/rv64-m9-proof-params.md`.

| file | what | label |
|---|---|---|
| `nsys-proof-kind.json` | kernel GPU-s split native/recursion x class x PCS phase, 5 profiled warm pairs (M8 fullstack 24628607; M6 vs D2 on 24628607 and 26235156), read-only on pod sqlite (paths inside), `scripts/rv64_m9/nsys_proof_kind.py` | M |
| `pow-bench-dev5090.jsonl` | grind ms per proof, p16-p28, as built vs check-every-64, 4 seeds, nonce parity; `src/backends/cuda/native/pow/bench/m9_pow_bench.cu` on dev pod a (RTX 5090) | M dev-5090 |
| `leaf-cap-census.log` | exact CPU census of the D2 leaf verifier at cap 0 vs 3 + circuit validity (`zig build test-d2-circuit-census`, macOS host) | M |
| `model.json` | `scripts/rv64_m9/proof_params.py`: security table, leaf fit, per-layer sweeps, joint search, named sets, sensitivity | D/E |
| `plan-model.json` | `scripts/rv64_m9/plan_model.py` with the PARAMS / PARAMS_POW levers (gas sample sha256 52578c5a...f05544, out of git) | E |
