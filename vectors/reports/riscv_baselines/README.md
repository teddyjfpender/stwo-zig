# RISC-V performance baselines

Committed, machine-annotated baseline reports for the RISC-V performance
boards. Unlike the ephemeral `vectors/reports/*.json` outputs (gitignored),
these are tracked point-in-time snapshots — the reference the autoresearch
harness measures candidates against.

| File | Board | Produced by |
| --- | --- | --- |
| `corpus_baseline.json` | `riscv` (hand-assembled corpus) | `autoresearch/benchmarks/riscv_stark_v_benchmark.py` |
| `crypto_baseline.json` | `riscv` (compiled crypto guests) | `autoresearch/benchmarks/riscv_crypto_benchmark.py` |

The native (`core_cpu`) board's tracked history lives separately under
`vectors/reports/benchmark_history/`.

## Machine context

Every report carries a `host_environment` block (schema
`riscv_benchmark_host_environment_v1`): chip, machine model, logical CPU
count, physical memory, OS product/build version, and the Zig/rustc/Python
toolchain versions. A timing number is only comparable against another taken
on the same hardware — always read the ratios (`zig_over_rust_*`), which are
machine-relative, and treat absolute seconds as valid only within one report's
`host_environment`.

## Relationship to the autoresearch anchor

`autoresearch/MANIFEST.json` holds `harness.anchor_prove_ms` per board, still
null. A null anchor disables judged promotion (drift budgets can't be
evaluated). Freezing the anchor is a deliberate, human-reviewed commit owned by
the team, sequenced after the RF-01 adapter release; these baseline reports are
the evidence that freeze draws from. Regenerate a baseline only when
intentionally re-freezing, and record the machine it was taken on (the
`host_environment` block does this automatically).

## Regenerating

```sh
python3 autoresearch/benchmarks/build_crypto_guests.py --stark-v-source <checkout>   # crypto guests only
python3 autoresearch/benchmarks/riscv_stark_v_benchmark.py --stark-v-source <checkout> \
    --report-out vectors/reports/riscv_baselines/corpus_baseline.json
python3 autoresearch/benchmarks/riscv_crypto_benchmark.py --stark-v-source <checkout> \
    --report-out vectors/reports/riscv_baselines/crypto_baseline.json
```

The Stark-V checkout must be at the pinned commit with `stark-v-bench` built
`--features parallel` (the harness fails closed if the Rust lane is serial).
