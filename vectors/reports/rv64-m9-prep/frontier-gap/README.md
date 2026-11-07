# M9 prep: frontier gap receipts

This directory holds the receipts for the m9-frontier-gap stream. The full analysis is in `design/riscv-proving-stack/rv64-m9-frontier-gap.md`.

| file | what | label |
|---|---|---|
| `model.json` | `scripts/rv64_m9/frontier_gap_model.py` output: frontier table, ethproofs snapshot, single-lever deltas, the search over plan-best + {STACK, BLAKE3R, GRIND26, NGKRFULL, D2REV}, 4-GPU view and the mainnet-weighted view | D/E |
| `width-census-24628607-d2.json` | per committed tree: columns opened per query, coefficient words, average column height | M (log) / D |

## Inputs (raw artifacts, out of git)

- **gas sample:** `gas_sample.json`, 2,897 distinct blocks, Sep–Oct 2026. sha256 `52578c5a916ade03414e899517ae21b0d52c26e0e52b2135fc2e567f30f05544`.
- **producer log:** `design/riscv-proving-stack/m7-handoff/receipts/device-service/sparse-rc/daemon-24628607-r2-sparse-d2-22g/producer.stderr`, as committed on `codex/rv64-m9-poseidon2-leaves`. sha256 `c4bb809a15b960b81571241918ab18122a8f078c060bd1b21961f40224d97a0b`.
- **plan model:** `origin/codex/rv64-m9-plan:scripts/rv64_m9/plan_model.py` (rev 4). It is loaded unchanged.
- **frontier trees, read only:**
  - `zksync-airbender` @ 0decdcd;
  - Airbender v3 @ 36e57d3;
  - `pil2-proofman` @ 27b2fc2;
  - `zisk` @ 64a1f16.
- **published numbers:** ethproofs.org/clusters, fetched 2026-11-07.

## Reproduce

```
python3 -I scripts/rv64_m9/frontier_gap_model.py --gas-sample gas_sample.json --json vectors/reports/rv64-m9-prep/frontier-gap/model.json
python3 -I scripts/rv64_m9/frontier_gap_width_census.py producer.stderr --json vectors/reports/rv64-m9-prep/frontier-gap/width-census-24628607-d2.json
python3 -I scripts/tests/test_rv64_m9_frontier_gap_model.py   # 6/6
```

## Headline (central) [E]

The base is the plan's best 2-GPU set, plus STACK, BLAKE3R, GRIND26, NGKRFULL and D2REV:

| case | wall | cut |
|---|---:|---:|
| p50 | 7.92 s | −60% |
| p95 | 13.33 s | −59% |
| basket | 119.9 s | −59% |
| pessimistic, p50 | 12.70 s | −47% |
| optimistic, p50 | 5.64 s | −68% |

- p50 kernel GPU-s goes 16.12 → 11.14, which is ×0.69.
- Every lever is gated (doc §5) before it counts.
