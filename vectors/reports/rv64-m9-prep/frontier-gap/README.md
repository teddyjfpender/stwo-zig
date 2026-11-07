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
python3 -I scripts/tests/test_rv64_m9_frontier_gap_model.py   # 8/8
```

## Headline [E], after review 1 (2026-11-07)

The base is the plan's best 2-GPU set, plus STACK, BLAKE3R, NGKRFULL and D2REV. GRIND26 dropped out: at the as-built device grind of about 1.1 G/s it is a net loss, and break-even is 16.7 G/s.

| case | warm (class hits) | cut | production (new block) | cut |
|---|---:|---:|---:|---:|
| central p50 | 8.22 s | −58% | 14.08 s | −53% |
| central p95 | 13.81 s | −58% | 22.95 s | −54% |
| central basket | 124.4 s | −58% | — | — |
| pessimistic p50 (+STACK+BLAKE3R) | 12.70 s | −47% | 23.70 s | −45% |
| optimistic p50 | 5.79 s | −67% | 8.14 s | −61% |
| 4×5090 + STACK + BLAKE3R, central / pess p50 | 5.57 / 8.59 s | −72% / −64% | — | — |

- p50 kernel GPU-s goes 16.12 → 11.59, which is ×0.72 against the ×0.67 needed.
- Mainnet-weighted mean: 8.4 s warm, 14.2 s production.
- Every lever is gated (doc §5) before it counts. The review findings are in doc §8.
- Tests: 8/8.
