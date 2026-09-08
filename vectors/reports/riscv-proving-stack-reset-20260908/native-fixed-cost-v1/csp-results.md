# CSP preservation diagnostic

All 128 launches completed: 16 canonical cases × CPU/Metal × baseline/current × two alternating paired rounds. Each launch retained five verified timing samples (640 total), one warmup, workers=16, unchanged secure PCS parameters and recursion-disabled worker policy. All guest/input/output/proof/statement identities matched across arms and backends, and every retained verification receipt came from its clean pinned source snapshot. All 128 per-launch report hashes were rechecked after the run.

| Backend | Case | Proof median change | Peak RSS median change | Repeated >5% increase |
| --- | --- | ---: | ---: | --- |
| cpu | sha256/128 | +0.59% | -0.41% | none |
| metal | sha256/128 | -0.15% | +0.14% | none |
| cpu | sha256/256 | -0.26% | +0.40% | none |
| metal | sha256/256 | -0.12% | +0.00% | none |
| cpu | sha256/512 | -0.19% | -0.06% | none |
| metal | sha256/512 | -0.29% | +0.18% | none |
| cpu | sha256/1024 | +1.34% | -0.17% | none |
| metal | sha256/1024 | +0.70% | +0.11% | none |
| cpu | sha256/2048 | +2.70% | +0.01% | none |
| metal | sha256/2048 | -0.91% | +0.43% | none |
| cpu | keccak/128 | +0.08% | -0.11% | none |
| metal | keccak/128 | -0.14% | -0.22% | none |
| cpu | keccak/256 | +0.39% | -0.25% | none |
| metal | keccak/256 | +0.72% | -0.23% | none |
| cpu | keccak/512 | +0.18% | -0.00% | none |
| metal | keccak/512 | +0.29% | +0.09% | none |
| cpu | keccak/1024 | +0.03% | -0.09% | none |
| metal | keccak/1024 | +0.59% | +0.05% | none |
| cpu | keccak/2048 | -0.22% | +0.27% | none |
| metal | keccak/2048 | -0.37% | +0.00% | none |
| cpu | poseidon2_m31/2 | -0.47% | -0.19% | none |
| metal | poseidon2_m31/2 | +0.55% | -0.20% | none |
| cpu | poseidon2_m31/4 | -2.82% | +0.35% | none |
| metal | poseidon2_m31/4 | +0.03% | -0.04% | none |
| cpu | poseidon2_m31/8 | +1.82% | +0.12% | none |
| metal | poseidon2_m31/8 | +0.19% | +0.02% | none |
| cpu | poseidon2_m31/12 | -0.45% | +0.09% | none |
| metal | poseidon2_m31/12 | -0.38% | -0.03% | none |
| cpu | poseidon2_m31/16 | +0.60% | +0.02% | none |
| metal | poseidon2_m31/16 | -0.61% | -0.05% | none |
| cpu | ecdsa_secp256k1/32 | -1.78% | -0.11% | none |
| metal | ecdsa_secp256k1/32 | -1.40% | +0.06% | none |

No case had a proof-time or RSS increase above 5% in both paired rounds. CPU SHA-256/2048 had a +6.48% second-round proof increase, following −1.11% in the first round; its paired-median change was +2.70%. The apparent single-round regression did not reproduce. CPU Poseidon/4 similarly varied from −5.88% to +0.41%; do not claim that isolated improvement.

**This is diagnostic evidence, not normative performance promotion.** None of the 128 host preflights met the strict quiet-host idle thresholds. The runner records `promotion_ready: false`; the host gate and thresholds were not weakened. A reproducible regression would block promotion regardless of Ethereum or small-proof gains. A quiet-host rerun is still required for formal performance admission.

Source snapshots:
- baseline: `8ecfd1dba5b43adaf6e79a4a50b00b70703227d0`
- current: `ad273a96721e1ccc1dd62a861fac11b44d0c680d`

The current snapshot is the committed optimization `ad273a96`. Subsequent changes only refine the small memory fixture and its tests; they do not change CSP proving code. See [the retained report](csp-paired/report.json) and [plan](csp-paired/plan.json) for source manifests, exact environment, per-round values and receipt hashes.
