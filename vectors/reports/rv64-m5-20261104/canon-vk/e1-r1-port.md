# canon-vk E1: recsize port merged, r1 default — GPU byte parity (2026-11-04)

Closes the gate the diet stream left open (`diet/recsize-port/README.md` "Not done"): the k-ary / m3-profile port, merged
into canon-vk (`97e391d1a`; the receipts' `source_commit` `3bdbcfacd` is the same tree before a message-only amend), is byte-identical to the M3/M4 baseline under the default r1 binary profile on GPU.

| block | proofs compared | identical | fresh receiver | request | recursion | load 1m |
|---|---:|---|---|---:|---:|---:|
| 26235156 | 37 | yes | accepted | 32.27 s | 15.31 s | 24.4 |
| 24628607 | 55 | yes | accepted | 45.37 s | 21.11 s | 25.5 |

- Harness: `rv64_m3_pod.py bench <b> --gpus 2` one-shot (no ArtifactStore, so setup is cold: 9.3 / 13.0 s), M4 env
  (`NARROW_RUNS`, `GPU_CPU_REPLAY`, `CORE_SINGLE_STREAM`, `DEVICE_ARENA`). Reference: `/workspace/m3/runs/integrate/<b>-2gpu-scale`.
- Load average was 24-27 (quiet bar is 8): timings are **not quotable**; this receipt is a parity receipt. [M] single observation.
- Binaries: driver/receiver/library built from this tree (`/workspace/m3/build/m5-canon-vk/build.json`).
