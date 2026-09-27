# Same-binary canonical parent streaming comparison

One observation per arm, streaming then monolithic, CPU ReleaseFast, two workers,
70 queries / 26 PoW bits for child and parent. This is a diagnostic fixture,
not a production latency or whole-tree qualification. Both arms use the frozen
`parent-test` executable identified in `binary.json`.

| Measurement | Monolithic | Streaming |
| --- | ---: | ---: |
| Main commitment seconds | 19.023705 | 6.871722 |
| Sum of recorded parent stages seconds | 59.840922 | 47.610342 |
| Tracked peak allocation bytes | 15001594618 | 15001605778 |

Both artifacts are 850599 bytes and have SHA256
`8659d8493978c707aa8cf3159f39ae3b546219db6a76d3ad7a3dc65cb81ac8aa`.

Independent child/parent verification, transcript replay, fixed-plan reuse,
worker rekey and outputs outliving the worker all pass. Stage sums exclude
preparation outside the profile, verification, compilation and scheduling.
There is no measured peak-memory saving. This compares two BLAKE3 paths and
cannot establish improvement over Poseidon. Single fixed-order observations
need repeated production CPU/Metal measurements before performance qualification.

Commands:

```sh
STWO_RISCV_RECURSIVE_PARENT_PROFILE=1 python3 scripts/zig_serial_build.py --cwd . test-riscv-statement-codecs -Driscv-test-filter='compact range provider canonical recursive parent verifies' -Doptimize=ReleaseFast --summary all --verbose
STWO_RISCV_RECURSIVE_PARENT_PROFILE=1 STWO_RISCV_PARENT_MONOLITHIC_MAIN=1 autoresearch/notes/2026-09-23-parent-streaming-parity/parent-test
```

The streaming command built and executed the binary subsequently frozen here.
`comparison.json` preserves all recorded stage timings. Raw logs preserve both
artifact fingerprints and qualification outcomes. The source change in this
checkpoint adds profile-only artifact SHA output; streaming was implemented in
the preceding current-recursion-audit checkpoint.
