# Terminal Blake development loop

Use the dedicated terminal test root instead of rebuilding the complete OP
fixture root for every producer/fresh-receiver iteration:

```sh
zig build check-riscv64-op-terminal-blake -Doptimize=ReleaseSafe -j1
zig build test-riscv64-op-terminal-blake -Doptimize=ReleaseSafe -j1
```

The check target emits no LLVM/test binary. The test target includes the two R6
and R7 physical format/source-authority tests, the two environment-gated actual
selected-root tests, a separate R7 fresh-only receiver test, and the two
fresh-path/allocation-failure tests, plus an env-gated native-profile CPU
source-cost model (no proof). Its pinned
filters select `terminal Blake` or `terminal fresh path`, with a minimum of eight
named tests. An explicit caller filter replaces those patterns and keeps the
existing unmatched-selection guard:

```sh
zig build test-riscv64-op-terminal-blake -Doptimize=ReleaseSafe \
  -Driscv-test-filter='terminal fresh path' -j1
```

For an already retained R7 proof, run the existing source-only receiver and
negative controls through the same narrow artifact:

```sh
STWO_OP_TERMINAL_BLAKE_R7_CONFIG=/absolute/path/config.json \
STWO_OP_TERMINAL_BLAKE_R7_NATIVE=/absolute/path/source-only-directory \
STWO_OP_TERMINAL_BLAKE_R7_OUT=/absolute/path/retained-root-directory \
STWO_OP_TERMINAL_BLAKE_R7_P2_CONTROL=/absolute/path/valid-same-source-p2-root-directory \
STWO_OP_TERMINAL_BLAKE_R7_MODE=verify \
zig build test-riscv64-op-terminal-blake -Doptimize=ReleaseSafe \
  -Driscv-test-filter='terminal Blake R7 fresh-only' -j1
```

The `fresh-only` entry invokes a compile-time receiver-only specialization.
It never instantiates native production, native physical verification callbacks,
or terminal root proving. MODE must be absent or `verify`; selecting `prove` or
`from-guest` fails instead of widening this entry. It shares the exact existing
Reception implementation, independently rebuilt source keys/AIR and all nine
controls; there is no authority cache or proof shortcut. The original actual
entry still supports its existing modes and environment variables unchanged.

The source-only directory omits `detached-op.bin`; it retains
`detached-op.json` and `cells.bin` for independent source admission. The P2
control directory contains the matching `root.bin`. Use the matching P2 control and
source metadata for the same fixture. On the original actual entry, `MODE=prove` consumes retained native
proofs; `MODE=from-guest` generates native proofs too and requires fresh disjoint
NATIVE/OUT directories. Actual modes remain gated by explicit environment
variables, the selected fixture/resource policies and existing receiver checks.
Changing this build root does not introduce an execution admission mode.

The root imports only terminal format tests, the shared actual R6/R7 harness,
and the path helper. Real production dependencies (native verifier, source
inventory, R7 equations and keys) remain dependencies: changes there SHOULD
invalidate this artifact. Unrelated dense/G2/Miller test fixtures are no longer
extra imports. Existing `test-riscv64-op-pure-p2` and all old qualification roots,
filters and defaults are unchanged; this narrower loop does not replace broader
regression gates before integration.
