# Second recursive optimization and bounded scaling

Baseline source: `3f3a7336`. `before.json` pins the previously measured binary
and three fresh complete broad-gate runs. `after-build.log` contains the new
optimized build and broad complete-proof regression. Timing comparisons use
the same broad gate; ladder measurements use the same narrow gate for every
size. Do not attribute omitted diagnostic work to prover optimization.

The ladder uses one canonical finite ADDI/BNE counter-loop program for every
size. One instruction initializes a counter to 64; each iteration increments
an accumulator, decrements the counter, and branches. A terminal self-loop
marks completion after 193 retirements. All tested prefixes plus their actual
16-cycle continuations precede that marker. The continuation establishes the
fixture's endpoint; it is not a second proved child.

The first fixture attempt treated JAL-to-self as a retired repeating jump.
`steps-4.log` retains its immediate failure: requested 4 cycles, observed 3.
`attempt-01-source.patch` and `failure-reproduction.json` reconstruct its exact
source. The revised execution-only check and the proof path share assertions
on actual cycles, opcode counts, PC, register values and continuation. The
failed attempt's `after*.json`, `after-*.log`, and `steps-*.log` are historical;
accepted measurements use `final-*` files.

All cases use the same native and outer development PCS parameters. Native
steps, actual native trace rows/tree heights, and derived outer component log
sizes are separate dimensions. The outer verifier still consumes retained
native admission input, so this is not a detached root.

From the repository root, run the broad acceptance gate:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  run-recursive-segment-v2-concrete-outer-proof -Doptimize=ReleaseSafe --summary all
```

Then select each small size explicitly (1, 4, 16, 64):

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  run-recursive-segment-v2-concrete-outer-proof -Doptimize=ReleaseSafe \
  --summary all -- --native-steps 16
```

Each size proves all 39 outer components and checks all 47 relation domains,
serializes, destroys outer producer allocations, freshly decodes and verifies,
and rejects truncated/trailing artifacts. Process shutdown checks allocator
leaks. The narrow mode omits the broader standalone component, recorder and
mutation diagnostic fleet, while sharing complete proof acceptance with it.

Before proving, replace `--native-steps 16` with `--check-workload` to validate
all four execution sizes. The warm command took0.13s including the build wrapper
(`workload-warm.log`); its executable check took2ms. Cold changed-source build
plus first check took159.71s (`workload-build.log`), so this is a fast runtime
gate, not a claim of faster compilation.

`results.json` checks every retained successful process exit, log hash, exact
39/47 coverage, worker/profile settings, producer destruction, codec rejections,
requested vs actual cycles, and disjoint per-run phase sums. It reports medians
of three broad runs before/after and three full processes at each corrected
ladder size. Component logs are invariant across repeats at a given size.

The corrected ladder completes all12 proofs. The broad gate completes all3
new-source runs, including its mutation and downstream replay checks. Invalid
size inputs0,3,65 and nonnumeric input are rejected before proving; see
`cli-rejections.json`. The native input remains required for outer admission.
