# Native public-boundary input sources

The authoritative native statement encoder supplies the exact statement prefix
position and contents. Preparation compares the transcript operations at those
positions, including statement metadata and wire identity; it does not search for
matching values. The authenticated statement view supplies public words and
canonical register/memory byte and nonzero-selector derivations. Every value is
checked against the validated public-boundary evaluation before producing rows.

Existing boundary AIR constraints bind 1,280 public coordinate rows. Sixteen
private scalar producers supply the four published QM31 domain sums, constrained
by the existing public-boundary arithmetic. Exact arithmetic use counts determine
all producer multiplicities. Together with the existing 32 challenge routes and
four total producers, these cover all 1,332 native public-boundary inputs.

The real native gate checks complete input coverage, fixed/live metadata parity,
public expected coordinates, private fixed-value clearing, and rejection after
changing a transcript statement word. The earlier public-sum mutation and
challenge/global-cancellation checks remain active in the same gate.

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment -Doptimize=ReleaseSafe --summary all
```

Initial compilation failed because Plan.validate takes no allocator argument;
that call was corrected. Final run reached terminal exit 0: 4/4 steps and 3/3
tests passed, compilation 1 min / 4 GiB, tests 23 s / 1 GiB. Formatting and
`git diff --check` passed. No broad suite ran and no build remains live.

This is statement-specialized preprocessing. It does not establish a reusable
parent key or a complete recursive-parent STARK. Next: assemble the five
arithmetic graphs and their prepared producers/consumers, replacing superseded
rows exactly once, then prove and independently verify the complete native
parent. CPU/Metal parent-of-parent and production artifact qualification remain.
The q1/PoW0 diagnostic is not a production benchmark or evidence of speedup.
