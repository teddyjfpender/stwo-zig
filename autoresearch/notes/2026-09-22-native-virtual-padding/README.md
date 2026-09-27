# Typed virtual padding: complete interaction parity

The component-level census corrects the earlier denominator hypothesis: native
BLAKE3 G padding has 56 live relation events. Zero main/preprocessed values do
not make that component's lookup traffic inert. All other 19 roster AIRs have
zero padding numerators and match the implicit omitted-row path. The G mismatch
changes claimed sums and interaction columns, and also requires table registration.

Added generatePreparedWithPadding to the canonical interaction runtime. It evaluates
an explicit typed padding row once through the authenticated plan and reuses those
pairs for omitted logical rows. The existing public entrypoints retain null-padding
behavior. No independent equation or interaction-generation loop was introduced.

Across every native AIR, explicit four-row padding matches the new virtual path
for prefixes of length zero through three: every column and claimed sum agree,
including the proof-kind selector parameters. Existing workspace allocation,
failure-atomicity and alias checks also pass. Focused ReleaseSafe gate:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-recursive-fused-pcs-opening -Doptimize=ReleaseSafe --summary all
```

Exit 0, 4/4 steps, 11/11 tests, run 548 ms / 4 MiB, compile 21 s / 2 GiB.
This gate includes existing PCS arithmetic, lookup closure, matcher and admission
checks. It does not yet replace the native producer's padded-row allocation.

Next integrate repeated-row table counter registration and compare it to explicit
rows, then switch the producer to borrowed logical rows plus virtual typed padding.
The G padding multiplicities must be preserved in both counters and interaction
columns. Full proof verification and tracked allocation measurement are required
before claiming the copy removal as implemented or beneficial.
