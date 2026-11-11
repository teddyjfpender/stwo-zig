# Heavy OP CPU performance requirement

The hard target is **at least 10x** faster complete proving of OP Mainnet block
121065789, including execution, capture, setup, native proving and all recursion.
The [pinned case](heavy-cpu-target.json) has an existing D2 native plus M6 root
baseline of **3,328.446 s**; the target is **332.845 s** on the same M5 Max.
This speedup has not been achieved.

Three workstreams are active: algebraic native/recursive transcripts, Kona
pairing/client reductions, and fused field/tower delegations. New execution
profiles and cryptographic suites stay closed until their physical joins and
fresh receivers qualify. The label remains **128-bit security target under
documented assumptions**, with `security_qualified=false`.

## Complete CPU measurement

`opstack/cpu.py --recursive-runner PATH` produces an execution root before
fresh reception and corruption trials. The strict fresh receiver verifies both
native and recursive inventories, exact output and selected profiles. Native-only
mode and its defaults stay unchanged. The [pilot qualification](cpu-root-harness.json)
reproduces all five old native binaries and all five old recursive proof bytes,
and passes both native corruption controls. Concurrent engineering was active;
its 41.68 s production time is an integration check, not a speedup claim.

Use the existing `opstack/cpu.py` invocation with these explicit additions:

- `--recursive-runner zig-out/bin/rv64-word16-ethereum-gkr-recursion`
- `--recursive-profile m6_outer_diet_k3_r1_b2_q108_p20_fold4_v1`
- `--recursive-workers 16`

Select `--native-profile d2_native_b4_q54_p20_fold4` for the pinned baseline.
Use the selected ELF's actual symbols and operator-sized resource admissions.
The fixed-key cap is inside requested-live limits; freed-block caches are
additional. The heavy baseline used 8 GiB fixed setup and 52 GiB recursion live.
A native-only receipt cannot count as completion of this requirement.

## New execution-only runtime

The isolated `ethereum_services_op_v1` profile carries the fused Miller-line
call under tag `0x00040001`. Its event stores 80 input words and 48 output
words separately from the unchanged legacy curve event. The bounded
`RV64TP02` envelope reconstructs the unchanged 32-word tail from the inputs;
all earlier profiles keep `RV64TP01`. The [runtime and codec qualification](op-runtime-wire.json)
covers 44 tests in both ReleaseSafe and ReleaseFast, including atomic errors,
allocation failures and malformed envelopes. Production proof admission remains
closed until the arithmetic provider, RAM join and recursive receiver qualify.

The [guest receipts](guest/README.md) establish actual execution savings and
independent Unicorn agreement, not a measured end-to-end proving speedup.
The pure-P2 CPU verifier now checks complete real CPU fixture proofs in its
circuit; the [recursion design](../../../design/riscv-proving-stack/op-pure-p2-recursion.md)
records its actual cell cost. Physical leaf/fold qualification and full service
coverage remain open. The 10x heavy-block target above remains unmet.
