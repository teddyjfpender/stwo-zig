# Native BLAKE3 capture into canonical recursive FRI arithmetic

Previous goal turn: progress (complete typed folding-subtree implementation and
passing full subtree proof). This turn advances the arithmetic connection.

`fri_arithmetic_capture.Owned` copies the field/routing portion of a successful
verifier capture without importing Poseidon digest types. Its caller supplies
an independently chosen canonical FRI profile. Admission validates profile,
query/layer/value counts, fold widths/steps, upper path depths, raw query bounds,
per-layer positions against shifted original queries, and canonical QM31 words.
It derives offsets and terminal positions, and owns every input slice. Capture
provenance and commitment authentication remain the caller's responsibility.

The extended complete-group gate creates real BLAKE3 PCS captures for fold1/2/4
and evaluates the EXISTING canonical production FRI arithmetic graph over every
query and layer. Every (layer, query, offset, word) input binding matches the
corresponding captured hash coordinate; the test checks the full coordinate
count. This exercises circle-to-line folding, subsequent line folds and terminal
polynomial checks. Changed DEEP answers fail with UnsatisfiedCircuit. Inconsistent
layer routing fails adapter admission. Mutating the original capture leaves the
owned input snapshot unchanged. std.testing.allocator checks successful owner
release. The previous complete six-component typed subtree proof still passes.

Command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-fri-group -Doptimize=ReleaseSafe --summary all
```

Result: all four build steps passed, one guarded test passed; approximately
3 seconds runtime, 378 MiB max RSS; 23 seconds compilation on M5 Max. Initial
compilation caught an incorrect QM31 constructor call; corrected before the
successful gate. Formatting and diff checks pass.

Evidence boundary: canonical FRI arithmetic is evaluated and checked on the
host, while the complete typed outer proof still covers the hash subtree with
public auxiliary source tuples. This is NOT a proof of a combined private FRI
arithmetic/hash relation. The production FRI input component consumes scalar
`recursion_fri_merkle_value_word` tuples, whereas the hash encoder consumes a
QM31 `recursion_wire`; the next integration must supply both from the same
constrained values and close the full arithmetic lookup ledger. Production
capture ownership still retains its Poseidon-specific storage; it has not been
switched to this adapter. Transcript admission, CPU/Metal suite/key transition
and parent-of-parent qualification remain. No speed or security improvement is
claimed and the active goal remains unfinished.
