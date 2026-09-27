# Private opening values shared by arithmetic and authentication

Previous turn: progress; sampled values private, but queried trace and FRI opening
values still had public leaf and arithmetic anchors. This stage removes those
anchors and shares actual scalar wires with authentication.

Trace query nodes come from canonical DEEP queried_value bindings. A deterministic
(tree, column, projected row) map assigns one canonical scalar producer to each
lifted row. Per-query routed scalar sources consume that producer once and emit
DEEP-use-count plus one encoder read. Canonical producer weights equal the raw
reference counts, retaining repeated-query consistency inside the lookup system.
The scalar AIR forces literal zero extension coordinates. Canonical field-byte
encoding emits only the first coordinate into the leaf's original payload slot.

FRI nodes come from fri_hash_wire_plan. Each private scalar source supplies its
arithmetic uses plus one pack read. Existing QM31 packing reconstructs every value;
field-byte encoding feeds all four coordinate words into the complete folding
subtree. All original trace paths, FRI subtrees and root comparisons remain.

Path preparation now returns external source metadata and encoder/packing rows
instead of public leaf payload producers. Parent assembly rejects duplicate,
non-input/out-of-range, overlapping and mismatching scalar bindings, removes their
arithmetic boundary rows, and reconstructs private scalar schedules with zero
witness placeholders. Encoder and pack preprocessing are independent of values.
The parent now uses thirteen existing AIRs; no equation or semantic digest changes.
The opening-input builder's allocations belong to the owning parent path arena.

Wire namespaces: composition/DEEP/FRI retain 1500/1502/1504; path payload words use
3,000,000, canonical trace rows use 5,000,000, and FRI packed tuples use 5,000,001.
These remain separate from transcript sources and hash schedules.

Claims, sampled values and opening values now have shared private sources in this
fixture. FRI answers/terminal coefficients and several challenge/root/query values
remain public fixture inputs; dynamic path routing and rejection schedules still
prevent a reusable production key. The fixture still starts from native-verified
capture data. Production admission, CPU/Metal, parent-of-parent and performance
qualification remain incomplete. Production still uses Poseidon; no speedup or
migration completion is claimed.

Validation:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-combined-fri test-blake3-fri-arithmetic-proof -Doptimize=ReleaseSafe --summary all
```

Eight steps succeeded; both guarded tests passed. Combined original/parent gate:
29 seconds / 6 GiB peak RSS, compilation 36 seconds / 2 GiB. Single-graph FRI
regression: 5 seconds / 368 MiB, compilation 30 seconds / 2 GiB. The first attempt
had a parser error from using the reserved word `packed` as a field name; the
field was renamed before the successful run. Both logs are retained. Formatting
and diff checks passed. No broad suite was run. Timings are fixture qualification
costs, not production recursion latency.
