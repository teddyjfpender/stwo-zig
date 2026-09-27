# Native BLAKE3 FRI arithmetic and DEEP-answer routes

The native FRI adapter consumes the concrete verified BLAKE3 capture and validated
native DEEP preparation. The fold schedule follows configured degree transitions;
the hash-independent FRI capture adapter checks proof layer widths, positions,
query counts, terminal coefficients and encodings against that schedule. The
existing canonical FRI graph evaluates the witness. No new arithmetic law or
hash primitive was introduced.

Canonical terminal binding lookup identifies each DEEP answer coordinate and
corresponding FRI input. Each DEEP scalar producer emits its graph use count plus
one; the FRI routing row consumes that additional emission and produces the FRI
graph's required uses. Values must agree coordinate by coordinate and remain
base-field scalars. The returned source and destination rows must each be
included once in the complete parent. Terminal coefficient node mappings are
retained for the later transcript encoding join.

The integration gate compares source/destination values and fixed schedules,
then changes a DEEP answer and a terminal coefficient independently; both must
fail canonical FRI evaluation with UnsatisfiedCircuit. Existing native composition,
transcript, payload and shared sample checks remain in the same gate.

Serial qualification command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment -Doptimize=ReleaseSafe --summary all
```

Terminal exit 0: 4/4 build steps, 3/3 tests passed. The native FRI graph has
3,684 nodes and 94 zero outputs; the one-query gate routes four answer scalars.
Compilation: 59 s / 4 GiB; tests: 20 s / 1 GiB. Formatting and git diff --check
pass. No broad suite ran and no live build remains. This remains a tiny q1/PoW0
qualification case, not canonical CSP or a performance acceptance campaign.

Remaining: join transcript challenges/queries and terminal coefficient encodings,
trace/FRI paths and public-boundary authority, then include all rows in a complete
native recursive parent proof. Statement-independent keys, production artifact
admission, Metal and parent-of-parent qualification remain outstanding. Graph
replay and route construction alone do not establish a recursive parent proof.
