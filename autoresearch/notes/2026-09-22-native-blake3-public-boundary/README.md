# Native BLAKE3 public-boundary arithmetic

The existing SegmentV2 public-sum arithmetic is now evaluated directly from a
concrete verified native BLAKE3 capture. Its public facade exposes the canonical
graph builder, typed input-source mapping and arithmetic graph mirror. The older
outer-roster wrapper remains unchanged; no parallel public-sum formula or new
hash primitive was introduced.

The adapter validates the capture, obtains its authenticated canonical public
wire, derives the canonical memory-byte layout, and maps every graph input from
the existing source schema: wire words, four domain sums, total, first four native
relation pairs, register bytes, memory bytes and selectors. It owns copies of all
input values/bindings and the arithmetic graph/evaluation. Every designated output
must be zero, including the public-sum recomputation and snapshot identity checks.

The integration gate evaluates the real nonfinal BLAKE3 capture, validates its
graph mirror, and changes a published sum input. The changed input must fail with
InvalidNativePublicBoundary. All prior native preparation and proof checks remain.

Serial command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment -Doptimize=ReleaseSafe --summary all
```

Final terminal exit 0: 4/4 steps and 3/3 tests passed. The public-boundary graph
has 4,351 nodes, 1,332 inputs and 21 zero outputs. Compile 1 min / 4 GiB; tests
23 s / 1 GiB. Formatting and git diff --check pass. No broad suite ran and no
live build remains. The native q1/PoW0 case is
qualification, not canonical CSP or production performance/security evidence.

Remaining: bind public-boundary input words/bytes/selectors and shared relation
challenges in the parent; connect its published total to transcript aggregate
claims; include this graph and every prepared AIR row in a complete native parent
STARK. Graph evaluation alone does not authenticate those inputs in an outer proof.
Statement-independent keys, production artifact admission, Metal and parent-of-
parent qualification remain unfinished.
