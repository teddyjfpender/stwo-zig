# Compact immutable metadata in BLAKE3 parent proving plans

The persistent parent plan previously cloned full logical metadata rows and zeroed
their main-column prefixes, even though interaction generation reads all main
values from the separately retained column buffers. It now retains only each
row's fixed tail: preprocessing fields plus any selector parameters. Initial
preprocessing projection reads the admitted source rows directly. Repeated proving
validates every fixed tail against the immutable compact copy.

The shared interaction column view accepts either full metadata or compact
row-major fixed tails. Compact reads reconstruct the same logical row from those
tails and the committed-layout main columns. Validation requires exact tail length,
valid row/column geometry and exclusive metadata representation. Alias checking
covers compact tails against output columns and inversion scratch before writing.
Existing full-row callers keep their original representation and behavior.

No AIR, lookup equation, PCS parameter, transcript or key identity changes. The
optimization removes a redundant copy in the persistent worker; it does not yet
compact prepared witness metadata or change the large PCS commitment allocations.

## Qualification commands

`python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-memory-update -Driscv-test-filter='compact parent metadata' -Doptimize=ReleaseSafe --summary all`

Passed in 9 seconds / 832 MiB: row reconstruction and every interaction column
and claim match the full-row oracle, including non-power-of-two live rows/padding.
Mixed metadata, truncated tails, invalid main geometry and scratch aliases reject.

`python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-canonical-chain -Doptimize=ReleaseSafe --summary all`

The unchanged q70/PoW26 leaf-to-parent fixture checks real proof construction,
codec roundtrip, independent root verification and allocator custody after both
worker and witnesses are released. Baseline worker routed peak was 23,106,927,066
bytes, with 4,214,454,616 bytes of prepared columns, recorded in the preceding
canonical-chain note. This experiment measures storage reduction; it is not a
proof of an end-to-end latency speedup or a completed BLAKE3 production migration.

The canonical chain passed in 4 minutes build/test with 24 GiB peak RSS. Both
proof levels retain q70/PoW26; the prepared witness stays at 4,214,454,616 bytes
and the independently verified artifact at 860,503 bytes. Compact immutable plan
metadata occupies 376,119,932 bytes. Routed worker peak fell from 23,106,927,066
to 21,518,565,568 bytes: 1,588,361,498 bytes (6.87%) less on this fixture. Both runs
used the same 24 GiB worker cap. This is a measured allocation improvement, not
a demonstrated latency speedup; the build/test summaries both round to 4 minutes.

Native regression:
`python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment -Doptimize=ReleaseSafe --summary all`

Passed 3/3 tests (1 minute compile / 6 GiB; 50 seconds run / 1 GiB). Existing
fixed-row/geometry mutation checks, same-key plan reuse, bounded failure and
cancellation, pipeline overlap and output verification after worker destruction
remain intact. Its worker routed peak is 930,536,163 bytes, versus 982,008,191 in
the preceding shared-pipeline regression, under the unchanged 4 GiB cap.
