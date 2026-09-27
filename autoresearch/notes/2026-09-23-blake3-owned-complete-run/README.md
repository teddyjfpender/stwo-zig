# Own full-width Ethereum public I/O from a complete runner result

Status: Ethereum canonical CPU integration passed; base complete-run ownership proof is implemented and queued.

The Ethereum full-width witness now exposes initRun, which derives the public
statement and owns packed input words and output words from the runner result.
This removes manual public-data construction and borrowed-I/O lifetime management
from that entry point. Complete runs and leaf-local segments share one I/O packer;
segment clock/boundary admission and all existing witness cross-checks remain.

The existing Ethereum fixture uses initRun for its valid owner and retains the
caller-data API for malformed-I/O rejection checks. Its canonical CPU gate is
queued with a cached leaf, which is independently admitted and fully verified.
The gate also qualifies the compact parent fixed-row representation. No product
CLI default/routing switch or production-wide migration is claimed.

```sh
STWO_B3EH_LEAF_ARTIFACT=/tmp/stwo-b3eh-canonical-leaf.artifact python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments '-Driscv-test-filter=BLAKE3 execution commitment Ethereum canonical recursive parent independently verifies' -Doptimize=ReleaseSafe --summary all
```

## Canonical CPU result

Canonical 70-query/26-PoW Ethereum leaf-to-parent qualification passed with the
owned complete-run constructor and compact fixed rows. Prepared retention fell
from 10,150,562,296 to 5,953,718,776 bytes (4,196,843,520 bytes / 41.35% less).
This storage is outside the worker budget. Tracked worker peak remains
32,530,488,858 bytes against the unchanged 38,654,705,664-byte cap. Parent artifact
size remains 907,988 bytes and verifies independently after worker/row destruction.

The 5,587,689-byte cached leaf was independently admitted and verified. The gate
also passes public-I/O, artifact and capture mutation rejection. Build/run wrapper:
9 minutes, 39 GiB MaxRSS versus prior 43 GiB. These include compilation and cached
leaf verification, so they are not end-to-end latency benchmarks. Canonical
aggregation and the compact-layout Metal/SMP gate remain queued/active separately.

## Base complete-run integration

Base execution now exposes the same owned complete-run construction as Ethereum.
Complete runs and segments share one internal witness assembly path. The existing
base real-proof fixture uses this owner, destroys the runner result before proving,
and retains its independent verification, mutation rejection and artifact checks.
This removes the fixture's manual public-data packing and duplicated memory/plan/
hash/native preparation. The test is queued; it is not yet a passing result.

```sh
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments '-Driscv-test-filter=BLAKE3 execution commitment real runner proves' -Doptimize=ReleaseSafe --summary all
```
