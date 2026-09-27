# Bound canonical BLAKE3 parent commitment residency

Status: Metal v3 failed during core proof cleanup with a combined-buffer ownership error; canonical CPU retry passed.

The checked-allocator baseline passed leaf CPU verification, parent preparation,
key admission and interaction generation, but exceeded the 36 GiB worker cap at
interaction commitment. It retained 10,150,562,296 prepared bytes outside the
worker. Tracked worker peak before refusal was 36,176,603,674 bytes.

Parent plans and proofs now select the core PCS `.never` coefficient-retention
policy: committed extended-domain columns supply openings without a second
persistent coefficient copy. Interaction commitment uses existing owned streaming
PCS with eight columns per preparation batch, including Metal (which otherwise
prefers monolithic commitment). Original column indices, roots, transcript and
70-query/26-PoW parameters must remain unchanged. The worker cap stays 36 GiB.

The gate includes the allocator-authority fix; it uses the checked allocator.
A successful stateless-allocator parent run remains separate work. CPU verification
and real Metal dispatches during parent proving are required by the fixture.
No lower peak, speedup or completed proof is claimed until the run completes.

## Qualification commands

Metal (failed):

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal test-blake3-ethereum-parent-aot -Dmetal-core-aot-bundle=/tmp/stwo-blake3-core-aot-20260922 -Doptimize=ReleaseSafe --summary all
```

CPU (passed):

```sh
STWO_B3EH_LEAF_ARTIFACT=/tmp/stwo-b3eh-canonical-leaf.artifact python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments '-Driscv-test-filter=BLAKE3 execution commitment Ethereum canonical recursive parent independently verifies' -Doptimize=ReleaseSafe --summary all
```

The CPU cache only skips leaf generation. The fixture reconstructs admission,
bounded-decodes the artifact, and independently verifies it before lowering the
parent. Neither cached bytes nor their embedded metadata define the trusted key.

See [streaming backing ownership](../2026-09-23-blake3-streaming-backing-ownership/README.md) for the failure and pending fix.

## CPU qualification result

Canonical Ethereum leaf and recursive parent independently verified at 70 queries
and 26 PoW bits. Parent artifact: 907,988 bytes. Prepared rows retained
10,150,562,296 bytes outside the worker. Worker peak: 32,530,488,858 bytes against
unchanged 38,654,705,664-byte limit. The worker and rows were released before
parent artifact round-trip verification. The cached 5,587,689-byte leaf was fully
verified against independently reconstructed admission; it was not regenerated.

Build/run wrapper reported 9 minutes and 43 GiB MaxRSS (includes compilation).
This is qualification evidence, not an end-to-end proving latency sample.
The build includes direct chunk projection and base admission changes, but predates
the Metal combined-buffer detachment fix; CPU ordinary column ownership does not
exercise that fix. Metal canonical recursion remains unqualified.
