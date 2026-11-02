# Independent Sail corpus on the current OM31/GKR coordinator

The pinned continuous Sail workload now proves and passes a separate-process
fresh receiver on the current OM31/services coordinator, under both the
q70/P26/fold4 control and beta2/q256/P0/fold4 engineering candidate. This closes
the current-lane functional Sail-corpus gap. It does not certify128-bit security,
independent Rust verification or the CSP suite.

## Reference and execution authority

The existing `word16_qualification/sail_image.zig` pins the expected ELF and
oracle, including Sail revision `8c7f2da58de0ba5e4457e4de07e0046f0439f35f`.
The existing `sail_capture.zig` streams and hashes the exact consumed RVFI bytes,
compares every retirement against the independent trace, and checks final PC,
all32 registers and the two data words. The workload contains1,032,240
retirements and12,903 target cases, covering all63 ordinary RV64IM opcodes.
The ELF SHA256 is
`ffd638bf944f6b43d8e96d8a2d495939abb9b17a6474f67afe912d27dd089229`.

The opt-in `rv64-om-sail-qualification` tool adds a small adapter to the existing
collector/coordinator and durable bundle transport. After independent capture,
it requires all63 ordinary opcodes and zero ECALL/EBREAK/service records. It
then explicitly selects the existing services tape/ROM profile for those same
ordinary semantics. No production profile or collector guard is changed.
The statements and keys bind that selected profile; this is not a claim that
old and new proof bytes or protocol identities match.

The fresh verifier starts from the pinned expected image, reconstructs program
and setup, validates declared geometry before setup construction, checks the
oracle's CPU/RAM endpoint, and verifies every physical proof and global closure.
For beta2 it independently constructs a new fixed-authority cache/lease. It has
no tape or captured witness input. Both modes reject a changed expected final
register, and each rejects the other mode's bundle with
`GlobalGkrManifestExecution`.

## Measurements

ReleaseFast, M5 Max, eight workers, one CPU proof and no service truths. These
are single functional observations on the shared host, not a controlled speed
comparison. Earlier QM31 receipts use a different field/protocol.

| Cost | OM control q70/P26/f4 | OM candidate beta2/q256/P0/f4 |
|---|---:|---:|
| Independent capture |0.368s|0.347s|
| Preparation and immutable setup |0.638s|1.059s|
| Complete proving |2.820s|3.811s|
| GKR within proving |0.967s|0.950s|
| Native completion within proving |1.595s|2.397s|
| Whole producer process |4.45s|5.28s|
| Fresh load/setup/verification and endpoint mutation |0.366s|0.775s|
| Physical proof bytes |569,304|1,903,064|
| Producer maximum RSS |5.796GB|6.280GB|

The tool uses the qualified large-block recycler with a4GiB cache, a48GiB
requested-allocation owner, GKR16GiB/global4GiB/retained8GiB limits and an
optional2GiB beta2 immutable cache. The separate recycler cache is not counted
as live requested bytes after frees. Allocator counters are not RSS. No MAIN
parking is needed for this one-worker workload. Runtime receipts retain the
actual requested peaks, recycler statistics and per-worker phase breakdown.

## Reproduction

```sh
zig build rv64-om-sail-qualification -Doptimize=ReleaseFast -j2
lockf /private/tmp/stwo-rv64-perf-heavy.lock \
  zig-out/bin/rv64-om-sail-qualification prove-control CONFIG NEW_DIRECTORY
lockf /private/tmp/stwo-rv64-perf-heavy.lock \
  zig-out/bin/rv64-om-sail-qualification verify-control CONFIG NEW_DIRECTORY
```

Use `prove-candidate`/`verify-candidate` for the existing engineering candidate.
The actual pinned config was
`/private/tmp/stwo-rv64-delivery/word16-independent-qualification-v1/sail/config.json`.
Generate portable equivalents with the existing pinned Sail workload tooling;
all referenced files remain hash checked. Proof binaries and the90MB RVFI
corpus remain outside Git. Checked-in receipts retain their hashes, commands,
source/tool identity, timings and fresh acceptance.

Next independent workload gate: a representative CSP request with current OM
acceptance, then the complete suite. Its expected output and endpoint scope must
come from the independent reference contract, not be silently taken from the
producer's observed endpoint. The old five-instruction Rust adapter remains
outside the current OM31/GKR qualification scope.
