# Transfer BLAKE3 parent preprocessing directly into PCS

Status: table projection allocation-failure gate passed (3 seconds). The Metal
canonical leaf/parent gate is now compiling. Full ownership-path qualification
is pending. This change was not in the failed tiled-interaction CPU binary.

Parent key derivation and persistent worker plan initialization previously kept
projected preprocessed columns in an arena while PCS cloned them. Both now
allocate columns through the supplied allocator and transfer the column vector
with `commitOwned`. The list is cleared on transfer; PCS consumes it on both
success and error, and local defers clean up any pre-transfer partial projection.

The table projection helper now frees the most recently allocated column if
appending its descriptor fails. Existing arena callers remain valid. A focused
allocation-failure test covers the table helper under a freeing allocator.

This reduces redundant setup storage by ownership transfer. It does not change
admission, fixed-column values, protocol parameters, or key derivation inputs.
No peak-memory or runtime improvement is claimed until measured.

```sh
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-memory-update '-Driscv-test-filter=BLAKE3 memory update proves table projection' -Doptimize=ReleaseSafe --summary all
```

The next canonical/Metal parent qualification must cover the ownership change.

Subsequent parent gates report the last entered phase and worker peak/limit on
failure. Workspace cleanup preserves the phase for diagnostics. This does not
change allocation caps or proof semantics.

The Metal canonical leaf/parent binary compiled and started running. Its parent
telemetry window includes worker initialization. A follow-on gate edit narrows
the parent telemetry assertion to `worker.prove` itself, excluding fixed-column
setup, and prints errors for the whole fixture (including admission/runtime
failures). That edit is not in the currently running binary and still requires
compilation/runtime validation; any result from the current run retains the
broader telemetry qualification scope.

The next-build parent path also uses the existing
`proveExWithExecutionDiagnosed` core entry point with the same default options
as `prove`, releasing its auxiliary output exactly as the original wrapper did.
Workspace failure state retains the core phase/composition subphase and original
cause. Fixture diagnostics print these alongside the worker phase and peak.
This follow-on edit is pending compilation and is not in the live Metal binary.

## First Metal runtime result

The combined gate compiled (4 minutes / 8 GiB compiler RSS), then failed with
signal 6. Before the crash, it completed independent CPU verification of the
full-width Ethereum leaf at q70/PoW26, with equal independently derived CPU/Metal
preprocessing, a 5,587,689-byte artifact, 162 Metal dispatches and 3 CPU fallbacks.
The process crashed in prepared-row destruction during the parent portion. No
parent artifact or successful combined qualification exists. The printed test
count is not a passing gate: the build explicitly reports signal-6 failure.

The next run uses the checked test allocator and preparation/key/worker stage
markers, plus the previously prepared whole-fixture/core error diagnostics and
narrower parent dispatch window. These are diagnostic changes, not a confirmed
fix for the crash. It also contains the leaf tiled-interaction implementation,
whose all-component parity gate passed separately.
