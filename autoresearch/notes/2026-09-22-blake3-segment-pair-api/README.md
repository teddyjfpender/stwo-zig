# Shared BLAKE3 execution-segment pairing

The public segment-to-parent API now owns adjacent leaf pairing. Callers supply
two independent pinned execution verifiers, owners, expected key identities and
Span statements. It rejects owner aliasing and nonadjacent Spans, then validates
both full execution statements and both ordinary/full-memory custody conversions
before consuming either interaction phase. It reuses those admitted conversions
during proving and transfers both prepared child witnesses into the existing
namespace-safe aggregate. Failed proving may consume owners; admission failures
leave both owners usable. No authority is inferred from returned artifacts.

The four-leaf qualification now uses this public pairing API for both distinct
intermediate aggregates. It checks rejection of an invalid second-child key
without consuming either owner, alias rejection, then proves and independently
verifies the intermediate nodes and their two-level binary root through the
existing bounded persistent-worker pipeline.

Command:

```sh
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-aggregation -Driscv-test-filter='four-leaf tree' -Doptimize=ReleaseSafe --summary all
```

This is a diagnostic q8/PoW0 CPU orchestration qualification. Production routing,
extension support, canonical multi-segment CPU/Metal qualification and defaults
remain open. It does not demonstrate a latency improvement.

## Next integration boundary inspected

`blake3_execution_trace.Owner.init` rejects nonzero recorded external steps and
requires native row count to equal the public clock.
`Blake3ExecutionStatement.validateBlake3Execution` independently enforces that
native opcode rows sum to the complete step count. Component assembly and
recursive capture currently authenticate this base-only statement. Extension
support must add authenticated external execution accounting and its existing
precompile AIR providers across these layers together; simply relaxing either
check would leave execution steps unproved. The CSP ECDSA entrypoint still calls
`guest_precompile/ethereum_orchestration.zig` and the legacy public-memory
contract, even when its outer PCS/transcript suite selects BLAKE3.

## Result

The focused gate completed successfully in 5 minutes / 9 GiB peak RSS. Four
actual segments verify through two aggregate levels. The bounded root pipeline
verified both outputs after worker destruction, preserved persistent-plan reuse,
and recorded 11,162,379,333 ns preparation/proving overlap. Routed worker peak
was 4,944,533,268 bytes under the unchanged 8 GiB worker limit. Root artifact
size remains 131,497 bytes. This single run is not a latency comparison.
