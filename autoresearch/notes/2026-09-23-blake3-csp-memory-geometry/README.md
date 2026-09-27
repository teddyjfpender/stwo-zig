# Full-width ECDSA: bounded memory and path geometry

Canonical input, pinned odd-parity precompile ELF, CPU ReleaseSafe, 16 workers,
70 queries / 26 PoW bits, one sample and no warmup. This is a failed qualification,
not a benchmark result. No artifact/report was published.

The new optional `ecdsa-csp-bench --host-byte-budget BYTES` bounds allocations
inside the full-width product transaction, including its pool and fresh CPU
verification. It is not a limit on device allocations, outer CLI input reads,
thread stacks or process RSS. Budget ownership outlives all allocator clients;
the returned report is copied to the caller before the budget is destroyed.
A one-byte limit rejected before work. The 36 GiB run failed cleanly with
HostMemoryBudgetExceeded at peak 38,645,770,980 bytes, without an allocator-lifetime
panic or output publication.

## Observed shape

- Guest steps: 1,828.
- Memory boundary words: 303; program words: 404.
- Four independent 30-level paths per word, with 61 compression blocks per path.
- Total: 172,508 BLAKE3 compression blocks and 9,660,448 G rows.
- G domain pads to 2^24 rows.
- Witness live allocations: 10,971,429,417 bytes.
- Independent admission peak: 19,771,255,944 bytes.
- Proving exceeded the 36 GiB limit even after duplicate coefficient retention
  was removed and preparation was batched.

## Implemented follow-up

Counting every trusted path was redundant. Census now validates the entire
admission, constructs one representative memory word and one program word, and
uses checked multiplication to derive exact component counts. The existing
mixed-word witness gate confirms counts against full trusted and actual emission
and rejects a changed admission identity.

A deterministic sparse path topology now merges common ancestors, preserves
separate roots, and enumerates uncomputed sibling subtrees as frontier inputs.
Four adjacent leaves need 66 compressions rather than 244. Coordinate/ordering
and allocation-failure tests pass. A diagnostic geometry helper derives candidate
counts from admitted program, initial-memory and final-memory schedules.

This topology is NOT yet the production hash witness or AIR. The next engineering
step is shared hash/route emission with authenticated leaf callers, exact fanout,
frontier digest constraints, and root binding, then independent key derivation
and real canonical proof qualification. Do not claim a 3.7x or 10x E2E speedup
from the compression-count comparison.

Final CPU/Metal builds including budget diagnostics, census and candidate topology
are in progress at this checkpoint. Existing defaults and legacy route removal
remain unfinished; expanded Ethereum block work remains deferred.

Final qualification: both CPU and Metal builds passed (4/4 steps). The canonical CPU base proof after the census shortcut is byte-identical to the preceding retained artifact, and separate verification passed. The candidate shared topology remains unintegrated into AIR emission.
