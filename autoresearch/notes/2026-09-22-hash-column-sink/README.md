# Canonical hash evaluation directly into committed columns

Refactored the canonical hash evaluator over comptime row and column sinks. Owning
prepare, borrowed prepareInto and new prepareColumns use the same graph evaluation
and typed G/XOR constructors. Boundary construction shares one emitter with trusted
preprocessing. The column sink writes each completed logical row immediately at
framework.committedRow(first + index, log_size), avoiding full intermediate hash
row arrays. It writes all logical coordinates; main/fixed arrays can be selected
by the receiving adapter. Graph/wire scratch remains local.

Column destination validates every domain size, column length and logical range
before evaluation writes. It preserves surrounding caller-owned ranges and padding.
The caller must supply nonoverlapping storage and discard partial output on later
errors. This is witness generation, not proof admission or independent key authority.

## Qualification

ReleaseSafe test-blake3-hash plus test-blake3-frame-witness passed 5/5 tests.
A stronger sentinel rejection check then reran only test-blake3-hash: 4/4 passed,
629 ms / 17 MiB. Live committed columns match the owned-row reference at every
coordinate for empty, multi-block and multi-chunk inputs, using nonzero logical
offsets. Padding/adjacent cells retain sentinels. Malformed later-cohort lengths and
out-of-range offsets reject before any earlier-cohort sentinel is overwritten.
Existing standard digest vectors through unbalanced 8,193-byte trees, fixed parity,
lookup-closure mutations and routed-frame ownership checks remain passing.

No native producer switches to the column sink yet, and no full parent proof or
speedup is claimed for this API. Next integrate adapter destinations and provide
interaction generation with an equivalent view over committed columns, preserving
virtual padding and source inventory. The old row sink remains the differential
oracle while that integration proceeds. Production keys/security profiles, Metal,
multi-level recursion and parameter experiments remain unfinished.
