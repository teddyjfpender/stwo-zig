# Ordered BLAKE3 draw attempts

Task: authenticate an exact contiguous prefix of native channel attempts starting
at a given u64 counter. Every attempt before the last must reject; the final
attempt must accept and supply the scalar outputs. Never let an untrusted host
choose a later favorable draw without proving all intervening rejections.

Exact canonical match (derived): bounded execution of a deterministic rejection
sampling loop. Fixed preprocessing enumerates counters start+i, binds each hash
frame to the same state and canonical domain, and fixes status expectations to
0,...,0,1. The existing challenge AIR computes actual statuses. Hash outputs are
private wires, consumed by challenge rows. Only the last row emits scalar values.
Native semantics: src/core/channel/blake3.zig drawBaseFelts/drawU32s.

Alternative: a dynamic transition AIR for an entire private transcript. Necessary
later for private state transitions, but it must enforce the same prefix property.
The fixed-prefix construction is exact for a public state/start/count statement;
it does not replace full transcript admission. No arbitrary retry cap or security
parameter change is introduced. Checked counters forbid wrapping, including the
native post-draw increment. Work and memory O(attempts * hash-frame circuit size).

Selected transfer: reusable witness and sibling trusted-preprocessing builders,
sharing schedules but with trusted construction never hashing the input. Typed
components and existing tables remain sole constraint evaluators. No external
implementation copied. Performance prediction: no production claim; this closes
an admission gap. Falsifier: accepting two consecutive attempts when the first
is already accepted, accepting a skipped counter, or accepting altered outputs.

Tests: native accepted draw parity, exact fixed-column reconstruction, forced
extra attempt rejection via constraint evaluation, counter overflow and zero
attempt rejection, complete CPU STARK through the existing focused proof gate.
Rare rejected BLAKE3 digests are covered at the challenge component's exact word
boundary tests; do not fabricate an end-to-end rejected hash preimage.
