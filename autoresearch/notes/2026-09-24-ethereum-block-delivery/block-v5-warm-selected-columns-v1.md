# Selected columns for warm caller projections

`block_v5_committed_projection_columns_v1` validates every retained fixed/main
column against the independently admitted trace geometry plus the configured
blowup. It then recovers each selected span once with the existing canonical
circle FFT helper. Unselected columns carry geometry only. Overlapping slot
spans share the same recovered trace buffer.

Lookup first-round borrowing no longer regenerates the arithmetic main
matrix just to check its geometry. Lookup and state proof APIs expose
`proveFromCommitted`; their previous `prove` signatures remain compatible
wrappers. The warm stage calls these APIs with the independently replayed
record statement and step count. Family12 uses the same selected-column
helper. Canonical admission/key/instance/root/configuration checks remain,
and the original family11 scheme owns its source trees throughout all hooks.

The family11 physical commit still generates its arithmetic main matrix once.
Lookup, state and program warm hooks contain no `Profile.mainWitness` call and
construct no first-round LDE or Merkle tree. Recovery does perform bounded
interpolation/evaluation for selected columns; no setup-time or peak-memory
gain is claimed without measurement.

The existing two caller replay fixtures now exercise all three warm callbacks
and freshly verify arithmetic, table, state and program proofs. They retain
the signed six-table counter oracles and claim/root/key negatives, and add a
wrong-retained-geometry negative before projection generation. The focused
ReleaseFast/native q8/PoW0 gate passed all 13 tests with clean
`std.testing.allocator` teardown. Both SHA2/Keccak1 and signer1/Keccak1 cases
fresh-verified all three projections and arithmetic after the bounded replay,
using exactly two witness loads per case. The authentic SHA, Keccak and signer
memory tuple regressions also passed.

Exact command and output are recorded in `block-v5-warm-selected-columns-q8.json`.
This qualifies the changed warm projection internals. The earlier complete
caller global kernel gate used the previous internals; this run is not a
whole-kernel rerun, canonical q70 proof, detached transport, or mainnet block.
