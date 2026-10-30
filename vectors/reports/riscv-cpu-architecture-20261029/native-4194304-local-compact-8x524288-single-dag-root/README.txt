FAILED attempted saved4M compact eight-local bundle -> one recursive root.
No root.proof was produced. This directory is not a qualified root result.

The frozen CPU runner verifies/captures existing originals exactly once and
never executes the guest or reproves a source original. All8 local originals
were captured (7.921s) and independently profiled (5.765s). A conditional bridge
and compact global original were also captured. Source-cell census and physical
claim bytes are retained, but do not confer root proof authority.

The one-DAG parent exhausted allocation under a48GiB shared budget after
fixed compilation53.168s, fixed commitment36.373s, witness115.849s and plan12.196s.
Retained parent rows:26,422,967,500bytes (M31 native columns+compact M31 fixed rows,
not full QM31 rows). OS RSS max39.036GB, memory footprint peak48.103GB. Charged
peak was not emitted on the failure path, so the configured budget is not a
measured charged-peak value. See failure.json/runtime.log.

Timing is NOT isolated: parent observed an unrelated Python process occupying
one CPU for~30seconds during witness. It was not launched by this runner/agent.
Resource failure remains real. No increased-budget rerun is authorized/planned.

Frozen binary path and SHA, full source import archive, input proof/metadata
hashes: build.json, source-exact-manifest.json, source-exact.tar. Source-after
comparison will be added after the primary isolated timing hold releases.

Next work: exact per-AIR/source memory and padding census; drop duplicated cold
fixed-key/namespace state after parity/commitment; stream source column emission;
conditional local-group roots followed by one global bridge/provider root.
Current flatSource roster limit62 does not cover266cohorts; it must not be
presented as a complete full-block recursive architecture.
