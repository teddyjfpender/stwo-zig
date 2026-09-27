# BLAKE3 authenticated byte routing

Task: assemble canonical protocol frame words when digest bytes straddle word
boundaries. Canonical match: fixed affine byte selection plus signed copy
constraints, not a new hash algorithm. Each destination word selects four bytes
from at most two authenticated source words or verifier-owned constants.

Use a one-hot fixed selection matrix (4 outputs x 8 source bytes) and four fixed
constant bytes. Four degree-two roots equate output bytes to this affine map.
Two source consumes and one destination emission use existing recursion_wire.
The verifier derives all selectors/endpoints/multiplicities; witness selectors
are never authority. No new relation registry or handwritten evaluator.

Alternative bit-selector mux saves fixed columns but raises degree; byte-wise
partial tuple emissions would complicate closure. Fixed columns are small next
to the compression/provider traces, making linear selection the simple baseline.
Producer output use counts must equal routing consumers (often two per word),
not remain hard-coded to a single final-digest boundary.

Canonical frame writer will expose digest-role callbacks to symbolic sinks while
native sinks preserve identical bytes. This avoids a second transcription of
prefix lengths/order. Test source/output/selector mutations, native frame parity,
compiler export, and a full composed Merkle-node proof with authenticated child
hash outputs. Production path selection/keys/Metal remain later obligations.
