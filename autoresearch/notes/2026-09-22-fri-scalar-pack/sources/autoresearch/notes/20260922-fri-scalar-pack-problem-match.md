# FRI scalar arithmetic wires to QM31 hash payloads

Task: connect four canonical FRI arithmetic input wires to one QM31 field encoder
input without host-only tuple assembly. The arithmetic DAG represents each
coordinate as a scalar QM31 wire; the encoder consumes a packed QM31 wire.
Canonical match: exact wiring/tuple repacking with lookup conservation, no field
arithmetic or new hash primitive. One typed row consumes four scalar wires and
emits their four-coordinate tuple. Fixed source node IDs come from authenticated
canonical FRI graph bindings. Costs: four main fields, eight fixed fields, five
relation events, no polynomial arithmetic constraints.
Use existing recursion_wire schema and typed relation machinery. Reject aliasing
source/destination circuits and noncanonical coordinates. Graph producer counts
must include the extra scalar reads when used with full arithmetic lowering.
Validation: pin semantic digest; complete hash-group proof with scalar source
boundaries at real graph node IDs and repacking rows; fixed columns independent
of values, plus changed last-leaf source rejection. This proves repacking in the
hash path; it does not yet prove the arithmetic graph in that outer proof.
Existing native graph evaluation remains the arithmetic oracle. No production
profile, protocol or key changes. Next integration adds graph operation rows and
replaces public scalar boundaries with admitted private producers.
