# M7 leaf seed tapes

Status: the opt-in v1 emitter is qualified for byte identity. It remains off
by default because the first cache implementation regresses request time.

`STWO_RV64_LEAF_SEED_TAPE=check` records leaf seeds directly from the
independently verified native proof capture and public inputs, builds the full
trace-only graph, and compares every seed coordinate against its origin metadata.
`=1` enables graph-free preparation after an in-process class template and PP
have been constructed from the full graph. The default remains off until the
two-block production byte-identity and fresh-receiver gates pass.

The CPU emitter follows `proof.guess`, `Cpu.Statement.init`, and the local GKR
`wireProof` order. Every other guessed value in the verifier body is a derived
witness hint. Truth/Keccak emitters follow their respective statement prologues.
The shared proof emitter is the M6 fold emitter, including Merkle cap order.

Class keys bind the source FIXED root, any canonical binding identity, full PCS
geometry and mask offsets, exact local GKR roster and proof structure, outer
profile and padding shape. Scalars represented as public guessed wires remain
per-request seed data. Receiver code never trusts a class key or reads a tape.
The existing plan template checks seed count, constants, capabilities and plan
identity. A bounded-template cache miss rebuilds the ordinary graph. Durable
proof restoration and non-pipelined paths retain full graph construction.

This step removes warm per-leaf graph and host plan construction. It does not
yet replace the device's approximately 146k dependency levels with parallel
Blake compression fills, preinstall cold leaf/fold classes, or claim to meet the
M7 RSS limit. Native verification/capture and fresh outer verification remain
mandatory on the producer, and the independent receiver is unchanged.

## Retained negative measurements

All numbers below are loaded-pod observations [M], not quiet-run gains.
The same-session M6 warm control was 13.44/13.52 s on 26235156 and
18.82/18.93 s on 24628607. V1 tape-on measured 13.35/13.37 s and
24.06/23.07 s, respectively. V2 compressed leaf host templates with a
portable varint codec and restored request-leased leaf device placement:
13.27/12.76 s and 22.98/21.64 s. Neither variant is promoted.

V1 and V2 each passed every complete proof-artifact comparison over six
requests and fresh cache-disabled M6 receivers on both blocks. Each check
mode compared all seed coordinates on 56 leaf builds. V2 additionally
compared decoded template tasks and PP columns against fresh full graphs.
Exact WIP source patches and their SHA-256 lists are retained beside the
receipts under `vectors/reports/rv64-m7-20261105/leaf-tape/`; source labels
must not be confused with a later integrated binary.

The cache limits exposed two real problems: partial PP/plan cache pairs
caused redundant fallback work, and using the fold's immutable device
placement for leaf task plans caused churn. V2 fixes those but still has
raw fold entries consuming the shared caps and slow varint decoding.
The next candidate uses independently decoded LZ4 blocks on the existing
bounded proof pool and can compress fold entries too. That candidate has
codec round-trip/corruption tests; it has no production performance claim yet.
