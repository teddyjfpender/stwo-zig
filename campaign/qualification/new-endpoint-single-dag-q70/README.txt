Canonical experimental closed-window recursive root

Scope: declared nonterminal window, 8 RV32IM instructions, two 4-cycle cohorts.
One STARK proves two Local11 original verifiers, one late endpoint-root bridge,
and one Compact7 global RAM verifier. All source physical claims and exact
transcripts/PCS checks are included. CPU PC/register adjacency and incoming /
outgoing boundaries, exact endpoint root rebinding and the global transition
sum close in the same arithmetic DAG. The compact global verifier separately
closes initial, final and range/count claims. Snapshot delta public ports: 0.
This is not a terminal whole-Ethereum-block result. Production defaults remain off.

root.proof: 987593 bytes
SHA256: 8865bd8fc37c492862ca52ec473514738140075a076da78871720c9d93a6b50e
Security: 70 FRI queries, 26 PoW bits.

The source production run generated this proof and passed a newly rebuilt
receiver after destroying all producer profiles and decoded local originals.
The surrounding original fixture's later directory-only verification failed
InvalidProofShape (also in its two standalone tests). That unrelated transport
failure is preserved in production-qualification.log, not hidden as an exit-zero.

A SEPARATE byte-only root receiver then passed ALL 6 tests, exit zero, using only
root.proof, physical-claims.bin, local metadata JSON, independently pinned guest
ELF and complete snapshots, and global first-root/selection nominations. It
loads NO original proof, producer key or host closure receipt. It independently
reconstructs all source scopes/epochs/fixed keys and the joined root key, with
an added same-ELF/program guard. Eight CPU workers: 10.2347025 seconds receiving.
See byte-receiver-qualification.log and qualification.json.

Pure closure tests reject changed global transition, endpoint root-word and CPU
register-byte operands. These pass in production-qualification.log.

source-exact.tar and source-exact-manifest.json freeze the production import
closure (2266 files). receiver-source-exact.tar/manifest freeze the strict
receiver closure (2232 files). source-after-delta.json records the one existing
source change: the stricter joined-program admission. The algebraic key and
proof bytes were unchanged; the strict receiver verifies the saved proof.

Reproduce the byte-only gate from repository root:
python3 scripts/zig_protocol_test.py --lock /tmp/stwo-zig-build.lock \
  src/frontends/riscv/block_v8_endpoint_join_saved_receiver_test_root.zig \
  -O ReleaseFast --test-filter 'canonical saved endpoint root'

Production proof timing was serial and not isolated; it is qualification only.

RESOLVED: The bridge directory depth bug was fixed by its owner. The sibling
new-endpoint-single-dag-q70-parallel4 artifact then passed the COMPLETE focused
production + strict directory + closure mutation gate, ALL 10 exit zero, with
exactly the same root bytes. See that artifact for final qualification.
