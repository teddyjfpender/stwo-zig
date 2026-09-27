# Completed staged BLAKE3 tree adoption

2026-09-22. Extended the existing completed-arena ownership handoff to admit the
explicit staged BLAKE3 encoding with BLAKE3 family and two retained state offsets.
It retains the same exact runtime/arena/plan/completed-command provenance checks,
full tree geometry and one-time consumption of the completion record. No tree
hashing, shader, default suite or alternate ownership path was introduced.

ReleaseSafe test-blake3-staged-tree passes 16/16 tests, 3/3 steps. Each of eight
complete CPU-parity trees now also checks:
- adoption before encoding rejects;
- adoption after encoding but before submit rejects;
- an independently prepared, geometrically identical plan rejects;
- a different arena rejects;
- the matching completed plan/arena adopts and its tree root equals CPU;
- a second adoption from the same completed epoch rejects.

The successful adoption after mismatched attempts verifies those attempts do
not consume matching provenance. All earlier assertions still pass: reused plans,
all leaf/parent digests and arena guards, one command buffer, one wait and zero
intermediate waits. The test releases each adopted tree before reusing its arena.
It does not independently exercise source-owner destruction before tree access.

Command:
```sh
python3 scripts/zig_serial_build.py --cwd src/backends/metal test-blake3-staged-tree -Doptimize=ReleaseSafe --summary all
```

Next production integration is specifically runtime/heterogeneous_commit.zig:
its initial hash-domain admission still rejects BLAKE3, staging choice is
Poseidon-only, scratch allocation assumes 16 words/row and prepare dispatch only
selects staged Poseidon or the existing direct families. Replace those selected
path assumptions with exact BLAKE3 admission and width-sized scratch planning;
do not globally admit unfinished transcript/decommit paths. Full Metal proof
qualification, prover-owned Poseidon identities and recursion remain incomplete.
No new end-to-end performance claim is made by this ownership gate.
