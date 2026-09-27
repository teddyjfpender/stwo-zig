# Two-level shared Merkle frontier primitive — 2026-09-24

## Implemented and qualified scope

A new typed witness primitive computes three shared node hashes: two child hashes
and their root. It uses existing G, XOR, boundary, byte-route, private-word and
path-select AIRs. No new roster component or semantic digest is introduced.

Each branch has a private Boolean activity flag. An active branch adopts its computed
hash; an inactive branch adopts an opaque digest. Every query proves that its selected
branch is active, then proves equality of all 16 ordered input words to that branch's
shared preimage. Consequently, an unqueried branch needs no known preimage, while a
queried branch cannot bypass hashing. The shared root remains tied to the canonical
root source. All IDs, use counts and fixed columns depend on public shape/query ordinal,
not private query positions or activity.

The primitive is **not yet connected to native STARK path preparation**. Production
recursion still uses the previously qualified root-only sharing path. No new full-tree
speed or memory improvement is claimed here.

## Verification

The final focused ReleaseSafe target passes **15/15 checks**, including a real standalone
STARK proof over all six component types and their lookup tables. This standalone
fixture uses the proof helper's diagnostic q8/PoW0 settings; it is not a q70/PoW26
native recursion-tree qualification.

Tests cover both queried branches, only the left branch, only the right branch, a
queried inactive branch, and both flags inactive. Invalid activity cases keep matching
hash preimages so membership alone must reject them. Valid cases deliberately poison
unused hash preimages and opaque alternatives, demonstrating the intended selection.
Every fixed column is identical across these private choices. The real proof derives
trusted columns from different private choices and rejects a changed preprocessing
root. Existing root-sharing tests continue to cover exact lookup closure and input,
root-word and query-bit mutations.

The first run rejected a zero-use path-select output at its constructor. The AIR
already permits a zero output weight; the constructor now accepts one unused output,
while continuing to reject both outputs unused. This broadens constructor admission
without changing the typed constraints, digest or behavior of existing two-output
callers. The failed run and subsequent passing runs are archived.

## Measured geometry, projected benefit

The frozen root-sharing executable was profiled with canonical q70/PoW26 parameters.
`profile.log` contains its successful seven-test tree run and six actual hash inventories.
`project.py` derives `geometry.json` from those receipts. For each tree of depth at least
two, replacing the existing `1 + queries` top hashes with three hashes removes
`(queries - 2) * 112` G rows. Deeper paths and one-level trees are unchanged.

| Aggregate | Current G rows | Projected G rows | Current padded rows | Projected padded rows |
|---|---:|---:|---:|---:|
| Left pair | 4,461,408 | 4,141,536 | 8,388,608 | 4,194,304 |
| Right pair | 4,487,000 | 4,167,128 | 8,388,608 | 4,194,304 |
| Root | 6,853,504 | 6,457,472 | 8,388,608 | 8,388,608 |

These are G-only projections using the current child artifacts. Routing overhead,
changed parent artifacts, next-level geometry, and total proving time still require
native integration and measurement. A smaller G domain does not establish a halved
end-to-end time. The full 30–38% sharing opportunity is not implemented by this primitive.

## Lookup contract

The shared preimage producers supply `queries + hash_input_uses` copies per word.
Each query consumes both candidate preimages through path-select, and consumes its
chosen output plus its external lower-path word through an equality route. One
additional selection/equality enforces that the chosen activity flag equals the fixed
constant one. Each activity flag supplies `queries + 8` uses: query membership plus
eight adopted digest words. The query high bit therefore needs **17 uses**; each external
ordered input word needs **one use**. Root output and canonical root each need `queries`
uses per word. Unused mux outputs have fixed zero multiplicity, never witness-controlled
weights.

`integration.md` records the remaining native wiring and acceptance requirements.
The broader persistent scheduling, CSP recovery, fusion/direct-emission and reviewed
parameter experiment requirements remain open.

## Reproduction

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-recursive-fused-pcs-opening -Doptimize=ReleaseSafe --summary all
python3 autoresearch/notes/2026-09-24-two-level-frontier/project.py
```

The profile used the frozen executable in `../2026-09-24-shared-root-hashes` and the
archived authenticated bundle in `../2026-09-24-canonical-parent-pipeline/core`, with
SMP allocation, eight workers, `STWO_RISCV_PATH_SHARING_CENSUS=1` and
`STWO_RISCV_RECURSIVE_PARENT_PROFILE=1`. Changed-source snapshots are not a complete
clean-checkout reproduction of this dirty workspace.
