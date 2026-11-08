# RV64 consolidation archive index

The canonical checkout is `/Users/theodorepender/Coding/stwo-zig`, branch
`codex/rv64-gpu-hygiene`. All 162 retired working copies were preserved before
removal. Archived code remains historical and unqualified.

## Published history and remote retirement

Origin contains 242 distinct annotated `archive/*` tags: the original 233,
seven additional exact remote-head archives, the recovery-index tag and the
pre-retirement receipt snapshot below.
Both tag objects and peeled commit targets were verified against origin.
Annotated tags produce two `ls-remote --tags` records each; count tag refs
without the `^{}` records when checking the distinct-tag total.

- Inventory: `archive/consolidation-20261108/inventory`, commit
  `f062114ac634eb0f4a93c1a4f69c4366873c0203`.
- Recovery index: `archive/consolidation-20261108/recovery-index-v1`, commit
  `a2d4ae6e0a831dcd50e0a9b789b428cd2b00bccb`.
- Pre-cleanup integrated source:
  `archive/consolidation-20261108/worktrees/rv64-m8-gn-bind`.

The recovery-index commit contains `remote-branches.literal.txt` and
`remote-branch-retirement-list.json`: 72 literal names, exact head commits
and archive mappings. Every head matched a published archive before deletion;
none was an open PR head. An atomic push with an expected-head lease for each
literal ref retired all 72. Their absence and preservation of the active
hygiene and integration/PR heads were verified afterwards.

## Current preservation status (2026-11-08)

The user accepts local storage on this laptop for recovery archives and raw
GPU evidence. No public upload of untracked recovery payloads is authorised.
The local recovery bundle was rechecked: all 338 payload files match their
recorded sizes and SHA-256 values (21,557,449 bytes), with no extra files.

The unqualified source checkpoint `0fd4c01b25b38be507165645366ba71a3d3b9b55`
is preserved on origin branch `codex/rv64-gpu-hygiene-local`. This is a backup,
not a hardware-qualified integration or default promotion. At publication,
origin `codex/rv64-gpu-hygiene` remained at `51897dc265593df7580c4abf0b232909fc105e34`.
All 242 archive tags and their 484 object/peeled records were rechecked against
local refs, with no missing or differing records.

The RunPod copy below was verified when copied; it is not a durable-storage
claim. Pod `cps13bvat3xhdo` is stopped with a negative account balance and an
80 GB pod volume, not a network volume. Raw logs, traces and proofs referenced
by pod paths are not all confirmed local. On the next funded restart, copy
and independently hash-verify that evidence onto this laptop before any new
benchmark, cleanup or volume retirement. Keep the pod and volume intact.

## Recovery data off the laptop

The verified copy is on RunPod pod `cps13bvat3xhdo`, persistent path:

```
/workspace/m3/archives/rv64-consolidation-20261108/recovery-bundle-v1
```

The bundle has 338 payload files (21,557,449 bytes), plus the manifest.
Its manifest SHA-256 is
`8e6a206805e9b9281663368a5c240e95cd5e109e9c0b6f2b0575e903ad4994d7`.
Exact file set and individual hashes were checked after copying. It contains
working-copy archives and the intentionally pending canonical edits, including
`rv64-gpu-hygiene.md`, `rv64-m8-handoff.md` and `dev_test.py` as captured before
the first deletion batch. See the current productionisation receipt for their
subsequent validation and delivery status.

The local original is under
`/Users/theodorepender/Coding/ge-artifacts/rv64-gpu-hygiene-20261108/consolidation/`.
Its retirement ledger records each historical HEAD, archive ref and local
data hash. Verify the manifest and archive hashes before recovery. Inspect
committed code with `git show <archive-tag>:<path>`; extract working-data
archives into an artifact directory and review their patches before applying
selected changes to the canonical checkout.

## Historical receipt preservation

`archive/receipts-20261108/pre-retirement-v1` preserves the complete published
`7c0686ae7c21be9bd5675f3d7b8f2b8439a07713` report tree: 14,947 files,
1,981,949,006 bytes. Its annotated tag object is
`998e43fc209ae0e119cda002a8718882e56e22e4`. Both the tag object and peeled
source commit were checked on origin before any report retirement.

The manifest records each path, Git blob, byte count and SHA-256. Its SHA-256 is
`afc46613fe84bd063826ea05a406e30cacc0d84e48d5e1ab5b802976ae2de7c1`.
The manifest, summary and recursive-input dependency closure are also copied
off the laptop, with hashes checked, to pod `cps13bvat3xhdo`:

```
/workspace/m3/archives/rv64-consolidation-20261108/receipt-retirement-v1
```

Receipt bytes remain recoverable from the published tag using
`git show archive/receipts-20261108/pre-retirement-v1:<original-path>`.
After preservation, 34 live inputs moved byte-identically to maintained
fixtures, retaining their pins and recursive relative references. The fixture
manifest records their original paths and archive blobs. A literal, rehashed
list then retired 7,004 files (1,570,076,423 bytes) from these historical roots:

- `riscv-proving-stack-reset-20260908`
- `recursive-product-20260917`
- `recursive-product-20260918`
- `rv64-foundations-20261030`
- `rv64-qualification-20261030`

The retirement plan SHA-256 is
`99d2f5cc1f811cb1fa7fdfd97b97cbe76f43dd05840088a400c78c57349e1293`.
Its literal list and completion ledger are retained with the consolidation
artifacts. File moves and 67 embedded historical code snapshots receive no
production-code deletion credit. Current M7/M8/M9 receipts and live benchmark
and interop history remain pending their owning workflow's migration.
