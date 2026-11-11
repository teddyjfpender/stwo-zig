# RV64 consolidation archive index

The canonical checkout is `/Users/theodorepender/Coding/stwo-zig`, branch
`codex/rv64-gpu-hygiene`. All 162 retired working copies were preserved before
removal. Archived code remains historical and unqualified.

## Published history and remote retirement

Origin contains 241 distinct annotated `archive/*` tags: the original 233,
seven additional exact remote-head archives and the recovery-index tag.
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
