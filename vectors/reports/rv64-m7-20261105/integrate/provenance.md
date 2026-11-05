# Takeover measurement provenance

The same-session M6 control (`m6-control.json`) used the existing M6 driver
and CUDA image from `/workspace/m3/build/m6-integrate`. Its driver build record
labels source `1345c6eb9` (driver SHA-256
`b7a4615f8348fd81c0c3e22b3533a5e3fd56454d5f553aed8513565b77f6e700`).
There are no Zig/CUDA source differences between that commit and `26ca20793`;
later M6 changes are the harness's default profile and receipts. The current
M7 harness explicitly selects that M6 default.

The resident harness's `source_commit` records the synced harness tree even
when `--build-stream` selects another binary. Consequently the control's
`source_commit` field names the handoff/harness commit, **not** the M6 binary's
build commit. Binary hashes are the actual identity. Do not promote that field
to a source-bound binary claim. Candidate WIP builds are similarly labeled as
uncommitted, with a separate SHA-256 snapshot of every changed prover source.

All takeover timings so far are observations on a loaded shared pod. The load
is recorded in each receipt; they do not enter the quiet-run best-so-far table.
Receipts retain the original stage boundaries and do not sum overlapped stages.
