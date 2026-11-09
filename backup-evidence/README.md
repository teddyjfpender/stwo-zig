# Delivery evidence backup

This backup ref preserves raw local CPU/formal evidence separately from the PR.
Every checkpoint retains its own passing, failing and unqualified statuses.
The archive parts are Git LFS objects; normal source checkouts fetch only pointers.

To recover, install Git LFS, check out this backup ref in an artifact directory,
run `git lfs pull`, then verify every part against `MANIFEST.json` and concatenate
parts in manifest order before extracting the gzip tar. The archive contains the
supplemental hosted-CPU checkpoint; earlier checkpoints remain in the original backup ref.
The source snapshot is pinned by `source_PR_commit` in the manifest. Original commit
IDs remain reachable through `backup/delivery-20261109-c7d950b46399`; the
budget-message rewrite map is retained inside the latest evidence checkpoint.
No new correctness, performance, release or hardware claim follows from backup.
