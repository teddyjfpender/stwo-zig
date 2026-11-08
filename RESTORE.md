# Consolidation archive

The canonical checkout is /Users/theodorepender/Coding/stwo-zig.
The retirement ledger records each historical HEAD, its archive tag, and the
SHA-256 of its local working-data archive under ge-artifacts. Each archive
contains exact staged/unstaged/working patches and all changed, untracked
and non-cache ignored files. Rebuildable caches were excluded. All archive
contents were checked before any working copy was removed.

Inspect committed source with git show <archive-tag>:<path>. Do not create
component worktrees. For recovery, first verify the recorded archive SHA-256;
extract into a temporary artifact directory. Review metadata/working.patch
and files/ before applying any selected work to the canonical checkout.
Archived code is historical, potentially unqualified, and is not promoted by
its preservation. Remote archive publication/branch retirement is separate.
