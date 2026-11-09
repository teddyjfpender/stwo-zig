# Branch retirement evidence, 2026-11-09

The manifest records exact branch heads and verified remote archive refs.
Status in the manifest is authoritative; archive verification precedes deletion.
All active PR heads, trunk and backup refs are excluded by policy.
Restore one branch with the exact archive ref and branch from its entry:
`git push origin <archive_ref>:refs/heads/<branch>`.
This is source-retention evidence, with no correctness or performance claim.
