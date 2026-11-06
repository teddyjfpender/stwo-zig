# Receipt policy

Commit compact summary JSON and Markdown, under about 1 MB per checkpoint. Keep raw Nsight reports, SQLite databases, payload captures, logs, copied source trees and full source hash maps on the pod or in the artifact directory. Summaries must give their path and SHA-256, evidence scope, source identity and acceptance status. Reproduction source belongs in tests or tools, not copied receipt trees.

`raw-artifacts-summary.json` maps the removed historical raw directories to verified artifact copies and SHA-256 manifests. Existing checkpoint links into those directories are historical paths; resolve them through this mapping. Git history is preserved. Current native/profile evidence is summarized in `p1/inter-contributions-summary/summary.json` and remains on pod cps13bvat3xhdo.
