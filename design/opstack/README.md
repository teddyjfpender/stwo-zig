# OP Stack design records

- [`integration.md`](integration.md) is the design of record for bringing PR #372
  onto `main` as its own product line.
- [`integration-map.tsv`](integration-map.tsv) maps every branch file to its
  target, action, stage and RFC.

The other notes in this directory are the OP research records of PR #372, kept
as written apart from path updates. They describe the branch at
`https://github.com/teddyjfpender/stwo-zig/tree/089bc2437`:

- `zig build` steps, `STWO_OP_*`/`STWO_RV64_*` switches and roots named in them
  exist only on that branch. On `main` they arrive with S2/S3 (RFC-2 to RFC-9)
  as package steps and explicit options.
- Receipt links point at the PR head. `main` keeps no `vectors/reports` evidence.
- Measurements are the branch's own, taken on its hosts.
