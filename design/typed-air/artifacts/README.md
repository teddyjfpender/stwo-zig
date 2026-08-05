# Checked compatibility artifacts

This directory pins deterministic evidence emitted by the isolated typed-AIR
compatibility implementation. Artifacts are reviewed protocol data, not
benchmark output and not production-activation receipts.

## M2 production shadow report

- [`m2-production-shadow-report-v1.tsv`](m2-production-shadow-report-v1.tsv)
  is the machine-readable, tab-separated record for all 17 opcode families.
- [`m2-production-shadow-report-v1.md`](m2-production-shadow-report-v1.md)
  is the corresponding human-readable view.

Both files are rendered from `air/lang/protocol_report.zig`; `embedded.zig`
exposes them to the otherwise isolated RISC-V package test. Any semantic change
therefore fails the golden comparison until the versioned artifact is
deliberately reviewed and regenerated. The report
describes the current production program imported in shadow mode; it does not
authorize a generated lowering or alter production proving behavior.
