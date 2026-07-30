# Decomposition plan for baselined legacy findings

Repository-local ledger for the source-conformance ratchet. The full historical
narrative lives in the `stwo-zig-og-docs` archive; this file records the
closeout state and the rules for any future regression.

## Rules

- A new finding fails CI immediately; the baseline never grows.
- Removing debt removes its baseline entry in the same commit.
- `--update-baseline` runs are reviewed: the diff must only shrink.

## Current state

`conformance/source-baseline.json` is empty. The ratchet reports zero explained
legacy findings and zero new violations. There is no active oversized-file or
package-layering waiver.

## Completed legacy extractions

| Former owner | Resulting owners |
| --- | --- |
| `tools/stark-v-trace-dump/src/main.rs` | CLI facade plus `decode`, `elf`, `execute`, and test modules |
| `tools/stwo-cairo-verifier-rs/src/lib.rs` | verifier facade plus framing, support, verification, and test modules |
| `tools/stwo-cairo-verifier-rs/src/compact_codec.rs` | codec facade plus protocol, statement, reconstruction, proof-codec, and test modules |
| `src/integrations/cairo_metal/arena_binding.zig` | facade plus composition recipe, decommitment, prepared proof/validation, proof assembly, and streaming commitment modules |
| `src/tools/metal_arena_plan/main.zig` | public facade plus geometry/cache, liveness plan, Metal session, base/interaction/protocol execution, timing, reporting, and test owners |

## Future policy

Further decomposition is an ordinary owner-scoped improvement, not waived
debt. A source that exceeds the policy ceiling or introduces an undeclared
package edge fails immediately. If a future limit change discovers historical
debt, its exception must name an owner, a bounded next extraction, and this
ledger; the baseline still may not grow merely to land unrelated work.
