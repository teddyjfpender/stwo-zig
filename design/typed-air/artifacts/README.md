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

## M3 `compat-v1` family manifests

- [`m3-compat-v1/index-v1.tsv`](m3-compat-v1/index-v1.tsv) is the readable
  family-ordered whole-manifest, source/semantic, layout, runtime, degree, and
  formal digest index together with geometry, export counts, and maximum
  degrees.
- `m3-compat-v1/*.stwairc` are the 17 canonical section-framed binary
  identities described by
  [ADR-0017](../decisions/0017-sectioned-compatibility-manifests.md).

Each `STWAIRC\0` version-1 binary has seven ordered, length-framed sections:
identity, physical layout, direct runtime program and roots, lookup runtime
program/events/batches, complete degree analysis, hint recipes, and formal AIR
IR v2 exports. Direct and lookup runtime bodies are embedded exactly. Formal
entries retain opcode, mnemonic, byte length, and SHA-256 after the typed and
production emitters have compared the complete AIR IR body byte for byte.

The package suite regenerates and byte-compares every file in memory. Run the
same fail-closed check directly with:

```sh
zig build typed-air-manifest --build-file src/frontends/riscv/build.zig \
  -Doptimize=ReleaseFast
```

An intentional reviewed replacement uses the same command with
`-Dtyped-air-manifest-mode=update`. Update mode writes atomically and never runs
from an ordinary test. During allocation-failure testing, the legacy production
symbolic builder uses stable scratch storage while every allocation introduced
by the runtime/receipt result boundary is exhaustively failed and cleaned up.
Normal generation uses one allocator. These receipts remain compatibility
evidence, not a production activation or proof-protocol change.

The A-012 comparator parses and validates both complete v1 bodies without
allocation. It reports the first changed semantic path, including expected
logical and physical names where available. Check mode renders that result and
fails closed. Explicit update mode renders the same generated-versus-on-disk
result before atomically replacing the file; malformed or oversized existing
artifacts are never silently accepted. The TSV index remains a raw byte/digest
comparison because it is the readable projection rather than a second binary
protocol object.

The exact clean-snapshot commands, tool versions, aggregate identities, proof
results, and deliberately open release gates are recorded separately in the
[M3 milestone receipt](../receipts/m3-compatibility-v1.json). The receipt does
not change or supersede these compatibility artifacts.

## H-009 Poseidon2 materialization cost frontier

- [`h009-poseidon2-cost-v1/frontier.stwairm`](h009-poseidon2-cost-v1/frontier.stwairm)
  is the canonical section-framed search receipt.
- [`h009-poseidon2-cost-v1/frontier-v1.tsv`](h009-poseidon2-cost-v1/frontier-v1.tsv)
  is its exact tabular review projection.
- [`h009-poseidon2-cost-v1/frontier-v1.md`](h009-poseidon2-cost-v1/frontier-v1.md)
  is the human review view.

The binary receipt authenticates the semantic program, fixed direct-polynomial
program, complete cost model, search configuration, accounting, seed, and 126
retained proposals. The TSV and Markdown deliberately select the fields useful
for review; they are byte-exact projections, not alternate complete encodings.
The complete one-pass neighbourhood is a structural cost
plateau: every retained proposal has the exact seed vector. It is evidence for
H-010 benchmark selection, not a speedup claim and not production activation.

The package suite decodes the binary and regenerates both readable views byte
for byte. These files are exposed only through the dedicated test bridge
[`h009_embedded.zig`](h009_embedded.zig); the compatibility-artifact bridge
does not carry them. The same fail-closed command is:

```sh
zig build typed-air-frontier --build-file src/frontends/riscv/build.zig \
  -Doptimize=ReleaseFast
```

An intentional reviewed replacement adds
`-Dtyped-air-frontier-mode=update`. Update is explicit and writes each file
atomically; ordinary tests and check mode never update artifacts.
