# Waist consumer coverage after the five-provider execution foundation

This is a source-backed qualification ledger for the candidate based on main
`62e2d2303`, not a second registry. Provider `package.contract.json` consumer
registrations and the assembled canonical module graph remain authoritative.
Registered roots are not executed coverage until their exact named cases run
in Debug and ReleaseFast through the provider target.

## Current scope

| Provider | Declared package edges | Registered roots | Unregistered package edges |
| --- | ---: | ---: | ---: |
| `stwo_backend_contracts` | 9 | 9 | 0 |
| `stwo_circuit_recursion_wire` | 2 | 2 | 0 |
| `stwo_core` | 34 | 34 | 0 |
| `stwo_proof_wire` | 5 | 8 | 0 |
| `stwo_prover_api` | 18 | 18 | 0 |
All 68 declared package edges now have consumer-owned registrations. Three
additional proof-wire rows cover actual postcard-mediated injections in the
RISC-V frontend, recursion child and RV32 child, for 71 roots and 74 named
cases per mode. The strict source-derived gate rejects any missing, extra or
newly introduced package edge; it separately includes these real postcard
routes. SDK/unpackaged product registrations and their actual source ownership
remain additional work; this matrix does not pretend they are package edges.

One private std-only fixture module owns shared test mechanics. Consumers
select the laws they rely on and pass actual provider namespaces and types.
Concrete CPU/Metal/backend and publicly reachable engine witnesses remain
consumer-owned assertions, without a fake backend or runtime testing export.

The build checks each consumer’s actual provider pointer against the canonical
provider and uses only registered public imports. Exact test discovery is
validated after execution. The four newly activated provider commands append
to existing focused lanes in both modes, preserving original commands/floors.

## Executed evidence and remaining gates

- New CPU/backend, prover/API, Native/proof-wire and RV64/recursion-wire roots
  pass bounded standalone public-module Debug execution. Earlier root-only
  ReleaseFast receipts used mixed optimization across imported modules and do
  not qualify provider ReleaseFast behavior; corrected checks are separate.
- The canonical proof-wire package passes 21/21 in both modes, including the
  D2 diagnostics, fixed-seed mutation corpus and allocation-failure cleanup.
- The aggregate five-target build hit the local 1 GiB memory cap. Its canonical
  module-pointer and post-run discovery gates remain **UNRUN**, not PASS.
- All nine initial roots, including four waist-to-Core roots and the revised CPU
  allocation budget, pass bounded standalone Debug checks (12 named cases).
  Their earlier root-only ReleaseFast result is mixed-optimization evidence,
  not provider ReleaseFast qualification. Remaining matrix bodies and concrete
  witnesses need final execution.
- Full consumer coverage, actual injected postcard/product registrations and
  all admitted platform compile routes remain open under issues #366/#367.

## Origin-specific error coverage

The existing circuit binary decoder retains its 0x5001/0x5002 meanings.
The candidate adds proof-wire’s five typed CodecError meanings and opt-in
diagnosed JSON/binary decoding in rc.2, used by Native interop verification.
Provider tests pin exact mappings, unknown/foreign refusal, stale-output
clearing, parser/OOM nonannotation and unchanged decode errors. Existing
golden-byte and allocation-failure roundtrips exercise diagnosed wrappers.

The Native process stderr/exit/failed-write contract still needs actual
process qualification. Core verification/FRI/Merkle, backend planning/recovery,
prover quotient/task lifetime, and remaining parser/recursion origins remain
unmapped. Five bands or declaration tests are not full D2 completion.

## Remaining qualification obligations

- Execute all 71 actual roots and 74 named cases in both modes through canonical
  provider targets, including concrete public backend/engine witnesses.
- Materialize the missing SM83, RISC-V Metal and circuit Metal consumer adapters
  against declared dependencies; fresh graph/closure evidence remains required.
- Qualify actual one-level postcard-to-proof-wire pointer identity, not just
  matching source names or a declaration of injection.
- Complete un-packaged product-root ownership registrations and source/build
  agreement under RFC #367; do not invent a second product list.
- Preserve full original provider commands, CPU proof bytes/refusal classes and
  all physical proof-corpus gates. No device execution is part of these tests.
