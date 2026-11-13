# Waist consumer coverage after the five-provider execution foundation

This is a source-backed qualification ledger for the candidate based on main
`62e2d2303`, not a second registry. Provider `package.contract.json` consumer
registrations and the assembled canonical module graph remain authoritative.
Registered roots are not executed coverage until their exact named cases run
in Debug and ReleaseFast through the provider target.

## Current scope

| Provider | Declared package edges | Actual injected edges | SDK edges | Registered roots |
| --- | ---: | ---: | ---: | ---: |
| `stwo_backend_contracts` | 9 | 0 | 1 | 10 |
| `stwo_circuit_recursion_wire` | 2 | 0 | 1 | 3 |
| `stwo_core` | 34 | 0 | 1 | 35 |
| `stwo_proof_wire` | 5 | 3 | 1 | 9 |
| `stwo_prover_api` | 18 | 0 | 1 | 19 |

All 68 declared package edges have consumer-owned registrations. Three
additional proof-wire rows cover actual postcard-mediated injections in the
RISC-V frontend, recursion child and RV32 child. Five SDK rows execute laws
through the actual public SDK namespaces and assert canonical provider identity.
The source-derived exact gate admits 76 roots and 79 named cases per mode;
missing/extra package, injected and constructed-product edges are rejected.

SDK roots belong to the canonical product build harness under
`build_support/products/contract_tests/stwo/`; their allowed owner directory,
actual builder/module root, public namespaces and exact CODEOWNERS paths derive
from the existing canonical product catalog. Package roots remain `src/` only.
The private std-only fixture lives at `build_support/products/consumer_laws.zig`.
There is no new SDK package, unpackaged source exception or public test-helper ABI.

One private std-only fixture module owns shared test mechanics. Consumers
select the laws they rely on and pass actual provider namespaces and types.
Concrete CPU/Metal/backend and publicly reachable engine witnesses remain
consumer-owned assertions, without a fake backend or runtime testing export.

The build checks each consumer’s actual provider pointer against the canonical
provider and uses only registered public imports. Exact test discovery is
validated after execution. The four newly activated provider commands append
to existing focused lanes in both modes, preserving original commands/floors.

## Executed evidence and remaining gates

- Corrected direct runs execute 62 actual roots and 65 exact named cases in
  each mode; every imported Zig module explicitly uses that optimization.
  Five SDK roots add five actual cases per mode, for 67 roots/70 named cases.
  Nine concrete-owner witness roots still require canonical hosted execution.
- Earlier root-only ReleaseFast receipts remain mixed-optimization evidence,
  not provider ReleaseFast qualification; correction receipts preserve history.
- The canonical proof-wire package passes 21/21 in both modes, including the
  D2 diagnostics, fixed-seed mutation corpus and allocation-failure cleanup.
- The aggregate five-target local build hit the 1 GiB cap. Its assembled
  canonical module-pointer and post-run discovery gates remain **UNRUN** locally.
- Missing SM83, RISC-V Metal and circuit Metal consumer adapters are now built
  against their actual declared dependencies; platform owners are compile-time
  witnesses, with no device execution. Registration is not execution evidence.

## Origin-specific error coverage

The existing circuit binary decoder retains its 0x5001/0x5002 meanings.
The candidate adds proof-wire’s five typed CodecError meanings and opt-in
diagnosed JSON/binary decoding in rc.2, used by Native interop verification.
Provider tests pin exact mappings, unknown/foreign refusal, stale-output
clearing, parser/OOM nonannotation and unchanged decode errors. Existing
golden-byte and allocation-failure roundtrips exercise diagnosed wrappers.

Core FRI configuration, Backend arena planning and Prover API quotient column
origins now have actual consumer wiring and bounded executed checks, recorded
in [the origin ledger](waist-error-boundary-rfc.md). Their full process/Engine
qualification remains separate. Core verification/FRI/Merkle, backend recovery/
native-AIR, task/lifetime/work and remaining parser/recursion origins stay open.
Five bands or declaration tests are not full D2 completion.

## Remaining qualification obligations

- Execute all 76 actual roots and 79 named cases in both modes through canonical
  provider targets, including the nine concrete public backend/engine witnesses.
- Qualify actual one-level postcard-to-proof-wire and SDK public-provider
  pointer identity in the assembled canonical graph, beyond direct root runs.
- Preserve full original provider commands, CPU proof bytes/refusal classes and
  all physical proof-corpus gates. No device execution is part of these tests.
