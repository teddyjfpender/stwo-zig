---
title: Native BLAKE3 composition replay and challenge routes qualified
author: Teddy Pender
created_utc: 2026-09-22T01:57:34Z
---

# Native BLAKE3 composition challenge routes

The real verified BLAKE3 nonfinal RISC-V capture now passes the existing native
V2 composition recorder and evaluator: 13,929 graph nodes, 29 designated zero
outputs. This reuses vm_air_composition_prepared_v2 and its authenticated physical
lookup profile. It does not substitute the fixture universal relation inventory.

blake3_native_challenge_links prepares all 104 scalar challenge routes: 12 native
relation pairs times eight coordinates, plus four composition randomness and
four OODS seed coordinates. It joins semantic transcript roles to authenticated
VM graph input bindings. Missing/duplicate coordinates, universal roles, aliased
source endpoints, noncanonical endpoints and invalid input coordinates reject.
The fixed 104-entry endpoint alias check is quadratic in this small constant;
graph use counts and binding scans are linear in graph size.

The existing scalar_wire_source AIR consumes each transcript coordinate once
and emits its graph input with the shared lowering's exact use count. Fixed rows
contain only schedule coordinates and multiplicities, with a zero witness cell.
The module returns rows for inclusion in the parent; no new AIR or cryptographic
primitive was added. The parent must share challenges with additional consumers
(public-boundary arithmetic, PCS/DEEP) using explicit fanout accounting.

The native integration gate compares every routed scalar directly to the
canonical transcript operation's draw. All 104 match. Missing/duplicate exports
and aliased source endpoints reject; reordering exports preserves the schedule.
Every fixed row equals its live row outside the witness cell. Native composition
admission also replays every graph operation and requires every output to be zero.

Final serial command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment -Doptimize=ReleaseSafe --summary all
```

Final terminal exit 0, 4/4 steps, 3/3 tests passed; compile 57 s / 4 GiB, tests
20 s / 1 GiB. The gate includes both default Blake2s and BLAKE3 native segment
proofs and the rebased default case. Initial and strengthened final logs retained.
Formatting and git diff --check pass. No broad suite or live build remains.
Tiny q1/PoW0 proof timings are qualification diagnostics, not CSP or speed claims.

Remaining: claim/sample joins and public-boundary authority, shared challenge
fanout, full joined native parent proof, statement-independent preprocessing,
production artifact admission, Metal and parent-of-parent qualification. The
migration remains incomplete. This stage qualifies native composition replay
and route witness construction, not a STARK proof containing all those routes.

Next source boundary: physical_manifest.AuthenticatedStatement.mixInteractionClaim
absorbs canonical component aggregate sums. ContextV2.detailed_claims are a
separate selected physical inventory; the existing composition recorder's
bindTranscriptAggregates constrains their reduction to canonical sums. Preserve
that arithmetic reduction when routing aggregate payloads, rather than treating
the two arrays as interchangeable. Public-boundary native_challenge_word inputs
must share the same 12 relation-pair transcript outputs.
