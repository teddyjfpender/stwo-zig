---
title: Plan native hash domains before transcript and path witness emission
author: Teddy Pender
created_utc: 2026-09-22T08:11:40Z
---

# Plan combined hash geometry before live native witness generation

Separate canonical transcript replay/owned preprocessing from live emission.
Planned owns operation payloads, fixed plan and expected final channel; emit
consumes it only on success. Failures preserve the planning owner for cleanup.
Finalize arena-backed slices before copying arena ownership into the result.

Compute path G/XOR counts from capture trace column counts and query positions,
plus FRI group widths/depths. Use canonical group sizing once per shape, checked
multiplication by opening count, then sum with trusted transcript counts. This is
sizing only, not proof/capture admission: existing verified capture checks and all
path construction checks remain. Compare the plan with actual emitted counts and
derived domain logs before publishing State.

This is a two-phase geometry/witness preparation change. It supplies global sizes
and transcript/path offsets before live emission, required by the native column
sink. It does not yet replace logical row storage or qualify column integration.
Validate planned/actual counts, geometry mutation rejection and independent native
proof/key/codec/ownership parity; record any allocation changes without speed claims.
