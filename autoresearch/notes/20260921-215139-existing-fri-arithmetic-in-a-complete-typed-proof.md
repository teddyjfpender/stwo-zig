---
title: Existing FRI arithmetic in a complete typed proof
author: Teddy Pender
created_utc: 2026-09-21T21:51:39Z
---

# Commit canonical FRI arithmetic through existing typed components

Task: move existing native FRI evaluation and arithmetic lowering into a complete
CPU STARK proof using existing multiply/inverse/linear AIRs. Preserve exact graph
inputs, constants, zero outputs and graph-derived use counts.
Canonical match: existing arithmetic-DAG lowering; no new arithmetic algorithm.
The hash proof harness currently passes empty component parameters. Add an
explicit parameter tuple entry point and logical-row aliases for existing AIRs.
Prove all lowered operations with public input boundaries as an intermediate
integration gate; full private hash connection remains a subsequent composition.
Validation: real BLAKE3 PCS fold4 capture -> canonical FRI circuit -> lowering ->
existing typed AIR rows -> outer proof and core verification, false PP rejection.
No parameter weakening or new production identities. No performance claim.
