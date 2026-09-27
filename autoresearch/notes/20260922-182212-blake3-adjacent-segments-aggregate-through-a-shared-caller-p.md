---
title: BLAKE3 adjacent segments aggregate through a shared caller-pinned preparation API
author: Teddy Pender
created_utc: 2026-09-22T18:22:12Z
---

# BLAKE3 adjacent segment aggregation and canonical preparation API

Two real leaf-local runner segments now prove a six-instruction execution with
nonzero output, fold their authenticated Spans, and independently verify both the
aggregate and another recursion level. The aggregate binds both child keys,
configs, graph/transcript identities, original Spans, custody bindings and
namespace mappings. Children occupy disjoint relation namespaces. The final
columns are joined directly rather than expanded into logical witness rows.

A segment adapter owns public words and canonical execution/program/memory
witnesses. Boundary program-fetch compensation matches the commitment witness
in native and recursive BLAKE3 verification; the execution transcript advances
to version 3. Legacy compensation remains unchanged. The parent key advances
to version 3 to authenticate both child contexts and the aggregate identity.

The public `prover.blake3_segment_parent.ForBackend(Backend).prepare` entrypoint
borrows a reusable caller-admitted verifier, expected key, segment owner and Span.
It authenticates the owner's statement, constructs and checks full-memory custody
conversions before proving, independently verifies the resulting child and returns
owned recursive columns. Temporary capture/conversion storage is released before
return. The execution owner becomes single-use when interaction generation starts;
preflight admission failures leave it usable. The test uses this shared entrypoint
instead of a private copy of the orchestration.

## Qualification

Command:
`python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-aggregation -Doptimize=ReleaseSafe --summary all`

The original connected aggregation run passed in 3 minutes with 7 GiB peak RSS.
Aggregate and parent artifacts: 132,947 and 122,984 bytes. Aggregate preparation:
25,328 inputs and 1,082,774,500 retained bytes. Next-level preparation: 18,649
inputs and 538,770,400 retained bytes. These are build/test duration and retained
allocation counts, not end-to-end speed benchmark results.

Checks cover distinct child keys, full memory continuity, nonzero final output,
reversed segment rejection, child Span substitution, both child context/key
metadata mutations, artifact roundtrip, independent verification after proving
plan destruction and another recursion level with the aggregate identity retained.
The API adds wrong-pin and modified-Span rejection before interaction generation.
The final API-based run also passed in 3 minutes / 7 GiB, with identical artifact
sizes and retained column counts (see `segment-api.log`). Source snapshots match
this final run; `adjacent-aggregation.log` records the preceding connected test.

This remains diagnostic CPU q8/PoW0 qualification with specialized caller-admitted
keys. Production multi-segment scheduling and admission, extension/precompile
integration, canonical recursion parameters, Metal parity, default promotion and
removal of active prover-owned Poseidon remain incomplete. The original persistent
plans/scheduling, fused PCS/DEEP, final-layout witness and separately reviewed
parameter-experiment performance objective remains active; no 10x result is claimed.
