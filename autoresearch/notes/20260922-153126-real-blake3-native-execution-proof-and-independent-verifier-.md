---
title: Real BLAKE3 native execution proof and independent verifier API
author: Teddy Pender
created_utc: 2026-09-22T15:31:26Z
---

# BLAKE3 native execution proof integration

The new explicit execution API joins the shared typed native instruction, clock,
and lookup generators to full-width BLAKE3 program and ordinary memory
commitments. It reuses the existing base component assembly and a single
universal relation draw. Backend injection remains outside the frontend; the
CPU integration exports `Blake3Execution` without changing production defaults.

The protocol binds its version, PCS configuration, full-width public data,
canonical execution geometry and admitted commitment-plan identity before
committing traces or drawing challenges. Every active interaction claim is
transcript-bound. Verification consumes the owned proof, reconstructs fixed
columns from admitted statements/schedules, checks the preprocessed root, and
derives main/interaction geometry independently of witness buffers. It checks
relation closure including public execution/I/O compensation.

The real-run gate executes two ADDIs, one LUI, and a store publishing an empty
output, followed by an unretired self-loop. It proves the resulting execution,
program and memory components together and independently verifies the STARK.
Prover and verifier final transcripts must agree. It also rejects malformed
opcode widths/counts, table geometry, preprocessing-root substitution and reuse
of consumed preparation phases. Existing commitment column and admission checks
remain in the same focused gate.

This integration exposed a missing lookup census contribution: padded BLAKE3
G/XOR rows retain valid zero-table requests. Registering only the live prefix
left those requests unbalanced. The commitment owner now registers the repeated
padding row over the remaining domain, matching its interaction generator.
CPU-state, memory and program boundaries already balanced before this fix.

Validation: the focused execution gate passes (1 min, peak RSS 4 GiB), as does
the shared statement/codec regression gate (35 s, peak RSS 1 GiB), both in
ReleaseSafe. The execution gate enforces a minimum of two named tests.
These timings include build/test work and are not prover latency. The proof uses
explicit diagnostic q8/PoW0, not canonical CSP security parameters. This is a
real base-program proof, not an ECDSA precompile, a CSP suite result, or a
multi-level recursion qualification. No performance comparison is claimed.

Remaining: reusable complete verification-key/artifact admission, extension
and continuation orchestration, recursive child/parent admission and multi-level
qualification, production default promotion, then canonical CSP/recursion
measurements. Caller-supplied plan pins in this API must be independently
admitted; deriving a pin from an untrusted received plan is not key admission.
