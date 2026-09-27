---
title: Prepared BLAKE3 execution keys artifacts and recursion capture
author: Teddy Pender
created_utc: 2026-09-22T16:13:08Z
---

# Prepared BLAKE3 execution admission, artifacts, and recursion capture

Problem: the explicit execution API rebuilt fixed columns and their commitment
on each verification and allocated unused hash witness buffers. It also lacked
a bounded transport and a full-width capture for recursive transcript planning.

The API now provides a backend-injected `PreparedVerifier`. Preparation owns
copies of the public I/O and commitment schedules, derives a full execution key,
and retains authenticated typed plans, geometry, and decoder bounds. It releases
fixed column buffers after deriving their root and never allocates main witness
columns. Repeated verification uses this owner without reconstructing fixed
trace columns. The one-shot API delegates to the same verifier implementation.

The key binds security parameters, full-width public data and execution geometry,
the pinned commitment plan, typed native authorities, the relation registry,
BLAKE3 AIR geometry and identities, and the independently derived preprocessing
root. The expected key identity is supplied by verifier admission. The execution
transcript is version 2 to bind native authorities and distinguish an absent
lifting parameter from a present zero. This supersedes the earlier experimental
in-memory version; no production default or legacy artifact format changes.

The B3EXART1 codec carries the key identity and active detailed claims with the
canonical BLAKE3 postcard proof. It checks header lengths, canonical claim limbs,
and component-derived nested vector bounds before proof allocation. A serialized
key ID never selects its own key. Verification consumes rejected proofs too.

A successful capture retains the verified PCS/FRI data, claims, universal
relations and final transcript with a mutation-detecting transport seal. This
seal is not an in-circuit proof authority. Full-width execution transcript
planning uses the same prefix encoders as proving/verifying, then the shared
native BLAKE3 PCS replay suffix. It uses universal relation output ports and
preserves full-width roots without a legacy statement projection.

The real-program integration gate proves the four-instruction base program,
encodes it, releases the original proof, decodes two independent copies and
verifies them with one retained verifier. It rejects altered key/version/count,
noncanonical claims, truncation, wrong pins/configuration/root/statement,
modified claims, and modified capture samples. Caller mutation of original I/O
or schedules cannot change retained admission. The capture replay's final
transcript exactly matches the verified execution, and its reusable BLAKE3 hash
plan is materialized. Retained main and fixed column counts are both zero.

Qualification: `test-riscv-blake3-execution-commitments` passes in ReleaseSafe
(1 min, peak RSS 4 GiB). These are build/test costs, not proving benchmark numbers.
The proof uses diagnostic q8/PoW0. Shared recorder/transcript regression gates also pass (3 named tests;
recorder 673 ms and transcript plan 8 s runtime; separate compilation 3–4 s).

Remaining: the new capture must feed native parent composition and full-width
public-boundary wiring, followed by continuation and multi-level recursion.
Extension/CSP orchestration and production key selection/default promotion are
still pending. Keys here are specialized to the admitted public statement and
schedules; this does not establish reuse across different executions. No
canonical CSP result or end-to-end speedup is claimed.
