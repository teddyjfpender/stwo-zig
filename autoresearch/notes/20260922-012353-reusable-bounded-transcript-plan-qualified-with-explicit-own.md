---
title: Reusable bounded transcript plan qualified with explicit ownership
author: Teddy Pender
created_utc: 2026-09-22T01:23:53Z
---

# Reusable bounded transcript preprocessing plan

Added blake3_transcript_plan.Plan with explicit namespace and attempt_capacity.
It retains trustedBounded preprocessing for all eight transcript AIRs and prepares
multiple witnesses against that retained structure. Its SHA-256 artifact fingerprint
binds a domain/version, protocol identity, AIR count/identities/dimensions, row
counts, ordered fixed columns, semantic output roles and source/read receipts.
Length-delimited arrays and explicit little-endian integer encodings are used.
Private main columns, actual retry counts, native final digest/counter metadata
and private routed payload values are excluded from fixed authority.

The plan validates its retained fingerprint before preparing a witness and rejects
witnesses whose fixed structure or semantic exports differ. Capacity exhaustion is
explicit: no automatic escalation, truncation, new key selection or fallback.
Positive capacities use the existing namespace/resource admission. No production
capacity classes, availability probability or security guarantee is invented here.
SHA-256 is an artifact identity, not a PCS preprocessing root, full parent key or
change to the BLAKE3 Fiat-Shamir protocol.

Bounded transcript proof fixtures now consume the prepared plan. The parent prefix
accepts capacity explicitly from its caller (the current fixture chooses three),
admits its witness through the plan and retains its plan ID. It then consumes the
plan using intoFixed to take sole ownership of preprocessing before adding the
parent's separate trusted-root boundaries. Those extra parent boundaries are not
part of the transcript-plan fingerprint. The plan itself supports reuse; the
current parent fixture still constructs a plan per invocation, not a production
cache or persistent whole-parent proving engine.

Validation: the initial serial ReleaseSafe batch exited zero, 12/12 steps, 3/3
tests: plan reuse/admission (683 ms / 10 MiB), bounded transcript (9 s / 504 MiB,
two complete CPU proofs), and complete parent (32 s / 6 GiB). Review then identified
an arena ownership hazard in the initial prefix view: shallow copies can lose
ownership of blocks allocated during extension. An explicit consuming transfer
replaced it. Allocation-failure testing now forces one MiB of post-transfer arena
growth, proving cleanup through the sole owner on success and failure.

The final focused batch exited zero, 8/8 steps, 2/2 tests: plan/ownership test
1 s / 11 MiB (compile 4 s / 485 MiB), parent 32 s / 6 GiB (compile 42 s / 2 GiB).
No fingerprint equations, capacity semantics or bounded-transcript proof behavior
changed during the ownership correction. All three distinct tests passed.
These timings are qualification diagnostics, not matched speed measurements.

Coverage: same retained plan and same independently compiled fingerprint with
changed private integer payloads; ignored attempt metadata; genuine rejection;
wrong public operation shape; output-role substitution despite equal physical draw
shape; different-capacity fingerprints; capacity exhaustion; corrupted capacity
and fixed rows; zero-capacity rejection; all allocation failure positions and
post-transfer growth. Complete transcript and parent proofs use independently
constructed preprocessing and retain their wrong-preprocessing rejection checks.
Formatting and git diff --check pass. All sessions reached terminal exit; no
repository-wide suite was rerun.

Remaining: production child-proof source admission and reusable whole-parent
key/artifact families, production capacity/resource policy, Metal support,
CPU/Metal parent-of-parent qualification and matched end-to-end performance.
Production still uses Poseidon. This completes a reusable transcript component,
not the overall BLAKE3 migration or the original recursion performance goal.
