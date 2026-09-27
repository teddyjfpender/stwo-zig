---
title: Native parent fixed commitment shared ownership problem match
author: Teddy Pender
created_utc: 2026-09-22T04:15:56Z
---

# Native BLAKE3 parent fixed commitment reuse

Task and required semantics: reuse the authenticated fixed PCS tree across parent proofs, preserving roots, transcript order, proof values, and allocator custody.

Inputs/model: current standalone Plan commits fixed columns in init for admission and again per prove. Native diagnostic parent has 18 AIRs and two lookup tables. Retain one immutable LDE/coefficient/Merkle owner; each request acquires a constant-size lease.

Canonical match: immutable shared ownership with atomic reference counting (exact lifetime-management match). Source: https://doc.rust-lang.org/std/sync/struct.Arc.html . Reference counting makes ownership thread-safe, not arbitrary payload mutation. No external implementation copied.

Candidates: recomputation preserves current semantics but repeats transforms/hashing; deep cloning avoids recomputation but duplicates tree storage; a borrowed flag cannot independently protect lifetime; shared ownership retains one tree and permits independent scheme destruction. Select shared ownership. Derived acquisition/release overhead is O(1), last release performs ordinary O(storage) teardown. Memory tradeoff: retained fixed tree remains live for the plan lifetime.

Project mapping: promote an owned CommitmentTree to an immutable shared owner, retain a lease for appendCommittedTree, and release through ordinary scheme destruction. Move-only leases must not be duplicated by plain assignment. The original allocation allocator remains authoritative, independent of request allocators.

Audit: sampled_values.releaseTreeCoefficients currently frees coefficient arrays and nulls the descriptor; shared leases must detach only their local descriptor. Merkle host decommit reads layers and allocates request-local results. Backend thread safety remains a separate prerequisite; atomic ownership alone does not qualify Metal concurrency. Coefficient backing buffers and backend teardown tokens stay with the original owner until final release.

Prediction/falsifier: Plan.prove performs no fixed-tree commit; the key root and complete verified proof remain canonical. No latency magnitude prediction before measurement. Any payload mutation, allocator mismatch, or failure to survive owner/lease release order falsifies this implementation.

Validation: focused ownership tests for retained coefficients, allocation failure, independently allocated requests and release order; existing real BLAKE3 native parent proof with codec/independent verification; second proof against the same plan to exercise post-sampling reuse. Bounded scheduling and Metal concurrency remain subsequent work.
