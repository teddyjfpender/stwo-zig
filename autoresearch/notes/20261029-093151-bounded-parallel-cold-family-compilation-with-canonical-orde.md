---
title: Bounded parallel cold family compilation with canonical ordered assembly
author: Teddy Pender
created_utc: 2026-10-29T09:31:51Z
---

Task: compile independently admitted original verifier families concurrently without changing any canonical fixed row, namespace, wire, transcript context or resulting key.
Evidence: actual32K cold phase observed ~89s near one CPU before a resource guard; existing deriveWindow sequentially compiles each finite family and only then appends. Factories own separate budgeted graphs/fixed rows; caller capsules expose const compiler products and read-only validation; fixed roster construction allocates fresh row arrays before namespace mutation.
Canonical mapping: bounded fork/join DAG over independent family compiler jobs, ordered deterministic reduction/assembly. No scheduling optimization solver needed. Existing WorkPool and bounded native projection wave implementations supply maintained local primitives; no new helper threads or third-party code.
Constraints: one existing SharedHostBudget across all simultaneous pieces and growing builder; per-family budgets remain nested/clamped. At most requested2/4 family pieces retained simultaneously; external/nested unavailable WorkLease falls back serial, never waits for capacity. Every successfully constructed piece is destroyed on any failure after workers join.
Design: finite tagged Piece over original family Owned types; extract compileOne preserving original API/limit validation; WorkPool lease with default parallel_families1, bounded by pool/MAX_WORKERS. Compile one cohort, join, report earliest canonical failure, append pieces in exact original order then destroy. Existing hash-row partitioning unchanged. Public admission occurs once before jobs.
Cost/tradeoff: total work unchanged; span approaches longest family plus serial ordered row copy for each cohort. Peak live memory rises from one family piece to cohort sum, always limited by the same request owner; no per-worker independent aggregate allowance. A single dominating caller/compiler may limit speedup.
Validation: genuine metadata fixture serial vs2/4 fixed row/wire/context equality and key derivation; unavailable nested lease parity; forced row/resource failures after jobs, outer budget snapshot zero; allocation failure cleanup via bounded small compiler fixture. Parent does controlled actual-window timing after correctness.
Open risks: read-only capsules must remain alive until all jobs join; inner factory code must not require unavailable nested WorkPool leases. No claim that this resolves row-cap failure itself.
