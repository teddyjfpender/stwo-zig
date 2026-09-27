---
title: Native BLAKE3 transcript sequence compilation
author: Teddy Pender
created_utc: 2026-09-21T20:39:17Z
---

# Sequenced native transcript operations

Task: derive state producers and counters from ordered absorption/draw operations,
not caller-selected draw starting counters. Exact match: deterministic state
machine compilation into the existing authenticated hash/dataflow graph.
An integer absorption hashes the current state and public payload, creates a new
state producer and resets the draw counter. A secure draw preserves the state,
consumes a contiguous rejection prefix and advances its counter by attempt count.
The pinned native initial digest is the only initial state authority.

Use existing frame and ordered-draw builders; accumulate exact producer copy
counts across every consumer before proof generation. Namespace allocation is
checked for the complete operation list. Trusted assembly follows the same graph
without calculating private state values. Complexity is linear in total hash
work; no new AIR or cryptographic parameter. Alternative caller-supplied counters
cannot establish sequence semantics and is rejected at this integration layer.

Gate: native integer/draw/draw/integer/draw parity, reset behavior, fixed-column
parity, invalid attempt count and namespace overflow, complete five-component CPU
STARK, false output rejection. Scope initially integer absorption and secure draws;
private scalar/root absorption, raw queries and PoW remain explicit integration
work. No production speedup claim.
