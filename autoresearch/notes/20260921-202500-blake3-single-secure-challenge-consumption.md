---
title: BLAKE3 single secure challenge consumption
author: Teddy Pender
created_utc: 2026-09-21T20:25:00Z
---

# Native single-QM31 consumption

Task: preserve drawSecureFelt semantics in the reusable ordered draw builder.
The PCS deep randomness and each FRI folding alpha call this method. It checks
all eight raw words, returns four reduced words, discards the other four, and
advances the counter by the complete attempted-block count.

Exact mapping: existing bounded rejection loop with an output projection of four
or eight coordinates. Keep the entire block validity predicate. Restrict only
output wire multiplicities and public scalar boundaries. A two-value enum avoids
invalid partial sizes. No new evaluator, cryptographic parameter, or algorithm.
Source: core/channel/blake3.zig; callers core/pcs/verifier.zig and core/fri.zig.
Alternative half-block reuse changes the native protocol and is rejected.

Validate native first/following single draws, fixed-column parity and output-use
counts, unchanged whole-block rejection tests, and complete CPU proofs for both
four- and eight-coordinate modes. No performance claim beyond removing four
unconsumed boundary rows for single draws. Private transcript state integration
and raw-u32 query extraction remain separate obligations.
