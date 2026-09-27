---
title: BLAKE3 full hash graph problem matching
author: Teddy Pender
created_utc: 2026-09-21T19:23:38Z
---

# BLAKE3 fixed-length hash graph

Task: extend the qualified seven-round compression circuit to ordinary BLAKE3
hashing, with 32-byte output, for fixed publicly admitted message length. Preserve
empty/partial blocks, 1024-byte chunks, left-complete tree shape, chunk counters,
CHUNK_START/END, PARENT and ROOT. Keyed hashing and XOF are not used by our suite.

Canonical match: deterministic expression DAG / SSA expansion of the BLAKE3
specification, not a search/optimization problem. The tree is fully determined
by length. Build left subtree with the largest power-of-two number of chunks
strictly below total chunks, then the right subtree; emit calls in postorder.
Use ROOT on the last compression of the root node, avoiding an unused root CV.
Source: https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.tex
sections Tree Structure, Compression Function and Chunk/Parent processing.

Map constants/message words/prior output words to wire references, then inline
our existing canonical compression topology. Prior output references reuse the
same wire ID across calls. Derive global use counts from all consumers and the
eight digest boundary words; no prover-selected intermediate CVs. Public input
and output boundaries use the already qualified typed byte boundary AIR.
Fixed preprocessing derives from length, canonical graph and public statement.
No new arithmetic equations or relation registry schema are needed.

Alternatives: explicit separate compression-to-compression bridge (extra rows
and identities) or repeated public boundaries for every intermediate CV (would
require the verifier to recompute the hash, defeating recursion). Reuse global
wires to keep intermediates private and constrained by the existing relation.

Complexity derived: O(blocks + chunks) compression calls; 56 G and 16 XOR rows
per call; O(log chunks) scheduling stack. No performance claim before full proof
measurement. Large domains/table amortization remain open.

Validation: std.crypto.hash.Blake3 parity over empty, block/chunk boundaries and
non-power-of-two trees; exact reference graph and global multiset closure;
mutation of flags/counters/chaining/public digest rejected; allocation failures
unwind; a real multi-call hash STARK with verifier-owned preprocessing. Production
recursion/Metal and full suite migration remain separate required integration.
