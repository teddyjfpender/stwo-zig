---
title: Metal BLAKE3 PoW fixed-prefix compression and ordered search
author: Teddy Pender
created_utc: 2026-09-22T10:10:38Z
---

# Metal BLAKE3 PoW: fixed-prefix compression and ordered interval search

Task: exact lowest-u64 nonce for the existing BLAKE3 channel predicate, bits 1..32.
The current protocol prefix is exactly 64 bytes: 27-byte ID, domain tag, 32-byte
state, LE32 difficulty. Nonce is an eight-byte second block. Compute the first
CHUNK_START compression once with the core compression owner; device candidates
use that CV, counter zero, length eight, CHUNK_END|ROOT flags. Preserve all nonce
bits and the first-word trailing-zero predicate; do not reuse BLAKE2s flags.

Reuse existing bounded Metal interval search, atomic minimum offset and ordered
host advancement, with distinct BLAKE3 kernel/pipeline/export/ABI admission.
O(N) predicate work; bounded 2^20-candidate dispatches, fixed shared result word.
No host-grinding fallback; generic PCS revalidates returned nonces before mixing.
Transfer the existing seven-round core BLAKE3 compression schedule into MSL;
share the existing add/xor/rotate primitive only, not BLAKE2s compression semantics.
No claimed acceleration until actual device dispatch and CPU parity pass.

Tests: prepared-CV final block versus canonical channel for boundary nonces,
device lowest-nonce equality on several states/difficulties, real dispatch
telemetry and no fallback, legacy Metal PoW regression, generated ABI checks.
This qualifies PoW only; BLAKE3 Merkle/FRI/transcript device work remains separate.
