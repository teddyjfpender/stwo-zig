# Shared BLAKE3 word-memory migration (in qualification)

This is a shared protocol change, not a CSP-specific fast path. Program data uses
the root-authenticated public preprocessing introduced by the preceding experiment.
Private memory now commits one full u32 per aligned native word, replacing four
independent byte leaves. The memory-access tuple still contains all four byte
limbs and the original byte address, clock and direction. A single typed word
wire connects that tuple to the full-width BLAKE3 leaf input.

The canonical implementation is `blake3_state_tree.zig`; `blake3_byte_tree.zig`
was removed. State-tree frames use domain/version v2, execution public transcript
version 3, commitment-plan version 4, base execution protocol version 4, memory
update-chain identity version 2 and execution-span binding version 2. Old roots
and plans must not be interpreted under the new semantics.

Memory indices are checked aligned byte addresses divided by four. Program
indices remain decoded-field addresses. Both retain the common 30-level tree
shape; memory indices are restricted to 28 bits. The two unused high branches
are fixed empty digests in both shared commitment emission and individual path
AIR preprocessing. They are not free private frontier witnesses. This costs four
additional compressions per memory root versus a 28-level tree, while retaining
one canonical path layout. BLAKE3 rounds and all 256 digest bits are unchanged.

The migration includes host snapshot roots, independently reconstructed source
roots, native boundary tuples, typed leaf bridges, shared path geometry, single
word openings, full-width updates, public-I/O custody and continuation spans.
Public-I/O zero words still get explicit restoration edits. Full-width inserted
and deleted values (0xffffffff and 0xfedcba98) exercise all four byte limbs.

## Current evidence

- `qualification.log`: pinned memory-boundary typed identity
  4fd4e22797641f3660d6d3e5f8732b62071f6d08b1cd73a7d50486194e813e95;
  focused identity/tuple checks passed after intentional digest discovery.
- `span.log`: 31/32 tests passed. The one failure was an old assertion that path
  sharing must strictly reduce a single-word tree; one word already has one path.
  `assembly-retry.log` passes with equality required for that case and strict
  reduction retained for multi-leaf trees. Other span/tree tests include full-u32
  leaf binding, address bounds/alignment, and rejection of nonempty high siblings.
- `custody.log`: full-word insertion/deletion proof, independent preprocessing,
  altered intermediate roots, disconnected transitions and public-I/O custody
  checks passed.
- `integration.log`: joined native/hash relations, exact final-layout columns,
  padding and buffer reuse passed.

- `base-proof.log`: execution artifact verification, span attachment, parent and
  parent-of-parent checks pass. A 70/26 parent over an 8-query diagnostic child
  passes authenticated plan reuse and fresh verification.
- `canonical-parent.log`: canonical guest-Poseidon leaf and parent both pass
  70 queries / 26 PoW bits, fresh outer-artifact verification and source/pin
  mutation rejection. Four-worker testing-allocator total was 96.643911 s;
  this is qualification, not a matched recursion speedup experiment.

The complete pre-change CPU/Metal suite has finished: all 32 cases independently
verified. Old CPU/Metal executables and the matching AOT bundle are preserved
under ../2026-09-23-blake3-csp-regression/baseline-products/.

The supervisor in exec session 83181 is terminal with exit code 0. Both products
built successfully. All 32 candidate CSP cases and all eight paired ECDSA runs
independently verified. See [RESULTS.md](RESULTS.md), `ecdsa-summary.json`,
`stage-medians.json`, `suite/` and `ecdsa-pairs/`. The complete table is also in
vectors/riscv_csp/README.md. The source overlay matches the current source byte
for byte; the binaries and matching AOT bundle are retained in candidate-products/.

Measured ECDSA paired medians improved 6.902855 -> 3.557679 s CPU (1.94x) and
7.097355 -> 3.822391 s Metal (1.86x). SHA-256/128 improved 85.044773 -> 6.074877 s
CPU (14.00x) and 92.526896 -> 5.447985 s Metal (16.98x), using single cold samples.
CPU SHA-256/128 physical peak fell from 39,320,401,512 to 3,755,953,728 bytes.
The verified candidate artifact's plan implies exactly 451,640 G rows, padded
2^19, versus the old 4,997,216 rows padded 2^23. ECDSA geometry is 63,000 G rows,
padded 2^16, versus 489,328 padded 2^19. Row reductions are not timing ratios.

Historical approximately 0.88-second ECDSA is NOT restored. Remaining paired CPU
stage medians include main commitment 0.370 s, interaction commitment 0.445 s,
composition evaluation 0.468 s and PoW 0.854 s. Metal spends 0.502 s main,
0.585 s interaction commitment, 0.441 s composition, 0.301 s sampled evaluation,
0.805 s FRI quotient/commit, and 0.027 s PoW. Precompile interaction remains
approximately 0.017 s. The remaining gap is not primarily the ECDSA precompile.

Next investigate shared table/commitment geometry and backend PCS costs against
these profiles. The native lookup schemas include domains of size 2^18 through
2^20; measure which are active before attributing composition or commitment cost
to them. No sparse-table implementation or further speedup is claimed here.
The original recursion goals and repository-wide hash/PCS work remain active.
