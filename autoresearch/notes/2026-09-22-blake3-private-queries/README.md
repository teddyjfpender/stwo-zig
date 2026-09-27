# Private transcript queries and constrained Merkle directions

The parent exports ordered masked BLAKE3 query words, including the partial final
batch. A canonical field-byte encoder consumes each DEEP query-position scalar
and consumes the matching transcript word through output multiplicity p-1. DEEP
constrains its position to its query bits. Those same scalar bit sources feed
FRI and every Merkle path selector. FRI derived positions, offsets and last-layer
positions are private witnesses constrained by its existing arithmetic graph.
No public query/position/bit boundaries remain in this parent assembly.

The new typed `blake3_path_select` AIR consumes an authenticated bit, current
hash word, and sibling word, and emits ordered left/right words. Its equations
are bit*(bit-enable)=0, left=current+bit*(sibling-current), and
right=sibling+bit*(current-sibling), applied to all four bytes. Inputs are bounded
by their existing hash/private-word producers. It has 17 main columns, 12 fixed
columns, 9 direct roots, 5 relation events, 3 interaction batches / 12 columns,
and degree 2. Semantic identity:
`ca02f857d38bd44000ddfe833db1ce15cee6a3d983921b01facef5b5df665b7f`.

Every upper path level uses eight selector rows. Selected left/right digests
occupy disjoint ranges in one circuit. Framing admission now permits disjoint
same-circuit digest ranges and rejects overlaps; its existing witness resolver
already resolves both circuit and word range. Existing public group/transcript
APIs keep their previous behavior when private sources are absent.

Trace directions use parity-preserving projection: level 0 consumes raw bit 0;
higher levels consume raw bit (lifting_log-tree_log+level). FRI directions use
raw bit (lifting_log-path_depth+level). The distinction follows native
core.pcs.utils.prepareTreeQueryPositions. Original raw query order and duplicates
are preserved. Path multiplicities are accumulated at canonical DEEP bit nodes.

Validation history:
- An initial focused identity-generation run computed the new AIR digest and
  deliberately failed the zero placeholder pin before it was replaced.
- The first engineering batch exposed a Zig union-capture type mismatch and the
  old same-circuit framing restriction. Both were corrected; direct execution
  confirmed the selector failure was InvalidBlake3FrameCaller.
- Routed transcript tests and standalone arithmetic regression passed in that
  first batch. A second serial batch passed 6/6 tests: typed selector, byte
  routing/framing, canonical query mappings, and complete parent proof.
- Review then identified that the initial generic shift needed separate trace
  parity handling. A native-oracle projection test was added; its mapping and
  complete-parent rerun exited 0 (8/8 steps, 2/2 tests). The earlier parent fixture
  alone did not establish correctness for nonzero lifting differences.

Scope: the combined test proves an original native STARK and a joined parent
under BLAKE3, not a production RISC-V or parent-of-parent migration. The key-root
anchor remains intact. Lifted-column alias sharing still depends on captured
query geometry and is deliberately retained: removing it without replacing its
consistency obligation would weaken the admitted protocol. PoW nonce, rejection
scheduling, reusable key admission, alias scheduling, CPU/Metal qualification and
end-to-end performance remain unfinished. Production still uses Poseidon.

Final evidence spans nine distinct tests across six focused targets:

| Target | Tests | Runtime | Peak runtime RSS |
| --- | ---: | ---: | ---: |
| test-blake3-path-select | 1 | 475 ms | 3 MiB |
| test-blake3-byte-route | 3 | 644 ms | 8 MiB |
| test-qm31-pack-wire (final) | 1 | 1 s | 2 MiB |
| test-blake3-routed-transcript | 2 | 4 s | 352 MiB |
| test-blake3-combined-fri (final) | 1 | 30 s | 6 GiB |
| test-blake3-fri-arithmetic-proof | 1 | 5 s | 368 MiB |

All builds used the repository serial wrapper, ReleaseSafe and --summary all.
The final two-target build compiled mapping in 5 s and combined proof in 37 s.
Test times are diagnostics, not end-to-end speedup measurements. The arithmetic
profile explicitly admits domain logs at most 30, so its query-position field
encoding cannot encounter the noncanonical M31 value 2^31-1. All touched Zig
files pass formatting and `git diff --check` passes.
