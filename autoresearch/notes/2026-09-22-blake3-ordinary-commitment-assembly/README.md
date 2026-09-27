# Combined ordinary BLAKE3 commitment preparation

Shared program admission now produces the same canonical decoded instruction
fields and fetch multiplicities before hash selection. BLAKE3 program leaves
encode full canonical u32 field values with a distinct tag, reusing memory-tree
node framing/topology. Private leaf/path preparation supports the four-byte
field source as well as the existing one-byte memory source.

Owned prover preparation derives program and custody-aware ordinary memory
roots, disjoint boundary schedules, fail-atomic full-width public-root binding
and per-work-item memory witnesses. Verifier public compensation reuses the
execution and I/O terms without emitting scalar Merkle root tuples.

ReleaseSafe focused validation passed:
- test-riscv-statement-codecs: 39 s, 1 GiB; combined assembly plus legacy program
  admission and public-data/public-LogUp regressions are explicitly selected.
- test-riscv-blake3-memory-path: 33 s, 1 GiB; minimum test count raised to two.
  Both byte-memory and canonical program-field 0x7ffffffe openings prove and
  verify over all 30 levels; changed-root claims reject. Diagnostic q8/PoW0.

The path STARK sources are public fixtures; it is not a proved program fetch.
Production component placement, program-access-to-hash wiring, complete memory
relation closure and artifact/key admission remain required. No production
default, complete RISC-V proof or recursion speedup is claimed.
