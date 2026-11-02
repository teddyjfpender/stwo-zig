# Bounded RV64 AIR qualification — 2026-10-30

The concrete RV64 frontend now has genuine native STARK proofs, authenticated
register/RAM transitions and fresh-verifier rejection of arithmetic-valid state
forgeries. [Qualification receipt](qualification.json) includes exact source
hashes, security parameters, measurements, limits and non-green repository gates.
[Retained proof-test output](proof-tests.log) records the final ReleaseSafe run.

| Five-instruction fixture | Initial reference | Compact physical layout |
|---|---:|---:|
| Fixed columns | 229 | 21 |
| Main columns | 2,371 | 643 |
| Interaction columns | 36 | 36 |
| Trace rows | 32 | 32 |
| Committed trace cells | 84,352 | 22,400 |
| Composition cells | 512 | 512 |
| Trace opening-mask samples | 2,640 | 704 |
| Composition opening-mask samples | 16 | 16 |
| Full binary proof bytes | 512,424 | 127,224 |

The initial proof is a historical observation; its uncompacted source snapshot
was not separately retained. The receipt fingerprints the current compact source.
These figures are representation comparisons on one fixture. They are not a
retained-source timing A/B, CSP throughput or block-proving speedup.
The final measured compact run took 998.23 ms to produce a proof, 1.46 ms to
encode, 0.68 ms to independently construct reusable setup, and 43.27 ms to decode
and verify using that setup. One observation only; PoW and allocator-accounting
costs are included. Peak caller-tracked producer payload was 995,370 bytes;
that is not process RSS and excludes allocator overhead and untracked allocations.

A separate 63-step fixture contains every retiring RV64IM opcode and verifies a
564,576-byte proof. Another proof exercises backward branches and three-way
register aliases. Three malicious proofs retain valid local arithmetic while
forging register custody, initial RAM, or write permission; each is captured,
serialized, freshly decoded, and rejected by the verifier with `OodsNotMatching`.
The test suite also substitutes expected state, program, permissions and upper
address bits, alters access clocks, weakens configuration and corrupts openings.

The physical projection is derived from public program/path bytes, never witness
values. One shared polynomial evaluator serves domain and OODS checks. Witness
rows are built once and released after projection; source columns are released
after PCS preparation. Verifier setup owns copies of its immutable identity and
can serve distinct request states without accepting producer-supplied authority.
Setup is still path-specific; a reusable program-only ROM is separate work.

Reproduce from the repository root:

```sh
zig build test-riscv64-execution test-riscv64-air test-riscv64-proof -Doptimize=ReleaseSafe
python3 -m unittest scripts/tests/test_riscv64_tools.py
```

The envelope remains 256 retirements and 128 explicit memory words. Full CSP/OP
proofs, global continuation, independently sized crypto/RAM providers, recursive
verification and RV64 Sail qualification remain open. Broad source/package gates
have existing failures; formal refinement also lacks the pinned Sail checkout.
No complete release-gate pass is claimed. See the [AIR contract](../../../../design/riscv-proving-stack/rv64-air.md).
