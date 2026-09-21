# ECDSA benchmark boundaries

The qualified recursive-parent benchmark creates only the final parent of an
already-produced eight-segment RISC-V tree. It is not a native CSP or ECDSA run.

The canonical CSP manifest has 16 cases: SHA-256 at 128/256/512/1024/2048 bytes,
Keccak at those sizes, Poseidon2-M31 at 2/4/8/12/16 field elements, and secp256k1
ECDSA over a 32-byte digest. All declare uses_precompile=false. ECDSA executes
5,425,005 RV32IM instructions. Its invalid-signature fixture is also checked.

The retained August provider result was 166.911 ms CPU / 176.933 ms Metal for
proof production, plus 2.807 / 2.845 ms fresh verification. Its harness supplies
the public relation counterpart directly. Current source configures zero PoW
bits and three FRI queries (testing/secp256k1_proof_harness.zig). Canonical CSP
requires 26 PoW bits and 70 queries. These are different workload and security
boundaries; the provider number must not replace the CSP row.

Current Ethereum-profile code does include signer-recovery execution and caller
components, including memory transitions. That is a separate ABI/statement from
the pinned CSP signature-verification guest. This inspection does not claim that
all caller integration is absent; it establishes that it is not the canonical
CSP manifest's measured path.

Fresh suite: isolated clean source snapshot, host-native ReleaseFast CPU/Metal
products, all 16 cases each, 16 workers, one warmup and ten samples. Results are
written outside the snapshot. Dirty-tree and parameter admission are not bypassed.
The first active-tree build was stopped once its dirty provenance was identified;
no timing measurements from that build are used.
