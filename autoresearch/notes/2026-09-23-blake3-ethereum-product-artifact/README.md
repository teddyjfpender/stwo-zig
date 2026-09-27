# Full-width Ethereum product artifact (qualification pending)

Base B3RVART1 and Ethereum B3EVART1 now share bounded framing and fresh verification
through a compile-time profile implementation. Base facade API/wire identity stay
unchanged. The Ethereum artifact authenticates its B3EHADM1 manifest, checks actual
ELF/input and initial roots, derives a trusted verifier key, destroys decoded
metadata, then consumes the independently decoded proof.

Explicit BLAKE3 Ethereum-profile prove/bench requests now use the same product
transaction and atomic publication path as base execution. Verify routes by exact
artifact magic and derives the key on CPU. A bounded scoped pool is retained
across Ethereum benchmark samples. Report schema riscv_full_width_execution_v2
adds admission_ns and execution_profile; key construction is an explicit phase,
not hidden in proving or encoding. Total includes all six phases. Guest Poseidon
semantics and legacy/default profile routing are unchanged.

New proof fixture checks complete-artifact round-trip, fresh verification,
externally pinned identity rejection, truncation and base/Ethereum format
separation. Syntax checks passed; runtime/product qualification is pending:
- /tmp/blake3-shared-manifest-base-regression.log
- /tmp/blake3-ethereum-artifact-cpu-product-build.log
- /tmp/blake3-ethereum-full-artifact-proof.log

The earlier canonical Ethereum manifest-only gate passed in the neighboring
blake3-ethereum-manifest directory. It does not qualify this newer code. The
retained ELF reproduces the existing one-signer/one-Keccak fixture with full
release ABI and exact Ethereum note. Expanded block proving remains deferred.
Standalone Poseidon/Keccak profiles, CSP routing, defaults and old prover-owned
hash removal remain outstanding.


## Shared base regression passed; product correction pending

The base real-proof regression passed after shared profile framing extraction,
including its recursive subcases. The first CPU product compile failed because
WorkPool.InitOptions requires worker_count. The current product explicitly uses
min(host CPU count, 16), at least one worker, and retains that scoped pool across
samples. Corrected build: /tmp/blake3-ethereum-artifact-cpu-product-build-v2.log.

The full Ethereum artifact test is live under the originally queued handle;
no duplicate test was restarted. Its compiled code predates the following
public receipt extension, which must be qualified by the corrected product build
and subsequent CLI checks.

Public verification can now return a fixed-size summary only after successful
proof verification: transcript, output length/SHA-256, ELF/input SHA-256, and
execution steps. Output bytes are hashed from the authenticated prepared statement,
not copied from an unverified runner result. Product reports and fresh verifier
receipts expose this summary and selected PCS parameters. Benchmark reports also
include existing process resource telemetry. The original digest-only API remains
available without summary allocation or re-decoding.

CSP follow-up identified: the software benchmark harness still assumes a legacy
JSON artifact/report and must branch for the new binary full-width format, checking
these fresh-verifier output/source hashes and timing partitions. Its separate
ECDSA command still uses the older commitment path. No full-suite migration or
benchmark result is claimed before both are updated and qualified.


## Full artifact gate and corrected CPU product build passed

The q70/26 Ethereum outer artifact test passed, including independently derived
admission, fresh verification, wrong external identity, truncation and cross-profile
format rejection. This test predates the public-summary receipt extension. The
corrected CPU product build passed with that extension and the explicit worker
count. A canonical Ethereum CLI proof is now running at
/tmp/blake3-cli-ethereum-canonical-prove.log; no CLI success is claimed yet.


## Canonical CPU Ethereum CLI proved and freshly verified

The explicit full-width Ethereum product route passed a q70/26 CLI prove and a
separate CLI verify process. Artifact: 5,599,503 bytes; serialized STARK payload:
5,566,284 bytes. The binary CSP reader parsed both profiles' real canonical
artifacts. Output length/hash, ELF/input hashes, execution steps, artifact hash
and transcript agree between Ethereum prove and fresh verification receipts.
The previously retained base artifact also freshly verified with the correct
one-byte output hash under the new public-summary API.

This tiny one-signer/one-Keccak ReleaseSafe fixture took 154.286922125 seconds:
execution 0.001230084, witness 18.307247375, admission 3.915553,
proving 125.707944791, encoding 1.043624167, fresh verification 5.311322708.
It is functional integration evidence, not a speed improvement or a comparison
with the ReleaseFast ECDSA CSP result. The report retains experimental status.

The canonical Ethereum artifact, ELF and receipts are retained here. Metal
Ethereum product qualification and dedicated ECDSA CSP migration remain unfinished.
