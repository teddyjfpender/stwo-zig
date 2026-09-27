# CSP full-width benchmark reader

The software benchmark reader recognizes riscv_full_width_execution_v2 and parses
B3RVART1/B3EVART1 binary framing. It checks serialized q70/26 policy, ELF/input
hashes, exact STARK payload lengths, report artifact hashes, additive nanosecond
partitions/median, actual Metal proof dispatches and CPU fallback counts. It then
requires a separate CLI verifier receipt matching source/output hashes, statement,
transcript, artifact, executable and commit. Dirty executable rejection remains.
Proving time includes execution, witness, admission and proof generation;
serialization is excluded. Fresh verification/key derivation is separate.

Proof size remains the serialized STARK payload, excluding metadata/claims. The
actual retained canonical base artifact parsed as 608,000 STARK bytes versus
609,851 file bytes. Unit tests explicitly cover framing/policy corruption,
source/output/timing drift, missing Metal dispatch and fresh receipt substitution.
34 focused tests passed, including prior suite/native-isolation/wiring tests.
The wiring fixtures needed their already-required suite field restored; production
cohort checks were not relaxed. Command:

    python3 -m unittest scripts.tests.test_riscv_csp_full_width scripts.tests.test_riscv_csp_proof_suites scripts.tests.test_riscv_csp_native_isolation scripts.tests.test_riscv_csp_benchmark_wiring

Rows explicitly identify commitment_model=full_width_blake3. Aggregate evidence
tracks whether every row uses that contract, preventing a core-hash-only ECDSA
row from silently qualifying the whole suite. No resident-polynomial acceleration
claim is inferred from general Metal dispatches. Full-width route qualification
and its timing definition are stated in report limitations.

No full CSP suite measurement is claimed: dedicated ECDSA routing is still on the
older commitment path, and the new reader needs an actual ReleaseFast suite run
once integration is complete. Existing legacy report/artifact reading remains.


Actual new Ethereum CLI output is now available in the neighboring product-artifact
directory. Its binary framing parsed successfully as B3EVART1, with 5,566,284 STARK
bytes out of 5,599,503 artifact bytes. Fresh verifier public/source/transcript
summaries matched the prover report. This validates the artifact/receipt inputs,
but is not an actual full CSP harness run: the synthetic fixture output is empty,
whereas CSP requires 32 bytes, and this executable is dirty/ReleaseSafe.
