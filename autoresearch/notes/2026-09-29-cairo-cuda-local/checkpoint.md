# CUDA qualification checkpoint

This checkpoint preserves Cairo frontend work, CPU and Metal performance improvements, canonical CUDA execution and witness support, local translation checks, independent Rust diagnostics, and benchmark scripts and receipts.

CUDA qualification is still in progress. The canonical all-opcodes CUDA proof has not passed complete verification: composition OODS and FRI degree failures remain under investigation. No SN PIE CUDA proving measurement is accepted yet. Diagnostic runs must not be treated as benchmark results or as complete proof verification.

Canonical security stays fixed at 70 queries, 26 query PoW bits, 24 interaction PoW bits, blowup 1, fold step 1, last degree 0, no lifting and the full canonical preprocessed trace. CPU and Metal benchmark receipts already record qualified baseline results.

The checkpoint includes source, documentation, lightweight evidence and fixtures required by the source and tests. Generated executables, native captures, memory tables and proof dumps stay local. Runpod account, session policy, pod environment and private connection records are excluded. A credential scan covered the staged source and evidence.

For this in-progress checkpoint, source diff checks run separately from preserved patch and log evidence. Full build hooks and CI watching are deferred while CUDA work continues; this is not a qualification or release assertion.
