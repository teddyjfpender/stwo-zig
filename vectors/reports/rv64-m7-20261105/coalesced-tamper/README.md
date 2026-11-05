The actual 14-leaf coalesced headline proof rejects all six requested full-receiver mutations in fresh CPU-only processes. A seventh, stronger check coherently corrupts the top fold and exported root together and also rejects cryptographically. All original proof-directory file fingerprints remain byte-identical before/after every case. Fixtures use hard links; every modified file is atomically replaced, so no mutation writes through an original link.

| Mutation | Explicit nonzero rejection | Check reached |
|---|---|---|
|Merged add truth first_id+1|InvalidCombinedTruthSpan|Wire/source span admission, before native keys/fixed authority/proof verification|
|Merged add calls−1|InvalidCombinedTruthSpan|Wire/source coverage admission|
|Omit last truth declaration and its proof|InvalidCombinedTruthSpan|Wire/source coverage admission|
|Select M6 native profile for D2 bundle|GlobalGkrManifestExecution|Execution/profile binding after independent authority construction, before recursive verification|
|Flip merged add truth proof bit and coherently update bundle SHA|RootMismatch|Native cryptographic verification; no file-hash mismatch shortcut|
|Flip exported root.proof|RecursiveReceiverArtifactMismatch|Binds duplicate root export to independently reconstructed top fold, after native verification|
|Flip same bit in top fold AND exported root|RootMismatch|Recursive cryptographic verification; duplicate-root equality retained|

The first three stop in 0.29–0.31s before expensive proof verification. Wrong profile 12.85s, native corruption 16.76s, root export 40.27s, coherent root 40.03s are diagnostic rejection-process times, not performance claims. Every result has exit 1, an explicit error, no panic/signal, GPU visibility empty, GPU helper /bin/false, setup/class stores absent and fold cache disabled. Receiver SHA is ddcbcf4b24aaf770f8b42d22188ea3c3c9b7f57726db1d0aa9cb09be27069b42, identical to the accepted positive composed gate.

Reproduce the six cases with `python3 scripts/rv64_m7_coalesced_tamper.py --run /workspace/m3/runs/m7-fold-v3/daemon-24628607-r2-combined-d2-coalesce-v1 --receiver /workspace/m3/build/m7-combined-d2-receiver/zig-out/bin/rv64-word16-ethereum-recursion-receiver --out NEW_DIRECTORY`. Add `--cases recursive_root_corruption --coherent-root` for the stronger root check. Existing output directories are refused. Receipts bind complete original fingerprints, actual command/process usage, receiver isolation, mutations/omitted files and exact errors. Fresh positive acceptance is retained in the composed evidence package. Raw mutant fixtures remain at receipt paths on the pod; CPU request/stdout/stderr receipts are local.

The initial harness attempt encountered the expected exit 1 but its positive-only helper raised before recording a negative verdict. Its log is preserved. The fixed harness uses the exception's exact wait4 measurement; the completed six-case and coherent-root receipts above pass. Author: OpenAI Codex.
