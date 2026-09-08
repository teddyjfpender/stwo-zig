# Native19 verification-only preparation

Executed after the controlled v6 replay completed successfully. Native19 was
freshly verified and accepted with exit zero; accepted inventory is now
**21 leaves (0–19 and 120)**. No previous leaf was re-verified and no producer
was started. The canonical proof and raw producer metadata remained unchanged.

The verifier reported 63.780496 seconds per request, 60.346030 seconds in its
verification field, and 1,321,354,800 bytes peak physical footprint. The admitted
monitor measured 63.879298 seconds and 1,312,998,936 bytes peak, within the
3 GiB envelope. This is a complete native verification request, not an isolated
STARK kernel benchmark. Exact acceptance/custody evidence is
`operation-accepted.json`, with the fresh verifier request, execution, scheduling
and stdout receipts alongside it.

The only repository change extracts the controller receipt predicate and makes
its metadata-to-published-object binding explicit. The predicate reads original
metadata once, compares canonical JSON (including JSON type distinctions), and
checks the receipt hash against those original bytes. Existing controller
resume semantics remain unchanged: every resumed proof is freshly verified.

The frozen v5 Python closure derives from admitted v3 and changes only the
controller and its focused test file. Its bounded verifier and global lock
remain byte-identical to v3. v4 is superseded by v5 before any launch.
46 active tests and 38 frozen tests passed. Direct receipt mutations cover every
receipt binding, the outer fixed-program endpoint, and unrelated/type-changed
published metadata. The one-off operation script was syntax checked only.

The reviewed operation will lock the existing campaign, require native19 still
unaccepted, recheck pinned source and candidate custody, then invoke exactly the
retained one-worker fixed-program-v5 native verifier through the admitted bounded
lane. It publishes append-only request, execution, scheduling and stdout receipts.
Only exit zero plus the shared receipt check and post-execution custody checks
permits canonical leaf-000019.json publication. It never calls the production
loop, re-verifies earlier leaves, or starts producer20. The final whole-block
verifier still has to validate exact coverage and continuation.

This accepts a separately pinned successful native verifier execution; parsing
a stdout receipt alone is not cryptographic verification. A failed attempt is
retained and its output directory cannot be reused; a retry needs a new pinned
request/attempt. Resource admission may reject before launching, and only this
operation's verifier can be terminated by the admitted monitor.

Executed command (retained attempt is create-only; do not re-run):

```sh
cd /Users/theodorepender/Coding/stark-proving-engineering/stwo-zig/.git/local-ethereum/bounded-native-verifier-source-v5/source
python3 /Users/theodorepender/Coding/stark-proving-engineering/stwo-zig/.git/local-ethereum/native19-verification-only-v1/accept_candidate.py /Users/theodorepender/Coding/stark-proving-engineering/stwo-zig/.git/local-ethereum/native19-verification-only-v1/request.json f280392c76c47a860f10a6326a6665ea9d1311eb40b7f0900354b79492f31073
```
