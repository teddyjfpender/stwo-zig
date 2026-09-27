# Retained short-message BLAKE3 optimization

Production change: `Blake3Hasher.hash` handles messages up to one chunk (1024 bytes) without constructing streaming state or a CV stack. It uses the existing canonical compression implementation, with compile-time lane indices. Larger messages and streaming hashing keep the standard implementation. Hash framing, domains, digest bytes, and security parameters are unchanged.

## Matched commitment + 70 openings + verification

Same contract as the parent README. Frozen old local, new local, and peer binaries are alternated in one battery-powered session, one CPU worker each. Seven medians after warm-up, in milliseconds.

| Rows | Bytes/row | Before | After | Peer | Peer / after |
|---:|---:|---:|---:|---:|---:|
| 1,024 | 32 | 0.392 | 0.281 | 0.334 | 1.19× |
| 65,536 | 32 | 9.372 | 6.326 | 8.544 | 1.35× |
| 1,048,576 | 32 | 147.696 | 99.628 | 134.928 | 1.35× |
| 65,536 | 256 | 18.726 | 15.558 | 20.907 | 1.34× |
| 65,536 | 1024 | 56.826 | 52.916 | 71.171 | 1.34× |

New local commitment/opening and verification medians individually beat the peer in all five fixtures. All nodes and paths match; cross-verification succeeds; mutated roots and paths fail. This establishes superiority on these measured CPU fixtures, not across architectures or full provers.

## Native framed production commitment

Same native LDE/commit pipeline and inputs before/after; identical roots, one worker. These timings are not compared to ZisK’s different native protocol. Commit medians in milliseconds:

| Input rows | Columns | Before commit | After commit |
|---:|---:|---:|---:|
| 1,024 | 8 | 0.831 | 0.804 |
| 16,384 | 8 | 6.417 | 6.177 |
| 65,536 | 8 | 18.674 | 17.989 |
| 16,384 | 64 | 7.157 | 7.233 |

Narrow native commitments improve approximately 3–4%; the wide case is effectively unchanged (about 1% slower commitment, approximately unchanged pipeline total in this run). Native leaf hashing still uses streaming and native parent frames require two compression blocks. Do not transfer the matched-protocol speedup wholesale to native proof estimates.

## Qualification

- 65 ReleaseSafe tests passed. Differential check against standard BLAKE3 at every length 0 through 4097, including empty input, full blocks, full chunks and multi-chunk fallback.
- `test-blake3-proof`, `test-blake3-challenge-proof`, `test-blake3-routed-proof`, and `bench-keccakf-blake3-system` passed with the serialized build wrapper. The last uses 70 queries, 26 PoW bits and 16 workers. Its single timing is qualification only, not an end-to-end speedup claim.
- Matched harness checks every tree node, 70 paths, roots, cross-verification and corruption rejection on all five fixtures. Native benchmark checks unchanged roots.

## Reproduction

From the repository root:

```sh
python3 autoresearch/notes/2026-09-24-zisk-matched-commitment/build.py optimization/after.dylib
python3 autoresearch/notes/2026-09-24-zisk-matched-commitment/run_optimization.py
python3 autoresearch/notes/2026-09-24-zisk-matched-commitment/build_native.py
python3 autoresearch/notes/2026-09-24-zisk-matched-commitment/run_native.py
```

Raw samples, binary identities, power metadata, qualification logs, and frozen source archive accompany this report. Baseline comparison needs the retained baseline binaries. No full CSP suite or recursion timing was rerun for this bounded change.
