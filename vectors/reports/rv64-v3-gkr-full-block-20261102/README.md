# Complete V3 native GKR block qualification

Ethereum mainnet block **24,628,607** completes through the authenticated V3
services lane. Seven CPU GKR proofs and eleven OM31 classic truth proofs close
one shared execution's RAM, Keccak I/O and service Wire claims. Truth-local
lookup claims close inside each truth proof; they do not escape as unauthenticated
execution claims.

| Measurement | Result |
|---|---:|
| Retired instructions | 26,894,777 |
| CPU / truth proofs | 7 / 11 |
| Proving | 81.775 s |
| Producer process wall | 93.33 s |
| Fresh verification, excluding setup | 1.229 s |
| Fresh receiver process wall | 10.26 s |
| Producer peak memory footprint | 20,224,803,736 bytes |
| Retained MAIN bytes after proving | 0 |

These are single correctness runs on the local CPU, with profiling enabled.
They exclude recursion and GPU work and establish no controlled speedup claim.
The profile is OM31, blowup 2, 256 queries, no PoW and fold step 4: **128-bit
security target under documented assumptions**, not certified whole-protocol
128-bit security. Source-derived lookup admission is independently recomputed
by the fresh receiver. See the [V3 source accounting review](../../../design/riscv-proving-stack/rv64-v3-source-accounting.md)
for its distinction from the old nine-namespace diagnostic envelope.

All CPU shards use the authenticated U8-pair CPU representation and LS-D64
head/tail routing. Sponge call/permutation providers and bulk/JUMPDEST providers
are joined to the same shared execution. The actual truth roster contains four
Keccak spans (including R27 throughput policy), three secp ADD spans, two secp
DOUBLE spans, SHA-256 and arith256. Curve families absent from this Ethereum
block have separate physical proof/fresh-verifier tests in the V3 truth suite.
The three two-shard execution fixtures separately exercise endpoint/claim
mutations and split truth spans in ReleaseSafe and ReleaseFast.

`request.json` pins the ELF, ABI symbols, input and expected 43-byte output.
The producer was built from `1016e3cf3` plus the retention correction committed
as `f76113f06`; the binary hash is in `qualification.json`. A fresh process built
from `6423bc59e` accepts the serialized bundle and derives identical source shape
and lookup degrees, after integrating PR308 through `b059ed0be`. It also accepts
the unchanged complete V2 candidate bundle. `artifacts.json` hashes the retained
scratch proof files; large proofs and RAM sidecars are deliberately not committed.

The guest ELF measured here predates the final PR308 guest patches. Those source
changes are merged but are not a new guest benchmark in this receipt. Additional
classic fused lookup layouts are deliberately disabled and rejected in GKR until
their query projections are separately qualified; they are not needed to prove
this full V3 guest. Optimization, compact-decode GKR adaptation, recursion and GPU
qualification are separate work.

The first block attempt found an obsolete V2-only guard in truth retention
planning. The correction validates the selected Keccak policy and uses its
actual table sizes and pair-row geometry. `initial-retention-guard-rejected.log`
retains that failure; `producer.log` records the successful run.

Final integration check: PR308 through `57c541894` is merged. The runtime at
`167e1b887` freshly accepts both complete V3 and unchanged V2 bundles and derives
the same V3 source bounds. The V3 ReleaseSafe suite passes after that merge.
The separately registered admission mutation test rejects all five unqualified
classic layout flags, including compact decode. See `latest-*.json/log`.
