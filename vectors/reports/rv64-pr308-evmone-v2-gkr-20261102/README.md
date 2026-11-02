# First admitted evmone v2 guest + OM31/GKR integration

Complete block24,628,607: **44,755,877 instructions,11CPU+4truth proofs,143.851s proving,158.44s process wall,37.786GB peak RSS**. The fresh receiver accepts the complete block and the43-byte output matches the independently compiled native host. Previous guest:104,253,913 instructions,25CPU+5truth,292.261s proving. **2.03x observed proving improvement**, one run, no recursion/GPU. Different guest and proof inventory; no byte-parity comparison across guests.

The RV64IM admitted guest and native host were built from pinned PR308 snapshot2490495dd on the isolated integration branch. ABI symbols and terminal PC are derived from this ELF. The input adapter generates untrusted recovery hints checked by the guest. Source revision06f1c3ee6 includes the v2 geometry-hash compatibility fix. Build manifest, request identities, resource profile, native collection, proof hashes and receiver output are recorded here. Large ELFs/work packets/proof binaries remain in the scratch paths named by request.json; they are not committed.

The native assumption-qualified128-bit target is re-budgeted from the fresh receiver's15-proof shape using `model.py --reviewed-v2-envelope`. The optional model accepts only a monotone subset of the original reviewed v2 envelope; it rejects v3 providers, throughput Keccak, new CPU pair layouts and excess support. Original model output is identical under both modes on the old fixture;12 unauthorized mutations reject. `security_qualified=false` still denotes no certified whole-protocol claim.

V3 support, new layout adapters, final-client EEST and current-profile recursion remain separate work. This is a usable integration checkpoint while PR308 continues, not its final merge or final performance.
