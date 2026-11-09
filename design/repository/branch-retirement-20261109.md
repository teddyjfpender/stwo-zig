# Remote branch retirement policy, 2026-11-09

Owner-directed B2 transaction after PR #323; tracked in GitHub issue #334.
This is the frozen literal-name policy, not an execution receipt.
Source main: `99f2e13f713be28951c7faff4b6286a9524f1c96`. Observed UTC: 2026-11-09T17:37:22.485511+00:00.

Publish archive tags for the exact SHAs below and verify their remote targets
before deleting any matching branch. Delete only literal names with SHA leases.
Changed heads, conflicting tags and newly opened PRs must be skipped.
Protect default main, backup/*, all open PR heads, active post-merge branches,
active CI heads and the parked typed-witness benchmark candidate.

Explicit active branch protections:

- `main`
- `codex/typed-witness-benchmark-candidate-20261109`
- `codex/phase0-workspace-contracts-20261109`
- `codex/phase0-branch-retirement-20261109`
- `codex/sweep-flags-20261109`
- `codex/sweep-versioned-copies-20261109`
- `codex/sweep-riscv-packages-20261109`
- `codex/sweep-ethereum-statement-20261109`

## Eligible literal names

Columns: branch, exact commit, archive tag.

```tsv
archive/pre-restructure-20261108	51897dc265593df7580c4abf0b232909fc105e34	archive/branches-20261109/archive/pre-restructure-20261108
archive/riscv-ethereum-block-v5-20261006	f374b1db65653919be2c36bbe71713adf27a7f2f	archive/branches-20261109/archive/riscv-ethereum-block-v5-20261006
challenge/proof-v2-stage-timers	8cf3b41909ec1a5ba190e65ac42bffcf9be47721	archive/branches-20261109/challenge/proof-v2-stage-timers
codex/cas05-canonical-input-boundary-20261013	884d090c7fa63782b38f6c7159f20a9c20d5eb62	archive/branches-20261109/codex/cas05-canonical-input-boundary-20261013
codex/cas05-extractor-channel-pin-20261013	2b090356cbb2e5146c11675e4b3c6f9571545fd8	archive/branches-20261109/codex/cas05-extractor-channel-pin-20261013
codex/cas05-merkle-byte-separation-20261013	5ef41db51bf9eff06eba0e6d3ad98f32b51ba579	archive/branches-20261109/codex/cas05-merkle-byte-separation-20261013
codex/cas05-native-boundary-followup-20261013	f2201e75710d1e01a1df0798a63791e43a62cb61	archive/branches-20261109/codex/cas05-native-boundary-followup-20261013
codex/cas05-native-relation-bridge-20261013	52d8dd369cf3f01da80298e3cc7589d8d7e7d5d0	archive/branches-20261109/codex/cas05-native-relation-bridge-20261013
codex/cas05-operational-extractor-20261013	45921058d779bc3bbf9bfa68f4b2951138431eb2	archive/branches-20261109/codex/cas05-operational-extractor-20261013
codex/cas05-protocol-join-20261013	7787a00ba80d688160c65bb4ba8f33b4aa76d5be	archive/branches-20261109/codex/cas05-protocol-join-20261013
codex/cas05-round-cost-bound-20261013	356f1845bd63725e98c77c14ce8c21055c5f2c6b	archive/branches-20261109/codex/cas05-round-cost-bound-20261013
codex/cas05-sampler-pin-followup-20261013	b87d10e11fa0895441c293fa0f956d15c4dfb365	archive/branches-20261109/codex/cas05-sampler-pin-followup-20261013
codex/cas05-secure-draw-tail-20261013	654fa7415b79a3e72c173b85fa5c3f0dd3a19c33	archive/branches-20261109/codex/cas05-secure-draw-tail-20261013
codex/cas05-sparse-profile-audit-20261013	9cd3f2989a96eb32fdf6b6443cf87fa2a71a0a57	archive/branches-20261109/codex/cas05-sparse-profile-audit-20261013
codex/cas05-typed-transcript-20261013	6bad05d860404da039e3d6f1b0300237cdc32227	archive/branches-20261109/codex/cas05-typed-transcript-20261013
codex/circuit-lookup-repeat2	5f6e30934e27e35d13f9a24d2e35070c3172296b	archive/branches-20261109/codex/circuit-lookup-repeat2
codex/circuit-om31-native	6ff10e31777221316ec7a65f025fd358a2bf4c2d	archive/branches-20261109/codex/circuit-om31-native
codex/circuit-production-trace-only	c4af54c528d1ecd10755a5dd02e53920910a1eae	archive/branches-20261109/codex/circuit-production-trace-only
codex/circuit-witness-dag-trace	f694101bc1812236425460e12319388a4ffe6a8d	archive/branches-20261109/codex/circuit-witness-dag-trace
codex/cuda-ingress-transform-snapshot	e7c6b2c57ed31a1bdae704f8f7dd17cfb7eb3648	archive/branches-20261109/codex/cuda-ingress-transform-snapshot
codex/empty-lifted-capture-20261013	1770e013915edb9846ab867ff72c4ae195a5ff08	archive/branches-20261109/codex/empty-lifted-capture-20261013
codex/ethereum-block-fast-lab	b3af8f298e96d87f72382d0ab6d98988b6c1e52e	archive/branches-20261109/codex/ethereum-block-fast-lab
codex/keth-ethereum-op-proving	9f65f77779f700d9e01f9ae7a33667b6b8ff142a	archive/branches-20261109/codex/keth-ethereum-op-proving
codex/migrate-macos-15-runners	e1ebfa9fa99e269b3e3d1ea4a50b8bc5a394d3ef	archive/branches-20261109/codex/migrate-macos-15-runners
codex/riscv-v3-field-witness	9d8b31ad834e33860c164c75e4747bf5a0ae0ce5	archive/branches-20261109/codex/riscv-v3-field-witness
codex/rv64-4gpu-realtime-design	cc05b4d8c60033abdb3b8d6de7c908ad8e87b7da	archive/branches-20261109/codex/rv64-4gpu-realtime-design
codex/rv64-arith-memory	88f89752d2f0c40ed2cf35ab737d5c2fcc1c5815	archive/branches-20261109/codex/rv64-arith-memory
codex/rv64-block-to-inputs	6d28779ce4870eb3f4566e6b508fae825a011bd8	archive/branches-20261109/codex/rv64-block-to-inputs
codex/rv64-candidate-facts	7517d42054f59e32e028f3149ff30ff128a8a6f5	archive/branches-20261109/codex/rv64-candidate-facts
codex/rv64-capture-cli	5adaab6a6128c8a71702edeac9a89a99b1f5cd62	archive/branches-20261109/codex/rv64-capture-cli
codex/rv64-capture-prefetch	822e7a1d72e40772d445d7230f4c798869b1987d	archive/branches-20261109/codex/rv64-capture-prefetch
codex/rv64-classic-packed-inline	9730a7e04839e837d8d44359b238b8b12b3d97c5	archive/branches-20261109/codex/rv64-classic-packed-inline
codex/rv64-classic-witness-parallel	9302378ebdbe4d85ec1dd0a673be5796ea8164b3	archive/branches-20261109/codex/rv64-classic-witness-parallel
codex/rv64-cmp-bits-harness	90d31dc674dd5b653534a356034cf5fb7277499f	archive/branches-20261109/codex/rv64-cmp-bits-harness
codex/rv64-cmp-capture-design	13e318377df3bd23caa68be3f7c1c66be9e19b36	archive/branches-20261109/codex/rv64-cmp-capture-design
codex/rv64-cmp-guest-compare	8804e0d7f24b4d3d692a2553067203443aaadd0b	archive/branches-20261109/codex/rv64-cmp-guest-compare
codex/rv64-cmp-segment-size	334e5e7ed04129075d19d6a87cb000b5f9147c25	archive/branches-20261109/codex/rv64-cmp-segment-size
codex/rv64-combined-air-preflight	402c805a9bcfa3aaf89ef48e4ce4fb389a0bfd21	archive/branches-20261109/codex/rv64-combined-air-preflight
codex/rv64-composed-security-analysis	941aac03927b2e3dfa44deb45c8848cdf55e4730	archive/branches-20261109/codex/rv64-composed-security-analysis
codex/rv64-composite-diagnostics	93ae0182e3e6fe63671662cef40303373f7c2461	archive/branches-20261109/codex/rv64-composite-diagnostics
codex/rv64-composition-coefficient-lease	7b2c75b1a0a93fa6c4aeac264f94b704afb4350d	archive/branches-20261109/codex/rv64-composition-coefficient-lease
codex/rv64-composition-pool-trim	d91938999a86c032cdf31602728d68c0178a2dca	archive/branches-20261109/codex/rv64-composition-pool-trim
codex/rv64-cuda-ethereum	d950665ea0ac6d2a6f7ec6550da5e12de6634eb4	archive/branches-20261109/codex/rv64-cuda-ethereum
codex/rv64-cuda-resident-gkr	26f1bda5eebfc09ed13aafadc28a6e38602cd4bd	archive/branches-20261109/codex/rv64-cuda-resident-gkr
codex/rv64-curve-basket-coverage	8d5b2a3d8112df53e077eee5b7734d74a1ccc273	archive/branches-20261109/codex/rv64-curve-basket-coverage
codex/rv64-deep-dot4-combine	5ef209c5cc4193560093b9be83f5ff7204caf336	archive/branches-20261109/codex/rv64-deep-dot4-combine
codex/rv64-deferred-binding-witness	af8244b32313e238ab4b5c963a8e9c246f60af7d	archive/branches-20261109/codex/rv64-deferred-binding-witness
codex/rv64-device-fixed-ingress-reuse	c0632a6977ebfa6526929b222b8c1ddaa5e89b48	archive/branches-20261109/codex/rv64-device-fixed-ingress-reuse
codex/rv64-dot4-evidence	aa02ee3e9005f8e6f96b88812cfc57dea6149510	archive/branches-20261109/codex/rv64-dot4-evidence
codex/rv64-fixed-column-sharing	161e35b0d9f575ffbeebe26f86c111b6f4204f14	archive/branches-20261109/codex/rv64-fixed-column-sharing
codex/rv64-fixed-native-cache	84bee6108702533cbe405b92e800c7b933c0ca5f	archive/branches-20261109/codex/rv64-fixed-native-cache
codex/rv64-fixed-source-audit	25e84029fcbe264f30af478eccfbe5a5eca63bc0	archive/branches-20261109/codex/rv64-fixed-source-audit
codex/rv64-full-candidate-7282	f90040da6b4423981c88f18bccdb5110448bf33f	archive/branches-20261109/codex/rv64-full-candidate-7282
codex/rv64-ge-base-merge	74d5d5f042ed79d1a787cebb755a36019aea5e7b	archive/branches-20261109/codex/rv64-ge-base-merge
codex/rv64-ge-bulk	b2e1e1d34eff5c713ad93885adbc1d809cac67c0	archive/branches-20261109/codex/rv64-ge-bulk
codex/rv64-ge-calib	87b2bed778b2942d13721d7ca34a184f80049bca	archive/branches-20261109/codex/rv64-ge-calib
codex/rv64-ge-capture	4a56a2229f9088630a1441698b60399eaf16ed01	archive/branches-20261109/codex/rv64-ge-capture
codex/rv64-ge-cells	566b1666bf46f745fc31fdd2716282fbeec37288	archive/branches-20261109/codex/rv64-ge-cells
codex/rv64-ge-cells-fused-tail	e942212128999b4a3afb2e0e7201e94064ad7524	archive/branches-20261109/codex/rv64-ge-cells-fused-tail
codex/rv64-ge-client3	98006b4e720415066922b8f7abe6fdcf0c363268	archive/branches-20261109/codex/rv64-ge-client3
codex/rv64-ge-compexport	71673c23f0a1c7debb5d1857cd6018fccd54d9dd	archive/branches-20261109/codex/rv64-ge-compexport
codex/rv64-ge-curves	2f80736fe75fdcc139b604691fd3f704aa9bea0b	archive/branches-20261109/codex/rv64-ge-curves
codex/rv64-ge-decode	2d8f0c97512003236a9700072699c5acffcc8562	archive/branches-20261109/codex/rv64-ge-decode
codex/rv64-ge-docs	0f062ebd8a49252c2c8b2188e5241b0f4487009f	archive/branches-20261109/codex/rv64-ge-docs
codex/rv64-ge-eest2	3bf1c7b0cc2565d2bd2b17ac5fb20139c67f0047	archive/branches-20261109/codex/rv64-ge-eest2
codex/rv64-ge-fastexec	36ea2091a658415d10fc83c9a6d09ff55f6fd62b	archive/branches-20261109/codex/rv64-ge-fastexec
codex/rv64-ge-final	807d0b5319914144a4d389264be716c79731147a	archive/branches-20261109/codex/rv64-ge-final
codex/rv64-ge-fused-fix	9a4348252f78a059976331c127daeb04e0cf53f0	archive/branches-20261109/codex/rv64-ge-fused-fix
codex/rv64-ge-fused2	ead02e3982129395f32f3fbc0982ff31793f1e54	archive/branches-20261109/codex/rv64-ge-fused2
codex/rv64-ge-gkr-fast	11d62fd3bb16293a267966dee9258dc4d7a7af85	archive/branches-20261109/codex/rv64-ge-gkr-fast
codex/rv64-ge-gkr-v3perf	d6ca3122d0f021e491499c9d0b88fb6279629867	archive/branches-20261109/codex/rv64-ge-gkr-v3perf
codex/rv64-ge-interp	d9054448f222ec4238106a68ea8a37f915aa7c99	archive/branches-20261109/codex/rv64-ge-interp
codex/rv64-ge-jumpdest	637175180dd0881a860468045aeb3dc353556edb	archive/branches-20261109/codex/rv64-ge-jumpdest
codex/rv64-ge-keccak-tput	b83ca8577677ea2338932cea6ccf2e859f3f7028	archive/branches-20261109/codex/rv64-ge-keccak-tput
codex/rv64-ge-keccak2	c58f443b11208bf5115cf40183bd84180bbc24d5	archive/branches-20261109/codex/rv64-ge-keccak2
codex/rv64-ge-logup	9096b4cd776d621d06c2111b4cafa0e4df1dedfa	archive/branches-20261109/codex/rv64-ge-logup
codex/rv64-ge-ls64	94ab999f480f93e4fa71541f18e1db8aa07dff70	archive/branches-20261109/codex/rv64-ge-ls64
codex/rv64-ge-measure	cb7f1f50b2ce9601125499552727207c0d0b94bd	archive/branches-20261109/codex/rv64-ge-measure
codex/rv64-ge-secp	68a0bf90b211127bfd1ca0557cfa3ea3ea28401e	archive/branches-20261109/codex/rv64-ge-secp
codex/rv64-ge-seg23	4e94b9dfc6efbd844b39645ee344c17479ba9b40	archive/branches-20261109/codex/rv64-ge-seg23
codex/rv64-ge-sponge	4c850edf2e6320e4332601eef70e0295990e3b35	archive/branches-20261109/codex/rv64-ge-sponge
codex/rv64-ge-zbb	6ff3450b60229698a665612a95a28db3f66447c7	archive/branches-20261109/codex/rv64-ge-zbb
codex/rv64-ge-zbb2	28976d8c6269c2b302b665e45af7b5f61c7b9a1c	archive/branches-20261109/codex/rv64-ge-zbb2
codex/rv64-generated-inter-accounting	fb552c64c8d5a9329a39cc297f7db0075d03f6fe	archive/branches-20261109/codex/rv64-generated-inter-accounting
codex/rv64-gkr-batched-fold-sum	017f38ec411bcbcc010221e84e2f63e933d0030c	archive/branches-20261109/codex/rv64-gkr-batched-fold-sum
codex/rv64-gkr-beta2-authority	e2c82f01323430ed7a7a5fa1a7fd21ee40d92324	archive/branches-20261109/codex/rv64-gkr-beta2-authority
codex/rv64-gkr-consuming-inputs	ffcc9ba91b5445c809bdf42b86cd2b3c5701e4e0	archive/branches-20261109/codex/rv64-gkr-consuming-inputs
codex/rv64-gkr-direct-capture	913188f0d037a2c66c4fe6b5e37e3722f1e09b36	archive/branches-20261109/codex/rv64-gkr-direct-capture
codex/rv64-gkr-eq-parallel	4ea5f187d893245f9802e5a4fbd25a8a10500114	archive/branches-20261109/codex/rv64-gkr-eq-parallel
codex/rv64-gkr-gate-fusion	36c0b2a0897e4490252fdaa0691a1bdec95149d5	archive/branches-20261109/codex/rv64-gkr-gate-fusion
codex/rv64-gkr-hybrid-tree	6027b32bae786b374e5d8a6126617b7e28b076b1	archive/branches-20261109/codex/rv64-gkr-hybrid-tree
codex/rv64-gkr-late-binding	dbeca8ffcefb2a629051ed960c366e71fd88fb36	archive/branches-20261109/codex/rv64-gkr-late-binding
codex/rv64-gkr-lazy-checkpoint	ca7dd131cd0f90eca6b11ab09ef90e6026db22cf	archive/branches-20261109/codex/rv64-gkr-lazy-checkpoint
codex/rv64-gkr-mixed-fold-sum	7231bbed8ac05b50f3c4ad90c9f6c5ae288e297b	archive/branches-20261109/codex/rv64-gkr-mixed-fold-sum
codex/rv64-gkr-owned-fold	65f79bdc27bb77c0c21cfa5fa55b19034e306680	archive/branches-20261109/codex/rv64-gkr-owned-fold
codex/rv64-gkr-owner-memory	d5037079b2eb0e2e71db65db578bc008b859c0c3	archive/branches-20261109/codex/rv64-gkr-owner-memory
codex/rv64-gkr-paired-fold	81f30b1a6e4c06c313d487199ff976a360c76e42	archive/branches-20261109/codex/rv64-gkr-paired-fold
codex/rv64-gkr-parallel-rows	c645f06ac51faa32d28e9a6a6351859bce48e303	archive/branches-20261109/codex/rv64-gkr-parallel-rows
codex/rv64-gkr-public-aux	07ad5b1fff089e8765c20e2f03de5b5f9d03d5c2	archive/branches-20261109/codex/rv64-gkr-public-aux
codex/rv64-gkr-readiness-guards	fbcd9aaff5832614b4fa01027f6d5dd51888ae16	archive/branches-20261109/codex/rv64-gkr-readiness-guards
codex/rv64-gkr-resource-bound	16c5af89e6c24e72f26be0f8836f0976ce53717a	archive/branches-20261109/codex/rv64-gkr-resource-bound
codex/rv64-gkr-route-speedups	01fff37d829a6280bd846833552dfb2eced472bc	archive/branches-20261109/codex/rv64-gkr-route-speedups
codex/rv64-gkr-stream-bottom	98a870e84d1d281f4afc454268c420ed59de18ce	archive/branches-20261109/codex/rv64-gkr-stream-bottom
codex/rv64-gkr-stream-dense-upper	c30c8f52e786acd5c8166248fb91e842c25ce574	archive/branches-20261109/codex/rv64-gkr-stream-dense-upper
codex/rv64-gkr-unit-cross	51776a7e787164d5dc247a75b30a0695faa5ed25	archive/branches-20261109/codex/rv64-gkr-unit-cross
codex/rv64-gkrmem	3a0873e7cca1a341d2e019f79fab9b4bfae2cf3c	archive/branches-20261109/codex/rv64-gkrmem
codex/rv64-gpu-316-320-integration	47a622cef8031e27f720de174ad30b01d1815ebc	archive/branches-20261109/codex/rv64-gpu-316-320-integration
codex/rv64-gpu-hygiene	51897dc265593df7580c4abf0b232909fc105e34	archive/branches-20261109/codex/rv64-gpu-hygiene
codex/rv64-gpu-hygiene-local	4892bffa6f77dce3dda68aea0053dfff71e7f0cd	archive/branches-20261109/codex/rv64-gpu-hygiene-local
codex/rv64-gpu-padding-range-candidate	698381bf4cdcad3b41ba462a884861e3290452b1	archive/branches-20261109/codex/rv64-gpu-padding-range-candidate
codex/rv64-gpu-ready-fixed-integration	a8f4e64312818115ef7d2633cc6ce07f344cff1e	archive/branches-20261109/codex/rv64-gpu-ready-fixed-integration
codex/rv64-guest-candidate-curves	683c40b2b00bf62d12027212d25499579dc5ba58	archive/branches-20261109/codex/rv64-guest-candidate-curves
codex/rv64-guest-candidate-isa	b9a1dd66eb981e1c677f924d5fcf1fceeb4717e3	archive/branches-20261109/codex/rv64-guest-candidate-isa
codex/rv64-guest-candidate-services	a687d3b85e5829d91a45e446312b42bae74a031a	archive/branches-20261109/codex/rv64-guest-candidate-services
codex/rv64-guest-client-eest-fixes	d98987b6419ed29c3d2c88057c8a8bd126e29f90	archive/branches-20261109/codex/rv64-guest-client-eest-fixes
codex/rv64-guest-client-evmone	4f3794320ce26f2e6b9c282ccffe0db247f325df	archive/branches-20261109/codex/rv64-guest-client-evmone
codex/rv64-guest-client-interpreter	7a18e04a9d8104ed927988d954fa051efcc066fb	archive/branches-20261109/codex/rv64-guest-client-interpreter
codex/rv64-guest-client-interpreter2	68a0867d39a27e51cb4d8747858108a429c514fe	archive/branches-20261109/codex/rv64-guest-client-interpreter2
codex/rv64-guest-client-trie-state	4b1d0265ec9c6f78d1f15f0965d267bdce33a560	archive/branches-20261109/codex/rv64-guest-client-trie-state
codex/rv64-guest-efficiency	36ea2091a658415d10fc83c9a6d09ff55f6fd62b	archive/branches-20261109/codex/rv64-guest-efficiency
codex/rv64-guest-prover-arith256	defa80e9d77d889d9acd060992ade209ff92cc7a	archive/branches-20261109/codex/rv64-guest-prover-arith256
codex/rv64-guest-prover-bulk-memory	1d2f62e8c35ef6d6010bd2bebe18a7ab4a2d82a6	archive/branches-20261109/codex/rv64-guest-prover-bulk-memory
codex/rv64-guest-prover-bulk-unaligned	6806dec8cfd73e13d1c4f0e3723a8fb9594c6fd1	archive/branches-20261109/codex/rv64-guest-prover-bulk-unaligned
codex/rv64-guest-prover-curves	e15fb991a6598198d08d6111d516a8ab3efc2823	archive/branches-20261109/codex/rv64-guest-prover-curves
codex/rv64-guest-prover-eest	bf466df5b44383c4edee018f05483487cd933834	archive/branches-20261109/codex/rv64-guest-prover-eest
codex/rv64-guest-prover-keccak-sponge	fb253bde8c32cd37747fdbf2bcd112c37ccccb9c	archive/branches-20261109/codex/rv64-guest-prover-keccak-sponge
codex/rv64-guest-prover-recursion-v3	701ee5f0b22c81322ab01df33fc4021f8b377cf7	archive/branches-20261109/codex/rv64-guest-prover-recursion-v3
codex/rv64-guest-prover-sha256	f0c0e1247e340ce09cdf472a1b13c5c63013518d	archive/branches-20261109/codex/rv64-guest-prover-sha256
codex/rv64-guest-prover-v3-integration	b25175ff6b69772aab4447d61891c08e34a883c8	archive/branches-20261109/codex/rv64-guest-prover-v3-integration
codex/rv64-guest-rust-lean	9d00afb7cf4d2282bcffbb47d9ef828f2e5f8982	archive/branches-20261109/codex/rv64-guest-rust-lean
codex/rv64-guest-services-base	71b25b2cdcc94f581d156a4d61a72be22a438818	archive/branches-20261109/codex/rv64-guest-services-base
codex/rv64-inspect-recursion-schedule	14cb0cda136fa735bac7971ef8c8c4987df5da8b	archive/branches-20261109/codex/rv64-inspect-recursion-schedule
codex/rv64-integration-308-311	3b7c8b2b2f65295a717bbb397dbd058b12ffda94	archive/branches-20261109/codex/rv64-integration-308-311
codex/rv64-keccak-memory-cost	7c9362a3d8e13351c1ead28382ae9ec3bf1919cd	archive/branches-20261109/codex/rv64-keccak-memory-cost
codex/rv64-keccak-prefix-lowering	067ccaca757d91bbe7b20167d6e38bf80c71f66d	archive/branches-20261109/codex/rv64-keccak-prefix-lowering
codex/rv64-keccak-quartet-truth	60cf711909f14bd7a7be0be65836939f74d6b87d	archive/branches-20261109/codex/rv64-keccak-quartet-truth
codex/rv64-keccakdeep	833c0f463dd799655c7aa8b5be62f236737f7e8d	archive/branches-20261109/codex/rv64-keccakdeep
codex/rv64-ls32-qualified	3a5c53d0d091ead8d5380365bb48e4631348e5ab	archive/branches-20261109/codex/rv64-ls32-qualified
codex/rv64-m3-host	b009891ecebfcf54bd991194bea8ab6ae0a8fdc2	archive/branches-20261109/codex/rv64-m3-host
codex/rv64-m3-infra	c81a8bd1fd843b2d660339765f840592d0e0d2f3	archive/branches-20261109/codex/rv64-m3-infra
codex/rv64-m3-integrate	bcd401ce447af9f34b7461c11fd92a7b52e104f5	archive/branches-20261109/codex/rv64-m3-integrate
codex/rv64-m3-mem	6d11915537bf649e75456a5080d53906d781969c	archive/branches-20261109/codex/rv64-m3-mem
codex/rv64-m3-pipe	8c93f14025262c809eb67535e1c7d3fcfaf6c6ff	archive/branches-20261109/codex/rv64-m3-pipe
codex/rv64-m3-recsize	5d68d0f0129670e1d627d4fce26d815f816878aa	archive/branches-20261109/codex/rv64-m3-recsize
codex/rv64-m3-topo	fe0fc87d3b4af9fd06250a98475f58b095dd725b	archive/branches-20261109/codex/rv64-m3-topo
codex/rv64-m4-arena	d3835ed12e360def6294741d627b965ef32419fb	archive/branches-20261109/codex/rv64-m4-arena
codex/rv64-m4-capture	ed09c445c8b6b4acb27ebcf8535a343fa7990c7b	archive/branches-20261109/codex/rv64-m4-capture
codex/rv64-m4-diet	abf1c48cf92209c58b114148ded4fb8373b0fab0	archive/branches-20261109/codex/rv64-m4-diet
codex/rv64-m4-integrate	78c3bd5d236f3e4ba25e90615573ba0dff239666	archive/branches-20261109/codex/rv64-m4-integrate
codex/rv64-m4-kernels	c8f9ee76b10bc897c3d9141196cb147c74850fe2	archive/branches-20261109/codex/rv64-m4-kernels
codex/rv64-m4-measure	6f398efa02d35f30862b1c0c452f3317e4e9fd85	archive/branches-20261109/codex/rv64-m4-measure
codex/rv64-m4-profiles	6fb652849a8ad860d90a74ab94fb8702e6b54c0f	archive/branches-20261109/codex/rv64-m4-profiles
codex/rv64-m4-recsize-port	d4cdf05fa540c720ffe0dfae5351c576d6f6dc6e	archive/branches-20261109/codex/rv64-m4-recsize-port
codex/rv64-m4-resident	0fee57fe7f4bdf9330063de5562062347210305f	archive/branches-20261109/codex/rv64-m4-resident
codex/rv64-m5-blake-gadget	72a77871ee1d6202d153a7428c0695f49a7d3f3d	archive/branches-20261109/codex/rv64-m5-blake-gadget
codex/rv64-m5-canon-native	3ab5390673677b515ba509cd34ecd3779e070b93	archive/branches-20261109/codex/rv64-m5-canon-native
codex/rv64-m5-canon-vk	aa0761d4e4813530a51b40e4ad81e187fd0500b7	archive/branches-20261109/codex/rv64-m5-canon-vk
codex/rv64-m5-capture	26a18f94cab43281d5e6d78b12eb6727fb8c75a4	archive/branches-20261109/codex/rv64-m5-capture
codex/rv64-m5-integrate	95d40063d8b4723338535cf06b7a1b11cdbba0f9	archive/branches-20261109/codex/rv64-m5-integrate
codex/rv64-m5-native-gkr	2fc4b878b2192486e21c8c5484e87e2c44cfb498	archive/branches-20261109/codex/rv64-m5-native-gkr
codex/rv64-m5-outer-gkr	c6a9659dc1ff58cbbf7dff93d18cf934eb9c47a3	archive/branches-20261109/codex/rv64-m5-outer-gkr
codex/rv64-m5-platform	f6c4f3d4c984240a1e2a3435cde72efbf35f0cff	archive/branches-20261109/codex/rv64-m5-platform
codex/rv64-m5-profiles	9fe0ae3811daf631d8ac7f79ef57cd99a7477427	archive/branches-20261109/codex/rv64-m5-profiles
codex/rv64-m5-rootverify	955445de658635eed74ea34fd334707fed5c1fb5	archive/branches-20261109/codex/rv64-m5-rootverify
codex/rv64-m6-capture	b657b8c5f396132dd6011f42b96191ec9ac9e6f8	archive/branches-20261109/codex/rv64-m6-capture
codex/rv64-m6-diet-wire	7f2d09c8d15da1524f66b4bc0ec1f0fa69b263ee	archive/branches-20261109/codex/rv64-m6-diet-wire
codex/rv64-m6-enqueue	20e903f58424c9d02fa80f1cdb3c01882da52bd4	archive/branches-20261109/codex/rv64-m6-enqueue
codex/rv64-m6-fold-v3	4c579d9e5f5a6e7aa4dff072e92c690642139e9c	archive/branches-20261109/codex/rv64-m6-fold-v3
codex/rv64-m6-hint-tape	b99bf5f66fe5036317cededa1c335e86618958f5	archive/branches-20261109/codex/rv64-m6-hint-tape
codex/rv64-m6-integrate	26ca2079314833704137aae900955ece81ae49e9	archive/branches-20261109/codex/rv64-m6-integrate
codex/rv64-m6-native-format	efe0eae6a7bffec03828131dfad13b12b87965f4	archive/branches-20261109/codex/rv64-m6-native-format
codex/rv64-m6-native-stream	e31f190415af8fe8613823f6d95314e73f4d42ec	archive/branches-20261109/codex/rv64-m6-native-stream
codex/rv64-m6-profiles	f27bce5ebc57b36ad320c9728d4540a3393103e3	archive/branches-20261109/codex/rv64-m6-profiles
codex/rv64-m6-sched	df7ceb5d33be9da346992e71829ca155cfa3468e	archive/branches-20261109/codex/rv64-m6-sched
codex/rv64-m7-admission	147406998dfebd742159cc2b663d4113753ff0fd	archive/branches-20261109/codex/rv64-m7-admission
codex/rv64-m7-blake-inputs	b053aefe2ec792277103268e545f4f722e3bd748	archive/branches-20261109/codex/rv64-m7-blake-inputs
codex/rv64-m7-callback-retire	14442686ded590b1c4e6d2d91871a7db75be2b75	archive/branches-20261109/codex/rv64-m7-callback-retire
codex/rv64-m7-capture	8954ddf8487d1eeb71be0d9e54bc222bb6d709ce	archive/branches-20261109/codex/rv64-m7-capture
codex/rv64-m7-cpu-prestage	2ff01fc4fd5eb8b0d9a2ad7362960e4c510f8899	archive/branches-20261109/codex/rv64-m7-cpu-prestage
codex/rv64-m7-critical-chain	e547961153ced86480a8076dc4d0d56a2b16cc1e	archive/branches-20261109/codex/rv64-m7-critical-chain
codex/rv64-m7-device-fs	a91bb8b4ac6fdb59f9408afcb35149d1af906afb	archive/branches-20261109/codex/rv64-m7-device-fs
codex/rv64-m7-device-fs-p1	3134125938154d987506e433f93edf295b576347	archive/branches-20261109/codex/rv64-m7-device-fs-p1
codex/rv64-m7-device-fs-p2	95e0002b104909239c5f602a7777034a1bb5244f	archive/branches-20261109/codex/rv64-m7-device-fs-p2
codex/rv64-m7-device-graph	5924a1d62198a2343822f550c63a7353be3b0084	archive/branches-20261109/codex/rv64-m7-device-graph
codex/rv64-m7-device-lanes-checkpoint	6615fb2dec99c9457e7bb09c82487f3fd35cf8bb	archive/branches-20261109/codex/rv64-m7-device-lanes-checkpoint
codex/rv64-m7-early-recursion	cee957756f6ba3af7f568d3d80f5f9aebd1d403e	archive/branches-20261109/codex/rv64-m7-early-recursion
codex/rv64-m7-fold-circuit	e189ab4081887a9809493012d6730ec64696904e	archive/branches-20261109/codex/rv64-m7-fold-circuit
codex/rv64-m7-fold-expanded	3b7f0d5a7fd346ea420627f772a2296f61788e5e	archive/branches-20261109/codex/rv64-m7-fold-expanded
codex/rv64-m7-graph-checkpoint	2f7645fec71181f33b54e96a41904fbaeb6a2d51	archive/branches-20261109/codex/rv64-m7-graph-checkpoint
codex/rv64-m7-graph-shape-checkpoint	86817b07fb6465d0c48ef1941bd3e6a0dfa12b63	archive/branches-20261109/codex/rv64-m7-graph-shape-checkpoint
codex/rv64-m7-integrate	4a4d01bd5999bd6489fe71062c9e46ccdbcd73bb	archive/branches-20261109/codex/rv64-m7-integrate
codex/rv64-m7-keccak-batches	beb9f865bd98aee004d93f8e6441ba6b23231b21	archive/branches-20261109/codex/rv64-m7-keccak-batches
codex/rv64-m7-keccak-stream	333263e76ad754ca811a74e57ce68f8ec2960e69	archive/branches-20261109/codex/rv64-m7-keccak-stream
codex/rv64-m7-memory-census	9b0aee2ea9d893d4e29273c4e6ca544dcf05e706	archive/branches-20261109/codex/rv64-m7-memory-census
codex/rv64-m7-native-capture	c147aa41cff77a03d54624ab30540d81035cbf28	archive/branches-20261109/codex/rv64-m7-native-capture
codex/rv64-m7-native-gkr	44dd10e652d922b2a70cf4600616edbea9cb4423	archive/branches-20261109/codex/rv64-m7-native-gkr
codex/rv64-m7-native-inter-retire	ce88816fcf841b9f870a4e3ab25bd76bcf14c47a	archive/branches-20261109/codex/rv64-m7-native-inter-retire
codex/rv64-m7-native-witness	0013ec6de671993b0dc68a5e35351e531db464c6	archive/branches-20261109/codex/rv64-m7-native-witness
codex/rv64-m7-outer-gkr	36a079de524273cb063fed78c7611f256373b88d	archive/branches-20261109/codex/rv64-m7-outer-gkr
codex/rv64-m7-owner-cleanup	c2ae434463d0f9082cd8fd5bf821fb07dc3c84b8	archive/branches-20261109/codex/rv64-m7-owner-cleanup
codex/rv64-m7-projection-cost	fb6b004c3aee82c0de55b6b96c45cf861d109865	archive/branches-20261109/codex/rv64-m7-projection-cost
codex/rv64-m7-rc-sparse	f828e0ab2edaf0cd1ca4ffcc6e07bfd6df825722	archive/branches-20261109/codex/rv64-m7-rc-sparse
codex/rv64-m7-rc-workspace	5a2f41ef4cd50435d37f2e94bb1a0939581557a6	archive/branches-20261109/codex/rv64-m7-rc-workspace
codex/rv64-m7-stage1-cost	0fef70e45203a257643120f59b86e52692cc9e1a	archive/branches-20261109/codex/rv64-m7-stage1-cost
codex/rv64-main-merkle-parking	3c8058e67445ddbf94a2d86574483d713c0a5d2e	archive/branches-20261109/codex/rv64-main-merkle-parking
codex/rv64-main-prefetch-qualified	42e0023e38003bb361ec87f1fabf994461ab460b	archive/branches-20261109/codex/rv64-main-prefetch-qualified
codex/rv64-narrow-driver-integration	9c08ec054ff24cb558c7becccfe38bf9361b8815	archive/branches-20261109/codex/rv64-narrow-driver-integration
codex/rv64-native-image-qualification-plan	80cf4fa12d8aa2892df0ae6d4184513a9e088ff3	archive/branches-20261109/codex/rv64-native-image-qualification-plan
codex/rv64-offhost-input-mapping	e8a0113b3ef4635d099f1a16dde1a9c373a0ada5	archive/branches-20261109/codex/rv64-offhost-input-mapping
codex/rv64-offhost-receiver	61fe4cb9292ac86f2a0f1354d62f5307e7a661c2	archive/branches-20261109/codex/rv64-offhost-receiver
codex/rv64-om-classic-control	37f7b37b207cd111422b90c77e2e70df237a2455	archive/branches-20261109/codex/rv64-om-classic-control
codex/rv64-om-domain-pool	9d69b01510610fa4507704cbd725c68f26cf902c	archive/branches-20261109/codex/rv64-om-domain-pool
codex/rv64-om-fri-packed	f5f942e32b9d08a1d437db3a287b0e373b70dfd1	archive/branches-20261109/codex/rv64-om-fri-packed
codex/rv64-om31-compact	eddd33db85dbd12c883eab88632a8994a3bcaffa	archive/branches-20261109/codex/rv64-om31-compact
codex/rv64-om31-core	b590d724c2942b02c66d6fc280420dc7875e8e97	archive/branches-20261109/codex/rv64-om31-core
codex/rv64-om31-cost	5846448e5c6da2879ec65fbf4d6e5e0c6e6ca894	archive/branches-20261109/codex/rv64-om31-cost
codex/rv64-om31-fri	2f3fd95d99b10ceb330ecbfa37a09071cf097daf	archive/branches-20261109/codex/rv64-om31-fri
codex/rv64-om31-gkr	8ba1c8f8268547728b088d9498ef63c42080fcb4	archive/branches-20261109/codex/rv64-om31-gkr
codex/rv64-om31-pcs	95154d0c3e92b1e7ef81f7b8bbbbc68d82bcd408	archive/branches-20261109/codex/rv64-om31-pcs
codex/rv64-om31-security-candidate	ad6c946c545313f91be467b9c2e2b1f2b45d2a9d	archive/branches-20261109/codex/rv64-om31-security-candidate
codex/rv64-om31-wrap-resume	fad2ea9829c275fcea31936b89b7dc34a315b079	archive/branches-20261109/codex/rv64-om31-wrap-resume
codex/rv64-outer-assignment-narrow-runs	ac9efd7f6d7c75017a63ef0ed7eb7fce5c6f442c	archive/branches-20261109/codex/rv64-outer-assignment-narrow-runs
codex/rv64-outer-device-fixed	b935620d99b5534809ad48b7f24577131614dd75	archive/branches-20261109/codex/rv64-outer-device-fixed
codex/rv64-outer-largest-memory	9eb2a2cb68f28531f3c5a7534befa40b62633e62	archive/branches-20261109/codex/rv64-outer-largest-memory
codex/rv64-packed-gkr	47063c48c6c3e25e5bff83a424f49ea732cb68fe	archive/branches-20261109/codex/rv64-packed-gkr
codex/rv64-packed-om-air	75d2f402cea9a5814df1d497c6892fafbadfec34	archive/branches-20261109/codex/rv64-packed-om-air
codex/rv64-padding-range-prototype	680b130d278a876f880c9feca39a7f64a5cbeb37	archive/branches-20261109/codex/rv64-padding-range-prototype
codex/rv64-padding-range-real-cpu0	5f04e2d3d40f9249b87c7eb0589425aa0629a13f	archive/branches-20261109/codex/rv64-padding-range-real-cpu0
codex/rv64-parking-qualified	bddd8243c710d1c447dcb781aa8cef4cf60291ae	archive/branches-20261109/codex/rv64-parking-qualified
codex/rv64-pcs-default-pool-diagnostics	bd3d66665f925836eb59b6a19ffb1eb5c80b92cb	archive/branches-20261109/codex/rv64-pcs-default-pool-diagnostics
codex/rv64-pcs-idle-cache-cap	b08bb38039c34101207439a106db675a53425f61	archive/branches-20261109/codex/rv64-pcs-idle-cache-cap
codex/rv64-pcs-oom-pool-diagnostics	aaf4851c8d0ff4658bb9b6806fadec12aa187230	archive/branches-20261109/codex/rv64-pcs-oom-pool-diagnostics
codex/rv64-perf-expansion-cleanup	6a7e76a3030052cb48f0190e14f547f64035ef9e	archive/branches-20261109/codex/rv64-perf-expansion-cleanup
codex/rv64-perf-half-scratch-default	4d9b5228c33c97f2cbfc4d2b76e6523f3ff76ee2	archive/branches-20261109/codex/rv64-perf-half-scratch-default
codex/rv64-perf-quotient-setup	0d616fbd2696806e698898cebdc92029477d7285	archive/branches-20261109/codex/rv64-perf-quotient-setup
codex/rv64-perf-secp-interaction	14edd8ac905b756999fe45b52bd3bf4a6e0a0187	archive/branches-20261109/codex/rv64-perf-secp-interaction
codex/rv64-perf-truths-first	fbd37f54b5b1866dda7a100c2918b97f0c57b9ee	archive/branches-20261109/codex/rv64-perf-truths-first
codex/rv64-perf-wave1-integration	c2fffdf1707563714d26259b2ec0a104485cc4e1	archive/branches-20261109/codex/rv64-perf-wave1-integration
codex/rv64-perf2-air-boundary	4a1e04256cbfacdfc47ade6d32fc58bf2533d876	archive/branches-20261109/codex/rv64-perf2-air-boundary
codex/rv64-perf2-air-div-trims	243ce82428031e87272c355ad2c42e5670cbb3c4	archive/branches-20261109/codex/rv64-perf2-air-div-trims
codex/rv64-perf2-air-integration	eac3b7c076ad876775dc52b09456fb6801c6d741	archive/branches-20261109/codex/rv64-perf2-air-integration
codex/rv64-perf2-air-ls32	d873812af9d424ea99083df82ffe85b9f18e3d3a	archive/branches-20261109/codex/rv64-perf2-air-ls32
codex/rv64-perf2-air-small-trims	b0f4f2bff5118a391345da6d69dd3c3607b43a4d	archive/branches-20261109/codex/rv64-perf2-air-small-trims
codex/rv64-perf2-composition-queue	eac3b7c076ad876775dc52b09456fb6801c6d741	archive/branches-20261109/codex/rv64-perf2-composition-queue
codex/rv64-perf2-gkr-prototype	89099a0c5878fc74a76e194f295f4039942191d6	archive/branches-20261109/codex/rv64-perf2-gkr-prototype
codex/rv64-perf2-interaction-gen	09a48a6e01d142bdaa387c7f7aec37accda96db1	archive/branches-20261109/codex/rv64-perf2-interaction-gen
codex/rv64-perf2-sched-sweep	c4e6d1e07d8ee6386200c2a9c3ef3ced3b0fa6ad	archive/branches-20261109/codex/rv64-perf2-sched-sweep
codex/rv64-post-merge-hygiene-backup	201bb2f449331f9f7c5bd542122df44405c55125	archive/branches-20261109/codex/rv64-post-merge-hygiene-backup
codex/rv64-pr308-compact-guard	383cabfc9e43c3eaf8e1f4cd7e5288693cf07fc4	archive/branches-20261109/codex/rv64-pr308-compact-guard
codex/rv64-pr308-integration-review	5f06a9ea6f5b9e1e6c07d89f86ae5690d430a938	archive/branches-20261109/codex/rv64-pr308-integration-review
codex/rv64-prefix-bank-sizing	3e0e4325a873cd6366ddb5ddbb36a689674f774d	archive/branches-20261109/codex/rv64-prefix-bank-sizing
codex/rv64-program-metadata-arc	e2457d31c1188d796503360df2f9e64248794cda	archive/branches-20261109/codex/rv64-program-metadata-arc
codex/rv64-ready-basket-harness	a0f6a5f00bb9951ab6c4b38dba4c5b4f55395183	archive/branches-20261109/codex/rv64-ready-basket-harness
codex/rv64-ready-device-fixed	94d271077a753bf6ba7ec63e1b163774ab0cb959	archive/branches-20261109/codex/rv64-ready-device-fixed
codex/rv64-ready-fixed-snapshot	5a847212b78a8d0908316a4fb95a3316d3b6eea4	archive/branches-20261109/codex/rv64-ready-fixed-snapshot
codex/rv64-ready-recycler-budget	6130d6396f97a4a5868d58e3438c282bf046a4b7	archive/branches-20261109/codex/rv64-ready-recycler-budget
codex/rv64-receiver-budget	e630ff1f49b632fe1acb4ec97e3c44b64f38c4d5	archive/branches-20261109/codex/rv64-receiver-budget
codex/rv64-recovered-composition	46541d5bdaa2cf568be95290ed596f9c60f07c35	archive/branches-20261109/codex/rv64-recovered-composition
codex/rv64-recovered-composition-layout	de566db0090c4003554c424b3e874383d55c877c	archive/branches-20261109/codex/rv64-recovered-composition-layout
codex/rv64-recovered-div-review	0c79e958c2323c223e4e2c27f1d0b65662a7210a	archive/branches-20261109/codex/rv64-recovered-div-review
codex/rv64-recovered-gkr	a5e960d6f0b00e556bc4094daa14ac46058835de	archive/branches-20261109/codex/rv64-recovered-gkr
codex/rv64-recovered-interaction-layout	f6cf001f0fb1fe13cd76b98b6fcda348dae8f97a	archive/branches-20261109/codex/rv64-recovered-interaction-layout
codex/rv64-recovered-interactions	4f93e748104ae2d266f686b3bcf58ebe4bd11865	archive/branches-20261109/codex/rv64-recovered-interactions
codex/rv64-recovered-scheduling	7c3f90a28a71db8dd19ffee3831cb7cc3881263a	archive/branches-20261109/codex/rv64-recovered-scheduling
codex/rv64-recursion-ready-lanes	fbd9b32c7976e063f903cacb314178b02915bbbf	archive/branches-20261109/codex/rv64-recursion-ready-lanes
codex/rv64-resident-ready-candidate	467c4c763fbc352928ad2f6a98f96fa9df4702e3	archive/branches-20261109/codex/rv64-resident-ready-candidate
codex/rv64-retained-cpu-lde	63f029c71ddb19fbda857e96ed71a7ba8823137f	archive/branches-20261109/codex/rv64-retained-cpu-lde
codex/rv64-selective-half	193034a7fdd0d019f230d498c4f1f33e82246c46	archive/branches-20261109/codex/rv64-selective-half
codex/rv64-serial-device-fixed	21509686024a5bf7987829a6677294cfee084851	archive/branches-20261109/codex/rv64-serial-device-fixed
codex/rv64-services-gkr-binding	c06bbb279df83caf2a199e0dccf87e918fe124d4	archive/branches-20261109/codex/rv64-services-gkr-binding
codex/rv64-setup-cache	298bb29cab128844342da390a91a402a7ee6bc0e	archive/branches-20261109/codex/rv64-setup-cache
codex/rv64-sponge-gkr-integration	894d6b497ac03b1502687a5aff92f8a04cf7a2cc	archive/branches-20261109/codex/rv64-sponge-gkr-integration
codex/rv64-truth-dispatch-qualified	b952376b78f4f053faf528ab54223d40dd3f0814	archive/branches-20261109/codex/rv64-truth-dispatch-qualified
codex/rv64-truth-parallel-composition	8ec72a9a237bae226f461b8cae804fc60c70f1ef	archive/branches-20261109/codex/rv64-truth-parallel-composition
codex/rv64-truth-range-source	f8e6d949066194d2259e991fc7458242958f9b42	archive/branches-20261109/codex/rv64-truth-range-source
codex/rv64-truth-retention-contract	79e6b268968743a43c00e2cfe37bec690dcc8075	archive/branches-20261109/codex/rv64-truth-retention-contract
codex/rv64-truth-v3-om31	f0844dbedb16c7072b36f90076af98719927f5fb	archive/branches-20261109/codex/rv64-truth-v3-om31
codex/rv64-v3-closure-completion	59f3a28d784726c93c3cf2e4b48718c6dff614c5	archive/branches-20261109/codex/rv64-v3-closure-completion
codex/rv64-v3-source-accounting	e48129df08c9c205b70830678c2c4eab14e3f906	archive/branches-20261109/codex/rv64-v3-source-accounting
codex/rv64-wide-deep-phase-profile	bab5ce36e0d449f8aab3a6b10532f3f45e8dbf07	archive/branches-20261109/codex/rv64-wide-deep-phase-profile
codex/rv64-wide-finalize-blocked	ac3a543638733e3b7415f65e5ce091d572964b94	archive/branches-20261109/codex/rv64-wide-finalize-blocked
codex/rv64-wide-fixed-setup	d43b60e1ae32fd3ef6c7e47b1c3c925b7d05c8ad	archive/branches-20261109/codex/rv64-wide-fixed-setup
codex/rv64-wide-quotient-batch	298d8ea62e554f8f4f970d0634b7b27849b2bc42	archive/branches-20261109/codex/rv64-wide-quotient-batch
codex/rv64-wide-quotient-rows	94a769c33166e686e07328389527103e52af56dd	archive/branches-20261109/codex/rv64-wide-quotient-rows
codex/rv64-wide-sampled-values	73553f751b67317f62e0a28468a0b82cdbcf21cc	archive/branches-20261109/codex/rv64-wide-sampled-values
codex/rv64-witness-append-inline	fbedb6ff04bf39c39790755769aae5ebd9968ec6	archive/branches-20261109/codex/rv64-witness-append-inline
codex/rv64-witness-task-capacity-audit	6cb72d79a890bb6c164703fe15c50df8bb152401	archive/branches-20261109/codex/rv64-witness-task-capacity-audit
codex/rv64-zisk-comparison	b9b99c101eceed1550bef890448e5c8954d804ad	archive/branches-20261109/codex/rv64-zisk-comparison
codex/rv64im-frontend	caeb185e15c82136531dd7881a585ec13ed8fc59	archive/branches-20261109/codex/rv64im-frontend
codex/s31-blake2s-counter-guard-20261013	59e1f115250b8af01712b9bf3d71616e53094964	archive/branches-20261109/codex/s31-blake2s-counter-guard-20261013
codex/s31-mixed-phase-timing-20261011	f889c2a03f4e8ae5e4a9e2db39f26c5b6a315719	archive/branches-20261109/codex/s31-mixed-phase-timing-20261011
codex/tensor-accuracy	973e720aa4912eae2bd0a121fdfee58e33b2ec58	archive/branches-20261109/codex/tensor-accuracy
codex/tensor-attn	6eb2444584f96dfce28467f2ebf69ac53429a75f	archive/branches-20261109/codex/tensor-attn
codex/tensor-cuda	5e071f5bd8ecc5e2cf18b7d5f92f568cc43add4a	archive/branches-20261109/codex/tensor-cuda
codex/tensor-cuda2	8d9d3388639069ba0c8789e5e953fe2258474ac1	archive/branches-20261109/codex/tensor-cuda2
codex/tensor-fix-kern	38d9eb5d941cb086c7a130454a7b469e454260b4	archive/branches-20261109/codex/tensor-fix-kern
codex/tensor-fix-pcs	59dca42c05c22c25b586ade39630e965b2def60f	archive/branches-20261109/codex/tensor-fix-pcs
codex/tensor-fix-stmt	aabd851ad4624194284da830db2b409a1b4dce95	archive/branches-20261109/codex/tensor-fix-stmt
codex/tensor-int2	597b40b837eb5786f82024d8e227c5154bbb4cc5	archive/branches-20261109/codex/tensor-int2
codex/tensor-integrate	8332d5af750240efbba0957e8875a26984afc854	archive/branches-20261109/codex/tensor-integrate
codex/tensor-integrate2	6bc0a0df64d1aa8201f7de6e6003852ecb905fbc	archive/branches-20261109/codex/tensor-integrate2
codex/tensor-lean	903beed143cd26fd20722bd8f867ca8770c6e049	archive/branches-20261109/codex/tensor-lean
codex/tensor-lean2	13dc3ca3c95bd117a76de662999c4d904a2a5661	archive/branches-20261109/codex/tensor-lean2
codex/tensor-lmclose	6b63720ce5faf9148d0e10e1ee84e99fd2fde66e	archive/branches-20261109/codex/tensor-lmclose
codex/tensor-lmfix	f489044dd1f0b7a5a5ae4adf4d5cc424e848486b	archive/branches-20261109/codex/tensor-lmfix
codex/tensor-metal	f3fc59075d7392d71745380d8c6e89d030ee935b	archive/branches-20261109/codex/tensor-metal
codex/tensor-perf	0ca265d6552fd632d0a838126f8fa1a65658dde5	archive/branches-20261109/codex/tensor-perf
codex/tensor-r2-sec	2e79af5094d1fc943e2131cabb8bb7531a993b05	archive/branches-20261109/codex/tensor-r2-sec
codex/tensor-r2-serve	5d4ff2ef06818ef9e9949013d1fae47ac9481d2d	archive/branches-20261109/codex/tensor-r2-serve
codex/tensor-r2-speed	0f5700706f01f1a809c9cf5ed4c650a50aee0d9f	archive/branches-20261109/codex/tensor-r2-speed
codex/tensor-r2-zk	7383013cfab069b6da3fca99a748d3cc9d139f57	archive/branches-20261109/codex/tensor-r2-zk
codex/tensor-review-ext	4cd5cf51edfe460b289e411c32453ae217e27c69	archive/branches-20261109/codex/tensor-review-ext
codex/tensor-review-kern	4cd5cf51edfe460b289e411c32453ae217e27c69	archive/branches-20261109/codex/tensor-review-kern
codex/tensor-review-parity	4cd5cf51edfe460b289e411c32453ae217e27c69	archive/branches-20261109/codex/tensor-review-parity
codex/tensor-review-pcs	4cd5cf51edfe460b289e411c32453ae217e27c69	archive/branches-20261109/codex/tensor-review-pcs
codex/tensor-review-proto	4cd5cf51edfe460b289e411c32453ae217e27c69	archive/branches-20261109/codex/tensor-review-proto
codex/tensor-reviewb-sec	e2df5d85a8a6ee664775781f9022fbe1ce7962c4	archive/branches-20261109/codex/tensor-reviewb-sec
codex/tensor-reviewb-serve	e2df5d85a8a6ee664775781f9022fbe1ce7962c4	archive/branches-20261109/codex/tensor-reviewb-serve
codex/tensor-reviewb-zk	e2df5d85a8a6ee664775781f9022fbe1ce7962c4	archive/branches-20261109/codex/tensor-reviewb-zk
codex/tensor-sec-fast	24643f16e7ce00fca1828845f88a9bcc5be2b8cc	archive/branches-20261109/codex/tensor-sec-fast
codex/tensor-sec128	f4e234dfc78a57289321c885e2121b07406e4406	archive/branches-20261109/codex/tensor-sec128
codex/tensor-sec2	cfa6a91049b04a798cd2cf73b250f46adae03bb0	archive/branches-20261109/codex/tensor-sec2
codex/tensor-secfix	3a11803652f8e404a9b65bf4cf18ef4c4ac7b599	archive/branches-20261109/codex/tensor-secfix
codex/tensor-size	c597204deb834add82ec1649e395861a66d0cead	archive/branches-20261109/codex/tensor-size
codex/tensor-wide	029c83ae128db31d645fa2742c83b96e302561cd	archive/branches-20261109/codex/tensor-wide
codex/tensor-wire	71421bd915d2a5bfd39cf23e0e4eaab6c9486a67	archive/branches-20261109/codex/tensor-wire
codex/tensor-wv-attn-virtual-d-sel	e2a5b61d597bbb1b5051d18fe224b7766b370d2f	archive/branches-20261109/codex/tensor-wv-attn-virtual-d-sel
codex/tensor-wv-fused-glu	46c00679fb51d916fb1475c20b2a467aaf555cf3	archive/branches-20261109/codex/tensor-wv-fused-glu
codex/tensor-wv-ledger	d3545530f1299a0f2611a3b8b62748ddada81ec3	archive/branches-20261109/codex/tensor-wv-ledger
codex/tensor-wv-wide-slack-key	66f34036a459a49313c0e29fcb513c10414fa135	archive/branches-20261109/codex/tensor-wv-wide-slack-key
codex/tensor-zk	9c7a323297ee00b7f5dcb23e645d4f4464ba48e0	archive/branches-20261109/codex/tensor-zk
codex/tensor-zk-matched	7b5bd5b20c7f87393ecbdb05e4039c3abfd53586	archive/branches-20261109/codex/tensor-zk-matched
codex/tensor-zkfast	2d08da491f6eadbd6308d3afa748e67f8487c869	archive/branches-20261109/codex/tensor-zkfast
codex/tensor-zkfix	e44d0448285dee10436f521781e905b34f954c9d	archive/branches-20261109/codex/tensor-zkfix
codex/tensor-zksec	4e8cf96252b3c30662eff232f915015ce5b628be	archive/branches-20261109/codex/tensor-zksec
experiment/bend-compute-pr198	ca30292008592f504a4d984bb68653339310cd84	archive/branches-20261109/experiment/bend-compute-pr198
feat/s31-mixed-verified-trace-audit-20261011	c2d0ec41674cc8f50606ac5dfcc14796b5d16922	archive/branches-20261109/feat/s31-mixed-verified-trace-audit-20261011
feature/s31-circuit-dsl	1877b0839b2bd2c36ca8255127e8db50557a2346	archive/branches-20261109/feature/s31-circuit-dsl
feeder-preview-nh	3dbcc7e33675408dc3ba62d8fa0f29d75ec33d14	archive/branches-20261109/feeder-preview-nh
recovery/rv64-wave2-20261101/composition-queue	0ea417bcca0908ebf874f699b1c7e37ffc174c24	archive/branches-20261109/recovery/rv64-wave2-20261101/composition-queue
recovery/rv64-wave2-20261101/gkr-prototype	e129aa435e5ed0fe32dbe8badfe80defd76f05e7	archive/branches-20261109/recovery/rv64-wave2-20261101/gkr-prototype
recovery/rv64-wave2-20261101/interaction-gen	8261bc7c09e77266c11c9b239e3db48677406b08	archive/branches-20261109/recovery/rv64-wave2-20261101/interaction-gen
```

## Skipped at the census

Columns: branch, exact commit, reason.

```tsv
autoresearch/rtx6000-pro-two-rounds	7ee2773ddb25e07c23ff91d56dd341a134b4e93a	open PR #252
backup/branch-retirement-20261109	b7c9f385f82ae07800ba683f4a985073fd62a772	backup ref
backup/circuit-oracle-regeneration-20261109	21a03a5db6506e8afa19a00a0943b2e747f92f8a	backup ref
backup/delivery-20261109-c7d950b46399	c7d950b463998f71ac027e2b3e17535dfb0b2f56	backup ref
backup/delivery-evidence-20261109	a91e52860ee4806fdc4d96693b805547cf6a8589	backup ref
backup/delivery-evidence-a1-cpu-20261109	efd5ee62d950967bce881a48b86d4e9e91aade90	backup ref
backup/delivery-evidence-cm31-20261109	5fb583432ae26114051180b145be68f7d18594fb	backup ref
backup/delivery-evidence-cm31-minimal-20261109	3da377b3a86d0dc5f168d9d80ece4c71b87482b3	backup ref
backup/delivery-evidence-cm31-native-20261109	be37f1dc354ce7a9908a5e5e5002a8d73e011407	backup ref
backup/delivery-evidence-cm31-native-avx512-20261109	ac3ad6688494d35cef20b631e540e3442d274e6e	backup ref
backup/delivery-evidence-cm31-optimizer-20261109	bcb3c66d5ad54aef5714bfdabd31d2257699a788	backup ref
backup/delivery-evidence-contracts-20261109	a367797b152202d58a03fc301a4df1748589b59d	backup ref
backup/delivery-evidence-cpu-followup-20261109	813228feb0af9d67e80088eca1ced0741fdcc90f	backup ref
backup/delivery-evidence-cpu-results-20261109	54e342793b7f004ebd24fd8d3aa40f08206eb18e	backup ref
backup/delivery-evidence-cpu-validation-20261109	b36330c5c61e62b756ba1ec8714e29264c9409ff	backup ref
backup/delivery-evidence-cpu-worker-20261109	42325b26cb33177cec1cd8179f6048fa704f159b	backup ref
backup/delivery-observation-wip-20261109	3b00f32b72d6224ef97c356ce2ca7c8c8c35611d	backup ref
backup/exact-script-owners-20261109	7bd798ef7ba78d2ca0be002922bfc80857f7d928	backup ref
backup/hosted-cpu-diagnostics-20261109	257ef0fb8d9a82347906c42ace4bc2c3e7135326	backup ref
backup/live-sail-bindings-20261109	8cd0efadc12104c8675ad4928af8a8630a013135	backup ref
backup/local-20261108/codex/rv64-ge-calib	36ea2091a658415d10fc83c9a6d09ff55f6fd62b	backup ref
backup/local-20261108/codex/rv64-gpu-hygiene	4892bffa6f77dce3dda68aea0053dfff71e7f0cd	backup ref
backup/local-20261108/codex/rv64-opstack-study	9cc44f278a458dfe86598a1301346868fa1ce31b	backup ref
backup/local-20261108/codex/rv64-post-merge-hygiene	201bb2f449331f9f7c5bd542122df44405c55125	backup ref
backup/local-20261108/stash-0	8f99b041fe3ee7ff3bd52a1f02b50510a3a40ef5	backup ref
backup/local-20261108/stash-1	6789804ff599196edf675272df27ff7e044c6796	backup ref
backup/local-20261108/stash-2	82ea9234cd9c88f9a0cfdc2732cdfd40f041744b	backup ref
backup/local-20261108/stash-3	a26db5437122345d0850ce481ed8f4a9551ff737	backup ref
codex/cairo-cuda-bounded-openings	1fed7069b01bbb41fefcd41f16c24302cf0c68f0	open PR #239
codex/cairo-cuda-dense-prefetch	0ee54abce9a9cad960bac11cf991b224db0fb5ef	open PR #240
codex/cairo-cuda-managed-arena	155c5116ac4f3163d3c25390716daea853056d3e	open PR #232
codex/cas05-independent-degrees-20261014	d8da18851128f1679d7ded4493032d887b8a5dab	open PR #276
codex/cas05-key-artifact-binding-20261014	f77ab4ced7fe93d8fe5432f39af43dd077a8b1b8	open PR #267
codex/cas05-production-admission-20261014	d927a4ee63820b24fd3d3671d3143589e4d012b2	open PR #265
codex/cas05-sparse-heights-20261014	859409aa1e00a71a21a0f240b7f9f5c5a64fd3f8	open PR #269
codex/cas05-versioned-verifier-dispatch-20261014	1f51083ed64757b9eec311159e0edfd5ae1329ca	open PR #266
codex/cas07-accepted-relation-20261014	bacbeb4c4fa48f25e67d21b770f95d59ae75ad84	open PR #273
codex/cas07-four-slot-map-native-20261014	880f992dd1812fce0c9805628166f3f89b1bc056	open PR #275
codex/cas07-gate-quotient-degree-20261014	ffc66d625485c29bb3d0a83d1f31688fee05bb3d	open PR #274
codex/cas09-independent-heights-20261014	617f20112bb1b3d6aa6eff87ebd139bc51db7023	open PR #277
codex/cas10-four-root-openings-20261014	5d5a2eaa2aa292d387f82959d158619903778c38	open PR #278
codex/cas10-source-wire-20261014	6751da4be7db44a1a84eff8688f6565a430652b3	open PR #279
codex/cas11-four-root-h1-20261014	bdd54c18a22121c33b1e6538c5e86d39a705a38d	open PR #281
codex/cas12-framed-raw-query-join-20261014	6f5d8add5b9ef1288a44b2f1ec9213afa8b89637	open PR #283
codex/cas13-typed-gate-events-20261014	596d79b428c4f9ea4c9ecfa5a8b08ae8c683548d	open PR #285
codex/native-empty-tree-capture-20261014	cf9381c7e1a84b5a426e8ce43f27d654f7761aad	open PR #272
codex/native-pcs-fri-reduction-20261014	52a43a21ab28b3b2b93da32425590d9c592b4804	open PR #270
codex/native-pcs-fri-shape-20261014	eab24e3fe7cff5bb61721e8d1eb7f8192cb57568	open PR #271
codex/p07-adjacent-line-pairs-20261014	cdcef5db15e7c9a3edc4403a3029d6279ca858a9	open PR #291
codex/p07-authenticated-source-ood-20261014	79c9b629efdaffceb7360fbd816ca1f51397225e	open PR #292
codex/p07-framed-channel-v2-20261014	db2062df1438d77605824ca1565f346d1eab5a9d	open PR #282
codex/p07-line-admission-cache-20261014	94411c6dbb5cb1db6e95bf077618ce72df689962	open PR #288
codex/p07-line-descriptor-binding-20261014	a97f678d590242e473efe3712972fa0caf34412a	open PR #287
codex/p07-owned-h1-fold-equation-20261014	29647b474296ddee4f65976f95e0f1fc096bb0f3	open PR #293
codex/p07-owned-verifier-custody-20261014	787f67046477c83d5982d9d275bc756b9e62701b	open PR #289
codex/p07-paired-event-plan-20261014	1174534ff9836dd47dd9a73fb810545ee46c7a74	open PR #284
codex/p07-personalized-line-merkle-20261014	59fd38501825dee7f9bb500621ce7d489edf00ab	open PR #286
codex/p07-query-bound-line-openings-20261014	76774630ca37d324c56a02c507a2d8659a02bb38	open PR #290
codex/p07-sparse-h3-fold-equations-20261014	0eafefbc1f81983451cc3551c23187350133393e	open PR #295
codex/p07-sparse-h3-literal-claim-pairs-20261014	3616e34f05ef349b9166ca4643c5a7f8d58b5f0f	open PR #296
codex/p07-sparse-h3-source-projection-20261014	8a8537d158aec32f582794ffa2800fd3f86880a1	open PR #294
codex/p07-sparse-h3-terminal-fold-20261014	1c86c348f0ce48191c4a25c486509b75196baeb2	open PR #297
codex/p07-sparse-h3-weighted-receipt-20261014	4d293505e628aed80250a9e92f65251bdf379313	open PR #298
codex/p08-uniform-query-v1-20261014	a585f04f0d32d2f7d4e23f1a7320145fbe041eb0	open PR #280
codex/paired-degree-protocol-20261013	234ac67b2819e6b102e8d43da93a38a4a902075e	open PR #249
codex/pie-construction-geometry	7cb438ad5d48433e6895a799ef31bfaa87e8193a	open PR #230
codex/repo-standards	257ef0fb8d9a82347906c42ace4bc2c3e7135326	active CI run 42664616499
codex/riscv-large-program-quality	c1f3e734032447ea637d8136cb0d97c45a6dd55e	open PR #227
codex/rv64-global-ram-recursion-gates-20261101	f94150c77158c27e5d11d115e688681d0f1d29e6	open PR #306
codex/rv64-opstack-study	ece598f3903a124f1d591df98046e33ae8aea45d	open PR #322
codex/s31-cas05-transcript-prelude-20261014	54a5b7fa60775acc0c1b383e140ba51cec3a09ce	open PR #268
codex/s31-engine-extraction	7d544c6839497ca19b6c7ef9b982e464f10cfeed	open PR #237
codex/tensor-frontend	97dc093f24cb0437291bdbd68026e65f798305dc	open PR #321
codex/typed-witness-benchmark-candidate-20261109	976ca18b11d49a447776e5436a3111610374891d	explicit owner-requested parked optimisation
experiment/stwo-zig-lab-20261006	0bb6dc542490762de686aca0d87d6eb81286f43e	open PR #223
feature/riscv-recursion-audit-realignment	66e26f6eddfc16e45aa4aeca68df89adf715ad84	open PR #303
main	99f2e13f713be28951c7faff4b6286a9524f1c96	default branch
ryan/s31-math-eq-ne-prod	3fe707a0d6f4874071beeffc3d48aff70546147d	open PR #236
```

Raw verification/deletion receipts live outside the source tree. Issue #334
records the published tag verification and actual retirement result.
No code, runtime flag, launcher, proof pin or GPU qualification changes.
