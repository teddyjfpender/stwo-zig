# Receiver-owned beta2 fixed authority for OM services

This adds an explicitly selected engineering route. The existing beta1 benchmark, wire codecs and default producer/receiver entrypoints remain unchanged. It does not issue a whole-protocol128 certificate.

`fixed_authority.Binding.acquire(cache, trustedSourceKey, config)` derives a beta2 immutable cache lease from the trusted source key's retained, ordered M31 coefficients. `WideFixedKey.requireSource` independently checks suite/shape and re-hashes the actual source coefficients; a producer root or coefficient identity cannot choose a different ROM/table key. The binding checks beta2 supported configuration, retains its own allocator/key owner, and authenticates the descriptor, coefficient identity and committed root before append.

CPU/truth workers expose additive `initWithAuthority` and `verify...WithAuthority` functions. Default functions pass no authority and keep beta1 admission. An authority-bearing worker owns a retained lease until deinit; the PCS tree independently retains shared backing. Its statement and transcript bind a distinct beta2-engineering tag, fixed identity and root. The old immutable source setup remains the authority for program, fixed column order, component geometry and masks. The source setup is not replaced by producer metadata.

`fixed_authority_set.Set.init` constructs the complete receiver-ordered set from trusted CPU and truth setup, under the caller's bounded cache. It binds the exact configuration, CPU count, total count, ordinals, coefficient identities and roots. `Inventory.initWithAuthority`, `coordinator.produceWithAuthority`, `Bundle.verifyWithAuthority` and `execution.verifyWithAuthority` thread this same context through statement construction, stage-one child/manifest admission, physical append and fresh verification. The receiver builds its own set from independently reconstructed setup. The operational resource JSON cannot select this protocol or supply its roots.

The set and original native setup remain live across a synchronous producer/receiver call. Workers retain individual leases; releasing the cache handle after set construction is safe. Temporary partial sets release every acquired lease on failure. Requested cache bytes include immutable key owners and sealing scratch; host capture, legacy source setup, native proof scratch and allocator/OS residency remain separate owners.

## Qualification

The physical worker slice passes Safe/Fast gates for actual fully parked CPU Keccak and ADD/DOUBLE shards, and K/ADD truth proofs, under beta2 engineering q12/P0/fold1. All default beta1 tests remain active. Wrong source coefficient identity, stale root/descriptor/configuration and cache lifetime failures are rejected; immutable cache allocation-failure sweeps remain active.

The complete fixture uses the exact numeric `om31_security_candidate.config()` point: beta2, q256, P0, fold4. Two CPU shards plus K/ADD/DOUBLE truths prove a seven-instruction execution, with full MAIN coefficient/node parking, local GKR binding, explicit classic-truth locals and separate RAM/KIO/Wire closure. A fresh receiver independently reconstructs all setup and immutable leases. The default receiver refuses candidate promotion. Changed query configuration, swapped trusted bindings, swapped physical proofs and altered pure-global debt are rejected. A populated-cache caller-allocation sweep and a later uncached-key OOM case cover set teardown/retry. This is a functional qualification, not a block benchmark or controlled performance comparison.

## Remaining production gates

The engineering route admits an explicit supported beta2 configuration; it does not yet derive and bind all of `Candidate.Facts` from the complete source constraint/lookup roster, instantiate the applicable security reductions or install a reviewed certificate. `requireWholeProtocolPromotion` continues to reject even when every review flag is true. The explicit engineering tag is deliberately distinct from the final candidate security identity.

The Ethereum CLI still selects the unchanged beta1 control. A beta2 CLI command must create its authority set from receiver-owned ELF/program/image/setup, keep the new identity explicit in transport, apply source-derived geometry/count/mass admission before costly setup, and obtain real prefix/full-block qualification with a bounded setup plan. No selector should be added to the resource JSON.

Initial source setup still constructs and retains its legacy beta1 key before the beta2 cache derives a new tree from retained coefficients. Fixed rows are not reconstructed and immutable beta2 sealing is cached, but this is not a claim that setup memory or startup work is optimal. A future coefficient-only source/setup authority should avoid constructing an unused beta1 tree, while retaining independent receiver reconstruction and layout validation.

New-profile recursion remains separate. The numerical OM GKR circuit adapter and native physical proofs do not automatically produce a recursive Ethereum proof. GPU residency, an equally secure baseline and whole-protocol128 remain separate qualified deliverables.
