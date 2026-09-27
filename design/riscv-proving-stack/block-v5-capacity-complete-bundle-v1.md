# Typed capacity complete bundle transport v1

The existing CPU bundle Store, policy builder, receiver-policy file and detached receiver now expose `ForCapacity(comptime bool)`. Their top-level APIs select `false`; explicit `block_v5_cpu_capacity_*_v1` wrappers select `true`. The producer chooses this typed stack independently. Proof bytes, semantic family labels, received claims and register mode cannot select it.

Capacity native files use the actual `NativeCapacity.Proof` and `B5CTART1` codec. Capacity native-fused files use the actual `CapacityFused.Proof` and `B5CFART1` codec. Every other semantic family retains its original typed proof and codec. No capacity proof or receipt passes through NativeV3, and no separate native program/table/opcode proof can enter the capacity inventory. Genuine empty native projections still retain the required base native frame proof and typed access admission; a nonexistent fused obligation gets no file.

`Policy.ForCapacity(true).collect/build` accepts only `Capacity.Global.Pins`. It validates the complete independent source seal/catalog/public admission, derives physical capacity columns including the committed active selectors, exact projection/access counts, frame, witness root and source mode, and derives capacity codec Expected policies through the already qualified artifact admission helpers. Full claim and geometry counts and resource caps are checked before transport array allocations. The Store rederives B5CF inventories and geometry, and native physical columns/claim census, before persistent slot ownership. Provider plans and caller/program/memory/range families remain independently planned and freshly closed by Capacity.Global.

The capacity bundle inventory is explicitly distinct:

- proof names: `block-v5-capacity-{family}-{index}.proof`;
- manifest: `block-v5-capacity-bundle.files`, magic `B5CFILE1`;
- receiver policy: `block-v5-capacity-receiver-policy.json`, format `stwo-zig/block-v5/capacity-receiver-policy`, version1.

Legacy file names, `B5FILES1` manifest, metadata format/version and individual legacy codec payload decisions remain unchanged. Non-native capacity proof payloads use their original codec and bind independently derived capacity bundle policy where that codec includes policy identity.

`Detached.ForCapacity(true).verify` reads the SHA-pinned typed receiver policy from disk under the out-of-band public identity and owned-byte budget. It then rebuilds all file allocation policies, reloads the fixed-width SHA-pinned bundle inventory, opens all four original endpoint source files, and calls `Capacity.Global.ForBackend(Cpu).verifyCompleteDetached` with typed proof loaders and the independently pinned capacity forest manifest. It requires every admitted proof file to be consumed. No producer receipt is accepted. The metadata remains alive until the Store and receiver finish because policy shape/statement pointers borrow its immutable owned storage.

Publication and loading share one bounded Store state machine. Its mutex covers all mutations, file snapshots and consumption checks. Successful durable publication consumes proof ownership; every failure retains the producer proof. A failed load still consumes that file slot, preventing replacement during the same fresh receiver session. Native/fused decoded owners remain independent of wire buffers.

## Driver connection

Select all four factories with the same compile-time bool:

```zig
const Store = @import("block_v5_cpu_bundle_store_v1.zig").ForCapacity(capacity);
const Policy = @import("block_v5_cpu_bundle_policy_v1.zig").ForCapacity(capacity);
const Metadata = @import("block_v5_cpu_receiver_policy_file_v1.zig").ForCapacity(capacity);
const Detached = @import("block_v5_cpu_detached_receive_v1.zig").ForCapacity(capacity);
```

Capacity `Store.executionSink()` exports native and ROM callbacks, with no separate request callback. `Store.fusedSink()` returns the actual capacity fused stage Sink. The program loader uses actual capacity Native/Fused proofs; shared caller/provider/sorted-memory sinks are unchanged. The driver must publish all jobs before writing the file inventory, write the typed receiver policy, pin its returned digest and the typed forest/bundle manifest digests, and invoke Detached.verify with the original public input. Capacity planning/execution/recursive producer integration is owned by the root/other agents; this source slice does not itself activate or run that driver.

## Qualification candidate

Source formatting is checked. No compiler, tests, proofs, guest, segment, device or benchmark were run by this agent. The new root is `src/frontends/riscv/block_v5_capacity_bundle_unit_test_root.zig`, filter `capacity bundle`:

```sh
python3 autoresearch/notes/2026-09-24-ethereum-block-delivery/test_sha_memory_proof.py --root src/frontends/riscv/block_v5_capacity_bundle_unit_test_root.zig 'capacity bundle'
```

Six bounded fixtures cover distinct typed/magic/metadata identities, literal native durable roundtrip and retained ownership on failed publication, literal B5CF four/five-tree roundtrip and wrong count/root/geometry/caps, early metadata/resource rejection, exhaustive fused-policy allocation failures, and actual dual detached consumer/policy/store body retention. These are structurally valid literal postcard envelopes, not accepted AIR proofs. Function-address retention does not invoke either complete receiver. The source batch requires root compiler/codegen qualification; actual capacity Complete STARK/runtime qualification remains outstanding and is not implied by these fixtures.
