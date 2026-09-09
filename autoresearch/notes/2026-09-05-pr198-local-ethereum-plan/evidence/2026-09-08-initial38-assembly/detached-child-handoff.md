# Initial38 detached-child publication: remaining integration

Read-only source review after the Initial38 assembly gates passed. No new proof was launched. Ordinary saved children 2/3 and their parent remain the immediate priority.

## Reusable authority already present

`ethereum_wrapper_root_verifier_v1.zig`, `ethereum_wrapper_root_command_v1.zig`, `ethereum_wrapper_verifier_components_v1.zig`, and `ethereum_wrapper_child_shape_v1.zig` already expose explicit `Types(ManifestMod)` / `Initial38` selection. Initial key admission, independent proof verification, 38-row components and fixed proof dimensions therefore have one existing implementation. The complete Initial38 producer and fresh-root lifecycle compile; this is not yet an executed real initial proof.

`CaptureLayoutV3.initEthereumInitialWrapperV1` and its matching validator already admit the exact 38-row geometry. `ProgramRecorderForManifest(ManifestMod, .binary_node, 38)` is already parameterized; its authenticated-binary validator compares the exact selected manifest count. Neither needs 20 duplicated component owners.

The existing composition input ABI is 41 claims wide: physical capacity 39, provider partial slots 39/40. Initial38 fits: physical claims 0..37, slot 38 constrained to zero, unchanged partial slots 39/40 and wire-boundary item 41. Widening the shared ABI or moving ordinary slots is unnecessary. The missing part is an explicitly admitted 38-claim policy; existing universal binary policy still expects 36 and constrains its tail to zero.

## Minimal consuming chain still needing selected admission

1. `ethereum_wrapper_detached_transcript_v1.zig`: select the existing verifier/claims/key types by manifest module. Its `OwnedV1`, replay storage and replay mix currently name ordinary aliases. Keep verification before publication and compare the recorded terminal against the native verified terminal.
2. `recursive_secure_transcript_program_v1.zig`: add an explicit initial field-program admission entry to the existing operation builder. Current `initEthereumFieldFieldsV1` uses the ordinary manifest type, ordinary exact geometry and layout; `initAdmitted` rejects any count other than 36. Selected initial admission must retain its own exact manifest/layout validation and feed all 38 claims into the shared transcript ordering. Provider and wire ABI offsets can stay unchanged.
3. `ethereum_wrapper_detached_composition_v1.zig` plus the shared recording functions in `recursive_common_ethereum_incremental_leaf_composition_capture_owner_v4.zig`: select the existing Initial38 components and layout. The shared recorder currently fixes the ordinary manifest, 36-claim sum, universal claim policy and recorder specialization. Introduce only a selected shared recording helper, preserving the ordinary wrapper entry point. Record the two new component equations and sum all 38 physical claims; route the same authenticated public/boundary inputs.
4. The composition claim-policy admission/writer in `recursion_air_composition_circuit_v3_program_roster_v3.zig` and `recursion_air_composition_circuit_v3_write_inputs_from_validated_profile_and_policy.zig` needs an explicit initial profile (or comparably explicit admitted policy) for 38 claims and the zero slot at 38. Reuse the existing 41-slot ABI; do not alter the universal/H1 defaults.
5. `ethereum_wrapper_detached_fold_v1.zig`: its dimensions are generic, but child ownership/transcript/composition/shape types are ordinary aliases. `TypesForManifest` also takes the ordinary concrete manifest. Consume the selected owners here after their isolated replay/composition gate passes.

## Distinct pair-0/1 boundary

The current fold adapter takes one `dimensions` value and one `Child` type for both children. `Live.validate` requires both shapes equal that value, `initCapturedFriPair` uses the left protocol and common claimed-sum count, and `recursive_common_fold_fixed_wire_v2.zig` requires each projection's claims length equal the common dimension. Initial0 has 38 claims; ordinary1 has 36. Merely adding `Types(InitialManifest)` to the adapter does **not** admit the heterogeneous pair.

After standalone initial child publication is proven, pair0/1 needs independently admitted left/right shape selection through the fixed-wire boundary, or a separately authenticated padding construction. Do not silently pad claims or infer the profile from candidate proof data. This is a concrete additional boundary beyond the already-working selected native root. It should not delay the ordinary pair2/3 milestone.

## Acceptance order and existing command route

After implementing selection, extend the existing detached transcript test with explicit Initial38 selection and independently pinned initial key/proof artifacts. The present command has only ordinary selection and is **not** an initial acceptance command today:

```sh
STWO_ETHEREUM_ROOT_REPLAY_DIR=/path/to/independently-verified-initial0 \
STWO_ETHEREUM_ROOT_KEY_SHA256=<independently-pinned-key-sha256> \
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  test-ethereum-detached-field-transcript \
  -Dethereum-proof-strip=true -Doptimize=ReleaseSafe --summary all
```

Require actual proof verification, producer/input destruction, native/recorded transcript terminal parity, all 38 composition equations, and AIR rejections for mutations of each initial claim, partials, public boundary and sampled composition values. Keep ordinary replay acceptance in the same selected test matrix.

Only then extend `ethereum_wrapper_saved_child_parent_v1_test.zig` and its selected test root for independently pinned children0/1. Existing `check-ethereum-saved-real-parent` and `test-ethereum-saved-real-parent` currently instantiate ordinary children2/3 with one measured geometry and are not initial-pair acceptance. The initial pair must retain parent serialization, producer destruction, independent parent key admission, and fresh parent verification, alongside reversed/duplicate/continuation rejection.
