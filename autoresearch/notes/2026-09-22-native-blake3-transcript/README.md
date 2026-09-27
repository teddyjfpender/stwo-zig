# Native V2 BLAKE3 transcript adapter

The adapter consumes the concrete verified native capture for a BLAKE3 engine,
validates its authorities, and replays the normal V2 physical-lookup protocol
through an owning recorder. It reuses the native public-data, main-claim,
manifest, relation and physical interaction-claim encoders. The existing PCS
transcript builder appends the remainder of the STARK verifier transcript.
Temporary encoder buffers and retained capture payloads are copied into owned
storage. Plan and witness arenas use the backing allocator directly, avoiding a
retained allocator pointer into a moved outer arena.

All 227 operations, 12 native relation pairs, final digest and draw counter match
the independently verified native channel. The plan ID in this gate is
`b55a838fc3d71ca1f7d03afa203c94b0408ab103cfdd0c57e85d1157ea760d99`.
A changed interaction claim fails replay against the captured proof. Native
relation exports use their own output role; fixture universal-relation links
explicitly reject this role. Existing plan role tags retain their values.

Final focused serial ReleaseSafe command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-recorder test-blake3-native-segment -Doptimize=ReleaseSafe --summary all
```

Terminal exit 0: 8/8 steps and 4/4 tests passed. Recorder ownership and exhaustive
allocation-failure test: 488 ms, 1 MiB; native segment tests: 20 s, 1 GiB.
Compiles: 3 s / 420 MiB and 55 s / 4 GiB respectively. The earlier adapter and
reusable-plan gate also passed 4/4 tests; its log is retained separately.
The native gate includes both default Blake2s and BLAKE3 proofs, plus the
existing rebased default-suite case. No broad suite ran.

Final BLAKE3 diagnostic: nonfinal proving 4000.513 ms, verification with capture
886.716 ms; final proving 4151.425 ms, verification 791.194 ms. These are tiny
one-query, zero-PoW qualification cases, not canonical CSP results or a matched
speed campaign. No proof speedup is established.

Scope: this is native transcript witness preparation and parity. The external
ports for roots, nonce, interaction claims and PCS payloads still need their
native composition/public-boundary joins in a complete recursive parent.
Public statement/configuration operands still specialize preprocessing; this
is not a statement-independent production key. Production suite selection,
state/guest Poseidon semantics, Metal and parent-of-parent qualification remain
unchanged. The migration is incomplete.

The source snapshot and relative-path SHA256 manifest pin this stage. Logs are
terminal outputs, not performance acceptance measurements.
