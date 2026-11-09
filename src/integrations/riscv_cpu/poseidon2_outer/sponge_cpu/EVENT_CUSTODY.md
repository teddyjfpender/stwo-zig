# Producer RAM-event custody candidate

`event_custody.zig` is an isolated producer utility. It is not registered in
capture, planning, execution or any production suite. It changes no proof or
source authority. Its SHA-256 digest protects producer temporary-file integrity;
it is not a new public cryptographic argument.

The caller derives `Descriptor` from the actual program identity, CPU boundary,
epoch, ordinal and event count. `park(store, original_allocator, descriptor,
&events)` reserves the same disk quota as MAIN/FIXED, streams initialized
66-byte records in little-endian order, and clears/frees the original slice only
after the complete write succeeds. Each record contains opcode, immediate,
A/B/C, event epoch/tick and both full RAM states. No native padding or u24
storage representation reaches disk. The codec rejects non-LS opcodes and
noncanonical rights bytes. It preserves event order and all values verbatim;
semantic validity remains the original LS/OWNER/RAM authority's job.

`token.restore(a, same_descriptor, &empty_events)` checks exact rounded file
length, canonical decoding and the complete digest before publishing one owned
native allocation. `retire(a, &events)` verifies that planning did not mutate it,
frees it and clears the non-owning token view. The token can restore the same
file again without another write. If source construction instead consumes and
clears the owning event slice, `consumed(empty_events)` clears only the token's
non-owning pointer. `deinit` closes only the reservation and file, and is
idempotent; it never frees a restored allocation. The caller must destroy live
slice owners before closing the Store. Original allocator matching is a caller
ownership contract, as with the existing metadata custody helper.

The intended integration is capture append -> park the just-appended
`Shard.events` -> restore one shard for planning -> retire it -> restore once
before source construction -> let the existing consuming pipeline free it.
The collector's live ledger and other service advice remain resident. Restored
count and order must feed the same independent request, dword routing and key
planning. No empty replacement may be exposed to a consumer before restore.
Errors after parking must retain custody until all restored views are released.
This integration still requires native proof-byte parity, source geometry
parity, cross-shard ordering, after-park capture failure and downstream planning
failure qualification. Those gates have not been claimed by these unit tests.

Focused ReleaseSafe tests cover complete-field codec equality, endian tags,
noncanonical encodings, 65-event chunk crossing, descriptor substitution, disk
quota, allocation failure sweep, failed restoration, corruption, truncation,
immutable planning retirement, repeated restoration and quota cleanup. An
initial test caught Zig's narrow inferred `@min` count arithmetic at 64 rows;
explicit `usize` chunk counts fix it and the full focused suite passes.

To run after adding the module import to the OP native test root:

```sh
zig build test-riscv64-op-native-join -Doptimize=ReleaseSafe \
  -Driscv-test-filter='OP event custody' -j1
```
