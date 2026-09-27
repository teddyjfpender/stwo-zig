# Private BLAKE3 transcript transition — 2026-09-22

The previous turn made verified progress on shared digest routing. This turn
connects it to full hash witness construction and a complete CPU proof.

`blake3_frame_witness.zig` builds arena-owned hash and route rows, removing every
message-input public boundary while retaining graph constants and final output
boundaries. It exports source-use counts so upstream producers emit exactly the
required authenticated copies. Trusted construction uses canonical shape and
literal payloads, not private digest bytes or native hash evaluation. Returned
row views contain no allocator pointing at the moved local arena.

The new proof fixture performs the native channel sequence mixU64(198), then
mixU64(42), starting from its pinned initial digest. The first absorption's output
is removed from the public boundary and routed into the second absorption as
private state. Only the final digest is claimed publicly. Trusted preprocessing
does not compute or receive the intermediate digest. This is not a claim of
zero knowledge; private here means outside the public statement.

Focused validation:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-transcript-proof -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-frame-witness -Doptimize=ReleaseSafe --summary all
```

Both guarded tests pass. The complete STARK closes real table interactions and
passes the core verifier. Changed final digest and substituted preprocessing
root fail trusted admission. The witness test confirms live/native hash parity,
exact fixed-column equality when private state bytes become zero placeholders,
matching source multiplicities, and every backing allocation failure.

Proof runtime: approximately 3 seconds, max RSS 347 MiB. Witness tests: 491 ms.
These are development fixtures on M5 Max, eight queries, blowup 1 and zero PoW;
not production performance or security qualification. Formatting and diff checks
pass; new source files remain well below the manual source-size ceiling.

Remaining: integrate private-state draws and ordered rejection attempts into one
transcript sequence; authenticate counters and absorption resets; handle private
scalar payload serialization, raw-u32 queries, PCS/FRI geometry and PoW; qualify
production source admission, identities, CPU/Metal parent-of-parent proofs and
same-security performance. Production still selects Poseidon. The original
recursion optimization goal also remains active.
