# BLAKE3 parent-of-parent integration

Successful parent verification now retains the universal challenges and publishes
a transport seal over the admitted key ID, proof capture, claims, challenges and
final transcript state. This seal detects later mutation; it does not replace
STARK verification or let received metadata select a key.

The parent transcript replays the actual admitted protocol domain, full key ID,
claims framing and shared PCS suffix through the existing bounded BLAKE3 planner.
A new parent composition adapter records the admitted typed roster's direct and
LogUp programs plus shared table equations, checks the exact constraint count,
reconstructs split composition and constrains the complete claim sum. Samples,
claims, challenges and OODS/composition randomness remain linked graph inputs.
DEEP geometry is reconstructed from admitted components through the same shared
helper used by execution leaves.

The existing owning preparation accepts either a verified base-execution child
or a verified typed parent. Both use the same transcript routing, root/nonce
binding, DEEP/FRI arithmetic, opening inventory, final-column hash emission,
row assembler and persistent proving API. The next level's context binds the
previous level's full key ID. The focused real-proof test creates distinct parent
keys, round-trips both artifacts and independently verifies both levels after
releasing their proving plans.

This is unary parent-of-parent integration at diagnostic q8/PoW0. It does not
qualify distinct-child aggregation, production parameters, continuation or CSP
extension orchestration, CPU/Metal parity or production default promotion. No
end-to-end speedup or subsecond recursion claim is made.

## Qualification

`python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments -Doptimize=ReleaseSafe --summary all`

Passed in ReleaseSafe: 2 minutes build/test time, 5 GiB peak RSS. The real
execution parent artifact is 124,866 bytes; its parent is 121,966 bytes. The
second-level preparation accounts for 18,565 inputs and retains 523,271,232
bytes. It uses 3,820 dot4 matches, 10,131 multiply-add matches and 2,256 fused
query groups, removing 9,024 scalar producer rows. These are structural counts,
not isolated proving timings.

Both artifacts are encoded/decoded and independently verified with distinct,
caller-pinned keys. Captured sample mutation rejects before next-level
preparation. Child-key, graph-ID and transcript-plan-ID substitutions also
reject. The existing real execution, graph equation, routing, opening, source
inventory and fail-atomic column-transfer checks remain in the same gate.
Formatting checks pass. No whole-repository suite or performance benchmark ran.
