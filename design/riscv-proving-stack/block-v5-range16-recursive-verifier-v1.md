# Range16 recursive verifier, version 1

This source candidate adds a distinct recursive verifier for the real packed
range16 provider. It is not enabled by the canonical CPU driver, CLI, global
receiver or execution forest. All-family detached verification remains
mandatory. No build, test, proof, guest, segment or device run was performed by
the implementing agent. Root qualification passes six nonproving checks (five
named and one import), and compiles the actual capture/preparation/publication/
fresh receiver bodies without invoking them. Failed fixture candidates and the
corrected shared recorder error path remain recorded in the cohesive receipts.

`block_v5_range16_recursive_admission_v1.Prepared.init` takes independently
pinned B5SS policy/roster, the exact range shard and plan digest, the two first
roots, and explicit capture/preparation caps. It fixes the physical domain at
log 16 with fixed/main/interaction widths 1/1/8 and two degree-2 equations.
Shard indices and request counts are bounded independently. The template ID
binds this ABI, source authority, fixed root and PCS security configuration;
changing shard metadata, main roots and public claims does not specialize it.

`Capture.ForBackend(B).verifyBorrowed` invokes the real core verifier and
returns an owned capture. It recomputes the deterministic range value-column
commitment, checks independently pinned first roots and the actual typed AIR,
and owns capture allocations under a bounded allocator. The original proof is
borrowed only until the call returns. Its mutation seal is an internal
consistency guard, not recursive proof authority.

The new composition adapter records the same generic range algebra used by
the CPU component. It constrains both normalized recurrences, the actual
coset denominator, Horner ordering and split-composition reconstruction.
DEEP masks come from that component. Existing symbolic FRI, query, Merkle,
opening, BLAKE3 and proof-of-work cohorts constrain the captured PCS material.
The shared parent preparer dispatches only on the exact range capture type;
all existing native and parent routes retain their previous behavior.

Transcript replay preserves B5SS framing, 47 universal challenge pairs, the
five word-memory suffix pairs, the range shard/plan encoding, the separate
four claim-sum limb encodings, and all subsequent PCS/FRI operations. The
fixed and main roots are external statement providers because the original
range proof channel resets after their commitments. Their actual Merkle path
reads close against those independently supplied roots.

The public bus supplies the seal, plan, exact shard index/extent/request
count, fixed and main roots, and sum/count through authenticated wire tuples.
It supplies both transcript byte words and the actual equation graph inputs,
using the same independent public values. The distinct parent protocol binds
the public schedule, child template and matched parent/child security config,
then closes the complete recursive wire claim against those providers.

`Stage.ForBackend(B).publish` fresh-verifies the borrowed range proof, builds
the real verifier row set, derives the parent setup, proves it, strictly
encodes it and freshly verifies it before ownership transfer to its sink.
`Leaf.verify` decodes and verifies those bytes under independently supplied
key, schedule, range policy and expected public open claim. The result is an
open provider equation; requester cancellation and global completeness remain
separate obligations. The current stage derives setup on each publication;
bounded reusable range setup caching is not integrated yet.

The safe pure filter is `range recursion:` in
`src/frontends/riscv/block_v5_range16_recursive_test_root.zig`. Its five named
fixtures check typed CPU OODS versus symbolic equation parity, sum/count/
previous-value/composition-chunk rejection, allocation cleanup, independent
policy admission, exact transcript bytes and dynamic public statement
binding. Literal metadata and arbitrary OODS values never pass a proof
acceptance path. The separate object root
`src/frontends/riscv/block_v5_range16_recursive_codegen.zig` retains actual
capture, preparation, publication, independent recursive receive and teardown
bodies without invoking them. Candidate commands and source hashes are in
`native-range16-recursion-source-candidate-v1.json` under the campaign's
`cpu-performance-gates-v1` directory.

Root results use `capacity-canonical-integration-range-recursion-result-v4.json`
and the corresponding range-body receipts. Exhaustive graph-allocation failure
found that the shared recorder hid its retained `OutOfMemory` behind
`GraphConstructionFailed`. It now preserves the first typed error unchanged;
the builder stays poisoned, rejects subsequent recording/finalization, and
unwinds all graph/arena ownership. Scalar equation and original transcript
parity pass alongside allocation cleanup. No recursive STARK was produced.

Remaining scope includes the sorted RAM-lane verifier, other provider families,
recursive global cancellation/completeness, durable provider-leaf transport,
setup cache integration and canonical orchestration. This candidate does not
claim a self-contained complete block proof or any performance result.
