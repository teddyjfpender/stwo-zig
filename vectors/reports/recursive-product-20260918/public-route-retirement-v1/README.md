# Public recursion route retirement, 2026-09-18

Removed 46 legacy segment/outer/temporal exports from the CPU integration API.
The 19 exports with in-repository member consumers were migrated to direct local
imports; the remaining 27 had no such consumers. Removed the Poseidon-ingress and
temporal-parent executable wrappers and their build/run steps. Their guarded
historical tests remain available. This is an intentional public API removal.

Leaf key setup now uses the canonical native ingress owner, without importing
its old proof-test harness or broad integration namespace. Actual native proof,
fresh verification and key derivation reproduced the independently pinned
16-address, one-segment leaf key exactly, without creating an outer proof.

Qualification:

- Fresh CPU/Metal/AOT four-segment products passed 384 checks, including fresh
  serialized verification, malformed proofs and same-geometry substitution.
  All 21 canonical artifacts are identical to the reviewed identity baseline.
- Three command tests, 228 parent-admission tests (one skipped), and 34 source
  closure checks passed. These are focused checks, not a full suite.
- Source snapshots matched between the complete products. The six subsequent
  changes are isolated historical test-support files: imports were made
  consistent within one Zig module, and one stale geometry diagnostic field was
  updated to the current input-profile owner. The recorded source delta matches
  exactly those files. A conservative local graph of 249 sources, including the
  broad CPU integration namespace, excludes all six from canonical commands.

The first retained-harness compile exposed mixed root/integration module imports.
After that repair, compilation exposed the stale diagnostic field. The retained
harness's final compile passed; no historical temporal proof execution is
claimed by this batch. Canonical recursive proofs are covered
by the complete product gates above.

Remaining: frontend V1 trace/public-I/O proof APIs still serve the ELF adapter and
benchmark. Their callers require migration before those APIs can be retired.
The canonical parent CLI also still forwards through the broad integration
namespace. The consumer inventory is adjacent. Final useful 1/2/4/8 continuation
qualification follows frontend/API cleanup. Speed and Ethereum expansion remain
deferred. This development profile is not production-security qualification.
