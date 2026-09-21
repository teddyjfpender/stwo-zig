# VM profile identity ownership and edit loop

Canonical SegmentV2 VM AIR profile identity encoding now has a pure owner,
`vm_air_profile_v2_identity.zig`. Its structural input introduces no derivation,
prover, witness or component-handle import. The existing profile API delegates to
it. A transitive import guard enforces this boundary. Post-format transfer audit
confirms every hash body and both domain constants are unchanged; no protocol
identity or pinned admission is regenerated. The profile owner falls from 924
to 838 lines. Source-conformance findings fall to 109 without baseline changes.

The existing `test-vm-air-profile-v2` target passed 21 tests but compiled broad
composition/provider cases in five minutes at about 6 GB. Added
`test-vm-air-profile-authority-v2` for the same three profile-authority tests plus
three import-discovery tests. Its first successful compile took seven seconds at
596 MB; execution took 958 ms at 4 MB. These are local dev-loop observations,
not proof-performance claims. The original broader target and tests remain.
The initial narrow root was placed too deep for Zig relative imports; a frontend
root wrapper fixes the module boundary and is registered in the test inventory.

Validation: 21 broader profile tests, six narrow tests, 44 ownership/isolation
checks and both inventory checks pass. Formatting/diff checks pass. Tests initially
needed approved access to Zig's standard library and cache outside the sandbox.
The count floor is six. Exact command results and the transfer audit are retained.
No complete-proof build was repeated for the unchanged encoding bodies. The prior
canonical-surface checkpoint remains the complete-proof evidence for its source.
Broader source-size findings and Linux artifact-store runtime qualification remain
open under the original goal.
