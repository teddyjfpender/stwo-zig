# Caller arithmetic and fused verifier capture, version 1

This additive source batch exposes genuine owned and borrowed verifier capture
for the original caller arithmetic STARK and its separate fused
projection/access STARK. The original owned APIs, proof bytes, protocol
versions, equations, component inventory and canonical defaults are unchanged.
No compiler, test, commitment, proof, guest, segment or device job was run by
the implementing agent; formatting alone passed. The source candidate and
nonproving/body commands are pinned separately for root qualification.

The arithmetic verifier retains all 19 typed components: 14 Ethereum
Keccak/signer/private-table components and 5 SHA components. Component log sizes
and fixed/main/interaction widths come from independently admitted statement
geometry. Every detailed batch and aggregate/scalar claim still validates and
mixes in the existing `ExtensionClaim` order; `componentSum` remains the open
VM residual. The verifier still reconstructs and commits the deterministic
fixed tree and compares the independently bound key/root before invoking the
complete actual assembly and core STARK verifier.

Fixed and main commit under the original empty first-round channel. The
arithmetic proof channel resets to B5SS, draws the 47 shared VM pairs and the
B5PF/profile-specific private extension suffix, mixes execution/key/instance
identities and both first roots, then the complete typed claims and interaction
root. Four commitments include composition. The fused proof has three real
initial trees: caller fixed, caller main and packed access witness. It resets
separately to B5SS 47+Word 5/B5CF, binds its exact instance and four independently
capped claim-array lengths/census/values, then commits interaction. Five
commitments include composition. Its exact Schedule/components preserve
program, PC/state, six-table/register and packed transition/universal/byte
claims with heterogeneous actual logs and original Keccak shifted openings.

`Family.ForBackend(B).verifyCaptureOwned` consumes the original arithmetic
proof on every path; `verifyCaptureBorrowed` preserves it on every path. Both
share `verifyInternal` with the existing `verifyOwned`. They call the core's
actual `verifyWithProofCapture` or `verifyBorrowedWithProofCapture` after the
same root, config, statement, claim, seal and component admission. Returned
`Family.VerifiedCapture` independently owns the complete core capture, exact
claims value, relations, terminal channel and actual open receipt. Its
`validate` rechecks independent statement/binding/B5SS authority, actual logs,
roots/security, claims/open residual, relation draws and mutation seal.

The shared `CompositePCS` module now has additive `verifyCaptureOwned` and
`verifyCaptureBorrowed` beside `verifyOwned`; all three use one exact kernel.
No root checks, trace commits, component handles or core checks are removed.
The captured result is the actual core capture plus terminal channel.
`Fused.ForBackend(B).verifyCaptureOwnedAfterFreshCaller` and
`verifyCaptureBorrowedAfterFreshCaller` reuse the original fused verifier
kernel and exact scoped receipts. The owned path transfers the four small
claim arrays into its capture; the borrowed path copies only those arrays.
Neither retains/clones the original STARK, PCS, arithmetic matrices or replay
witness. The capture owns its derived range receipt array and all core capture
vectors. `validateAfterFreshCaller` independently derives the actual Schedule,
checks every array before use, all four source log arrays and three initial
roots, redraws relations/challenges and recomputes every scoped receipt and
range claim. Mutation checksums are consistency guards, never proof authority.

The new full entry is
`block_v5_caller_verified_capture_v1.ForBackend(B).verifyOwned/verifyBorrowed`.
It takes both original proofs and existing independent `CallerReceiver.Pin`
plus B5SS policy/roster. It first performs the original receiver admission,
freshly verifies/captures arithmetic, checks its exact expected binding, then
freshly verifies/captures the fused proof. No caller-supplied scalar receipt
can enter this detached entry. Returned `Verified{caller,fused}` owns both
captures and exposes `validate` and `deinit`. Failure in either stage destroys
all owned captures; owned inputs are consumed, borrowed inputs remain live.
Each source proof must stay immutable and alive only until verification
returns. Allocations use the supplied allocator, so independent callers may
use the existing bounded host allocator; this slice does not invent new
resource authority or bypass original codec/policy bounds.

The safe root is `src/frontends/riscv/block_v5_caller_capture_unit_test_root.zig`,
filter `caller capture:`. Six named checks cover four-array clone isolation and
all allocation failures, borrowed arithmetic source preservation on repeated
early shape failure and every admission allocation failure, owned rejection
cleanup, shared PCS root rejection custody, dual-proof independent event
census rejection, exact separate transcript reset/geometry framing and actual
owned/borrowed/dual verification body retention. Deliberately malformed proof
objects reject before commitments/core verification; no synthetic successful
capture is constructed or accepted. The separate object root
`block_v5_caller_capture_codegen.zig` retains all actual verification and
capture consistency/teardown bodies without invoking them. Candidate commands
and hashes are in `caller-verifier-capture-source-candidate-v1.json` under the
campaign's `cpu-performance-gates-v1` directory.

This prepares the remaining genuine caller recursive verifier, but does not
implement its symbolic arithmetic/fused composition, exact two-channel replay,
DEEP/FRI/Merkle adapters, independent public bus, reusable parent key/leaf or
durable recursive transport/global closure. None of the captured open bus
claims grants complete block authority. Canonical native/caller/RAM/global
verification and mandatory all-family detached verification remain unchanged.
