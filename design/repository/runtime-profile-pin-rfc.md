# Approved RFC: runtime-profile source digest fixture

Status: approved in [RFC #326](https://github.com/teddyjfpender/stwo-zig/issues/326).
Owner decision: [approved by the repository owner, recorded by delegate](https://github.com/teddyjfpender/stwo-zig/issues/326#issuecomment-6739261335).
Owners: `riscv-frontend`, with `prover-api` consulted for the source schema.

## Affected contract and decision requested

Approve refreshing only the expected runtime-profile digest in
`src/frontends/riscv/air/lang/tests/runtime_profile_test.zig`, from
`427aa2e4f024e7996734808f58255c7a23aba58402b26f218f82398c213db38f` to
`f215072722d632f872f3ce0fb3fa123c6160e0e8e80604424aef1faf201f0c60`.
This is an exact fixture proposal, not authority to regenerate other pins.

## Cause and unchanged-contract alternative

Commit `5b8be3eb11` added optional `StageNode.process_usage` while retaining
the StageProfile JSON schema version. JSON omits the null field, but the typed
source hasher binds its presence and value. The golden fixture predates that
extension. Static-profile sources and the hash implementation are unchanged
from the golden update at `1c6c81ecf9`.

An isolated diagnostic constructs the exact fixture through the normal join.
It obtains the current digest above in Debug and ReleaseFast. A projection
using precisely the historical StageNode fields recovers the old golden
exactly; normal current-source admission rejects that projection. A synthetic
non-null process-usage record changes the current source identity, rejects
the former source binding and is admitted only after a normal fresh join.
The retained diagnostic has four passing cases in each mode. These diagnostic
cases do not replace acceptance of the original eight-case target.

Preserving the historical digest would require a deliberate source-encoding
compatibility policy or versioned interface. Ignoring process usage to obtain
a green test would weaken complete-source binding and is rejected. Owners
may instead require the broader versioned design; it is outside this proposal.

## Compatibility and versioning

The proposed edit changes only the fixture expectation and adds a mutation
branch within the existing complete-source binding test. It does not change
production hashing, validation, JSON, proof or wire bytes, public signatures,
error tags, dependencies or schema versions. No package version bump is
required for this test-only correction; the approved owner decision confirms
that classification under ENGINEERING_STANDARDS.md section 6.
There is no dual-admission window: historical projected source identities
remain invalid for current records. No consumer changes are proposed.

## Tests first and acceptance

Extend the existing complete-source binding test to mutate null process usage
to a synthetic record, require old-profile validation to fail, then restore
null and require validation to succeed. Retain every existing rejection and
all eight cases. After approval, update only the exact golden expectation,
run the unchanged target in Debug and ReleaseFast, and independently record
its executed names and verdicts. This establishes the fixture/source identity,
not complete CPU, recursive-proof, block, GPU or security qualification.

## Deprecation and budget

No implementation or interface is retired. Preserve the historical golden
and causal proof in the diagnostic receipt; never accept both as current.
Candidate implementation budget: at most +20 net test-code lines, no flags
or scripts, with documentation/configuration/receipts counted separately.
Existing complete-source binding owns the new mutation branch. Rollback
restores the test-only patch; production behavior is unchanged throughout.

The owner approved this exact test-only transaction and opening its RFC on
2026-11-09. The existing eight-case target is mandatory in Debug and ReleaseFast
before the original full frontend command in its hosted CPU lane. Hosted
acceptance remains pending until those commands actually execute successfully.
