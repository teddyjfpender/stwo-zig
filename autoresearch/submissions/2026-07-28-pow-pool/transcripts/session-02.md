# Session 02: non-canonical qualification repair canary

## Purpose and evidence boundary

PR 118 was green but still a draft, so its commit
`e973ff8b3061b5ebc0eaf2d13566037b1ad993a2` was not a canonical frontier.
To test the repair without misrepresenting it as submission evidence, a
diagnostic branch placed the unchanged PoW source delta on top of that repair.
The resulting fork commit was
`52c96d89990a0546f5f5890cf35f5a51d169c4d8`, with
`e973ff8b3061b5ebc0eaf2d13566037b1ad993a2` declared as its diagnostic
predecessor. Any receipt would have remained non-submit-eligible.

## Local qualification

The diagnostic tree changed only
`src/prover/pcs/proof_of_work.zig` relative to the repair commit. Source-policy
preflight accepted the ancestry, locked-tree identity, file mode, patch size,
and one editable path. The complete repository suite passed 373 tests, and the
six board-scoped setup regression tests passed separately.

## Hosted result

Fork run `30346576852` was bound to the expected diagnostic branch and exact
commit. It passed:

- checkout of the immutable diagnostic source;
- source-policy preflight against the repair commit;
- all 373 locked harness tests;
- installation of Zig 0.15.2;
- release-target setup on Ubuntu; and
- materialization of the repair commit as predecessor.

This proves that PR 118 repairs the original Linux setup failure: the default
setup explicitly skipped the Apple-only Metal group and reached the paired S3
benchmark.

The benchmark then failed on the first unchanged Blake regression guard before
receipt generation. Guard round one orders predecessor before candidate. The
predecessor arm consumed almost all of the hard 300-second per-guard wall
budget; only 6.44856008 seconds remained for the candidate arm, which timed
out. No guard ratio, verdict, receipt, artifact attestation, or remote
submission was produced.

## Classification and rejected interpretations

The result is `qualification-infrastructure-failed`, not a PoW candidate
failure. The timeout was created by the generic hosted runner and the
whole-guard wall budget after the unchanged predecessor ran first. It is not
evidence that the candidate regressed Blake, and it cannot be used as a
performance claim.

Blindly rerunning the same workflow was rejected: the first arm takes nearly
the full fixed budget, so cache luck cannot make the required predecessor and
candidate ABBA pair fit honestly. Raising the guard cap alone was also rejected
as an unreviewed workaround because the workflow has a 90-minute job limit and
twelve mandatory guards. The focused follow-up is to make the fork
qualification contract explicitly objective-only while preserving full guard
execution on the central judge, but that workflow-policy change requires
review before implementation.
