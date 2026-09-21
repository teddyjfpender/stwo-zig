# Canonical leaf cohort ownership

Moved circuit census and tuple-classification diagnostics out of the leaf cohort
owner, and moved claim/audit collection into its existing support module. Tree
ownership and public cohort methods remain in the canonical owner. Diagnostic
classification still follows envelope admission; the per-cohort-instantiation
census counter remains owned by the cohort and is explicitly borrowed by the
renderer. Claim collection retains the exact row coverage and closure checks,
including diagnostic behavior on relation failure.

Transfer audit compares all five moved function bodies, accounting only for the
validation call retained in the wrapper and structural receiver signatures.
No equation, authority identity, transcript, protocol parameter or provider
schedule changed. The cohort owner falls from 999 to 843 lines; the support
owner is 284 lines and the diagnostic owner 111. Source-conformance findings
fall from 108 to 107 without suppressing a baseline finding.

The concrete 39-row cohort/engine contract gate passes all 12 tests (16-second
compile, sub-second execution). All 44 ownership/isolation checks pass. Formatting
and diff checks pass. No complete-proof rebuild was repeated for this move.
The preceding canonical-surface checkpoint remains full proof evidence for its
frozen source; subsequent ownership batches have their scoped checks and transfer
audits. Broader source-size findings and Linux artifact-store runtime qualification
remain open under the original goal.
