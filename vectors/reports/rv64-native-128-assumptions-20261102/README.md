# Native128 assumption-qualified handoff

Classification: **128-bit security target under documented assumptions**.

The bounded engineering review is complete; this is not an independent cryptographic audit or certified whole-protocol claim. Recursion is excluded. The source-pinned review, exact model replay, changed-roster rejection, Safe/Fast security-policy gates, driver build and fresh complete-block receiver all pass.

The current receiver accepts the existing25CPU+5truth block proofs and emits the named assumption identity separately from `security_qualified=false`. Parameters, construction identity and proof transcript are unchanged. No new performance measurement is claimed for reporting-only changes.

See [review and assumptions](../../../design/riscv-proving-stack/rv64-native-128-assumptions-review.md). `review.json` records source hashes, checked scope and test evidence. `model.json` preserves the explicit bounded-work result and unresolved stronger certification obligations. Guest/geometry changes require a new budget.
