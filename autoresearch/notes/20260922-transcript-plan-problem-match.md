# Reusable bounded transcript preprocessing plan

Task: move the fixture's literal retry capacity into explicit verifier-owned
configuration, and compile reusable trusted transcript preprocessing once.
Canonical match: partial evaluation / immutable prepared execution plan. Reuse
existing trustedBounded/prepareBounded and all eight AIRs, rather than implementing
a second scheduler. Retain prepared fixed rows and a structural SHA-256 fingerprint
covering protocol identity, namespace, capacity, AIR identities/dimensions and
ordered fixed columns. The fingerprint is an artifact identity, not a PCS root,
full parent key, soundness guarantee or new channel transcript.

Compile costs O(fixed rows * columns), retained memory O(rows); live preparation
uses the existing witness builder and compares fixed columns against the retained
plan. No proof compilation occurs in that comparison. Private routed payloads,
private outputs and recorded attempt counts must not change the plan. Public
protocol operands, operation shape, sources and capacity must remain bound.
Capacity exhaustion is a deterministic error; never silently increase capacity,
change keys, truncate retries or reinterpret a proof under another plan.

Accept a positive u32 attempt capacity bounded by existing namespace admission;
do not invent production capacity classes or probability guarantees. The caller
must explicitly choose the capacity. Qualify reuse with changed private inputs,
ignored retry metadata, public/shape mismatches, capacity exhaustion, different
capacity identities, corrupted plan rejection and the existing complete bounded
transcript/parent proofs. Production artifact/key-family admission and Metal
remain separate unfinished obligations. No speedup prediction from this step.
