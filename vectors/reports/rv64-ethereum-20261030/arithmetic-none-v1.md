# Explicit empty arithmetic provider rosters

The service coordinator has opt-in `division_roster` and
`multiplication_roster` metadata, defaulting to historical `present` behavior.
`none` is admitted only with public count zero and canonical log5; MUL omission
requires the explicit D3 arithmetic policy. Omission enters transcript and cache
identity, and removes the provider's fixed/main/interaction columns and adapter.
Both eight-column CPU typed request buses remain committed and constrained;
lookup challenges still draw even without a provider. Omitted claims must be
canonical zero. The native batch helper selects omission for zero counts after
capturing a batch; manually constructed existing fixtures retain their defaults.

In the same one-step execution with immutable ROM admitting ADDI, DIV and MUL,
q70/P26 proof bytes drop from 521,580 (both present) to 149,932 (both omitted):
371,648 bytes saved, or 71.25%. This removes 1,222 provider main columns, 140
provider interaction columns and six fixed columns. CPU geometry and both CPU
request buses are unchanged. This is a small fixture opening-cost result, not a
whole-block time or memory estimate.

ReleaseSafe qualifies the genuine omitted proof, independent setup/receiver,
invalid roster/count/geometry and balanced-claim cases. Separate adversarial
cases execute actual DIV and MUL, erase the corresponding provider and sparse
request metadata, and reach `ConstraintsNotSatisfied` in proof generation.
Thus native metadata erasure cannot bypass the retained CPU query equations.
The durable proof also passes 21 fresh-process receiver cases, including the
previous DIV/MUL prefix openings. Raw metrics, proof and receiver identities are
recorded in `arithmetic-none-v1.json`; large proof artifacts remain ignored.

Provider count and first ID remain request data for `present` geometries. A
zero-request `present` setup continues to share its key with nonzero requests
of that same geometry. `none` is a separate, explicit roster geometry; it does
not silently change a count-dependent fixed table or opcode admission policy.
