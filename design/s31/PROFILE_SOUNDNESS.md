# S31 arithmetic profile consistency note

This is an implementation review note for `sparse-v3` and `direct-m31-v4`, not a cryptographic security proof. Both use the repository's pinned circuit AIR programs and Stwo PCS/FRI implementation. The [language guide](../../src/frontends/s31/LANGUAGE_AND_AIR.md) gives the source and row equations; the [roadmap](MVP_ROADMAP.md) records acceptance and measurement gates.

## Component dependency closure

| Profile | Circuit AIR components | Lookup producers and consumers |
| --- | --- | --- |
| `sparse-v3` | QM31 operations, M31-to-u32, range-16 | Arithmetic and output gates exchange `(GATE,address,value[4])` tuples. M31 conversion uses gate values and requests 16-bit range tuples. `range_check_16` supplies the `seq_16` table multiplicities. |
| `direct-m31-v4` | QM31 operations only | Arithmetic and output gates exchange `(GATE,address,value[4])` tuples. Every public word is a canonical M31 scalar, so there is no M31-to-u32 gate, range request or range table. |

The frontend rejects Eq, XOR and Blake-G rows in both profiles, and direct-v4 additionally rejects any M31-to-u32 row and every `u16` input. This check is on the compiled topology, before an assignment is proved. Its result cannot depend on witness values. The selected AIR programs are rebound from the pinned eleven-component bundle with preprocessed and trace offsets adjusted; inactive components contribute no trace columns, claimed sums or constraints.

In direct-v4, `guessM31` is constrained by the circuit's pointwise multiplication with the base-field unit. For a scalar wire `v = (v0,v1,v2,v3)`, the gate equation `v .* (1,0,0,0) = v` forces `v1 = v2 = v3 = 0`. Each public word is checked to be `< p = 2^31-1` before the verifier maps it to `(word,0,0,0)`. The circuit's output gate binds that value at its reserved public address. The common Gate lookup sum includes public endpoint terms for those addresses and the special `u` wire; a wrong public word changes the closure.

## Linked step chip

The chip has `R` rows and contributes four transition equations `out[j] - in[j]^2 - c = 0`. Its separate relation contains one positive tuple `(D,i,in[0..4])` and one negative tuple `(D,i+1,out[0..4])` per row. The verifier closes its claimed sum with `(D,0,x[0..4])` and `(D,R,y[0..4])`. The circuit binds those same public `x` and `y` values, and both AIR component sets are checked in one proof.

Here is the combinatorial boundary argument under collision-free lookup tuple compression. Treat every chip row as a directed edge from its input tuple at index `i` to its output tuple at index `i+1`, with indices in M31. Multiset balance leaves the public start with one excess outgoing edge and the public end with one excess incoming edge. The connected component containing the start must also contain the end, so it has a directed start-to-end trail. Every edge advances the index by one modulo `p`; a trail of at most `R` edges from index `0` to index `R`, with `R < p`, must have exactly `R` edges. The trace has exactly `R` rows, so no row remains for a disconnected cycle. Local transition equations then establish the recurrence on that trail. This reasoning depends on the random lookup compression's collision bound, correct LogUp AIR constraints, and the pinned Stwo soundness parameters; those require an independent formal review before production use.

## Transcript and replay boundaries

The v3 and v4 prover/verifier pairs mix distinct profile tags, the embedded source digest, and chip parameters before the first commitment. Their circuit identities hash the source digest, preprocessed root, geometry, PCS blowup and chip selection. The native verifiers require their own `S31NAT3G/C` or `S31NAT4G/C` envelope, reconstruct the exact commitment tree shapes, check public and chip lookup sums, and invoke the core verifier once. The packaged verifier checks its embedded source, key, pinned AIR bundle digest and PCS/FRI parameters. A profile replay or altered artifact is rejected by the [direct acceptance corpus](measurements/direct-acceptance-v4-2026-10-06.json).

Direct-v4 can have a chip trace taller than its eight circuit preprocessed columns. Its PCS config therefore lifts the preprocessed tree to `log2(padded_QM31_rows) + blowup` and the base, interaction and composition trees to `max(log2(padded_QM31_rows), log2(chip_rounds)) + blowup`. Prover and native verifier derive both heights from the sealed key and chip shape. This split preserves the short fixed-column commitment while admitting a long chip; using the circuit height for every tree fails with `InvalidTreeHeight`.

Open review items: formal bounds for tuple compression and LogUp in these exact parameter sets; an explicit generated component manifest and dependency checker for profiles beyond these hardcoded sets; authenticated private circuit-to-chip boundaries; and independent review of polynomial degree bounds and out-of-domain masks for the new chip. The current public-boundary chip does not authenticate an internal private wire shared with an arbitrary circuit region.
