# BLAKE3 compression SSA wiring

Task: connect the qualified compact G arithmetic into the exact seven-round
compression and feedforward graph, using canonical typed relation effects.

Canonical mapping: an acyclic single-assignment dataflow graph. Initial state
and message words occupy 32 source wires; each of 56 G calls creates four
fresh words; 16 final XORs create 16 output words. Consumer counts determine
emitter multiplicity. Expected graph: 272 wires, 56 G calls, 16 XOR calls.
No dynamic search, nondeterministic matching or field reduction of u32 words.

Transfer: existing recursion_wire(circuit, wire, four coordinates) with each
word represented by four bounded bytes. Circuit namespace is a trusted-plan
obligation, not a proof-supplied authority. Reuse canonical relation_effect
and universal_relation_binding compiler, not a separate tuple evaluator.
Sources: existing detached PCS wire components and exact multiset contraction
tests; shared canonical BLAKE3 schedule is source-pinned in preceding notes.

Invariant: schedules are committed preprocessed data derived from the fixed
plan. Outputs get fresh monotonically increasing IDs. Emission multiplicity
includes all internal consumers and final boundary consumption. Initial values
must bind CV, IV, counter, block length, flags and message; final output must
bind the claimed digest. Typed arithmetic alone does not discharge boundaries.

Validation: authenticate typed relation plans; degree checks; exact signed wire
multiset closure for all 56 G + 16 XOR calls against explicit input/output
boundaries; changed message, output, namespace, wire ID or multiplicity must
fail closure. Lookup table closure is a separate obligation and must not be
claimed from wire-only closure. No production key selection before full AIR,
provider and boundary qualification.
