# Scoped Sail/AIR composition statement

**Status:** conditional research theorem and evidence index, not a proof-verifier
theorem.

**Semantic authority:** the pinned Sail RV32IM model identified in
[`conformance/riscv/formal-corpus-evidence.json`](../conformance/riscv/formal-corpus-evidence.json).

This document says exactly how the row-local AIR work, the cross-row arguments,
and the Sail differential compose. It also records where they do not yet
compose. In particular, “the AIR determines an output” below always means
“under the exact-multiset, strict-clock, commitment, and row-refinement
premises stated here.” A successful production verifier invocation does not by
itself establish all of those premises in this repository.

## Objects and levels of assurance

Let

- \(p = 2^{31}-1\), the M31 modulus;
- \(S\) be a public RISC-V statement;
- \(W\) be the committed main and interaction witness;
- \(R(W)=(r_0,\ldots,r_{n-1})\) be its active opcode retirements;
- \(M(W)\) be its register and RW-memory access transitions;
- \(P(W)\) be its decoded `program_access` tuples; and
- \(\mathsf{Sail}(S)\) be the pinned Sail transition relation under the same
  RV32IM profile, initial state, and memory image.

Three different predicates must not be conflated:

1. **Exact AIR satisfaction**, \(\mathsf{AIR}_{\mathrm{exact}}(S,W)\): every
   direct constraint and fixed-table request holds, every relation has exact
   tuple-wise signed multiset balance over ordinary integer coefficients, all
   denominators are nonzero, and the public relation boundaries cancel.
2. **Production proof acceptance**, \(\mathsf{Accept}(S,\pi)\): the shipped
   verifier accepts a serialized proof under its Fiat–Shamir challenges.
   Turning this into the existence of a \(W\) satisfying
   \(\mathsf{AIR}_{\mathrm{exact}}\) needs the PCS/FRI reduction, proof-wire
   binding, and randomized LogUp soundness assumptions listed below.
3. **Tested agreement**, \(\mathsf{CorpusAgree}\): the runner, AIR checks, and
   Sail agree on named finite corpora. This is evidence for a universal
   refinement theorem, not the theorem itself.

The exact predicate is intentionally stronger than “the combined LogUp sum is
zero at one sampled challenge.” The graph arguments in CR-1, CR-3, and CR-4
need tuple-wise balance and an ordinary-integer coefficient lift. Randomized
LogUp is how the proof system reduces that stronger statement; its soundness
error is a cryptographic assumption, not a graph lemma.

## The conditional composition theorem

### Theorem SA-1 — accepted execution refines Sail, conditionally

For a statement \(S\), suppose an accepted proof \(\pi\) is binding to a
witness \(W\) with all of the following properties:

1. **Proof reduction.** Acceptance implies
   \(\mathsf{AIR}_{\mathrm{exact}}(S,W)\), except with the explicitly accounted
   PCS/FRI, Fiat–Shamir, and randomized-LogUp soundness error.
2. **Strict access order.** Every live register or RW-memory transition uses a
   strictly increasing ordinary access clock. Multiple accesses by one
   instruction have distinct ordered access clocks; no live transition has a
   zero gap. Long gaps are bridged as in CR-2.
3. **State and memory bounds.** All state clocks, access clocks, bridge clocks,
   row counts, and relation coefficients satisfy the source-bound no-wrap
   bounds required by CR-1 through CR-4.
4. **Commitment binding.** The program and RW roots use the canonical
   depth-30 tree shape and Poseidon2 function, and finding a different opened
   map with the same public root is infeasible.
5. **Universal local refinement.** For every admitted active opcode row, its
   row constraints and exact lookup tuples implement the corresponding
   pinned-Sail transition on the decoded instruction and the values supplied
   by the cross-row state, memory, and program chains.
6. **Public closure.** The canonical 28 component claims and public
   compensation are present, transcript-bound, and close exactly as in CR-5.

Then the active rows of \(W\) form one contiguous execution from the public
initial state to the public final state; every fetched decoded instruction is
bound to the public program root; every register and RW-memory read sees the
latest preceding value; and the public output and completion values are those
of \(\mathsf{Sail}(S)\).

This is a universal implication **over the premises**. The repository does
not currently prove premise 1 and premise 5 universally. Consequently it is
not yet valid to shorten SA-1 to:

> “Every proof accepted by the shipped verifier produces the Sail output.”

### Proof composition

CR-3 orders the opcode rows into the single public state path. CR-4 binds each
row’s decoded program tuple to the public program root. CR-1 and CR-2 turn the
register/RW bus into a value-continuous, strictly ordered path for each memory
key, including aliased sources within one instruction. Premise 5 therefore
applies to the actual state, instruction, and operands of each successive row.
Induction on the CR-3 path gives the same transition sequence as Sail. CR-5
identifies the induction’s endpoints and public I/O with \(S\), yielding the
claimed output.

The proof is short because all difficult qualifications are premises. The
rest of this document makes those qualifications auditable.

## The five cross-row lemmas

### CR-1 — offline memory consistency

Fix one key \(k=(\mathit{address\_space},\mathit{address})\). A memory state is
\((k,t,v)\), where \(t\) is an ordinary access clock and \(v\) is the four-byte
value. Each live access consumes one predecessor state and emits one successor
state. Assume:

- exact tuple-wise signed multiset balance;
- one public/boundary source \((k,t_0,v_0)\) and one public/boundary sink
  \((k,t_f,v_f)\);
- nonnegative integral edge multiplicities after signs are oriented from
  predecessor to successor; and
- \(t_{\mathrm{previous}} < t_{\mathrm{next}}\) for every live edge.

Then the finite component for \(k\) is one source-to-sink path and the value
consumed at every step is exactly the value emitted by its predecessor.

**Reason.** Strict clocks make the graph acyclic. At the least clock with
unaccounted positive flow, conservation and integrality leave exactly the
outgoing unit continuing the boundary path; branching would require at least
two incoming units. Repeating this argument reaches the unique sink. Any
detached finite component would have a least-clock vertex with no possible
incoming edge, contradicting zero boundary there.

The strict inequality is load-bearing. With two source operands at the same
instruction clock, a self-loop
\((k,t,B)\rightarrow(k,t,B)\) cancels identically and permits a forged \(B\).
The production strict-access-clock change exists to eliminate precisely that
case; this statement does not grandfather instruction-equal clocks.

Production statement validation also enforces the conservative per-side bound

\[
3\,n_{\mathrm{execution}}+n_{\mathrm{clock\ update}}
  +\sum n_{\mathrm{memory}}+2 < p.
\]

Every opcode contributes at most three memory edges, every clock-update or
RW-boundary row contributes one term, and at most two public terms can coincide
at one tuple. Therefore, once premise 1 supplies exact M31 tuple equality, no
nonzero same-sign integer coefficient can disappear modulo \(p\). This
discharges the coefficient-lift step used by this lemma for admitted production
geometry.

**Executable evidence:**

- [`scripts/riscv_infrastructure_uniqueness.py`](../scripts/riscv_infrastructure_uniqueness.py):
  `verify_offline_memory_chain`, the exhaustive small analogue, the detached
  cycle counterexample, and the same-clock alias counterexample;
- [`scripts/tests/test_riscv_infrastructure_uniqueness.py`](../scripts/tests/test_riscv_infrastructure_uniqueness.py):
  focused contracts and production-source bindings; and
- [`scripts/air_satisfaction.py`](../scripts/air_satisfaction.py): recomputation
  of `memory_access` terms on exported committed traces.

**Not discharged by CR-1:** the randomized LogUp-to-exact-multiset reduction or
proof binding. The production coefficient bound does not turn one sampled
LogUp equality into exact tuple-wise equality.

### CR-2 — monotone access clocks and \(2^{20}\)-window bridging

Let

\[
D = \mathsf{MAX\_CLOCK\_DIFF} = 2^{20}-1
\quad\text{and}\quad
G = 2^{20}.
\]

Production live accesses must use strict per-access clocks, including distinct
ordered clocks for aliased operands in one instruction. If the next honest
access is more than \(D\) after its predecessor, synthetic clock-update rows
advance by exactly \(D\) until the residual live-access gap lies in
\([1,D]\). A live access sends
`current_access_clock - previous_clock - 1` to `range_check_20`, so every
AIR-admitted live gap lies in \([1,G]\) and a zero gap is rejected by the
protocol, not merely omitted by the honest witness generator. Every emitted
predecessor, bridge endpoint, and live endpoint must lie in a source-bound
interval \([0,E]\) with

\[
E < p \quad\text{and}\quad p-E>G.
\]

Under those inequalities, an admitted live field gap in \([1,G]\) is the
ordinary positive integer difference. It cannot be a backward edge represented
by adding \(p\). Thus the access graph used by CR-1 is strictly ordered, while
arbitrary long honest executions remain connected by bridges.

The strict-clock layout assigns the zero-based live access ordinal
\(i\in\{0,1,2\}\) of one-based instruction clock \(c\) the clock

\[
A(c,i)=4(c-1)+i+1.
\]

Source operands precede destinations or the accessed memory word. Thus an
instruction’s live clocks occupy residues 1, 2, and 3 modulo 4 in semantic
order; residue 0 is reserved. At the maximum \(2^{24}\) instruction steps,
the maximum honest access clock is \(2^{26}-1\). A predecessor is decomposed
as `low20 + 2^20 * high6`, with `high6 < 64` established by the table tuple
`(high6, 4 * high6)`. The resulting source-bound snapshot is

\[
\begin{aligned}
B &= 2^{26} &&\text{(exclusive predecessor bound)},\\
E &= (2^{26}-1)+(2^{20}-1)=68{,}157{,}438,\\
\mathsf{max\_bridges}(0,2^{26}-1) &= 64
  &&\text{with residual gap }63.
\end{aligned}
\]

Public access clocks admit zero only at an initial boundary. A nonzero public
access clock is at most \(4n-1\) for an \(n\)-step statement and must occupy
one of the three live residues.

These numbers are a review snapshot, not an independent second source. The
normative values of \(B\), \(E\), the access-slot encoding, and the bridge
count are parsed from production and emitted by
[`scripts/riscv_state_chain_recurrence.py`](../scripts/riscv_state_chain_recurrence.py).
Any clock-layout change must update that source-bound certificate and its test;
SA-1 requires the certificate to be green, and this snapshot must then be
updated in the same change.

**Executable evidence:**

- `python3 -m scripts.riscv_state_chain_recurrence`;
- [`scripts/tests/test_riscv_state_chain_recurrence.py`](../scripts/tests/test_riscv_state_chain_recurrence.py),
  including small-ring exhaustion and the historical wrapped-cycle witness;
  and
- the clock-update and memory production bindings in
  [`scripts/riscv_infrastructure_uniqueness.py`](../scripts/riscv_infrastructure_uniqueness.py).

**Merge condition for the strict-clock change:** the production binding must
show distinct live access slots and the shifted
`range_check_20(current_access_clock - previous_clock - 1)` request; the
focused alias regression must reject the old self-loop witness; and the
certificate must separately report the bridge step \(D\), live gap bound
\(G\), `synthetic_addition_does_not_wrap`, and
`wrapped_gap_exceeds_table`.

### CR-3 — state-chain telescoping and cycle exclusion

Each active opcode row emits a state edge

\[
(\mathit{pc},t)\longrightarrow(\mathit{next\_pc},t+1)
\]

on `registers_state`. The public boundary supplies
\((\mathit{initial\_pc},1)\) and consumes
\((\mathit{final\_pc},n+1)\). Under exact tuple-wise balance, every internal
state tuple telescopes.

A detached state component would be a directed cycle because every edge
increments the clock by one. The additive order of \(1\) in M31 is \(p\), so
such a cycle requires at least \(p\) edges. Statement geometry admits fewer
than \(p\) active opcode rows and keeps \(n+1\) canonical. Therefore no
detached cycle fits, and the balanced state graph is the single public
source-to-sink path.

This lemma orders retirements and binds successive PCs. It does not decide
whether an individual `next_pc` is the Sail result; that is premise 5 of SA-1.

**Executable evidence:**

- `state_cycle_certificate` and the production recurrence/admission bindings
  in
  [`scripts/riscv_state_chain_recurrence.py`](../scripts/riscv_state_chain_recurrence.py);
- [`scripts/tests/test_riscv_state_chain_recurrence.py`](../scripts/tests/test_riscv_state_chain_recurrence.py);
  and
- the independent `registers_state` public-boundary recomputation in
  [`scripts/air_satisfaction_lib/logup.py`](../scripts/air_satisfaction_lib/logup.py).

### CR-4 — program binding, root to executed word

An opcode fetch demands the canonical decoded tuple

\[
(\mathit{pc},v_0,v_1,v_2,v_3)
\]

on `program_access`, where the meaning of \(v_1,v_2,v_3\) is selected by the
instruction’s canonical program shape. A program row supplies the same
decoded tuple with an integral multiplicity and supplies its four decoded
leaf values at consecutive depth-30 addresses under one root. Assume:

- exact ordinary `program_access` multiset equality;
- injectivity of the canonical decoder projection over admitted words;
- one canonical decoded leaf map, with no conflicting value for an address;
- exact ordinary `merkle`, `poseidon2`, and `poseidon2_io` multiset equality,
  including a valid coefficient lift;
- the public root tuple \((0,0,\mathit{root},\mathit{root})\);
- the depth-30 child/parent recurrence; and
- collision resistance of the committed Poseidon2 Merkle construction.

Then every executed decoded tuple is in the leaf map committed by the public
program root. The index recurrence is an integer recurrence, not merely field
division by `INV2`: from the public root, each child is
\(2\cdot\mathit{parent}+\mathit{bit}\). At depth 30 the resulting index is in
\([0,2^{30})\subset[0,p)\), so parity and the entire path are unique without
field wrap.

Within the admitted RV32IM language, the canonical decoder projection is
injective: the opcode protocol ID fixes opcode/funct fields and the remaining
tuple fields retain every live register or immediate field. Thus binding the
decoded tuple binds the executed supported word, not merely its opcode name.
[`src/frontends/riscv/air/program/decode.zig`](../src/frontends/riscv/air/program/decode.zig)
pins the projection across all 46 supported opcodes and its canonical signed
immediate representation.

Production first checks \(2\,n_{\mathrm{node}}<p\), bounding node
multiplicities and excluding a \(p\)-edge depth cycle. It additionally checks
the conservative all-source side bound

\[
2\,n_{\mathrm{node}}+n_{\mathrm{program}}
  +\sum n_{\mathrm{memory}}+3 < p,
\]

where three accounts for coincident public program, initial-RW, and final-RW
root terms. The formula deliberately permits malicious rows to collide across
noncanonical depths; it does not assume the honest source categories remain
separate. Under exact M31 tuple equality, this bound supplies the required
**all-source** field-to-integer coefficient lift. Together with the depth-cycle
bound, a nonempty detached finite component would have a source or sink and
cannot balance. The infrastructure certificate retains the now-rejected
coefficient-wrap witness that motivated the stronger admission rule.

These arithmetic guards do not themselves establish exact tuple balance,
Poseidon2 collision resistance, or binding of an accepted proof to the claimed
root.

**Executable evidence:**

- `verify_program_binding`, `merkle_connectivity_certificate`, and the explicit
  coefficient-wrap counterexample in
  [`scripts/riscv_infrastructure_uniqueness.py`](../scripts/riscv_infrastructure_uniqueness.py);
- the all-path symbolic index certificate and depth-cycle calculation in
  [`scripts/riscv_merkle_recurrence.py`](../scripts/riscv_merkle_recurrence.py);
- [`scripts/tests/test_riscv_merkle_recurrence.py`](../scripts/tests/test_riscv_merkle_recurrence.py)
  and
  [`scripts/tests/test_riscv_infrastructure_uniqueness.py`](../scripts/tests/test_riscv_infrastructure_uniqueness.py);
  and
- active narrow-row Poseidon2 functionality and six-table rigidity in
  [`scripts/riscv_poseidon_table_uniqueness.py`](../scripts/riscv_poseidon_table_uniqueness.py).

**Not discharged by CR-4:** the randomized reduction to exact Merkle balance,
Poseidon2 collision resistance, or proof-wire binding of the claimed root.

### CR-5 — public boundary closure and all 28 claims

The canonical transcript has exactly 28 component slots:

- 17 opcode families;
- program, RW-memory boundary, Merkle, Poseidon2, and clock update; and
- six preprocessed lookup tables.

For a supported statement, exact recomputation of every component claim plus
the public compensation binds:

- initial and final `(pc, clock)` state tuples;
- the program, initial RW, and final RW root-presence/value tuples;
- all 32 initial and final register words and their final access clocks;
- public input words at clock zero;
- public output words at their final access clocks;
- completion memory or the unretired program sentinel, as applicable; and
- the canonical claim order, including zero claims for absent opcode families.

If these terms close in their intended relation domains, the endpoints of
CR-1, CR-3, and CR-4 are the public fields of \(S\). Cancellation of one
combined sampled scalar is not a deterministic substitute for domain-wise
exact closure; SA-1 obtains the latter only through premise 1.

**Executable evidence:**

- [`src/frontends/riscv/air/transcript/claims.zig`](../src/frontends/riscv/air/transcript/claims.zig)
  and
  [`src/frontends/riscv/air/component_order.zig`](../src/frontends/riscv/air/component_order.zig)
  pin the 28-slot order;
- [`src/frontends/riscv/air/public_logup.zig`](../src/frontends/riscv/air/public_logup.zig)
  is the production public compensation;
- [`scripts/air_satisfaction.py`](../scripts/air_satisfaction.py) independently
  recomputes active rows, fixed-table requests, all 28 claims, the public
  compensation, and global closure from an exported committed trace; and
- [`scripts/tests/test_air_satisfaction.py`](../scripts/tests/test_air_satisfaction.py)
  requires 17 opcode plus 11 infrastructure components on the all-family
  export and checks malicious exports fail at the attributed layer.

The Python checker is not a verifier. It neither reads the proof nor
cryptographically binds the export to a PCS opening.

## What is actually established in this repository

The following are finite executable evidence, not universal quantifiers:

| Evidence | Established scope | Command or artifact |
| --- | --- | --- |
| Pinned Sail/Spike differential | Runner agrees with Sail on 17 programs, 472,827 retirements, and 6 negative dispositions recorded by the committed evidence. | `python3 scripts/riscv_sail_gate.py bind`; live truth requires `python3 scripts/riscv_sail_gate.py run` |
| Sail-derived operand classes | All 292 named cases compare the runner retirement fields with recorded Sail answers and exercise an honestly admitted corresponding AIR row. | `zig build test-riscv-release-exhaustive -Doptimize=ReleaseFast` |
| Committed family adversaries | Every one of the 17 opcode families has a pre-ingestion committed-row forgery and a paired honest prove/verify/Sail case; this is one adversarial board point per family, not all operands. | [`src/tests/riscv/opcode_family_committed_soundness_test.zig`](../src/tests/riscv/opcode_family_committed_soundness_test.zig) through the exhaustive build |
| All-component committed trace | One honest guest covers 17 opcode and 11 infrastructure component kinds, proves, verifies, and reaches a Sail tail. | [`src/tests/riscv/committed_trace_export_test.zig`](../src/tests/riscv/committed_trace_export_test.zig) |
| Independent AIR re-decision | Exported traces are re-evaluated outside the Zig evaluator; all 28 claims and public closure are recomputed, and focused forgeries are rejected. | `python3 -m unittest scripts.tests.test_air_satisfaction`; after generating exports, `python3 -m scripts.air_satisfaction check --dump zig-out/committed-trace/all_families.json` |
| Cross-row arithmetic/graphs | The five conditional lemmas above, small exhaustive analogues, production source anchors, and counterexamples to stronger statements. | Commands in the next section |

The strongest honest conclusion today is therefore:

> On the checked corpora, the runner agrees with pinned Sail; sampled honest
> committed witnesses satisfy and close the checked AIR; all opcode families
> have at least one committed adversarial rejection; and CR-1 through CR-5
> explain the global conclusion under explicit exact-balance, strict-clock,
> commitment, and proof-reduction premises.

The machine-checked statement “AIR satisfaction universally refines pinned
Sail” remains open. Row-local uniqueness is not row-local correctness, and
finite Sail agreement is not all-input refinement.

## Assumptions and explicit nonclaims

SA-1 depends on all of the following:

- sound randomized reduction from exact relation multisets to LogUp evaluations,
  including nonzero denominators and domain separation;
- continued enforcement of the production all-source coefficient guards that
  supply the field-to-integer coefficient lifts used by the graph arguments;
- Poseidon2/Merkle collision resistance for root binding;
- PCS commitment binding, FRI/list-decoding soundness, composition/OODS
  correctness, and Fiat–Shamir modeling with a reviewed aggregate bit bound;
- serialization, transcript, and verifier correctness for the actual proof
  wire; and
- universal opcode-row refinement to pinned Sail.

This document does **not** claim:

- an independent second verifier or proof-wire audit;
- a reviewed security-bit accounting;
- that `scripts/air_satisfaction.py` opens or verifies a proof;
- that the 17-program or 292-case corpora cover every RV32IM state;
- that row-local determinism alone implies Sail semantics;
- that the node guard \(2\,n_{\mathrm{node}}<p\) alone supplies the
  all-source Merkle coefficient lift, or that either admission guard without
  exact tuple balance and collision resistance root-connects an aggregate; or
- byte-for-byte compatibility with the retired Stark-V witness, relation, or
  proof layout.

Legacy Stark-V layout comparisons are not a premise of SA-1 and cannot
authorize a release. The archived CP-11 receipt reader is fail-closed
unconditionally; its old divergence-shape parser exists only to inspect
historical bundles.

## Reproduction and change control

Run the inexpensive certificates first:

```sh
python3 -m scripts.riscv_infrastructure_uniqueness
python3 -m scripts.riscv_merkle_recurrence
python3 -m scripts.riscv_state_chain_recurrence
python3 -m scripts.riscv_poseidon_table_uniqueness check
python3 -m unittest \
  scripts.tests.test_riscv_infrastructure_uniqueness \
  scripts.tests.test_riscv_merkle_recurrence \
  scripts.tests.test_riscv_state_chain_recurrence \
  scripts.tests.test_riscv_poseidon_table_uniqueness \
  scripts.tests.test_air_satisfaction
```

Then run the exhaustive Zig gate and, where the pinned formal workspace is
available, the live Sail gate:

```sh
zig build test-riscv-release-exhaustive -Doptimize=ReleaseFast
python3 scripts/riscv_sail_gate.py run
```

A change to access-clock slots or scale must update the source-bound output of
`riscv_state_chain_recurrence.py`; a change to relation coefficients must
revisit the integer-lift premises in CR-1 and CR-4; a change to component
ordering must update CR-5; and a change to opcode semantics must re-run both
the Sail evidence and the universal-refinement audit. No numeric clock bound,
source digest, corpus count, or green export should be copied forward merely
because this prose still renders.
