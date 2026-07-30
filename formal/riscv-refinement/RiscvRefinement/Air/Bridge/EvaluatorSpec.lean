-- The evaluator specification: the bridges' cons-loop evaluator *is* Team A's
-- push-accumulator evaluator.
--
-- Every AIR bridge in this directory evaluates a *localised* node table with
-- `evalLoop`, which threads a reversed memo table and reads node arguments at a
-- fixed back-offset from its head. Team A's `evalNodes` walks the *verbatim*
-- node table and pushes onto a forward-order accumulator, reading node
-- arguments at their absolute index. The two shapes are not definitionally
-- equal, and until now the only link between them was differential: the
-- generated `#guard`s at the bottom of `MulProgram.lean` and `MulhProgram.lean`
-- compare the two evaluators numerically on one witness row each.
--
-- /tmp/o1-bridge-report.md §3.2 records that as the last unproved link in the
-- bridge trust chain. This file closes it, for symbolic columns and for every
-- node table the decoder accepts:
--
--   evalNodes_eq_localised :  the reversed localised memo table, reversed back,
--                             is exactly A's push accumulator
--   localValue_eq_evalNodes:  therefore every `value` read the bridges perform
--                             is the node-order read of A's memo table
--
-- Both are stated at the level of `List Node`, deliberately: `Program`,
-- `MulhCircuit` and `DivCircuit` are three different records with the same
-- node/localisation/evaluation layer, so a theorem about the layer instantiates
-- to all three (and to any family record added later) in three lines. The
-- record-level corollaries for `Program` and `MulhCircuit` are at the bottom;
-- `DivCircuit`'s is in `DivBridge.lean`, which is where that record is
-- introduced.
--
-- The hypothesis in every statement is `nodesWellFormed`, which is A's decoder
-- side condition and nothing more. It is what makes the localisation
-- information-preserving: `Node.localise` rewrites an absolute argument `a` at
-- position `i` to the back-offset `i - 1 - a`, and `Nat` subtraction truncates,
-- so the rewrite is invertible exactly when `a < i` -- which is what
-- `Node.wellFormed` checks.

import RiscvRefinement.Air.Bridge.MulProgram
import RiscvRefinement.Air.Bridge.MulhProgram

namespace RiscvRefinement.Air.Bridge

/-! ## Team A's evaluator

`Node.eval` is `Node.evalLocal` with absolute argument indices: it reads the
memo table in node order, at the index the exported IR actually carries. -/

/-- Node semantics with **absolute** argument indices, over a forward-order memo
table. This is A's `Air/Eval.lean` node case, transliterated from `Array` to
`List`. -/
def Node.eval (columns values : List M31) : Node → M31
  | .const value => M31.reduce value
  | .col column => nth columns column
  | .add left right => nth values left + nth values right
  | .sub left right => nth values left - nth values right
  | .mul left right => nth values left * nth values right
  | .neg value => -nth values value

/-- A's `evalNodes`: fold the verbatim node table, pushing each value onto the
end of the accumulator. `Array.push` on a `List` is `values ++ [value]`, and
`Array.foldlM` over a total evaluator is `List.foldl`. -/
def evalNodes (columns : List M31) (nodes : List Node) : List M31 :=
  nodes.foldl (fun values node => values ++ [node.eval columns values]) []

/-- The same fold started from an arbitrary prefix, which is what the induction
below needs. `evalNodes` is the empty-prefix case. -/
def evalNodesFrom (columns : List M31) (values : List M31) (nodes : List Node) :
    List M31 :=
  nodes.foldl (fun values node => values ++ [node.eval columns values]) values

theorem evalNodes_eq_evalNodesFrom (columns : List M31) (nodes : List Node) :
    evalNodes columns nodes = evalNodesFrom columns [] nodes := rfl

@[simp] theorem evalNodesFrom_nil (columns values : List M31) :
    evalNodesFrom columns values [] = values := rfl

theorem evalNodesFrom_cons (columns values : List M31) (node : Node)
    (rest : List Node) :
    evalNodesFrom columns values (node :: rest) =
      evalNodesFrom columns (values ++ [node.eval columns values]) rest := rfl

/-! ## Reading a reversed table

`nth_reverse` in `MulProgram.lean` goes from a reversed read to a forward read.
The bridge direction is the other one: a *back-offset* read of the reversed
table is the absolute read of the forward table. -/

theorem nth_reverse_sub (values : List M31) (index : Nat)
    (bound : index < values.length) :
    nth values.reverse (values.length - 1 - index) = nth values index := by
  have inner : values.length - 1 - index < values.length := by omega
  rw [nth_reverse values _ inner]
  congr 1
  omega

/-! ## One node

Localisation composed with the back-offset evaluator is the absolute
evaluator. This is the whole mathematical content; everything else is
bookkeeping. -/

theorem Node.evalLocal_localise (columns values : List M31) (node : Node)
    (columnCount : Nat)
    (valid : node.wellFormed columnCount values.length = true) :
    (node.localise values.length).evalLocal columns values.reverse =
      node.eval columns values := by
  cases node with
  | const value => rfl
  | col column => rfl
  | add left right =>
      simp only [Node.wellFormed, Bool.and_eq_true, decide_eq_true_eq] at valid
      simp only [Node.localise, Node.evalLocal, Node.eval]
      rw [nth_reverse_sub values left valid.1, nth_reverse_sub values right valid.2]
  | sub left right =>
      simp only [Node.wellFormed, Bool.and_eq_true, decide_eq_true_eq] at valid
      simp only [Node.localise, Node.evalLocal, Node.eval]
      rw [nth_reverse_sub values left valid.1, nth_reverse_sub values right valid.2]
  | mul left right =>
      simp only [Node.wellFormed, Bool.and_eq_true, decide_eq_true_eq] at valid
      simp only [Node.localise, Node.evalLocal, Node.eval]
      rw [nth_reverse_sub values left valid.1, nth_reverse_sub values right valid.2]
  | neg value =>
      simp only [Node.wellFormed, decide_eq_true_eq] at valid
      simp only [Node.localise, Node.evalLocal, Node.eval]
      rw [nth_reverse_sub values value valid]

/-! ## The whole table

The invariant is `evalLoop`'s accumulator is the reverse of `evalNodes`'
accumulator, and the localisation index is the accumulator's length. -/

theorem evalLoop_localiseNodes (columns : List M31) (columnCount : Nat) :
    ∀ (nodes : List Node) (values : List M31),
      nodesWellFormed columnCount values.length nodes = true →
      evalLoop columns values.reverse (localiseNodes values.length nodes) =
        (evalNodesFrom columns values nodes).reverse := by
  intro nodes
  induction nodes with
  | nil => intro values _; rfl
  | cons node rest ih =>
      intro values valid
      simp only [nodesWellFormed, Bool.and_eq_true] at valid
      have head : (node.localise values.length).evalLocal columns values.reverse =
          node.eval columns values :=
        Node.evalLocal_localise columns values node columnCount valid.1
      have length : (values ++ [node.eval columns values]).length =
          values.length + 1 := by
        simp
      have reversed : (values ++ [node.eval columns values]).reverse =
          node.eval columns values :: values.reverse := by
        simp
      simp only [localiseNodes, evalLoop, evalNodesFrom_cons, head]
      rw [← reversed, ← length]
      exact ih _ (by rw [length]; exact valid.2)

/-- **The specification.** On any node table the decoder accepts, the memo table
the bridges evaluate -- reversed localised cons-loop -- read back in node order
is exactly the table A's push evaluator produces. -/
theorem evalNodes_eq_localised (columns : List M31) (columnCount : Nat)
    (nodes : List Node) (valid : nodesWellFormed columnCount 0 nodes = true) :
    (evalLoop columns [] (localiseNodes 0 nodes)).reverse = evalNodes columns nodes := by
  have step := evalLoop_localiseNodes columns columnCount nodes [] (by simpa using valid)
  simp only [List.length_nil, List.reverse_nil] at step
  rw [step, List.reverse_reverse, evalNodes_eq_evalNodesFrom]

/-! ## Lengths

`Program.value` indexes by `nodeCount - 1 - index`, so the read is only the
node-order read when the table has the length the record advertises. -/

theorem localiseNodes_length (nodes : List Node) :
    ∀ index : Nat, (localiseNodes index nodes).length = nodes.length := by
  induction nodes with
  | nil => intro _; rfl
  | cons node rest ih =>
      intro index
      simp only [localiseNodes, List.length_cons, ih (index + 1)]

theorem evalNodesFrom_length (columns : List M31) (nodes : List Node) :
    ∀ values : List M31,
      (evalNodesFrom columns values nodes).length = values.length + nodes.length := by
  induction nodes with
  | nil => intro values; simp
  | cons node rest ih =>
      intro values
      simp only [evalNodesFrom_cons, ih, List.length_append, List.length_cons,
        List.length_nil]
      omega

theorem evalNodes_length (columns : List M31) (nodes : List Node) :
    (evalNodes columns nodes).length = nodes.length := by
  simpa using evalNodesFrom_length columns nodes []

/-! ## The read the bridges actually perform

Every `*.value` in this directory is `nth (evalLoop columns [] localisedNodes)
(nodeCount - 1 - index)`. The theorem below says that expression is
`nth (evalNodes columns verbatimNodes) index` -- A's node-order read of A's memo
table -- for every index the table covers. -/

theorem localValue_eq_evalNodes (columns : List M31) (columnCount : Nat)
    (nodes : List Node) (index : Nat)
    (valid : nodesWellFormed columnCount 0 nodes = true)
    (covered : index < nodes.length) :
    nth (evalLoop columns [] (localiseNodes 0 nodes)) (nodes.length - 1 - index) =
      nth (evalNodes columns nodes) index := by
  have table := evalNodes_eq_localised columns columnCount nodes valid
  have length : (evalLoop columns [] (localiseNodes 0 nodes)).length = nodes.length := by
    have := evalLoop_length columns (localiseNodes 0 nodes) []
    simpa [localiseNodes_length nodes 0] using this
  have read :
      nth (evalLoop columns [] (localiseNodes 0 nodes)).reverse index =
        nth (evalLoop columns [] (localiseNodes 0 nodes))
          ((evalLoop columns [] (localiseNodes 0 nodes)).length - 1 - index) :=
    nth_reverse _ index (by omega)
  rw [length] at read
  rw [← read, table]

/-! ## `nodesWellFormed` from the decoder check

`Program.wellFormed` / `MulhCircuit.wellFormed` are the exported decoder side
condition; the node clause is the one this file needs. -/

theorem Program.nodesWellFormed_of_wellFormed (program : Program)
    (valid : program.wellFormed = true) :
    nodesWellFormed program.columns.length 0 program.nodes = true := by
  simp only [Program.wellFormed, Bool.and_eq_true] at valid
  exact valid.1.1.2

theorem Program.nodeCount_of_wellFormed (program : Program)
    (valid : program.wellFormed = true) :
    program.nodeCount = program.nodes.length := by
  simp only [Program.wellFormed, Bool.and_eq_true, decide_eq_true_eq] at valid
  exact valid.1.1.1.2

theorem MulhCircuit.nodesWellFormed_of_wellFormed (circuit : MulhCircuit)
    (valid : circuit.wellFormed = true) :
    nodesWellFormed circuit.columns.length 0 circuit.nodes = true := by
  simp only [MulhCircuit.wellFormed, Bool.and_eq_true] at valid
  exact valid.1.1.2

theorem MulhCircuit.nodeCount_of_wellFormed (circuit : MulhCircuit)
    (valid : circuit.wellFormed = true) :
    circuit.nodeCount = circuit.nodes.length := by
  simp only [MulhCircuit.wellFormed, Bool.and_eq_true, decide_eq_true_eq] at valid
  exact valid.1.1.1.2

/-! ## Record-level corollaries

These are the statements a bridge cites. `program` is the *verbatim* exported
table; `program.localise` is the table the bridge evaluates. -/

/-- Every value the bridge reads out of the localised `Program` is the value A's
evaluator computes for that node of the verbatim `Program`. -/
theorem Program.localise_value_eq_evalNodes (program : Program) (columns : List M31)
    (index : Nat) (valid : program.wellFormed = true)
    (covered : index < program.nodes.length) :
    (program.localise).value columns index =
      nth (evalNodes columns program.nodes) index := by
  have nodes := Program.nodesWellFormed_of_wellFormed program valid
  have count := Program.nodeCount_of_wellFormed program valid
  simp only [Program.value, Program.nodeValuesRev, Program.localise, count]
  exact localValue_eq_evalNodes columns program.columns.length program.nodes index
    nodes covered

/-- The list form: the constraint roots the bridge evaluates are A's values at
those roots. -/
theorem Program.localise_constraintValues_eq_evalNodes (program : Program)
    (columns : List M31) (valid : program.wellFormed = true) :
    (program.localise).constraintValues columns =
      program.constraints.map (nth (evalNodes columns program.nodes)) := by
  have bounds : ∀ root ∈ program.constraints, root < program.nodes.length := by
    intro root member
    have := valid
    simp only [Program.wellFormed, Bool.and_eq_true, List.all_eq_true] at this
    have := this.1.2 root (by simpa using member)
    simpa using this
  simp only [Program.constraintValues, Program.values, Program.localise]
  refine List.map_congr_left ?_
  intro root member
  simpa [Program.localise] using
    Program.localise_value_eq_evalNodes program columns root valid (bounds root member)

/-- Same statement for `MulhCircuit`. The proof is the record projection plus
the node-level theorem; adding a new family record costs exactly this. -/
theorem MulhCircuit.localise_value_eq_evalNodes (circuit : MulhCircuit)
    (columns : List M31) (index : Nat) (valid : circuit.wellFormed = true)
    (covered : index < circuit.nodes.length) :
    (circuit.localise).value columns index =
      nth (evalNodes columns circuit.nodes) index := by
  have nodes := MulhCircuit.nodesWellFormed_of_wellFormed circuit valid
  have count := MulhCircuit.nodeCount_of_wellFormed circuit valid
  simp only [MulhCircuit.value, MulhCircuit.nodeValuesRev, MulhCircuit.localise, count]
  exact localValue_eq_evalNodes columns circuit.columns.length circuit.nodes index
    nodes covered

/-! ## Tying it to the two shipped tables

`MulProgram.lean` and `MulhProgram.lean` each carry a `#guard` that the
localised table they proved against is the mechanical localisation of the
verbatim export. Those `#guard`s are re-proved here as theorems, so the chain

  hand transcription  ->  localised table  ->  verbatim exported table  ->
  A's evaluator

is proof-strength end to end, with no `#guard` link left in it. -/

set_option maxRecDepth 100000 in
theorem mulProgramCompiled_eq_localise : mulProgramCompiled = mulProgram.localise := by
  decide

set_option maxRecDepth 100000 in
theorem mulProgram_wellFormed : mulProgram.wellFormed = true := by decide

set_option maxRecDepth 100000 in
theorem mulhProgramCompiled_eq_localise :
    mulhProgramCompiled = mulhProgram.localise := by
  decide

set_option maxRecDepth 100000 in
theorem mulhProgram_wellFormed : mulhProgram.wellFormed = true := by decide

/-- The `mul` bridge's evaluator agrees with A's on every node, for every
column assignment. -/
theorem mulProgramCompiled_value_eq_evalNodes (columns : List M31) (index : Nat)
    (covered : index < mulProgram.nodes.length) :
    mulProgramCompiled.value columns index =
      nth (evalNodes columns mulProgram.nodes) index := by
  rw [mulProgramCompiled_eq_localise]
  exact Program.localise_value_eq_evalNodes mulProgram columns index
    mulProgram_wellFormed covered

/-- The `mulh` bridge's evaluator agrees with A's on every node, for every
column assignment. -/
theorem mulhProgramCompiled_value_eq_evalNodes (columns : List M31) (index : Nat)
    (covered : index < mulhProgram.nodes.length) :
    mulhProgramCompiled.value columns index =
      nth (evalNodes columns mulhProgram.nodes) index := by
  rw [mulhProgramCompiled_eq_localise]
  exact MulhCircuit.localise_value_eq_evalNodes mulhProgram columns index
    mulhProgram_wellFormed covered

end RiscvRefinement.Air.Bridge
