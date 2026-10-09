import S31.Semantics.Graph

namespace S31.Graph
variable {α Op : Type} [Inhabited α]

def Gate.accepts (constraint : Op → List α → α → Prop) (values : List α) : Gate α Op → α → Prop
  | .constant c, y => y = c
  | .apply op args, y => constraint op (args.map (values.getD · default)) y

/-- All intermediate wires are existential witnesses supplied by the prover.
This relation checks each primitive's constraints; it does not call `run`. -/
inductive Accepts (constraint : Op → List α → α → Prop) :
    List (Gate α Op) → List α → List α → Prop where
  | nil (values) : Accepts constraint [] values values
  | cons {gate gates values final y} :
      gate.accepts constraint values y →
      Accepts constraint gates (values ++ [y]) final →
      Accepts constraint (gate :: gates) values final

theorem accepts_sound (interpret : Op → List α → α)
    (constraint : Op → List α → α → Prop)
    (sound : ∀ op args y, constraint op args y → y = interpret op args)
    {gates values final} (h : Accepts constraint gates values final) :
    final = run interpret gates values := by
  induction h with
  | nil => rfl
  | @cons gate gates values final y hlocal htail ih =>
    have hy : y = gate.eval interpret values := by
      cases gate with
      | constant c => exact hlocal
      | apply op args => exact sound op _ y hlocal
    simpa only [run, hy] using ih

theorem accepts_complete (interpret : Op → List α → α)
    (constraint : Op → List α → α → Prop)
    (complete : ∀ op args, constraint op args (interpret op args))
    (gates : List (Gate α Op)) (values : List α) :
    Accepts constraint gates values (run interpret gates values) := by
  induction gates generalizing values with
  | nil => exact .nil values
  | cons gate gates ih =>
    apply Accepts.cons (y := gate.eval interpret values)
    · cases gate with
      | constant => rfl
      | apply op args => exact complete op _
    · exact ih _

def Code.accepts (code : Code α Op) (constraint : Op → List α → α → Prop)
    (inputs output : List α) : Prop :=
  ∃ final, Accepts constraint code.gates inputs final ∧
    output = code.outputs.map (final.getD · default)

theorem code_sound_complete (code : Code α Op) (interpret : Op → List α → α)
    (constraint : Op → List α → α → Prop)
    (correct : ∀ op args y, constraint op args y ↔ y = interpret op args)
    (inputs output : List α) :
    code.accepts constraint inputs output ↔ output = code.eval interpret inputs := by
  constructor
  · rintro ⟨final, h, rfl⟩
    rw [accepts_sound interpret constraint (fun op args y => (correct op args y).mp) h]
    rfl
  · rintro rfl
    exact ⟨_, accepts_complete interpret constraint
      (fun op args => (correct op args _).mpr rfl) code.gates inputs, rfl⟩

end S31.Graph
