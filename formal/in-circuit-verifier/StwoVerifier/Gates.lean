/-
**The circuit gate model** (`src/frontends/circuit/builder/circuit.zig`
`Circuit::check`, stwo-zig `4afa09dbf`).

A circuit is a list of gates over QM31-valued registers (`Var` = ℕ here).
`Holds ρ g` is exactly what `check` enforces on a value assignment `ρ` for
gate `g`. Guesses are unconstrained at emission; `finalizeGuessedVars`
constrains an M31 guess by `x ⊙ 1 = x` and a u16 guess by
`m31_to_u32(x) = x`, which the `guessM31`/`guessU16` ops carry directly.
Constants are pinned by the value table (`finalize_constants`), so
`Op.const` asserts the register's value.

The model follows starked-bitcoin's `Circuit/Ops.lean` (same builder,
same semantics), restated over this project's `QM31`.

Gadget emitters are written in the same generator style as the Zig code:
a function of the next-fresh register returning `(ops, outputs, next)`.
Soundness theorems quantify over every assignment that satisfies the
emitted ops.
-/
import StwoVerifier.Fields
import StwoVerifier.Blake2s

namespace StwoVerifier.Gates

open StwoVerifier

/-- Pointwise (coordinate-wise) product, `ivalue.pointwiseMul`. -/
def pmulQ (x y : QM31) : QM31 :=
  ⟨⟨x.c0.a * y.c0.a, x.c0.b * y.c0.b⟩, ⟨x.c1.a * y.c1.a, x.c1.b * y.c1.b⟩⟩

/-- `m31_to_u32` of a base value `x`: `(x mod 2¹⁶, x / 2¹⁶, 0, 0)`. -/
def m2uQ (x : QM31) : QM31 :=
  ⟨⟨((x.c0.a.val % 65536 : ℕ) : F), ((x.c0.a.val / 65536 : ℕ) : F)⟩, ⟨0, 0⟩⟩

/-- A base-field (M31) value: the three non-base coordinates vanish. -/
def IsBase (x : QM31) : Prop := x.c0.b = 0 ∧ x.c1 = CM31.zero

/-- `is_u32_limbs`: the limb form `(low₁₆, high₁₆, 0, 0)` of a `u32`. -/
def IsU32 (x : QM31) : Prop :=
  x.c0.a.val < 65536 ∧ x.c0.b.val < 65536 ∧ x.c1 = CM31.zero

/-- `ivalue.unpack_u32`: the word a limb-form register carries. -/
def wordOf (x : QM31) : Blake2s.Word :=
  BitVec.ofNat 32 (x.c0.a.val + 65536 * x.c0.b.val)

/-- `ivalue.pack_u32`: the limb form of a word. -/
def packW (w : Blake2s.Word) : QM31 :=
  ⟨⟨((w.toNat % 65536 : ℕ) : F), ((w.toNat / 65536 : ℕ) : F)⟩, ⟨0, 0⟩⟩

/-- One gate / builder event. Registers are naturals, `o` is defined. -/
inductive Op where
  | const (o : ℕ) (v : QM31)
  | add (o x y : ℕ)
  | sub (o x y : ℕ)
  | mul (o x y : ℕ)
  | pmul (o x y : ℕ)
  | eq (x y : ℕ)
  | m2u (o x : ℕ)
  /-- An unconstrained QM31 guess (`Context.guess`). -/
  | guess (o : ℕ)
  /-- A guess constrained to M31 at finalization. -/
  | guessM31 (o : ℕ)
  /-- A guess constrained to `[0, 2¹⁶)` at finalization. -/
  | guessU16 (o : ℕ)
  /-- `Context.inv`: a guess `o` with `x · o = 1`. -/
  | inv (o x : ℕ)
  /-- A TripleXor gate: `o = a ^^^ b ^^^ c` over `u32` limb wires. -/
  | tripleXor (o a b c : ℕ)
  /-- A BlakeGGate: `(o, o+1, o+2, o+3) = G(a, b, c, d, f0, f1)` over
  `u32` limb wires. -/
  | blakeG (o a b c d f0 f1 : ℕ)
  /-- A permutation gate: the output values are a permutation (as a
  multiset) of the input values. -/
  | perm (outs ins : List ℕ)
  deriving Repr

/-- What one gate enforces on an assignment (`Circuit::check` +
finalization constraints). -/
def Holds (ρ : ℕ → QM31) : Op → Prop
  | .const o v => ρ o = v
  | .add o x y => ρ o = ρ x + ρ y
  | .sub o x y => ρ o = ρ x - ρ y
  | .mul o x y => ρ o = ρ x * ρ y
  | .pmul o x y => ρ o = pmulQ (ρ x) (ρ y)
  | .eq x y => ρ x = ρ y
  | .m2u o x => IsBase (ρ x) ∧ ρ o = m2uQ (ρ x)
  | .guess _ => True
  | .guessM31 o => IsBase (ρ o)
  | .guessU16 o => (ρ o).c0.a.val < 65536 ∧ (ρ o).c0.b = 0 ∧ (ρ o).c1 = CM31.zero
  | .inv o x => ρ x * ρ o = QM31.one
  | .tripleXor o a b c =>
    IsU32 (ρ a) ∧ IsU32 (ρ b) ∧ IsU32 (ρ c) ∧
    ρ o = packW (wordOf (ρ a) ^^^ wordOf (ρ b) ^^^ wordOf (ρ c))
  | .blakeG o a b c d f0 f1 =>
    IsU32 (ρ a) ∧ IsU32 (ρ b) ∧ IsU32 (ρ c) ∧ IsU32 (ρ d) ∧
    IsU32 (ρ f0) ∧ IsU32 (ρ f1) ∧
    (ρ o = packW (Blake2s.mix (wordOf (ρ a)) (wordOf (ρ b)) (wordOf (ρ c))
        (wordOf (ρ d)) (wordOf (ρ f0)) (wordOf (ρ f1))).1 ∧
      ρ (o + 1) = packW (Blake2s.mix (wordOf (ρ a)) (wordOf (ρ b))
        (wordOf (ρ c)) (wordOf (ρ d)) (wordOf (ρ f0)) (wordOf (ρ f1))).2.1 ∧
      ρ (o + 2) = packW (Blake2s.mix (wordOf (ρ a)) (wordOf (ρ b))
        (wordOf (ρ c)) (wordOf (ρ d)) (wordOf (ρ f0)) (wordOf (ρ f1))).2.2.1 ∧
      ρ (o + 3) = packW (Blake2s.mix (wordOf (ρ a)) (wordOf (ρ b))
        (wordOf (ρ c)) (wordOf (ρ d)) (wordOf (ρ f0)) (wordOf (ρ f1))).2.2.2)
  | .perm outs ins => (ins.map ρ).Perm (outs.map ρ)

/-- All emitted gates hold. -/
def AllHold (ρ : ℕ → QM31) (ops : List Op) : Prop := ∀ op ∈ ops, Holds ρ op

theorem allHold_append {ρ : ℕ → QM31} {a b : List Op} :
    AllHold ρ (a ++ b) ↔ AllHold ρ a ∧ AllHold ρ b := by
  constructor
  · intro h; exact ⟨fun op hm => h op (List.mem_append_left _ hm),
      fun op hm => h op (List.mem_append_right _ hm)⟩
  · rintro ⟨ha, hb⟩ op hm
    rcases List.mem_append.mp hm with h | h
    · exact ha op h
    · exact hb op h

theorem allHold_cons {ρ : ℕ → QM31} {op : Op} {ops : List Op} :
    AllHold ρ (op :: ops) ↔ Holds ρ op ∧ AllHold ρ ops := by
  constructor
  · intro h; exact ⟨h op List.mem_cons_self, fun o hm => h o (List.mem_cons_of_mem _ hm)⟩
  · rintro ⟨h1, h2⟩ o hm
    rcases List.mem_cons.mp hm with rfl | hm
    · exact h1
    · exact h2 o hm

/-- An emitter result: the ops, the produced value (registers), and the
next fresh register. -/
structure Out (α : Type) where
  ops : List Op
  res : α
  next : ℕ

end StwoVerifier.Gates
