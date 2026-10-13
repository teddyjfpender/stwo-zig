/-
**The stwo field tower, executable.**

Mirrors `src/core/fields/{m31,cm31,qm31}.zig` of stwo-zig at `4afa09dbf`:
- `F = M31 = ℤ/(2³¹−1)`;
- `CM31 = F[i]/(i² + 1)`, stored as coordinates `a + b·i`;
- `QM31 = CM31[u]/(u² − (2 + i))`, stored as `c0 + c1·u`.

Every operation is a computable function on coordinates, so the whole
verifier spec built on top can run in `#eval` for differential testing.
The ring/field structure proofs against `AdjoinRoot` come later (they are
in starked-bitcoin's `Spec/QM31.lean` for the same tower).
-/
import StwoVerifier.Basic

namespace StwoVerifier

abbrev F : Type := ZMod P

instance : NeZero P := ⟨by unfold P; norm_num⟩

/-- `CM31`: `a + b·i` with `i² = −1`. -/
structure CM31 where
  a : F
  b : F
  deriving DecidableEq, Repr

namespace CM31

def zero : CM31 := ⟨0, 0⟩
def one : CM31 := ⟨1, 0⟩
def fromBase (x : F) : CM31 := ⟨x, 0⟩

instance : Zero CM31 := ⟨zero⟩
instance : One CM31 := ⟨one⟩

def add (x y : CM31) : CM31 := ⟨x.a + y.a, x.b + y.b⟩
def sub (x y : CM31) : CM31 := ⟨x.a - y.a, x.b - y.b⟩
def neg (x : CM31) : CM31 := ⟨-x.a, -x.b⟩
def mul (x y : CM31) : CM31 := ⟨x.a * y.a - x.b * y.b, x.a * y.b + x.b * y.a⟩
def mulM31 (x : CM31) (m : F) : CM31 := ⟨x.a * m, x.b * m⟩

instance : Add CM31 := ⟨add⟩
instance : Sub CM31 := ⟨sub⟩
instance : Neg CM31 := ⟨neg⟩
instance : Mul CM31 := ⟨mul⟩

/-- Norm `a² + b²`; zero exactly on the zero element (−1 is not a square mod P). -/
def norm (x : CM31) : F := x.a * x.a + x.b * x.b

/-- Multiplicative inverse; `none` for zero (mirrors Zig's `DivisionByZero`). -/
def inv? (x : CM31) : Option CM31 :=
  let n := norm x
  if n = 0 then none else some ⟨x.a * n⁻¹, -x.b * n⁻¹⟩

end CM31

/-- `QM31 = CM31[u]/(u² = 2 + i)`, stored as `c0 + c1·u`. -/
structure QM31 where
  c0 : CM31
  c1 : CM31
  deriving DecidableEq, Repr

namespace QM31

/-- The irreducible constant `R = 2 + i` (`qm31.zig`'s `R`). -/
def R : CM31 := ⟨2, 1⟩

def zero : QM31 := ⟨CM31.zero, CM31.zero⟩
def one : QM31 := ⟨CM31.one, CM31.zero⟩
def fromBase (x : F) : QM31 := ⟨CM31.fromBase x, CM31.zero⟩
def fromM31s (a b c d : F) : QM31 := ⟨⟨a, b⟩, ⟨c, d⟩⟩

instance : Zero QM31 := ⟨zero⟩
instance : One QM31 := ⟨one⟩

def add (x y : QM31) : QM31 := ⟨x.c0 + y.c0, x.c1 + y.c1⟩
def sub (x y : QM31) : QM31 := ⟨x.c0 - y.c0, x.c1 - y.c1⟩
def neg (x : QM31) : QM31 := ⟨-x.c0, -x.c1⟩
/-- `(a + bu)(c + du) = (ac + R·bd) + (ad + bc)u`. -/
def mul (x y : QM31) : QM31 :=
  ⟨x.c0 * y.c0 + R * (x.c1 * y.c1), x.c0 * y.c1 + x.c1 * y.c0⟩
def mulM31 (x : QM31) (m : F) : QM31 := ⟨x.c0.mulM31 m, x.c1.mulM31 m⟩
def mulCM31 (x : QM31) (m : CM31) : QM31 := ⟨x.c0 * m, x.c1 * m⟩

instance : Add QM31 := ⟨add⟩
instance : Sub QM31 := ⟨sub⟩
instance : Neg QM31 := ⟨neg⟩
instance : Mul QM31 := ⟨mul⟩

def square (x : QM31) : QM31 := x * x

/-- The four M31 coordinates in stwo's order `(c0.a, c0.b, c1.a, c1.b)`. -/
def coords (x : QM31) : List F := [x.c0.a, x.c0.b, x.c1.a, x.c1.b]

/-- `qm31.zig`'s `complexConjugate`: `u ↦ −u`, i.e. `(c0, −c1)`. -/
def complexConjugate (x : QM31) : QM31 := ⟨x.c0, -x.c1⟩

/-- Is this a base-field element? -/
def isBase (x : QM31) : Bool := x.c0.b = 0 ∧ x.c1 = CM31.zero

/-- Inverse via the tower norm: `(a + bu)⁻¹ = (a − bu) / (a² − R b²)`. -/
def inv? (x : QM31) : Option QM31 := do
  let d := x.c0 * x.c0 - R * (x.c1 * x.c1)
  let di ← d.inv?
  pure ⟨x.c0 * di, (-x.c1) * di⟩

def eql (x y : QM31) : Bool := decide (x = y)

end QM31

/-- Canonical `u32` value of an M31 element. -/
def F.toU32 (x : F) : Nat := x.val

end StwoVerifier
