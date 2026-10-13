/-
**Circle group, cosets, domains and line polynomials**
(`src/core/circle.zig`, `src/core/poly/{line.zig,circle/domain.zig,circle/canonic.zig}`,
`src/core/utils.zig`, stwo-zig `4afa09dbf`), executable.

Representation choice: a coset is `(initialIndex, logSize)` with step
`2^(31 − logSize)`. Every coset the verifier constructs has exactly that
step (subgroups, odds, half-odds, their doublings, and FRI's
`Coset.new(idx, n)`), so the Zig struct's cached step/half-step fields are
derived here. The circle-domain's conjugate half is inlined into `indexAt`.
-/
import StwoVerifier.Fields

namespace StwoVerifier

/-- A point on the unit circle `x² + y² = 1` over a ring `α`. -/
structure CPoint (α : Type) where
  x : α
  y : α
  deriving DecidableEq, Repr

namespace CPoint

variable {α : Type} [Add α] [Sub α] [Mul α] [Neg α] [Zero α] [One α]

def zero : CPoint α := ⟨1, 0⟩

/-- Group law `(x₁x₂ − y₁y₂, x₁y₂ + y₁x₂)`. -/
def add (p q : CPoint α) : CPoint α := ⟨p.x * q.x - p.y * q.y, p.x * q.y + p.y * q.x⟩

def conjugate (p : CPoint α) : CPoint α := ⟨p.x, -p.y⟩
def neg (p : CPoint α) : CPoint α := p.conjugate
def double (p : CPoint α) : CPoint α := p.add p
def antipode (p : CPoint α) : CPoint α := ⟨-p.x, -p.y⟩

/-- The doubling map on x-coordinates: `2x² − 1`. -/
def doubleX (x : α) : α := x * x + x * x - 1

/-- Scalar multiplication by binary decomposition (`mul`). -/
def smul (p : CPoint α) : Nat → CPoint α
  | 0 => zero
  | n + 1 =>
    let half := (smul p ((n + 1) / 2)).double
    if (n + 1) % 2 = 1 then half.add p else half

def repeatedDouble (p : CPoint α) : Nat → CPoint α
  | 0 => p
  | n + 1 => (repeatedDouble p n).double

end CPoint

abbrev PointF := CPoint F
abbrev PointQ := CPoint QM31

/-- Lift a base-field point into QM31 coordinates. -/
def PointF.intoQ (p : PointF) : PointQ := ⟨QM31.fromBase p.x, QM31.fromBase p.y⟩

/-- Generator of the M31 circle group, order `2³¹`. -/
def M31_CIRCLE_GEN : PointF := ⟨(2 : F), (1268011823 : F)⟩

def M31_CIRCLE_LOG_ORDER : Nat := 31
def circleOrder : Nat := 2^31

/-- Generator of the QM31 circle group (`SECURE_FIELD_CIRCLE_GEN`). -/
def SECURE_FIELD_CIRCLE_GEN : PointQ :=
  ⟨QM31.fromM31s 1 0 478637715 513582971,
   QM31.fromM31s 992285211 649143431 740191619 1186584352⟩

/-- `CirclePointIndex`: an index into the order-`2³¹` cyclic group. -/
abbrev PIdx := Nat

def PIdx.reduce (i : PIdx) : PIdx := i % circleOrder
def PIdx.add' (i j : PIdx) : PIdx := (i + j) % circleOrder
def PIdx.neg' (i : PIdx) : PIdx := (circleOrder - i % circleOrder) % circleOrder
def PIdx.mul' (i : PIdx) (k : Nat) : PIdx := (i * k) % circleOrder

/-- `subgroupGen log_size = 2^(31 − log_size)`. -/
def subgroupGen (logSize : Nat) : PIdx := 2^(M31_CIRCLE_LOG_ORDER - logSize)

def PIdx.toPoint (i : PIdx) : PointF := M31_CIRCLE_GEN.smul i.reduce

/-- A coset `initialIndex + k · 2^(31 − logSize)`. -/
structure Coset where
  initialIndex : PIdx
  logSize : Nat
  deriving DecidableEq, Repr

namespace Coset

def new (initialIndex : PIdx) (logSize : Nat) : Coset := ⟨initialIndex.reduce, logSize⟩
def subgroup (logSize : Nat) : Coset := new 0 logSize
def odds (logSize : Nat) : Coset := new (subgroupGen (logSize + 1)) logSize
def halfOdds (logSize : Nat) : Coset := new (subgroupGen (logSize + 2)) logSize

def size (c : Coset) : Nat := 2^c.logSize
def stepSize (c : Coset) : PIdx := subgroupGen c.logSize
def indexAt (c : Coset) (i : Nat) : PIdx := c.initialIndex.add' (c.stepSize.mul' i)
def at' (c : Coset) (i : Nat) : PointF := (c.indexAt i).toPoint
def double (c : Coset) : Coset := ⟨(2 * c.initialIndex) % circleOrder, c.logSize - 1⟩

def repeatedDouble (c : Coset) : Nat → Coset
  | 0 => c
  | n + 1 => (repeatedDouble c n).double

end Coset

/-- A circle domain: a half-coset and its conjugate (`CircleDomain`). -/
structure CircleDomain where
  halfCoset : Coset
  deriving DecidableEq, Repr

namespace CircleDomain

def logSize (d : CircleDomain) : Nat := d.halfCoset.logSize + 1
def size (d : CircleDomain) : Nat := 2^d.logSize

/-- `indexAt`: first the half-coset, then its conjugate (negated indices). -/
def indexAt (d : CircleDomain) (i : Nat) : PIdx :=
  let half := d.halfCoset.size
  if i < half then d.halfCoset.indexAt i
  else (d.halfCoset.indexAt (i - half)).neg'

def at' (d : CircleDomain) (i : Nat) : PointF := (d.indexAt i).toPoint

end CircleDomain

/-- `CanonicCoset.new(l)`: the odds coset of log size `l`; its circle domain
is `CircleDomain(halfOdds (l − 1))`. -/
def canonicDomain (logSize : Nat) : CircleDomain := ⟨Coset.halfOdds (logSize - 1)⟩

/-- The canonic coset's step point (`CanonicCoset.step`), the generator of
the order-`2^l` subgroup shifted group: `subgroupGen l ·G`. -/
def canonicStep (logSize : Nat) : PointF := (subgroupGen logSize : PIdx).toPoint

/-- `bitReverseIndex i log_size`. -/
def bitReverseIndex (i : Nat) (logSize : Nat) : Nat :=
  (List.range logSize).foldl (fun acc k => acc + (i / 2^k % 2) * 2^(logSize - 1 - k)) 0

/-- The OODS seed-to-point map `t ↦ ((1 − t²)/(1 + t²), 2t/(1 + t²))`
(`secureFieldPointFromRandomSeedChecked`); `none` at `t² = −1`. -/
def securePointFromSeed (t : QM31) : Option PointQ := do
  let t2 := t.square
  let d ← (t2 + QM31.one).inv?
  pure ⟨(QM31.one - t2) * d, (t + t) * d⟩

/-! ### Line domains and line polynomials -/

/-- A line domain is the x-projection of a coset (`LineDomain`). The validity
condition (unique x-coordinates) holds for every coset the verifier builds. -/
structure LineDomain where
  coset : Coset
  deriving DecidableEq, Repr

namespace LineDomain

def logSize (d : LineDomain) : Nat := d.coset.logSize
def size (d : LineDomain) : Nat := d.coset.size
def at' (d : LineDomain) (i : Nat) : F := (d.coset.at' i).x
def double (d : LineDomain) : LineDomain := ⟨d.coset.double⟩
def fromCircleDomain (d : CircleDomain) : LineDomain := ⟨d.halfCoset⟩

end LineDomain

/-- FFT-basis fold (`poly/utils.zig` `foldReference`):
`fold(v, f₀ :: fs) = fold(lo, fs) + f₀ · fold(hi, fs)`. -/
def fftFold (values : List QM31) (factors : List QM31) : QM31 :=
  match factors with
  | [] => values.headD QM31.zero
  | f :: fs =>
    let half := values.length / 2
    fftFold (values.take half) fs + f * fftFold (values.drop half) fs

/-- `[x, double(x), …, doubleⁿ⁻¹(x)]`. -/
def doublings (x : QM31) : Nat → List QM31
  | 0 => []
  | n + 1 => x :: doublings (CPoint.doubleX x) n

/-- `LinePoly.evalAtPoint`: fold the (FFT-order) coefficients against the
doubling stack of `x`, plain `x` at the outermost split (the Zig `fold`
consumes `folding_factors[len − 1 − merge_level]`, so the top split uses
`doublings[0] = x`). -/
def linePolyEval (coeffs : List QM31) (x : QM31) : QM31 :=
  fftFold coeffs (doublings x (Nat.log2 coeffs.length))

end StwoVerifier
