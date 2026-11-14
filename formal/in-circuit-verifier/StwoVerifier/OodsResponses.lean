/-
**`collect_oods_responses`, part 1: the period generators**
(`src/frontends/circuit/stark_verifier/oods.zig` `period_generators`,
stwo-zig `4afa09dbf`).

Per component, the circuit computes `component_size · trace_gen` from
the bits of the (power-of-two) component size: starting from the trace
generator, it doubles a scalar point per bit position and accumulates
`bit · coords` lane-wise, so a one-hot bit pattern selects the
`2^log`-fold generator. `periodChain_lane` is the general linear form
(each lane is the bit-weighted coordinate sum `bitComb`); the
`bitCombFull_onehot` specialization produces exactly the spec's period
shift `canonicStep(lifting).repeatedDouble(log + 1)` (the committed
column log is blowup-extended, which absorbs the lifting offset:
`subgroupGen(l+1)·2^(log+1) = subgroupGen(l)·2^log`).
-/
import StwoVerifier.TwiddleChain
import StwoVerifier.FoldBridge

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates StwoVerifier.Bridge

/-! ### Embedding facts -/

theorem fromBase_eq_baseHom (x : F) : QM31.fromBase x = baseHom x := rfl

/-- `intoQ` commutes with the group law. -/
theorem intoQ_add (p q : PointF) :
    PointF.intoQ (p.add q) = (PointF.intoQ p).add (PointF.intoQ q) := by
  unfold PointF.intoQ CPoint.add
  simp only [fromBase_eq_baseHom, map_mul, map_sub, map_add]

theorem intoQ_double (p : PointF) :
    PointF.intoQ p.double = (PointF.intoQ p).double := by
  unfold CPoint.double
  exact intoQ_add p p

/-- An embedded on-circle point satisfies the circle equation in `QM31`. -/
theorem intoQ_onCircle {p : PointF} (hp : OnCircle p) :
    (PointF.intoQ p).x * (PointF.intoQ p).x
      + (PointF.intoQ p).y * (PointF.intoQ p).y = 1 := by
  unfold PointF.intoQ
  show QM31.fromBase p.x * QM31.fromBase p.x
    + QM31.fromBase p.y * QM31.fromBase p.y = 1
  simp only [fromBase_eq_baseHom, ← map_mul, ← map_add]
  rw [hp]
  exact map_one baseHom

/-! ### The period-generator chain -/

theorem simdScalarMul_data_len (a : SimdReg) (s n : ℕ) :
    (simdScalarMul a s n).res.data.length = a.data.length := by
  show (lanewise2 (fun o x y => Op.mul o x y) a.data
    (a.data.map fun _ => s) n).res.length = a.data.length
  rw [lanewise2_length, List.length_map, min_self]

/-- One doubling-and-accumulate step per size bit (`period_generators`'
loop body): `gen ← double gen`, then `acc ← acc + bit ·ₗ gen` on each
coordinate. -/
def periodStep (one : ℕ) (b : SimdReg) (gen : PointReg) (ax ay : SimdReg)
    (n : ℕ) : Out (PointReg × SimdReg × SimdReg) :=
  let g2 := doublePoint one gen n
  let sx := simdScalarMul b g2.res.x g2.next
  let sy := simdScalarMul b g2.res.y sx.next
  let nx := simdAdd ax sx.res sy.next
  let ny := simdAdd ay sy.res nx.next
  ⟨g2.ops ++ sx.ops ++ sy.ops ++ nx.ops ++ ny.ops,
   (g2.res, nx.res, ny.res), ny.next⟩

/-- The chain over the remaining size bits. -/
def periodChain (one : ℕ) : List SimdReg → PointReg → SimdReg → SimdReg →
    ℕ → Out (SimdReg × SimdReg)
  | [], _, ax, ay, n => ⟨[], (ax, ay), n⟩
  | b :: rest, gen, ax, ay, n =>
    let st := periodStep one b gen ax ay n
    let tail := periodChain one rest st.res.1 st.res.2.1 st.res.2.2 st.next
    ⟨st.ops ++ tail.ops, tail.res, tail.next⟩

/-- `period_generators`: the trace generator as constants, `bit₀ ·ₗ gen`,
then the chain over the remaining bits. -/
def periodGensG (one : ℕ) (g : PointF) (bits : List SimdReg) (n : ℕ) :
    Out (SimdReg × SimdReg) :=
  match bits with
  | [] => ⟨[], (dummySimd, dummySimd), n⟩
  | b0 :: rest =>
    let cx : ℕ := n
    let cy : ℕ := n + 1
    let sx := simdScalarMul b0 cx (n + 2)
    let sy := simdScalarMul b0 cy sx.next
    let tail := periodChain one rest ⟨cx, cy⟩ sx.res sy.res sy.next
    ⟨.const cx (QM31.fromBase g.x) :: .const cy (QM31.fromBase g.y) ::
      (sx.ops ++ sy.ops ++ tail.ops), tail.res, tail.next⟩

/-! ### The spec: bit-weighted coordinate sums -/

/-- What the chain computes per lane: the bit-weighted sum of the
doubled generators' coordinates, the generator doubling once per bit
(`Σ_t b_t · (double^(t+1) P)` coordinate-wise). -/
def bitComb (P : PointF) : List F → F × F
  | [] => (0, 0)
  | b :: rest =>
    let r := bitComb P.double rest
    ((P.double).x * b + r.1, (P.double).y * b + r.2)

theorem bitComb_cons (P : PointF) (b : F) (rest : List F) :
    bitComb P (b :: rest)
      = ((P.double).x * b + (bitComb P.double rest).1,
         (P.double).y * b + (bitComb P.double rest).2) := rfl

/-- The whole gadget's per-lane value: bit 0 weighs the generator
itself, the rest the successive doubles. -/
def bitCombFull (P : PointF) : List F → F × F
  | [] => (0, 0)
  | b :: rest =>
    let r := bitComb P rest
    (P.x * b + r.1, P.y * b + r.2)

theorem bitCombFull_cons (P : PointF) (b : F) (rest : List F) :
    bitCombFull P (b :: rest)
      = (P.x * b + (bitComb P rest).1, P.y * b + (bitComb P rest).2) := rfl

theorem bitComb_zero : ∀ (m : ℕ) (P : PointF),
    bitComb P (List.replicate m 0) = (0, 0)
  | 0, _ => rfl
  | m + 1, P => by
    rw [List.replicate_succ, bitComb_cons, bitComb_zero m P.double]
    simp

/-- A one-hot tail (bit `k` set, counted from the first double) picks
out the `(k+1)`-fold double. -/
theorem bitComb_onehot : ∀ (k : ℕ) (P : PointF) (m : ℕ),
    bitComb P (List.replicate k 0 ++ 1 :: List.replicate m 0)
      = ((P.repeatedDouble (k + 1)).x, (P.repeatedDouble (k + 1)).y)
  | 0, P, m => by
    rw [List.replicate_zero, List.nil_append, bitComb_cons,
      bitComb_zero m P.double]
    show ((P.double).x * 1 + 0, (P.double).y * 1 + 0) = _
    simp [CPoint.repeatedDouble]
  | k + 1, P, m => by
    rw [List.replicate_succ, List.cons_append, bitComb_cons,
      bitComb_onehot k P.double m, repeatedDouble_shift]
    simp

/-- **One-hot bits select the `2^k`-fold generator**: with the binary
digits of `2^k` as lanes, the gadget's lane is `component_size ·
trace_gen` — the spec's periodicity shift. -/
theorem bitCombFull_onehot : ∀ (k : ℕ) (P : PointF) (m : ℕ),
    bitCombFull P (List.replicate k 0 ++ 1 :: List.replicate m 0)
      = ((P.repeatedDouble k).x, (P.repeatedDouble k).y)
  | 0, P, m => by
    rw [List.replicate_zero, List.nil_append, bitCombFull_cons,
      bitComb_zero m P]
    show (P.x * 1 + 0, P.y * 1 + 0) = _
    simp [CPoint.repeatedDouble]
  | k + 1, P, m => by
    rw [List.replicate_succ, List.cons_append, bitCombFull_cons,
      bitComb_onehot k P m]
    simp

/-! ### Soundness of the chain -/

/-- One chain step: the generator register doubles (staying an embedded
base-field point) and each accumulator lane gains `bit · coordinate`. -/
theorem periodStep_sound {ρ : ℕ → QM31} {one count len : ℕ} {b : SimdReg}
    {gen : PointReg} {P : PointF} {ax ay : SimdReg} {n : ℕ}
    (hone : ρ one = 1) (hc : len ≤ 4 * count)
    (hP : OnCircle P) (hgen : gen.val ρ = PointF.intoQ P)
    (hb : BitShape b len count)
    (haxc : ax.Covers) (haxl : ax.len = len)
    (hayc : ay.Covers) (hayl : ay.len = len)
    (h : AllHold ρ (periodStep one b gen ax ay n).ops) :
    (periodStep one b gen ax ay n).res.1.val ρ = PointF.intoQ P.double ∧
    ((periodStep one b gen ax ay n).res.2.1.Covers ∧
      (periodStep one b gen ax ay n).res.2.1.len = len ∧
      (periodStep one b gen ax ay n).res.2.2.Covers ∧
      (periodStep one b gen ax ay n).res.2.2.len = len) ∧
    ∀ j, j < len →
      SimdReg.lane ρ (periodStep one b gen ax ay n).res.2.1 j
        = SimdReg.lane ρ ax j + (P.double).x * SimdReg.lane ρ b j ∧
      SimdReg.lane ρ (periodStep one b gen ax ay n).res.2.2 j
        = SimdReg.lane ρ ay j + (P.double).y * SimdReg.lane ρ b j := by
  set g2 := doublePoint one gen n with hg2def
  set sx := simdScalarMul b g2.res.x g2.next with hsxdef
  set sy := simdScalarMul b g2.res.y sx.next with hsydef
  set nx := simdAdd ax sx.res sy.next with hnxdef
  set ny := simdAdd ay sy.res nx.next with hnydef
  replace h : AllHold ρ (g2.ops ++ sx.ops ++ sy.ops ++ nx.ops ++ ny.ops) := h
  rw [allHold_append, allHold_append, allHold_append, allHold_append] at h
  obtain ⟨⟨⟨⟨hg2h, hsxh⟩, hsyh⟩, hnxh⟩, hnyh⟩ := h
  have hcirc : ρ gen.x * ρ gen.x + ρ gen.y * ρ gen.y = 1 := by
    have hx : ρ gen.x = QM31.fromBase P.x := congrArg CPoint.x hgen
    have hy : ρ gen.y = QM31.fromBase P.y := congrArg CPoint.y hgen
    rw [hx, hy]
    exact intoQ_onCircle hP
  have hdval : g2.res.val ρ = PointF.intoQ P.double := by
    show (doublePoint one gen n).res.val ρ = PointF.intoQ P.double
    rw [doublePoint_sound hone hcirc hg2h, hgen]
    exact (intoQ_double P).symm
  have hdx : ρ g2.res.x = QM31.fromBase (P.double).x := congrArg CPoint.x hdval
  have hdy : ρ g2.res.y = QM31.fromBase (P.double).y := congrArg CPoint.y hdval
  have hbc : b.Covers := by
    show b.len ≤ 4 * b.data.length
    rw [hb.lenEq, hb.dataEq]
    exact hc
  have hsxd : sx.res.data.length = count := by
    rw [hsxdef, simdScalarMul_data_len, hb.dataEq]
  have hsyd : sy.res.data.length = count := by
    rw [hsydef, simdScalarMul_data_len, hb.dataEq]
  refine ⟨hdval, ⟨?_, ?_, ?_, ?_⟩, fun j hj => ⟨?_, ?_⟩⟩
  · show nx.res.Covers
    exact simdAdd_covers haxc (by rw [haxl, hsxd]; exact hc)
  · show nx.res.len = len
    exact haxl
  · show ny.res.Covers
    exact simdAdd_covers hayc (by rw [hayl, hsyd]; exact hc)
  · show ny.res.len = len
    exact hayl
  · have hsxlane : SimdReg.lane ρ sx.res j = (P.double).x * SimdReg.lane ρ b j :=
      simdScalarMul_lane hbc hdx hsxh j (by rw [hb.lenEq]; exact hj)
    have hnxlane : SimdReg.lane ρ nx.res j
        = SimdReg.lane ρ ax j + SimdReg.lane ρ sx.res j :=
      simdAdd_lane haxc (by rw [haxl, hsxd]; exact hc) hnxh j
        (by rw [haxl]; exact hj)
    show SimdReg.lane ρ nx.res j = _
    rw [hnxlane, hsxlane]
  · have hsylane : SimdReg.lane ρ sy.res j = (P.double).y * SimdReg.lane ρ b j :=
      simdScalarMul_lane hbc hdy hsyh j (by rw [hb.lenEq]; exact hj)
    have hnylane : SimdReg.lane ρ ny.res j
        = SimdReg.lane ρ ay j + SimdReg.lane ρ sy.res j :=
      simdAdd_lane hayc (by rw [hayl, hsyd]; exact hc) hnyh j
        (by rw [hayl]; exact hj)
    show SimdReg.lane ρ ny.res j = _
    rw [hnylane, hsylane]

/-- **The chain's lane is the bit-weighted coordinate sum**: starting
from accumulators `ax, ay` and an embedded on-circle generator `P`,
each output lane is `acc + Σ_t bit_t · (double^(t+1) P)`
coordinate-wise. -/
theorem periodChain_lane {ρ : ℕ → QM31} {one count len : ℕ}
    (hone : ρ one = 1) (hc : len ≤ 4 * count) :
    ∀ (bits : List SimdReg) (gen : PointReg) (P : PointF) (ax ay : SimdReg)
      (n : ℕ), OnCircle P → gen.val ρ = PointF.intoQ P →
      (∀ b ∈ bits, BitShape b len count) →
      ax.Covers → ax.len = len → ay.Covers → ay.len = len →
      AllHold ρ (periodChain one bits gen ax ay n).ops →
      ((periodChain one bits gen ax ay n).res.1.Covers ∧
        (periodChain one bits gen ax ay n).res.1.len = len ∧
        (periodChain one bits gen ax ay n).res.2.Covers ∧
        (periodChain one bits gen ax ay n).res.2.len = len) ∧
      ∀ j, j < len →
        SimdReg.lane ρ (periodChain one bits gen ax ay n).res.1 j
          = SimdReg.lane ρ ax j
            + (bitComb P (bits.map fun bb => SimdReg.lane ρ bb j)).1 ∧
        SimdReg.lane ρ (periodChain one bits gen ax ay n).res.2 j
          = SimdReg.lane ρ ay j
            + (bitComb P (bits.map fun bb => SimdReg.lane ρ bb j)).2 := by
  intro bits
  induction bits with
  | nil =>
    intro gen P ax ay n _ _ _ haxc haxl hayc hayl _
    refine ⟨⟨haxc, haxl, hayc, hayl⟩, fun j hj => ⟨?_, ?_⟩⟩
    · show SimdReg.lane ρ ax j = SimdReg.lane ρ ax j + 0
      exact (add_zero _).symm
    · show SimdReg.lane ρ ay j = SimdReg.lane ρ ay j + 0
      exact (add_zero _).symm
  | cons b rest ih =>
    intro gen P ax ay n hP hgen hshapes haxc haxl hayc hayl h
    rw [show (periodChain one (b :: rest) gen ax ay n).ops =
      (periodStep one b gen ax ay n).ops ++
        (periodChain one rest (periodStep one b gen ax ay n).res.1
          (periodStep one b gen ax ay n).res.2.1
          (periodStep one b gen ax ay n).res.2.2
          (periodStep one b gen ax ay n).next).ops from rfl,
      allHold_append] at h
    obtain ⟨hst, htail⟩ := h
    obtain ⟨hgval, ⟨hnxc, hnxl, hnyc, hnyl⟩, hslane⟩ :=
      periodStep_sound hone hc hP hgen (hshapes b List.mem_cons_self)
        haxc haxl hayc hayl hst
    obtain ⟨ihshape, ihlane⟩ := ih (periodStep one b gen ax ay n).res.1
      P.double (periodStep one b gen ax ay n).res.2.1
      (periodStep one b gen ax ay n).res.2.2
      (periodStep one b gen ax ay n).next (onCircle_double hP) hgval
      (fun bb hbb => hshapes bb (List.mem_cons_of_mem _ hbb))
      hnxc hnxl hnyc hnyl htail
    refine ⟨ihshape, fun j hj => ?_⟩
    obtain ⟨ih1, ih2⟩ := ihlane j hj
    obtain ⟨hs1, hs2⟩ := hslane j hj
    constructor
    · show SimdReg.lane ρ (periodChain one rest
        (periodStep one b gen ax ay n).res.1
        (periodStep one b gen ax ay n).res.2.1
        (periodStep one b gen ax ay n).res.2.2
        (periodStep one b gen ax ay n).next).res.1 j = _
      rw [ih1, hs1, List.map_cons, bitComb_cons]
      show SimdReg.lane ρ ax j + (P.double).x * SimdReg.lane ρ b j
          + (bitComb P.double (rest.map fun bb => SimdReg.lane ρ bb j)).1
        = SimdReg.lane ρ ax j + ((P.double).x * SimdReg.lane ρ b j
          + (bitComb P.double (rest.map fun bb => SimdReg.lane ρ bb j)).1)
      ring
    · show SimdReg.lane ρ (periodChain one rest
        (periodStep one b gen ax ay n).res.1
        (periodStep one b gen ax ay n).res.2.1
        (periodStep one b gen ax ay n).res.2.2
        (periodStep one b gen ax ay n).next).res.2 j = _
      rw [ih2, hs2, List.map_cons, bitComb_cons]
      show SimdReg.lane ρ ay j + (P.double).y * SimdReg.lane ρ b j
          + (bitComb P.double (rest.map fun bb => SimdReg.lane ρ bb j)).2
        = SimdReg.lane ρ ay j + ((P.double).y * SimdReg.lane ρ b j
          + (bitComb P.double (rest.map fun bb => SimdReg.lane ρ bb j)).2)
      ring

/-- **`period_generators` soundness**: with the trace generator pinned
as constants, each output lane is the full bit-weighted sum
`Σ_t bit_t · (double^t gen)` coordinate-wise. -/
theorem periodGensG_lane {ρ : ℕ → QM31} {one count len : ℕ}
    (hone : ρ one = 1) (hc : len ≤ 4 * count)
    {g : PointF} (hg : OnCircle g) {b0 : SimdReg} {rest : List SimdReg}
    {n : ℕ} (hb0 : BitShape b0 len count)
    (hshapes : ∀ b ∈ rest, BitShape b len count)
    (h : AllHold ρ (periodGensG one g (b0 :: rest) n).ops) :
    ((periodGensG one g (b0 :: rest) n).res.1.Covers ∧
      (periodGensG one g (b0 :: rest) n).res.1.len = len ∧
      (periodGensG one g (b0 :: rest) n).res.2.Covers ∧
      (periodGensG one g (b0 :: rest) n).res.2.len = len) ∧
    ∀ j, j < len →
      SimdReg.lane ρ (periodGensG one g (b0 :: rest) n).res.1 j
        = (bitCombFull g ((b0 :: rest).map fun bb => SimdReg.lane ρ bb j)).1 ∧
      SimdReg.lane ρ (periodGensG one g (b0 :: rest) n).res.2 j
        = (bitCombFull g ((b0 :: rest).map fun bb => SimdReg.lane ρ bb j)).2 := by
  set sx := simdScalarMul b0 n (n + 2) with hsxdef
  set sy := simdScalarMul b0 (n + 1) sx.next with hsydef
  replace h : AllHold ρ (.const n (QM31.fromBase g.x) ::
      .const (n + 1) (QM31.fromBase g.y) ::
      (sx.ops ++ sy.ops ++
        (periodChain one rest ⟨n, n + 1⟩ sx.res sy.res sy.next).ops)) := h
  rw [allHold_cons, allHold_cons, allHold_append, allHold_append] at h
  obtain ⟨hcx, hcy, ⟨hsxh, hsyh⟩, htailh⟩ := h
  simp only [Holds] at hcx hcy
  have hgenval : (PointReg.mk n (n + 1)).val ρ = PointF.intoQ g :=
    CPoint.ext' hcx hcy
  have hb0c : b0.Covers := by
    show b0.len ≤ 4 * b0.data.length
    rw [hb0.lenEq, hb0.dataEq]
    exact hc
  have hsxc : sx.res.Covers := by
    rw [hsxdef]
    exact simdScalarMul_covers hb0c
  have hsyc : sy.res.Covers := by
    rw [hsydef]
    exact simdScalarMul_covers hb0c
  have hsxl : sx.res.len = len := by
    show b0.len = len
    exact hb0.lenEq
  have hsyl : sy.res.len = len := by
    show b0.len = len
    exact hb0.lenEq
  obtain ⟨chainshape, chainlane⟩ := periodChain_lane hone hc rest ⟨n, n + 1⟩ g
    sx.res sy.res sy.next hg hgenval hshapes hsxc hsxl hsyc hsyl htailh
  refine ⟨chainshape, fun j hj => ?_⟩
  obtain ⟨c1, c2⟩ := chainlane j hj
  have hsxlane : SimdReg.lane ρ sx.res j = g.x * SimdReg.lane ρ b0 j :=
    simdScalarMul_lane hb0c hcx hsxh j (by rw [hb0.lenEq]; exact hj)
  have hsylane : SimdReg.lane ρ sy.res j = g.y * SimdReg.lane ρ b0 j :=
    simdScalarMul_lane hb0c hcy hsyh j (by rw [hb0.lenEq]; exact hj)
  constructor
  · show SimdReg.lane ρ (periodChain one rest ⟨n, n + 1⟩ sx.res sy.res
      sy.next).res.1 j = _
    rw [c1, hsxlane, List.map_cons, bitCombFull_cons]
  · show SimdReg.lane ρ (periodChain one rest ⟨n, n + 1⟩ sx.res sy.res
      sy.next).res.2 j = _
    rw [c2, hsylane, List.map_cons, bitCombFull_cons]

/-- One-hot size bits give the `2^k`-fold generator: the period shift
of a component of log size `k`. -/
theorem periodGensG_lane_pow {ρ : ℕ → QM31} {one count len : ℕ}
    (hone : ρ one = 1) (hc : len ≤ 4 * count)
    {g : PointF} (hg : OnCircle g) {b0 : SimdReg} {rest : List SimdReg}
    {n : ℕ} (hb0 : BitShape b0 len count)
    (hshapes : ∀ b ∈ rest, BitShape b len count)
    (h : AllHold ρ (periodGensG one g (b0 :: rest) n).ops)
    {j k m : ℕ} (hj : j < len)
    (hbits : (b0 :: rest).map (fun bb => SimdReg.lane ρ bb j)
      = List.replicate k 0 ++ 1 :: List.replicate m 0) :
    SimdReg.lane ρ (periodGensG one g (b0 :: rest) n).res.1 j
        = (g.repeatedDouble k).x ∧
    SimdReg.lane ρ (periodGensG one g (b0 :: rest) n).res.2 j
        = (g.repeatedDouble k).y := by
  obtain ⟨-, hlane⟩ := periodGensG_lane hone hc hg hb0 hshapes h
  obtain ⟨h1, h2⟩ := hlane j hj
  constructor
  · rw [h1, hbits, bitCombFull_onehot]
  · rw [h2, hbits, bitCombFull_onehot]

/-! ### Unpacking the generator lanes into points -/

/-- `simd.unpack` from lane `i`, `k` lanes: one `unpackIdx` per lane in
order (`builder/simd.zig` `unpack`). -/
noncomputable def unpackFrom (s : SimdReg) : ℕ → ℕ → ℕ → Out (List ℕ)
  | 0, _, n => ⟨[], [], n⟩
  | k + 1, i, n =>
    let u := unpackIdx (s.data.getD (i / 4) 0) (i % 4) n
    let rest := unpackFrom s k (i + 1) u.next
    ⟨u.ops ++ rest.ops, u.res :: rest.res, rest.next⟩

/-- Each unpacked register holds the base-field lift of its lane. -/
theorem unpackFrom_sound {ρ : ℕ → QM31} {s : SimdReg} :
    ∀ (k i n : ℕ), AllHold ρ (unpackFrom s k i n).ops →
      (unpackFrom s k i n).res.length = k ∧
      ∀ l, l < k →
        ρ ((unpackFrom s k i n).res.getD l 0)
          = QM31.fromBase (SimdReg.lane ρ s (i + l))
  | 0, _, _ => fun _ => ⟨rfl, fun _ hl => absurd hl (by omega)⟩
  | k + 1, i, n => by
    intro h
    rw [show (unpackFrom s (k + 1) i n).ops =
      (unpackIdx (s.data.getD (i / 4) 0) (i % 4) n).ops ++
        (unpackFrom s k (i + 1)
          (unpackIdx (s.data.getD (i / 4) 0) (i % 4) n).next).ops from rfl,
      allHold_append] at h
    obtain ⟨hu, hrest⟩ := h
    obtain ⟨ihlen, ihval⟩ := unpackFrom_sound k (i + 1) _ hrest
    refine ⟨?_, fun l hl => ?_⟩
    · show (unpackFrom s k (i + 1) _).res.length + 1 = k + 1
      rw [ihlen]
    cases l with
    | zero =>
      show ρ (unpackIdx (s.data.getD (i / 4) 0) (i % 4) n).res = _
      rw [unpackIdx_sound (Nat.mod_lt _ (by norm_num)) hu]
      rfl
    | succ l =>
      show ρ ((unpackFrom s k (i + 1) _).res.getD l 0) = _
      rw [show i + (l + 1) = i + 1 + l from by omega]
      exact ihval l (by omega)

/-- Pair the unpacked `x` and `y` registers into point registers. -/
def zipPoints : List ℕ → List ℕ → List PointReg
  | x :: xs, y :: ys => ⟨x, y⟩ :: zipPoints xs ys
  | _, _ => []

theorem zipPoints_length : ∀ (xs ys : List ℕ),
    (zipPoints xs ys).length = min xs.length ys.length
  | [], _ => by simp [zipPoints]
  | _ :: _, [] => by simp [zipPoints]
  | _ :: xs, _ :: ys => by
    show (zipPoints xs ys).length + 1 = _
    rw [zipPoints_length xs ys]
    simp only [List.length_cons]
    omega

theorem zipPoints_getD : ∀ (xs ys : List ℕ) (l : ℕ), l < xs.length →
    l < ys.length →
    (zipPoints xs ys).getD l ⟨0, 0⟩ = ⟨xs.getD l 0, ys.getD l 0⟩
  | [], _, _, hx, _ => absurd hx (by simp)
  | _ :: _, [], _, _, hy => absurd hy (by simp)
  | _ :: _, _ :: _, 0, _, _ => rfl
  | _ :: xs, _ :: ys, l + 1, hx, hy => by
    show (zipPoints xs ys).getD l ⟨0, 0⟩ = _
    exact zipPoints_getD xs ys l (by simpa using hx) (by simpa using hy)

/-- `period_generators`, complete: the chain, then both coordinate
vectors unpacked lane by lane into per-component point registers. -/
noncomputable def periodGeneratorsG (one : ℕ) (g : PointF)
    (bits : List SimdReg) (n : ℕ) : Out (List PointReg) :=
  let pg := periodGensG one g bits n
  let xs := unpackFrom pg.res.1 pg.res.1.len 0 pg.next
  let ys := unpackFrom pg.res.2 pg.res.2.len 0 xs.next
  ⟨pg.ops ++ xs.ops ++ ys.ops, zipPoints xs.res ys.res, ys.next⟩

/-- Each generator point register holds the embedded bit-weighted
coordinate sum of its component's size bits. -/
theorem periodGeneratorsG_sound {ρ : ℕ → QM31} {one count len : ℕ}
    (hone : ρ one = 1) (hc : len ≤ 4 * count)
    {g : PointF} (hg : OnCircle g) {b0 : SimdReg} {rest : List SimdReg}
    {n : ℕ} (hb0 : BitShape b0 len count)
    (hshapes : ∀ b ∈ rest, BitShape b len count)
    (h : AllHold ρ (periodGeneratorsG one g (b0 :: rest) n).ops) :
    (periodGeneratorsG one g (b0 :: rest) n).res.length = len ∧
    ∀ l, l < len →
      ((periodGeneratorsG one g (b0 :: rest) n).res.getD l ⟨0, 0⟩).val ρ
        = ⟨QM31.fromBase
             (bitCombFull g ((b0 :: rest).map fun bb => SimdReg.lane ρ bb l)).1,
           QM31.fromBase
             (bitCombFull g ((b0 :: rest).map fun bb => SimdReg.lane ρ bb l)).2⟩ := by
  set pg := periodGensG one g (b0 :: rest) n with hpgdef
  set xs := unpackFrom pg.res.1 pg.res.1.len 0 pg.next with hxsdef
  set ys := unpackFrom pg.res.2 pg.res.2.len 0 xs.next with hysdef
  replace h : AllHold ρ (pg.ops ++ xs.ops ++ ys.ops) := h
  rw [allHold_append, allHold_append] at h
  obtain ⟨⟨hpg, hxs⟩, hys⟩ := h
  obtain ⟨⟨-, hxl, -, hyl⟩, hlane⟩ := periodGensG_lane hone hc hg hb0 hshapes hpg
  obtain ⟨hxslen, hxsval⟩ := unpackFrom_sound pg.res.1.len 0 pg.next hxs
  obtain ⟨hyslen, hysval⟩ := unpackFrom_sound pg.res.2.len 0 xs.next hys
  have hxslen' : xs.res.length = len := by rw [hxsdef, hxslen, hxl]
  have hyslen' : ys.res.length = len := by rw [hysdef, hyslen, hyl]
  refine ⟨?_, fun l hl => ?_⟩
  · show (zipPoints xs.res ys.res).length = len
    rw [zipPoints_length, hxslen', hyslen', min_self]
  · obtain ⟨g1, g2⟩ := hlane l hl
    have hgd : (zipPoints xs.res ys.res).getD l ⟨0, 0⟩
        = ⟨xs.res.getD l 0, ys.res.getD l 0⟩ :=
      zipPoints_getD xs.res ys.res l (by omega) (by omega)
    show ((zipPoints xs.res ys.res).getD l ⟨0, 0⟩).val ρ = _
    rw [hgd]
    refine CPoint.ext' ?_ ?_
    · show ρ (xs.res.getD l 0) = _
      rw [hxsdef]
      rw [hxsval l (by rw [hxl]; exact hl), Nat.zero_add, g1]
    · show ρ (ys.res.getD l 0) = _
      rw [hysdef]
      rw [hysval l (by rw [hyl]; exact hl), Nat.zero_add, g2]

/-! ### The periodicity points and the previous-row point -/

/-- The `collect_oods_responses` periodicity loop: `addPoints` of the
OODS point with each component's period generator, in order. -/
def addPointsList (oods : PointReg) : List PointReg → ℕ → Out (List PointReg)
  | [], n => ⟨[], [], n⟩
  | p :: rest, n =>
    let a := addPoints oods p n
    let r := addPointsList oods rest a.next
    ⟨a.ops ++ r.ops, a.res :: r.res, r.next⟩

theorem addPointsList_sound {ρ : ℕ → QM31} {oods : PointReg} :
    ∀ (gens : List PointReg) (n : ℕ),
      AllHold ρ (addPointsList oods gens n).ops →
      (addPointsList oods gens n).res.length = gens.length ∧
      ∀ l, l < gens.length →
        ((addPointsList oods gens n).res.getD l ⟨0, 0⟩).val ρ
          = CPoint.add (oods.val ρ) ((gens.getD l ⟨0, 0⟩).val ρ)
  | [], _ => fun _ => ⟨rfl, fun _ hl => absurd hl (by simp)⟩
  | p :: rest, n => by
    intro h
    rw [show (addPointsList oods (p :: rest) n).ops =
      (addPoints oods p n).ops ++
        (addPointsList oods rest (addPoints oods p n).next).ops from rfl,
      allHold_append] at h
    obtain ⟨ha, hrest⟩ := h
    obtain ⟨ihlen, ihval⟩ := addPointsList_sound rest _ hrest
    refine ⟨?_, fun l hl => ?_⟩
    · show (addPointsList oods rest _).res.length + 1 = rest.length + 1
      rw [ihlen]
    cases l with
    | zero =>
      show ((addPoints oods p n).res).val ρ = _
      exact addPoints_sound ha
    | succ l =>
      show ((addPointsList oods rest _).res.getD l ⟨0, 0⟩).val ρ = _
      exact ihval l (by simpa using hl)

/-- The previous-row point: the conjugated trace generator as
constants, added to the OODS point
(`oods_point_at_prev_row = add_points(oods, (gen.x, −gen.y))`). -/
def prevPointG (g : PointF) (oods : PointReg) (n : ℕ) : Out PointReg :=
  let a := addPoints oods ⟨n, n + 1⟩ (n + 2)
  ⟨.const n (QM31.fromBase g.x) :: .const (n + 1) (QM31.fromBase (-g.y)) ::
    a.ops, a.res, a.next⟩

/-- The previous-row register holds `oods + conj(gen)` — on the circle,
`oods − gen`, the spec's previous-row sample point. -/
theorem prevPointG_sound {ρ : ℕ → QM31} {g : PointF} {oods : PointReg}
    {n : ℕ} (h : AllHold ρ (prevPointG g oods n).ops) :
    ((prevPointG g oods n).res).val ρ
      = CPoint.add (oods.val ρ) (PointF.intoQ g.conjugate) := by
  rw [show (prevPointG g oods n).ops =
    .const n (QM31.fromBase g.x) :: .const (n + 1) (QM31.fromBase (-g.y)) ::
      (addPoints oods ⟨n, n + 1⟩ (n + 2)).ops from rfl,
    allHold_cons, allHold_cons] at h
  obtain ⟨hcx, hcy, ha⟩ := h
  simp only [Holds] at hcx hcy
  have hgenval : (PointReg.mk n (n + 1)).val ρ = PointF.intoQ g.conjugate := by
    refine CPoint.ext' hcx ?_
    show ρ (n + 1) = QM31.fromBase (CPoint.conjugate g).y
    rw [hcy]
    rfl
  show ((addPoints oods ⟨n, n + 1⟩ (n + 2)).res).val ρ = _
  rw [addPoints_sound ha, hgenval]

/-- With one-hot size bits, each generator point register holds the
embedded `2^k`-fold trace generator. -/
theorem periodGeneratorsG_getD_pow {ρ : ℕ → QM31} {one count len : ℕ}
    (hone : ρ one = 1) (hc : len ≤ 4 * count)
    {g : PointF} (hg : OnCircle g) {b0 : SimdReg} {rest : List SimdReg}
    {n : ℕ} (hb0 : BitShape b0 len count)
    (hshapes : ∀ b ∈ rest, BitShape b len count)
    (h : AllHold ρ (periodGeneratorsG one g (b0 :: rest) n).ops)
    {l k m : ℕ} (hl : l < len)
    (hbits : (b0 :: rest).map (fun bb => SimdReg.lane ρ bb l)
      = List.replicate k 0 ++ 1 :: List.replicate m 0) :
    ((periodGeneratorsG one g (b0 :: rest) n).res.getD l ⟨0, 0⟩).val ρ
      = PointF.intoQ (g.repeatedDouble k) := by
  obtain ⟨-, hval⟩ := periodGeneratorsG_sound hone hc hg hb0 hshapes h
  rw [hval l hl, hbits, bitCombFull_onehot]
  rfl

/-- **The blowup extension absorbs the lifting offset**: the spec's
periodicity shift at a committed (blowup-extended) column log,
`canonicStep(l+1)·2^(k+1)`, is the circuit's `traceGen(l)·2^k`
(`generatorPoint(log) = subgroupGen(log).toPoint = canonicStep log`). -/
theorem canonicStep_double_shift {l : ℕ} (hl1 : 1 ≤ l) (hl : l ≤ 30) (k : ℕ) :
    (canonicStep (l + 1)).repeatedDouble (k + 1)
      = (canonicStep l).repeatedDouble k := by
  unfold canonicStep PIdx.toPoint PIdx.reduce subgroupGen M31_CIRCLE_LOG_ORDER
    circleOrder
  have h1 : (2 : ℕ) ^ (31 - (l + 1)) % 2 ^ 31 = 2 ^ (31 - (l + 1)) :=
    Nat.mod_eq_of_lt (Nat.pow_lt_pow_right (by norm_num) (by omega))
  have h2 : (2 : ℕ) ^ (31 - l) % 2 ^ 31 = 2 ^ (31 - l) :=
    Nat.mod_eq_of_lt (Nat.pow_lt_pow_right (by norm_num) (by omega))
  rw [h1, h2, CPoint.repeatedDouble_eq_smul, CPoint.repeatedDouble_eq_smul,
    ← pow_add, ← pow_add, show 31 - (l + 1) + (k + 1) = 31 - l + k from by omega]

/- Next (part 3): the response-list assembly — tying the periodicity,
previous-row and OODS point registers plus the proof's sampled-value
registers to the spec's `treesPairs` order (`collect_oods_responses`'
response list), and the one-hot discharge of the size-bit hypotheses
from `extractBits31_sound`. -/

end StwoVerifier.Gadgets
