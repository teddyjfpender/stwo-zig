/-
Security accounting (security.zig) as a union bound, with an exact checker.

security.zig sums, per proof configuration, a list of error terms: each term
is `count` rounds whose bad-challenge probability is at most
`2^(log2_err - pow)`, and `sum_with = -log2 (sum_i count_i 2^(log2_err_i - pow_i))`.

Proven here (zero-dependency):
* `union_le` : on a finite, uniformly sampled space, the number of samples in
  the union of a list of bad events is at most the sum of the events' counts:
  Pr[some round is bad] <= sum of the per-round bounds. This is the
  composition rule the calculator's `sum_*` readings implement.
* `dyadic_union_sound` : if every event `i` has probability at most
  `mant_i / 2^S` (an exact dyadic upper bound of term i) and
  `sum_i mant_i * 2^K <= 2^S`, then Pr[union] <= 2^-K. The premise is a
  Boolean check `dyadicOK` on natural numbers, decided by the kernel for a
  concrete term list (see `TensorFrontend/Data/*.lean`).

Not proven here: the per-term bounds themselves (sumcheck, LogUp: see
Sumcheck.lean / LogUp.lean; PCS proximity, Johnson list sizes, OOD,
lambda/query terms: not formalised), the proof-of-work discount
(`2^-pow` per grinding round, a random-oracle model claim), the Fiat-Shamir
compilation (`compiledLevel`), and the f64 evaluation of each term's
`log2_err` that produces the exported mantissas.
-/
namespace TensorFrontend.Security

/-- Count of samples in the union of `Es`. -/
def unionCount {α : Type} (Ω : List α) (Es : List (α → Bool)) : Nat :=
  Ω.countP (fun ω => Es.any (fun E => E ω))

theorem countP_or_le {α : Type} (l : List α) (p q : α → Bool) :
    l.countP (fun x => p x || q x) ≤ l.countP p + l.countP q := by
  induction l with
  | nil => simp
  | cons y l ih =>
    simp only [List.countP_cons]
    cases p y <;> cases q y <;> simp <;> omega

/-- **Union bound** (counting form). -/
theorem union_le {α : Type} (Ω : List α) (Es : List (α → Bool)) :
    unionCount Ω Es ≤ (Es.map (fun E => Ω.countP E)).sum := by
  induction Es with
  | nil => simp [unionCount]
  | cons E Es ih =>
    unfold unionCount at ih ⊢
    simp only [List.any_cons, List.map_cons, List.sum_cons]
    have := countP_or_le Ω E (fun ω => Es.any (fun E => E ω))
    omega

/-- The exact checker: `sum_i mant_i * 2^K <= 2^S`. -/
def dyadicOK (mants : List Nat) (S K : Nat) : Bool :=
  decide ((mants.sum) * 2 ^ K ≤ 2 ^ S)

theorem sum_mul_le {α : Type} (Es : List (α → Bool)) (mants : List Nat) (Ω : List α) (S : Nat)
    (hlen : Es.length = mants.length)
    (hterm : ∀ i (h1 : i < Es.length) (h2 : i < mants.length),
      Ω.countP (Es.get ⟨i, h1⟩) * 2 ^ S ≤ mants.get ⟨i, h2⟩ * Ω.length) :
    (Es.map (fun E => Ω.countP E)).sum * 2 ^ S ≤ mants.sum * Ω.length := by
  induction Es generalizing mants with
  | nil => simp
  | cons E Es ih =>
    cases mants with
    | nil => simp at hlen
    | cons m ms =>
      simp only [List.map_cons, List.sum_cons, Nat.add_mul]
      have h0 := hterm 0 (by simp) (by simp)
      simp only [List.get_eq_getElem, List.getElem_cons_zero] at h0
      have h1 := ih ms (by simpa using hlen) (fun i a b => by
        have := hterm (i + 1) (by simpa using a) (by simpa using b)
        simpa using this)
      omega

/-- **Dyadic union bound.** Every round's bad event `E_i` has probability
`<= mant_i / 2^S` and the checker accepts `(mants, S, K)`: then the
probability that any round is bad is `<= 2^-K`. -/
theorem dyadic_union_sound {α : Type} (Ω : List α) (Es : List (α → Bool)) (mants : List Nat)
    (S K : Nat) (hlen : Es.length = mants.length)
    (hterm : ∀ i (h1 : i < Es.length) (h2 : i < mants.length),
      Ω.countP (Es.get ⟨i, h1⟩) * 2 ^ S ≤ mants.get ⟨i, h2⟩ * Ω.length)
    (hok : dyadicOK mants S K = true) :
    unionCount Ω Es * 2 ^ K ≤ Ω.length := by
  have hc := of_decide_eq_true hok
  have hu := union_le Ω Es
  have hs := sum_mul_le Es mants Ω S hlen hterm
  have hpos : 0 < 2 ^ S := Nat.pow_pos (by decide)
  apply Nat.le_of_mul_le_mul_right _ hpos
  calc unionCount Ω Es * 2 ^ K * 2 ^ S
      = unionCount Ω Es * 2 ^ S * 2 ^ K := by rw [Nat.mul_right_comm]
    _ ≤ (Es.map (fun E => Ω.countP E)).sum * 2 ^ S * 2 ^ K :=
        Nat.mul_le_mul_right _ (Nat.mul_le_mul_right _ hu)
    _ ≤ mants.sum * Ω.length * 2 ^ K := Nat.mul_le_mul_right _ hs
    _ = Ω.length * (mants.sum * 2 ^ K) := by rw [Nat.mul_comm (mants.sum) _, Nat.mul_assoc]
    _ ≤ Ω.length * 2 ^ S := Nat.mul_le_mul_left _ hc

/-- Largest `K <= Kmax` the checker accepts (executable). -/
def bestBits (mants : List Nat) (S Kmax : Nat) : Nat :=
  ((List.range (Kmax + 1)).filter (fun K => dyadicOK mants S K)).foldl max 0

/-- Fractional reading for display: `-log2 (sum mants / 2^S)` in floating
point (an executable cross-check against the Zig printout, not a proof). -/
def floatBits (mants : List Nat) (S : Nat) : Float :=
  Float.ofNat S - Float.log2 (Float.ofNat mants.sum)

end TensorFrontend.Security
