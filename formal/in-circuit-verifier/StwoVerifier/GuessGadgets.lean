/-
**Guessed proof wires** (`stark_verifier/proof.zig` `guess`,
`builder/wrappers.zig` `guessU32`, `builder/blake.zig` `guessHash`).

A guessed `u32` word is two `u16` limb guesses recombined as
`low + high·i`; a hash is eight such words. `guessU32G_sound`: the wire
holds `packW` of the word `low + 2¹⁶·high` — so every root and auth-path
word the circuit reads is a well-formed limb pair by its own gates.
-/
import StwoVerifier.MerkleGadgets

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates

/-- `guessU32`: low and high `u16` guesses, `i`, `high·i`, `low + high·i`. -/
def guessU32G (n : ℕ) : Out ℕ :=
  ⟨[.guessU16 n, .guessU16 (n + 1), .const (n + 2) (QM31.fromM31s 0 1 0 0),
    .mul (n + 3) (n + 1) (n + 2), .add (n + 4) n (n + 3)], n + 4, n + 5⟩

/-- The word a guessed `u32` wire carries. -/
noncomputable def guessedWord (ρ : ℕ → QM31) (n : ℕ) : Blake2s.Word :=
  BitVec.ofNat 32 ((ρ n).c0.a.val + 65536 * (ρ (n + 1)).c0.a.val)

theorem guessU32G_sound {ρ : ℕ → QM31} {n : ℕ} (h : AllHold ρ (guessU32G n).ops) :
    ρ (guessU32G n).res = packW (guessedWord ρ n) := by
  simp only [guessU32G, allHold_cons, Holds] at h
  obtain ⟨⟨hl, hl0, hl1⟩, ⟨hh, hh0, hh1⟩, hc, hm, ha, -⟩ := h
  show ρ (n + 4) = _
  have hlt : (ρ n).c0.a.val + 65536 * (ρ (n + 1)).c0.a.val < 2 ^ 32 := by omega
  unfold guessedWord packW
  rw [BitVec.toNat_ofNat, Nat.mod_eq_of_lt hlt,
    show ((ρ n).c0.a.val + 65536 * (ρ (n + 1)).c0.a.val) % 65536 = (ρ n).c0.a.val by omega,
    show ((ρ n).c0.a.val + 65536 * (ρ (n + 1)).c0.a.val) / 65536 = (ρ (n + 1)).c0.a.val by omega,
    ha, hm, hc]
  simp only [ZMod.natCast_val, ZMod.cast_id', id]
  rcases hx : ρ n with ⟨⟨a, b⟩, c⟩
  rcases hy : ρ (n + 1) with ⟨⟨a', b'⟩, c'⟩
  rw [hx] at hl0 hl1
  rw [hy] at hh0 hh1
  simp only at hl0 hl1 hh0 hh1 ⊢
  subst hl0 hl1 hh0 hh1
  refine QM31.ext' ?_ ?_ <;> (ext <;> simp [QM31.fromM31s, QM31.mul_c0, QM31.mul_c1,
    CM31.mul_a, CM31.mul_b, CM31.zero, QM31.R] <;> ring_nf)

/-- `guessHash`: eight guessed words. -/
def guessHashG (n : ℕ) : Out (List ℕ) :=
  ⟨(List.range 8).flatMap fun k => (guessU32G (n + 5 * k)).ops,
   (List.range 8).map fun k => n + 5 * k + 4, n + 40⟩

/-- The words a guessed hash carries. -/
noncomputable def guessedHash (ρ : ℕ → QM31) (n : ℕ) : List Blake2s.Word :=
  (List.range 8).map fun k => guessedWord ρ (n + 5 * k)

theorem guessHashG_sound {ρ : ℕ → QM31} {n : ℕ} (h : AllHold ρ (guessHashG n).ops) :
    RegsWords ρ (guessHashG n).res (guessedHash ρ n) ∧ (guessedHash ρ n).length = 8 := by
  refine ⟨⟨by simp [guessHashG, guessedHash], fun j hj => ?_⟩, by simp [guessedHash]⟩
  have hj8 : j < 8 := by simpa [guessHashG] using hj
  have hops : AllHold ρ (guessU32G (n + 5 * j)).ops := fun op hop =>
    h op (List.mem_flatMap.mpr ⟨j, List.mem_range.mpr hj8, hop⟩)
  have := guessU32G_sound hops
  rw [show (guessHashG n).res.getD j 0 = n + 5 * j + 4 by
      simp [guessHashG, List.getD_eq_getElem?_getD, hj8],
    show (guessedHash ρ n).getD j 0 = guessedWord ρ (n + 5 * j) by
      simp [guessedHash, List.getD_eq_getElem?_getD, hj8]]
  exact this

end StwoVerifier.Gadgets
