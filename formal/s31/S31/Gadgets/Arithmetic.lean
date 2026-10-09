import S31.Gadgets.Packing

namespace S31.Gadgets.Arithmetic
open Words Radix Signed

/-- The reversed subtraction used for ≤ (cin=0) and < (cin=1). -/
theorem comparison_sound_complete (base : Nat) (hbase : base = 256 ∨ base = 65536)
    (xs ys : List Nat) (hx : Bounded base xs) (hy : Bounded base ys)
    (hxy : xs.length = ys.length) (cin : Nat) (hc : cin ≤ 1) :
    (∃ rs, SubChain base ys xs rs cin 0) ↔ decode base xs + cin ≤ decode base ys := by
  constructor
  · rintro ⟨rs, h⟩; exact (sub_chain_comparison hbase h).mp rfl
  · intro hle
    have hb : 1 < base := by rcases hbase with rfl | rfl <;> decide
    obtain ⟨rs, cout, h⟩ := sub_chain_complete base hb ys xs hy hx hxy.symm cin hc
    have he := (sub_chain_comparison hbase h).mpr hle
    exact ⟨rs, he ▸ h⟩

theorem twos_emod (half value : Nat) (_hh : 0 < half) (hv : value < 2 * half) :
    twos half value % (2 * half : Nat) = (value : Int) := by
  unfold twos
  split
  · have heq : (value : Int) - 2 * half = (value : Int) - (2 * half : Nat) * 1 := by simp
    rw [heq, Int.sub_mul_emod_self_left]
    exact Int.emod_eq_of_lt (by omega) (by exact_mod_cast hv)
  · exact Int.emod_eq_of_lt (by omega) (by exact_mod_cast hv)

def SignedAddAccepts (base half : Nat) (xs ys rs : List Nat) : Prop := ∃ carry,
  AddChain base xs ys rs 0 carry ∧
    addOverflow (encodeBool (decode base xs ≥ half)) (encodeBool (decode base ys ≥ half))
      (encodeBool (decode base rs ≥ half))

def SignedSubAccepts (base half : Nat) (xs ys rs : List Nat) : Prop := ∃ borrow,
  SubChain base xs ys rs 0 borrow ∧
    subOverflow (encodeBool (decode base xs ≥ half)) (encodeBool (decode base ys ≥ half))
      (encodeBool (decode base rs ≥ half))

theorem signed_add_sound_complete (base half : Nat) (hbase : base = 256 ∨ base = 65536)
    (hh : 0 < half) (xs ys rs : List Nat) (hx : Bounded base xs) (hy : Bounded base ys)
    (hr : Bounded base rs) (hxy : xs.length = ys.length) (hxr : xs.length = rs.length)
    (hlayout : base^xs.length = 2 * half) :
    SignedAddAccepts base half xs ys rs ↔
      twos half (decode base rs) = twos half (decode base xs) + twos half (decode base ys) := by
  have hb : 0 < base := by rcases hbase with rfl | rfl <;> decide
  have ha : decode base xs < 2 * half := hlayout ▸ decode_lt base hb xs hx
  have hbb : decode base ys < 2 * half := hlayout ▸ (hxy ▸ decode_lt base hb ys hy)
  have hrr : decode base rs < 2 * half := hlayout ▸ (hxr ▸ decode_lt base hb rs hr)
  constructor
  · rintro ⟨carry, hchain, hover⟩
    have heq := add_chain_equation hbase hchain
    simp only [Nat.add_zero, hlayout] at heq
    exact (checked_add_interpretation half _ _ _ carry hh ha hbb hrr
      (add_chain_bounded hchain).2 heq).mp hover
  · intro heq
    have hmod := congrArg (fun z : Int => z % (2 * half : Nat)) heq
    dsimp only at hmod
    rw [twos_emod half _ hh hrr, Int.add_emod,
      twos_emod half _ hh ha, twos_emod half _ hh hbb] at hmod
    have hwrap : decode base rs = (decode base xs + decode base ys) % base^xs.length := by
      rw [hlayout]
      exact_mod_cast hmod
    obtain ⟨carry, hchain⟩ := (add_chain_wrapping_sound_complete base hbase xs ys rs
      hx hy hr hxy hxr).mpr hwrap
    have hcarry := add_chain_equation hbase hchain
    simp only [Nat.add_zero, hlayout] at hcarry
    exact ⟨carry, hchain, (checked_add_interpretation half _ _ _ carry hh ha hbb hrr
      (add_chain_bounded hchain).2 hcarry).mpr heq⟩

theorem signed_sub_sound_complete (base half : Nat) (hbase : base = 256 ∨ base = 65536)
    (hh : 0 < half) (xs ys rs : List Nat) (hx : Bounded base xs) (hy : Bounded base ys)
    (hr : Bounded base rs) (hxy : xs.length = ys.length) (hxr : xs.length = rs.length)
    (hlayout : base^xs.length = 2 * half) :
    SignedSubAccepts base half xs ys rs ↔
      twos half (decode base rs) = twos half (decode base xs) - twos half (decode base ys) := by
  have hb : 0 < base := by rcases hbase with rfl | rfl <;> decide
  have ha : decode base xs < 2 * half := hlayout ▸ decode_lt base hb xs hx
  have hbb : decode base ys < 2 * half := hlayout ▸ (hxy ▸ decode_lt base hb ys hy)
  have hrr : decode base rs < 2 * half := hlayout ▸ (hxr ▸ decode_lt base hb rs hr)
  constructor
  · rintro ⟨borrow, hchain, hover⟩
    have heq := sub_chain_equation hbase hchain
    simp only [Nat.add_zero, hlayout] at heq
    exact (checked_sub_interpretation half _ _ _ borrow hh ha hbb hrr
      (sub_chain_bounded hchain).2 heq).mp hover
  · intro heq
    have hmod := congrArg (fun z : Int => z % (2 * half : Nat)) heq
    dsimp only at hmod
    rw [twos_emod half _ hh hrr, Int.sub_emod,
      twos_emod half _ hh ha, twos_emod half _ hh hbb] at hmod
    have hwrap : (decode base rs : Int) =
        ((decode base xs : Int) - decode base ys) % (base^xs.length : Nat) := by
      simpa only [hlayout] using hmod
    obtain ⟨borrow, hchain⟩ := (sub_chain_wrapping_sound_complete base hbase xs ys rs
      hx hy hr hxy hxr).mpr hwrap
    have hborrow := sub_chain_equation hbase hchain
    simp only [Nat.add_zero, hlayout] at hborrow
    exact ⟨borrow, hchain, (checked_sub_interpretation half _ _ _ borrow hh ha hbb hrr
      (sub_chain_bounded hchain).2 hborrow).mpr heq⟩

end S31.Gadgets.Arithmetic
