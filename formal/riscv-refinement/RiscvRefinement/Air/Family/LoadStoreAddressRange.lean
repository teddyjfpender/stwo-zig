import RiscvRefinement.Field.M31

/-!
Arithmetic for the current load/store one-GiB address profile. These lemmas
interpret the actual M31 subtraction/multiplication used by the low-20/high-8
lookups and doubled base-high lookup. They do not yet establish that the
exported circuit bridge supplies those premises; that migration is separate.
-/

namespace RiscvRefinement.Air.Family.LoadStoreAddressRange

-- The production high-byte lookup evaluates (quarter - low20) * 2^11 in M31.
-- Canonical representatives below express subtraction without Nat truncation.
theorem quarter_decomposition (quarter low high : Nat)
    (quarterCanonical : quarter < 2147483647)
    (lowRange : low < 1048576)
    (highRange : high < 256)
    (lookup : high = ((quarter + 2147483647 - low) * 2048) % 2147483647) :
    quarter = low + 1048576 * high := by
  omega

theorem doubled_base_high (high : Nat)
    (byteRange : high < 256)
    (lookup : (2 * high) % 2147483647 < 128) :
    high < 64 := by
  have small : 2 * high < 2147483647 := by omega
  rw [Nat.mod_eq_of_lt small] at lookup
  omega

open RiscvRefinement

theorem field_quarter_decomposition (quarter low : M31)
    (lowRange : low.val < 1048576)
    (highRange : ((quarter - low) * M31.reduce 2048).val < 256) :
    quarter.val = low.val + 1048576 * ((quarter - low) * M31.reduce 2048).val := by
  apply quarter_decomposition quarter.val low.val _ quarter.isLt lowRange highRange
  change (((quarter.val + M31.modulus - low.val) % M31.modulus) *
    (2048 % M31.modulus)) % M31.modulus = _
  rw [← Nat.mul_mod]
  rfl

theorem field_doubled_base_high (high : M31)
    (byteRange : high.val < 256)
    (lookup : (M31.reduce 2 * high).val < 128) :
    high.val < 64 := by
  apply doubled_base_high high.val byteRange
  exact lookup

/-- The two fixed-table checks bound the committed word address to 28 bits. -/
theorem quarter_lt_two_pow_28 (quarter low : M31)
    (lowRange : low.val < 1048576)
    (highRange : ((quarter - low) * M31.reduce 2048).val < 256) :
    quarter.val < 268435456 := by
  have decomposition := field_quarter_decomposition quarter low lowRange highRange
  omega

/-- The largest admitted word address is represented without field wrap. -/
theorem largest_word_address :
    ((M31.reduce 268435455 - M31.reduce 1048575) * M31.reduce 2048).val = 255 := by
  decide

/-- The high-byte lookup rejects the first word outside the one-GiB profile. -/
theorem first_out_of_range_word :
    ¬ ((M31.reduce 268435456 - M31.reduce 0) * M31.reduce 2048).val < 256 := by
  decide

/-- Keeping only the high-byte lookup would admit an oversized low limb. -/
theorem low_lookup_is_necessary :
    ((M31.reduce 268435456 - M31.reduce 268435456) * M31.reduce 2048).val < 256 ∧
    ¬ (M31.reduce 268435456).val < 268435456 := by
  decide

/-- Doubling is load-bearing: the former seven-bit check admitted this byte. -/
theorem doubled_base_lookup_is_necessary :
    (M31.reduce 64).val < 128 ∧
    ¬ (M31.reduce 2 * M31.reduce 64).val < 128 := by
  decide

/-- Byte decomposition plus the doubled lookup bounds the whole base register. -/
theorem base_lt_two_pow_30 (b0 b1 b2 : Nat) (b3 : M31)
    (range0 : b0 < 256) (range1 : b1 < 256) (range2 : b2 < 256)
    (range3 : b3.val < 256)
    (lookup : (M31.reduce 2 * b3).val < 128) :
    b0 + 256 * b1 + 65536 * b2 + 16777216 * b3.val < 1073741824 := by
  have high := field_doubled_base_high b3 range3 lookup
  omega

/-- Every nonnegative signed-12-bit displacement stays below the field modulus. -/
theorem base_displacement_no_wrap (base displacement : Nat)
    (baseRange : base < 1073741824) (displacementRange : displacement < 2048) :
    base + displacement < M31.modulus := by
  rw [M31.modulus_eq]
  omega

end RiscvRefinement.Air.Family.LoadStoreAddressRange
