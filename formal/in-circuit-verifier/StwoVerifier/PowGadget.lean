/-
**The in-circuit proof of work** (`stark_verifier/channel.zig` `pow`,
stwo-zig `4afa09dbf`).

The circuit hashes `POW_PREFIX ‖ 0¹² ‖ digest ‖ n_bits` (52 bytes),
then `prefixed ‖ nonce` (40 bytes), extracts the 31 bits of the first
reduced word and pins the low `n_bits` to zero; the spec counts the
trailing zero bits of the first 16 digest bytes. Low `n_bits` bits of
the first word zero implies at least `n_bits` trailing zeros
(`go_ge_of_dvd`): either the first nonzero byte sits inside the first
word with enough zeros, or the whole word is zero and the count has
passed 32 already. The nonce wire `(lo, hi, 0, 0)` is the spec nonce
`lo + 2³²·hi` (the high coordinates are masked to zero).
-/
import StwoVerifier.ChannelGadgets
import StwoVerifier.CircleGroup

namespace StwoVerifier.Gadgets

open StwoVerifier StwoVerifier.Gates

/-! ### Trailing zeros, spec side -/

/-- The little-endian value of a byte string. -/
def valLE : List UInt8 → ℕ
  | [] => 0
  | x :: rest => x.toNat + 256 * valLE rest

theorem tzNat_ge : ∀ (fuel n k : ℕ), n ≠ 0 → 2 ^ k ∣ n → k ≤ fuel →
    k ≤ Channel.tzNat fuel n
  | 0, _, k, _, _, hk => by simp [Channel.tzNat]; omega
  | fuel + 1, n, 0, _, _, _ => Nat.zero_le _
  | fuel + 1, n, k + 1, hn, hd, hk => by
    have h2 : 2 ∣ n := (Nat.dvd_of_pow_dvd (by omega) hd)
    have hodd : ¬ (n % 2 = 1 ∨ n = 0) := by omega
    rw [Channel.tzNat, if_neg hodd]
    have hd2 : 2 ^ k ∣ n / 2 :=
      Nat.dvd_div_of_mul_dvd (by rw [← pow_succ']; exact hd)
    have := tzNat_ge fuel (n / 2) k (by omega) hd2 (by omega)
    omega

/-- At least `k` trailing zeros when the leading `A` bytes' value is a
multiple of `2^k` and spans at least `k` bits. -/
theorem go_ge_of_dvd : ∀ (A B : List UInt8) (k : ℕ), 2 ^ k ∣ valLE A →
    k ≤ 8 * A.length → k ≤ Channel.trailingZeroBits.go (A ++ B)
  | [], B, k, _, hk => by simp at hk; omega
  | x :: rest, B, k, hd, hk => by
    rw [List.cons_append, Channel.trailingZeroBits.go]
    have hx := x.toNat_lt
    by_cases hx0 : x = 0
    · rw [if_pos hx0]
      by_cases hk8 : k ≤ 8
      · omega
      · have hv : valLE (x :: rest) = 256 * valLE rest := by
          rw [valLE, hx0]; simp
        rw [hv] at hd
        have hd' : 2 ^ (k - 8) ∣ valLE rest := by
          rw [show k = 8 + (k - 8) from by omega, pow_add] at hd
          exact Nat.dvd_of_mul_dvd_mul_left (by norm_num) hd
        have := go_ge_of_dvd rest B (k - 8) hd'
          (by simp at hk; omega)
        omega
    · rw [if_neg hx0]
      have hxn : x.toNat ≠ 0 := fun h => hx0 (UInt8.toNat_inj.mp h)
      -- `2^k` divides `x + 256·rest`, so `k < 8` and `2^k ∣ x`.
      have hk8 : k < 8 := by
        by_contra hge
        push_neg at hge
        have h256 : 256 ∣ valLE (x :: rest) :=
          Nat.dvd_trans (pow_dvd_pow 2 hge) hd
        rw [valLE] at h256
        omega
      have hdx : 2 ^ k ∣ x.toNat := by
        have h1 : 2 ^ k ∣ 256 * valLE rest :=
          Dvd.dvd.mul_right (Nat.pow_dvd_pow 2 (by omega : k ≤ 8)) _
        rw [valLE] at hd
        exact (Nat.dvd_add_right h1).mp (by rw [Nat.add_comm]; exact hd)
      exact tzNat_ge 8 x.toNat k hxn hdx (by omega)

/-- The first word's low `k` bits zero give `k` trailing zero bits. -/
theorem trailingZeroBits_ge {c : Channel.Bytes} (h4 : 4 ≤ c.length)
    {k : ℕ} (hk : k ≤ 32) (hd : 2 ^ k ∣ Channel.wordAt c 0) :
    k ≤ Channel.trailingZeroBits c := by
  unfold Channel.trailingZeroBits
  rw [show (16 : ℕ) = 4 + 12 from rfl, List.take_add]
  have hval : valLE (c.take 4) = Channel.wordAt c 0 := by
    match c, h4 with
    | a :: b :: d :: e :: _, _ =>
      simp [valLE, Channel.wordAt]
      ring
  refine go_ge_of_dvd (c.take 4) _ k (by rw [hval]; exact hd) ?_
  rw [List.length_take]
  omega

/-! ### Byte helpers -/

theorem u32Le_mod32 (x : ℕ) : Channel.u32Le (x % 2 ^ 32) = Channel.u32Le x := by
  unfold Channel.u32Le
  have e : ∀ a b : ℕ, a % 256 = b % 256 → UInt8.ofNat a = UInt8.ofNat b := by
    intro a b hab
    apply UInt8.toNat_inj.mp
    show a % 256 = b % 256
    exact hab
  rw [e (x % 2 ^ 32) x (by omega), e (x % 2 ^ 32 / 2 ^ 8) (x / 2 ^ 8) (by omega),
    e (x % 2 ^ 32 / 2 ^ 16) (x / 2 ^ 16) (by omega),
    e (x % 2 ^ 32 / 2 ^ 24) (x / 2 ^ 24) (by omega)]

theorem qm31Bytes_const {c : ℕ} (hc : c < P) :
    Channel.qm31Bytes (QM31.fromM31s ((c : ℕ) : F) 0 0 0)
      = Channel.u32Le c ++ List.replicate 12 0 := by
  rw [show QM31.fromM31s ((c : ℕ) : F) 0 0 0
    = (⟨⟨((c : ℕ) : F), 0⟩, ⟨0, 0⟩⟩ : QM31) from rfl,
    qm31Bytes_mk, ZMod.val_cast_of_lt hc]
  rfl

theorem chHash_true_length (b : Channel.Bytes) :
    (Channel.chHash true b).length = 32 := by
  simp [Channel.chHash, Channel.reduceDigest, Channel.u32Le]

/-- The spec nonce a `(lo, hi, ·, ·)` wire carries. -/
def nonceNat (x : QM31) : ℕ := x.c0.a.val + 2 ^ 32 * x.c0.b.val

theorem nonce_bytes (x : QM31) (hc1 : x.c1 = CM31.zero) :
    Channel.qm31Bytes x
      = Channel.u64Le (nonceNat x) ++ List.replicate 8 0 := by
  have hx : x = ⟨⟨x.c0.a, x.c0.b⟩, ⟨0, 0⟩⟩ := by
    refine QM31.ext' rfl ?_
    rw [hc1]
    rfl
  have ha : x.c0.a.val < 2 ^ 31 :=
    lt_of_lt_of_le (ZMod.val_lt _) (by unfold P; norm_num)
  have h1 : (x.c0.a.val + 2 ^ 32 * x.c0.b.val) % 2 ^ 32 = x.c0.a.val := by
    omega
  have h2 : (x.c0.a.val + 2 ^ 32 * x.c0.b.val) / 2 ^ 32 = x.c0.b.val := by
    omega
  conv_lhs => rw [hx]
  rw [qm31Bytes_mk]
  unfold Channel.u64Le nonceNat
  rw [← u32Le_mod32 (x.c0.a.val + 2 ^ 32 * x.c0.b.val), h1, h2]
  simp [ZMod.val_zero, Channel.u32Le, List.replicate]

/-- `2^k` divides a bit sum whose low `k` bits vanish. -/
theorem natOf_dvd {b : ℕ → F} {n k : ℕ} (hz : ∀ i, i < k → b i = 0) :
    2 ^ k ∣ BitDecomp.natOf b n := by
  unfold BitDecomp.natOf
  refine Finset.dvd_sum fun i _ => ?_
  by_cases hi : i < k
  · rw [hz i hi, ZMod.val_zero, zero_mul]
    exact dvd_zero _
  · exact Dvd.dvd.mul_left (Nat.pow_dvd_pow 2 (by omega)) _

/-! ### The gadget -/

/-- `Channel::pow` (`channel.zig`): the prefix hash, the nonce mask
check, the nonce hash, the 31-bit decomposition of its first word with
the low `nBits` pinned to zero, and the digest update. -/
noncomputable def powG (zero one low high nonce nBits n : ℕ) : Out (ℕ × ℕ) :=
  let pre := blake2sM31G [n, low, high, n + 1] 52 (n + 2)
  let m := pre.next
  let res := blake2sM31G [pre.res.1, pre.res.2, nonce] 40 (m + 2)
  let fw := res.next
  let eb := extractBits31 zero ⟨[fw], 1⟩ (fw + 1)
  let upd := blake2sM31G [low, high, nonce] 40 eb.next
  ⟨.const n (QM31.fromM31s ((Channel.POW_PREFIX : ℕ) : F) 0 0 0) ::
    .const (n + 1) (QM31.fromM31s ((nBits : ℕ) : F) 0 0 0) ::
    (pre.ops ++ [.const m (QM31.fromM31s 0 0 1 1), .pmul (m + 1) nonce m,
      .eq (m + 1) zero] ++ res.ops ++ [.pmul fw res.res.1 one] ++ eb.ops
      ++ ((List.range nBits).map fun i =>
          Op.eq ((eb.res.getD i dummySimd).data.getD 0 0) zero)
      ++ upd.ops),
   upd.res, upd.next⟩

set_option maxHeartbeats 4000000 in
/-- **The in-circuit proof of work is sound**: every satisfying
assignment carries a nonce wire whose spec nonce passes
`verifyPowNonce`, and the new digest wires are the spec's `mixU64`. -/
theorem powG_sound {ρ : ℕ → QM31} {zero one low high nonce nBits n : ℕ}
    {s : Channel.St}
    (hzero : ρ zero = 0) (hone : ρ one = QM31.one)
    (hd : ChDigest ρ low high s.digest) (hdlen : s.digest.length = 32)
    (hbits : nBits ≤ 30)
    (h : AllHold ρ (powG zero one low high nonce nBits n).ops) :
    Channel.verifyPowNonce true s nBits (nonceNat (ρ nonce)) = true ∧
    ChDigest ρ (powG zero one low high nonce nBits n).res.1
      (powG zero one low high nonce nBits n).res.2
      (Channel.mixU64 true s (nonceNat (ρ nonce))).digest := by
  set pre := blake2sM31G [n, low, high, n + 1] 52 (n + 2) with hpre
  set m := pre.next with hm
  set res := blake2sM31G [pre.res.1, pre.res.2, nonce] 40 (m + 2) with hres
  set fw := res.next with hfw
  set eb := extractBits31 zero ⟨[fw], 1⟩ (fw + 1) with heb
  set upd := blake2sM31G [low, high, nonce] 40 eb.next with hupd
  replace h : AllHold ρ
      (.const n (QM31.fromM31s ((Channel.POW_PREFIX : ℕ) : F) 0 0 0) ::
        .const (n + 1) (QM31.fromM31s ((nBits : ℕ) : F) 0 0 0) ::
        (pre.ops ++ [.const m (QM31.fromM31s 0 0 1 1), .pmul (m + 1) nonce m,
          .eq (m + 1) zero] ++ res.ops ++ [.pmul fw res.res.1 one] ++ eb.ops
          ++ ((List.range nBits).map fun i =>
              Op.eq ((eb.res.getD i dummySimd).data.getD 0 0) zero)
          ++ upd.ops)) := h
  rw [allHold_cons, allHold_cons] at h
  obtain ⟨hcp, hcb, h⟩ := h
  simp only [allHold_append] at h
  obtain ⟨⟨⟨⟨⟨⟨hpreh, hmask⟩, hresh⟩, hfwh⟩, hebh⟩, heqs⟩, huph⟩ := h
  simp only [Holds] at hcp hcb
  -- The prefix hash.
  have hPP : Channel.POW_PREFIX < P := by unfold Channel.POW_PREFIX P; norm_num
  have hNB : nBits < P := by unfold P; omega
  set Bpre := Channel.u32Le Channel.POW_PREFIX ++ List.replicate 12 0
    ++ s.digest ++ Channel.u32Le nBits with hBpre
  have hBprelen : Bpre.length = 52 := by
    rw [hBpre]
    simp [hdlen, Channel.u32Le]
  obtain ⟨hp1, hp2⟩ := blake2sM31G_sound (felts := [n, low, high, n + 1])
    (n := n + 2)
    (xs := [ρ n, ρ low, ρ high, ρ (n + 1)]) (bytes := Bpre) rfl
    (fun i hi => by
      match i, hi with
      | 0, _ => rfl
      | 1, _ => rfl
      | 2, _ => rfl
      | 3, _ => rfl)
    (by
      rw [hBprelen]
      show (Channel.qm31Bytes (ρ n) ++ (Channel.qm31Bytes (ρ low)
        ++ (Channel.qm31Bytes (ρ high) ++ (Channel.qm31Bytes (ρ (n + 1))
          ++ [])))) = _
      rw [hcp, hcb, qm31Bytes_const hPP, qm31Bytes_const hNB, List.append_nil,
        ← List.append_assoc (Channel.qm31Bytes (ρ low)), hd, hBpre]
      simp [List.append_assoc])
    (by rw [hBprelen]; rfl) (by rw [hBprelen]; exact hpreh)
  rw [hBprelen, ← hpre] at hp1 hp2
  have hpreD : ChDigest ρ pre.res.1 pre.res.2 (Channel.powPrefix true s nBits) := by
    show Channel.qm31Bytes (ρ pre.res.1) ++ Channel.qm31Bytes (ρ pre.res.2) = _
    rw [hp1, hp2, digestFelts_bytes]
    rfl
  -- The nonce mask.
  rw [allHold_cons, allHold_cons, allHold_cons] at hmask
  obtain ⟨hmc, hmp, hme, -⟩ := hmask
  simp only [Holds] at hmc hmp hme
  have hc1 : (ρ nonce).c1 = CM31.zero := by
    rw [hme, hzero, hmc] at hmp
    have ha := congrArg (fun q : QM31 => q.c1.a) hmp
    have hb := congrArg (fun q : QM31 => q.c1.b) hmp
    simp [pmulQ, QM31.fromM31s] at ha hb
    exact CM31.ext' ha.symm hb.symm
  -- The nonce hash.
  set Bres := Channel.powPrefix true s nBits ++ Channel.u64Le (nonceNat (ρ nonce))
    with hBres
  have hBreslen : Bres.length = 40 := by
    rw [hBres, List.length_append, Channel.powPrefix, chHash_true_length]
    simp [Channel.u64Le, Channel.u32Le]
  obtain ⟨hr1, -⟩ := blake2sM31G_sound
    (felts := [pre.res.1, pre.res.2, nonce]) (n := m + 2)
    (xs := [ρ pre.res.1, ρ pre.res.2, ρ nonce]) (bytes := Bres) rfl
    (fun i hi => by
      match i, hi with
      | 0, _ => rfl
      | 1, _ => rfl
      | 2, _ => rfl)
    (by
      rw [hBreslen]
      show Channel.qm31Bytes (ρ pre.res.1) ++ (Channel.qm31Bytes (ρ pre.res.2)
        ++ (Channel.qm31Bytes (ρ nonce) ++ [])) = _
      rw [List.append_nil, ← List.append_assoc, hpreD, nonce_bytes _ hc1, hBres]
      simp [List.append_assoc])
    (by rw [hBreslen]; rfl) (by rw [hBreslen]; exact hresh)
  rw [hBreslen, ← hres, (digestFelts_fromM31s Bres).1] at hr1
  -- The first word and its bits.
  rw [allHold_cons] at hfwh
  obtain ⟨hfwv, -⟩ := hfwh
  simp only [Holds] at hfwv
  have hlane0 : SimdReg.lane ρ ⟨[fw], 1⟩ 0
      = ((Channel.wordAt (Channel.chHash true Bres) 0 : ℕ) : F) := by
    show coord (ρ fw) 0 = _
    rw [hfwv, hr1, hone]
    show ((Channel.wordAt (Channel.chHash true Bres) 0 : ℕ) : F) * 1 = _
    rw [mul_one]
  obtain ⟨-, hnat⟩ := extractBits31_sound hzero
    (show SimdReg.Covers ⟨[fw], 1⟩ from show (1 : ℕ) ≤ 4 * [fw].length by simp)
    hebh 0 (by show 0 < 1; omega)
  rw [hlane0] at hnat
  have hwlt : Channel.wordAt (Channel.chHash true Bres) 0 < P := by
    unfold Channel.chHash
    rw [if_pos rfl, wordAt_reduceDigest _ (by omega)]
    exact reduceWord_lt (wordAt_lt _ 0)
  rw [ZMod.val_cast_of_lt hwlt] at hnat
  have hz : ∀ i, i < nBits →
      SimdReg.lane ρ ((extractBits31 zero ⟨[fw], 1⟩ (fw + 1)).res.getD i
        dummySimd) 0 = 0 := by
    intro i hi
    have he := heqs (Op.eq ((eb.res.getD i dummySimd).data.getD 0 0) zero)
      (List.mem_map.mpr ⟨i, List.mem_range.mpr hi, rfl⟩)
    simp only [Holds] at he
    show coord (ρ ((eb.res.getD i dummySimd).data.getD (0 / 4) 0)) (0 % 4) = 0
    rw [show (0 : ℕ) / 4 = 0 from rfl, he, hzero]
    rfl
  have hdvd : 2 ^ nBits ∣ Channel.wordAt (Channel.chHash true Bres) 0 := by
    rw [← hnat]
    exact natOf_dvd hz
  refine ⟨?_, ?_⟩
  · unfold Channel.verifyPowNonce
    exact decide_eq_true (trailingZeroBits_ge (by rw [chHash_true_length]; omega)
      (by omega) hdvd)
  -- The digest update.
  · set Bupd := s.digest ++ Channel.u64Le (nonceNat (ρ nonce)) with hBupd
    have hBupdlen : Bupd.length = 40 := by
      rw [hBupd, List.length_append, hdlen]
      simp [Channel.u64Le, Channel.u32Le]
    obtain ⟨hu1, hu2⟩ := blake2sM31G_sound
      (felts := [low, high, nonce]) (n := eb.next)
      (xs := [ρ low, ρ high, ρ nonce]) (bytes := Bupd) rfl
      (fun i hi => by
        match i, hi with
        | 0, _ => rfl
        | 1, _ => rfl
        | 2, _ => rfl)
      (by
        rw [hBupdlen]
        show Channel.qm31Bytes (ρ low) ++ (Channel.qm31Bytes (ρ high)
          ++ (Channel.qm31Bytes (ρ nonce) ++ [])) = _
        rw [List.append_nil, ← List.append_assoc, hd, nonce_bytes _ hc1, hBupd]
        simp [List.append_assoc])
      (by rw [hBupdlen]; rfl) (by rw [hBupdlen]; exact huph)
    rw [hBupdlen, ← hupd] at hu1 hu2
    show Channel.qm31Bytes (ρ upd.res.1) ++ Channel.qm31Bytes (ρ upd.res.2) = _
    rw [hu1, hu2, digestFelts_bytes]
    show Channel.chHash true Bupd = Channel.chHash true (s.digest
      ++ ([nonceNat (ρ nonce) % 2 ^ 32, nonceNat (ρ nonce) / 2 ^ 32].map
        Channel.u32Le).flatten)
    rw [hBupd]
    simp only [List.map_cons, List.map_nil, List.flatten_cons, List.flatten_nil,
      List.append_nil, u32Le_mod32]
    rfl

/-! ### `draw_point` -/

/-- The executable `inv?` succeeds away from zero. -/
theorem inv?_of_ne {x : QM31} (hx : x ≠ 0) : x.inv? = some x⁻¹ := by
  cases h : x.inv? with
  | some y => rw [(QM31.inv?_eq_some h).2]
  | none =>
    exfalso
    apply hx
    apply QM31.normQ_eq_zero
    apply CM31.norm2_eq_zero
    by_contra hn
    have hs : (x.c0 * x.c0 - QM31.R * (x.c1 * x.c1)).inv?
        = some ⟨(x.c0 * x.c0 - QM31.R * (x.c1 * x.c1)).a
            * (CM31.norm (x.c0 * x.c0 - QM31.R * (x.c1 * x.c1)))⁻¹,
          -(x.c0 * x.c0 - QM31.R * (x.c1 * x.c1)).b
            * (CM31.norm (x.c0 * x.c0 - QM31.R * (x.c1 * x.c1)))⁻¹⟩ := by
      unfold CM31.inv?
      rw [if_neg (by exact hn)]
    simp [QM31.inv?, hs] at h

/-- `draw_secure_felt` in m31 mode: the first four reduced words. -/
theorem drawSecureFelt_m31 (s : Channel.St) :
    Channel.drawSecureFelt true s
      = some (QM31.fromM31s
          ((Channel.wordAt (Channel.chHash true
            (s.digest ++ Channel.u32Le s.nDraws ++ [0])) 0 : ℕ) : F)
          ((Channel.wordAt (Channel.chHash true
            (s.digest ++ Channel.u32Le s.nDraws ++ [0])) 1 : ℕ) : F)
          ((Channel.wordAt (Channel.chHash true
            (s.digest ++ Channel.u32Le s.nDraws ++ [0])) 2 : ℕ) : F)
          ((Channel.wordAt (Channel.chHash true
            (s.digest ++ Channel.u32Le s.nDraws ++ [0])) 3 : ℕ) : F),
          ⟨s.digest, s.nDraws + 1⟩) := by
  unfold Channel.drawSecureFelt
  rw [drawBaseFelts_m31 Channel.drawFuel (by unfold Channel.drawFuel; omega) s]
  rfl

/-- `draw_point`: draw `t` (the first of two), then
`((1 − t²)/(1 + t²), 2t/(1 + t²))`. -/
noncomputable def drawPointG (low high nDraws n : ℕ) : Out PointReg :=
  let d := drawTwoQm31sG low high nDraws n
  let t := d.res.1
  let m := d.next
  ⟨d.ops ++
    [.mul m t t, .const (m + 1) QM31.one, .add (m + 2) m (m + 1),
     .inv (m + 3) (m + 2), .sub (m + 4) (m + 1) m, .mul (m + 5) (m + 4) (m + 3),
     .const (m + 6) (QM31.fromM31s 2 0 0 0), .mul (m + 7) (m + 6) t,
     .mul (m + 8) (m + 7) (m + 3)],
   ⟨m + 5, m + 8⟩, m + 9⟩

set_option maxHeartbeats 2000000 in
/-- **`draw_point` is the spec's OODS-point draw**: the drawn seed is
`drawSecureFelt`'s, the seed-to-point map succeeds (the `inv` gate
forces `1 + t² ≠ 0`), and the point registers hold its coordinates. -/
theorem drawPointG_sound {ρ : ℕ → QM31} {low high n : ℕ} {s : Channel.St}
    (hd : ChDigest ρ low high s.digest) (hdlen : s.digest.length = 32)
    (hnd : s.nDraws < P)
    (h : AllHold ρ (drawPointG low high s.nDraws n).ops) :
    ∃ t, Channel.drawSecureFelt true s = some (t, ⟨s.digest, s.nDraws + 1⟩) ∧
      securePointFromSeed t = some ((drawPointG low high s.nDraws n).res.val ρ) := by
  set d := drawTwoQm31sG low high s.nDraws n with hdd
  set m := d.next with hm
  replace h : AllHold ρ (d.ops ++
    [.mul m d.res.1 d.res.1, .const (m + 1) QM31.one, .add (m + 2) m (m + 1),
     .inv (m + 3) (m + 2), .sub (m + 4) (m + 1) m, .mul (m + 5) (m + 4) (m + 3),
     .const (m + 6) (QM31.fromM31s 2 0 0 0), .mul (m + 7) (m + 6) d.res.1,
     .mul (m + 8) (m + 7) (m + 3)]) := h
  rw [allHold_append] at h
  obtain ⟨hdh, h⟩ := h
  simp only [allHold_cons, Holds] at h
  obtain ⟨hsq, hc1, hden, hinv, hsub, hx, hc2, htt, hy, -⟩ := h
  have hdraw := drawTwoQm31sG_sound hd hdlen hnd hdh
  rw [drawSecureFelts_two] at hdraw
  have ht : ρ d.res.1 = QM31.fromM31s
      ((Channel.wordAt (Channel.chHash true
        (s.digest ++ Channel.u32Le s.nDraws ++ [0])) 0 : ℕ) : F)
      ((Channel.wordAt (Channel.chHash true
        (s.digest ++ Channel.u32Le s.nDraws ++ [0])) 1 : ℕ) : F)
      ((Channel.wordAt (Channel.chHash true
        (s.digest ++ Channel.u32Le s.nDraws ++ [0])) 2 : ℕ) : F)
      ((Channel.wordAt (Channel.chHash true
        (s.digest ++ Channel.u32Le s.nDraws ++ [0])) 3 : ℕ) : F) := by
    have := congrArg (fun o => (o.map fun p => p.1.head?)) hdraw
    simp at this
    rw [List.append_assoc]
    exact this.symm
  refine ⟨ρ d.res.1, by rw [drawSecureFelt_m31, ht], ?_⟩
  have hne : ρ (m + 2) ≠ 0 := by
    intro hz
    rw [hz, zero_mul] at hinv
    exact one_ne_zero (show (1 : QM31) = 0 from hinv.symm)
  have hinv' : ρ (m + 3) = (ρ (m + 2))⁻¹ :=
    eq_inv_of_mul_eq_one_right (by rw [hinv]; rfl)
  unfold securePointFromSeed
  dsimp only
  have hsqd : (ρ d.res.1).square + QM31.one = ρ (m + 2) := by
    rw [hden, hsq, hc1]
    rfl
  rw [hsqd, inv?_of_ne hne]
  show some (⟨(QM31.one - (ρ d.res.1).square) * (ρ (m + 2))⁻¹,
    (ρ d.res.1 + ρ d.res.1) * (ρ (m + 2))⁻¹⟩ : PointQ) = _
  refine congrArg some (CPoint.ext' ?_ ?_)
  · show _ = ρ (m + 5)
    rw [hx, hsub, hinv', hc1, hsq]
    rfl
  · show _ = ρ (m + 8)
    rw [hy, htt, hinv', hc2]
    have h2 : QM31.fromM31s 2 0 0 0 = 1 + 1 := by
      refine QM31.ext' ?_ ?_ <;> (ext <;> simp [QM31.fromM31s] <;> norm_num) <;> rfl
    rw [h2]
    ring

end StwoVerifier.Gadgets
