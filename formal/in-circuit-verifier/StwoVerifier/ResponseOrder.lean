/-
**`treesPairs` in closed form for the circuit statement's column
shapes.** Every circuit-AIR column samples either `[oods]` or
`[prev, oods]` (the cumulative sums), so the spec's push-order pair
list (`BatchesFlat.treesPairs`) decomposes into two recursions that
mirror `collect_oods_responses`' emission order exactly: one pushed
pair per single-sample column, and the periodicity duplicate, the
previous-row pair and the OODS pair — in that order — per two-sample
column, the random power advancing once per pushed pair. Matching the
emitter's response registers against these lists is then pointwise.
-/
import StwoVerifier.BatchesFlat

namespace StwoVerifier.Quotients

open StwoVerifier

/-! ### Per-column closed forms -/

theorem columnPairs_single (step : PointF) (rc pow : QM31) (fc : ℕ)
    (pt : PointQ) (v : QM31) (L : Nat) :
    columnPairs step rc pow fc [pt] [v] L = [(pt, ⟨fc, v, pow⟩)] := by
  simp [columnPairs, pushedPairs]

theorem columnPow_single (rc pow : QM31) (pt : PointQ) (v : QM31) :
    columnPow rc pow [pt] [v] = pow * rc := by
  simp [columnPow]

theorem columnPairs_double (step : PointF) (rc pow : QM31) (fc : ℕ)
    (prevPt pt : PointQ) (vp vo : QM31) (L : Nat) :
    columnPairs step rc pow fc [prevPt, pt] [vp, vo] L
      = [(pt.add (PointF.intoQ (step.repeatedDouble L)), ⟨fc, vo, pow⟩),
         (prevPt, ⟨fc, vp, pow * rc⟩), (pt, ⟨fc, vo, pow * rc * rc⟩)] := by
  simp [columnPairs, pushedPairs]

theorem columnPow_double (rc pow : QM31) (prevPt pt : PointQ) (vp vo : QM31) :
    columnPow rc pow [prevPt, pt] [vp, vo] = pow * rc ^ 3 := by
  simp [columnPow]
  ring

/-! ### Runs of single-sample columns -/

/-- The pairs of a run of single-sample columns at point `pt`: one
pushed pair per column, the power advancing once each. -/
noncomputable def singlesPairs (rc : QM31) (pt : PointQ) : List QM31 → QM31 → ℕ →
    List (PointQ × NumeratorData) × QM31 × ℕ
  | [], pow, fc => ([], pow, fc)
  | v :: rest, pow, fc =>
    let r := singlesPairs rc pt rest (pow * rc) (fc + 1)
    ((pt, ⟨fc, v, pow⟩) :: r.1, r.2)

theorem treePairs_singles (step : PointF) (rc : QM31) (pt : PointQ) :
    ∀ (vals : List QM31) (logs : List Nat) (pow : QM31) (fc : ℕ),
      vals.length ≤ logs.length →
      treePairs step rc pow fc
        ((List.replicate vals.length [pt]).zip
          ((vals.map fun v => [v]).zip logs))
        = singlesPairs rc pt vals pow fc
  | [], _, pow, fc, _ => rfl
  | v :: rest, [], pow, fc, hlen => absurd hlen (by simp)
  | v :: rest, L :: logs, pow, fc, hlen => by
    show (columnPairs step rc pow fc [pt] [v] L ++
        (treePairs step rc (columnPow rc pow [pt] [v]) (fc + 1)
          ((List.replicate rest.length [pt]).zip
            ((rest.map fun v => [v]).zip logs))).1,
      (treePairs step rc (columnPow rc pow [pt] [v]) (fc + 1)
        ((List.replicate rest.length [pt]).zip
          ((rest.map fun v => [v]).zip logs))).2) = _
    rw [columnPairs_single, columnPow_single,
      treePairs_singles step rc pt rest logs (pow * rc) (fc + 1)
        (by simpa using hlen)]
    rfl

/-! ### Runs of two-sample columns -/

/-- The pairs of a run of two-sample (cumulative-sum) columns: per
column the periodicity duplicate at `pt + step·2^log` carrying the
OODS value, the previous-row pair, then the OODS pair — the circuit's
response order — with the power advancing once per pair. -/
noncomputable def doublesPairs (step : PointF) (rc : QM31) (pt prevPt : PointQ) :
    List (QM31 × QM31) → List Nat → QM31 → ℕ →
    List (PointQ × NumeratorData) × QM31 × ℕ
  | [], _, pow, fc => ([], pow, fc)
  | _ :: _, [], pow, fc => ([], pow, fc)
  | (vp, vo) :: rest, L :: logs, pow, fc =>
    let r := doublesPairs step rc pt prevPt rest logs (pow * rc ^ 3) (fc + 1)
    ((pt.add (PointF.intoQ (step.repeatedDouble L)), ⟨fc, vo, pow⟩)
      :: (prevPt, ⟨fc, vp, pow * rc⟩) :: (pt, ⟨fc, vo, pow * rc * rc⟩)
      :: r.1, r.2)

theorem treePairs_doubles (step : PointF) (rc : QM31) (pt prevPt : PointQ) :
    ∀ (pairs : List (QM31 × QM31)) (logs : List Nat) (pow : QM31) (fc : ℕ),
      pairs.length ≤ logs.length →
      treePairs step rc pow fc
        ((List.replicate pairs.length [prevPt, pt]).zip
          ((pairs.map fun p => [p.1, p.2]).zip logs))
        = doublesPairs step rc pt prevPt pairs logs pow fc
  | [], _, pow, fc, _ => rfl
  | p :: rest, [], pow, fc, hlen => absurd hlen (by simp)
  | (vp, vo) :: rest, L :: logs, pow, fc, hlen => by
    show (columnPairs step rc pow fc [prevPt, pt] [vp, vo] L ++
        (treePairs step rc (columnPow rc pow [prevPt, pt] [vp, vo]) (fc + 1)
          ((List.replicate rest.length [prevPt, pt]).zip
            ((rest.map fun p => [p.1, p.2]).zip logs))).1,
      (treePairs step rc (columnPow rc pow [prevPt, pt] [vp, vo]) (fc + 1)
        ((List.replicate rest.length [prevPt, pt]).zip
          ((rest.map fun p => [p.1, p.2]).zip logs))).2) = _
    rw [columnPairs_double, columnPow_double,
      treePairs_doubles step rc pt prevPt rest logs (pow * rc ^ 3) (fc + 1)
        (by simpa using hlen)]
    rfl

/-! ### State-compositional appends -/

/-- `treePairs` over concatenated column runs: the second run continues
from the first run's power and counter. -/
theorem treePairs_append (step : PointF) (rc : QM31) :
    ∀ (c1 c2 : List (List PointQ × List QM31 × Nat)) (pow : QM31) (fc : ℕ),
      treePairs step rc pow fc (c1 ++ c2)
        = ((treePairs step rc pow fc c1).1
            ++ (treePairs step rc (treePairs step rc pow fc c1).2.1
                (treePairs step rc pow fc c1).2.2 c2).1,
           (treePairs step rc (treePairs step rc pow fc c1).2.1
             (treePairs step rc pow fc c1).2.2 c2).2)
  | [], c2, pow, fc => by
    show treePairs step rc pow fc c2 = ([] ++ (treePairs step rc pow fc c2).1,
      (treePairs step rc pow fc c2).2)
    rw [List.nil_append]
  | (colPoints, colValues, logSize) :: c1, c2, pow, fc => by
    show (columnPairs step rc pow fc colPoints colValues logSize ++
        (treePairs step rc (columnPow rc pow colPoints colValues) (fc + 1)
          (c1 ++ c2)).1,
      (treePairs step rc (columnPow rc pow colPoints colValues) (fc + 1)
        (c1 ++ c2)).2) = _
    rw [treePairs_append step rc c1 c2 (columnPow rc pow colPoints colValues)
      (fc + 1)]
    show (columnPairs step rc pow fc colPoints colValues logSize ++
      ((treePairs step rc (columnPow rc pow colPoints colValues) (fc + 1) c1).1
        ++ _), _) = _
    rw [← List.append_assoc]
    rfl

/-! ### Interaction-tree components -/

/-- One interaction component's pairs: the single-sample run, then the
four cumulative-sum columns, all at the component's column log. -/
noncomputable def componentPairs (step : PointF) (rc : QM31) (pt prevPt : PointQ)
    (sv : List QM31) (dv : List (QM31 × QM31)) (L : Nat) (pow : QM31)
    (fc : ℕ) : List (PointQ × NumeratorData) × QM31 × ℕ :=
  let s := singlesPairs rc pt sv pow fc
  let d := doublesPairs step rc pt prevPt dv (List.replicate dv.length L)
    s.2.1 s.2.2
  (s.1 ++ d.1, d.2)

theorem treePairs_component (step : PointF) (rc : QM31) (pt prevPt : PointQ)
    (sv : List QM31) (dv : List (QM31 × QM31)) (L : Nat) (pow : QM31)
    (fc : ℕ) :
    treePairs step rc pow fc
      ((List.replicate sv.length [pt]
          ++ List.replicate dv.length [prevPt, pt]).zip
        (((sv.map fun v => [v]) ++ dv.map fun p => [p.1, p.2]).zip
          (List.replicate sv.length L ++ List.replicate dv.length L)))
      = componentPairs step rc pt prevPt sv dv L pow fc := by
  rw [List.zip_append (by simp), List.zip_append (by simp), treePairs_append,
    treePairs_singles step rc pt sv (List.replicate sv.length L) pow fc
      (by simp),
    treePairs_doubles step rc pt prevPt dv (List.replicate dv.length L) _ _
      (by simp)]
  rfl

/-- The whole interaction tree, component by component. -/
noncomputable def interTreePairs (step : PointF) (rc : QM31)
    (pt prevPt : PointQ) :
    List (List QM31 × List (QM31 × QM31) × Nat) → QM31 → ℕ →
    List (PointQ × NumeratorData) × QM31 × ℕ
  | [], pow, fc => ([], pow, fc)
  | c :: rest, pow, fc =>
    let h := componentPairs step rc pt prevPt c.1 c.2.1 c.2.2 pow fc
    let r := interTreePairs step rc pt prevPt rest h.2.1 h.2.2
    (h.1 ++ r.1, r.2)

theorem treePairs_interTree (step : PointF) (rc : QM31) (pt prevPt : PointQ) :
    ∀ (comps : List (List QM31 × List (QM31 × QM31) × Nat)) (pow : QM31)
      (fc : ℕ),
      treePairs step rc pow fc
        ((comps.flatMap fun c => List.replicate c.1.length [pt]
            ++ List.replicate c.2.1.length [prevPt, pt]).zip
          ((comps.flatMap fun c => (c.1.map fun v => [v])
              ++ c.2.1.map fun p => [p.1, p.2]).zip
            (comps.flatMap fun c => List.replicate c.1.length c.2.2
              ++ List.replicate c.2.1.length c.2.2)))
        = interTreePairs step rc pt prevPt comps pow fc
  | [], pow, fc => rfl
  | c :: rest, pow, fc => by
    rw [List.flatMap_cons, List.flatMap_cons, List.flatMap_cons,
      List.zip_append (by simp), List.zip_append (by simp), treePairs_append,
      treePairs_component,
      treePairs_interTree step rc pt prevPt rest _ _]
    rfl

/-! ### Stable partitions by key

The circuit batches responses by point **wire** id (`computeFriInput`'s
`AutoArrayHashMap`), the spec by point **value** (`pushEntry`); two
components of equal log size share a periodicity point value under
distinct wires, so the groupings genuinely differ. `rowSum_perm` takes
any grouping whose flat view is a permutation of the spec's, and a
stable partition by any key is one: each group is the in-order fiber
of its key. -/

theorem flatMap_congr' {α κ : Type} {l : List κ} {f g : κ → List α}
    (h : ∀ k ∈ l, f k = g k) : l.flatMap f = l.flatMap g := by
  induction l with
  | nil => rfl
  | cons k rest ih =>
    rw [List.flatMap_cons, List.flatMap_cons, h k List.mem_cons_self,
      ih fun k' hk' => h k' (List.mem_cons_of_mem _ hk')]

/-- Partitioning a list into the fibers of a key function (any nodup
covering key order) permutes it. -/
theorem partition_flatMap_perm {α κ : Type} [DecidableEq κ] (key : α → κ) :
    ∀ (keys : List κ) (l : List α), keys.Nodup →
      (∀ a ∈ l, key a ∈ keys) →
      (keys.flatMap fun k => l.filter fun a => key a = k).Perm l
  | [], l, _, hcov => by
    cases l with
    | nil => simp
    | cons a rest => exact absurd (hcov a List.mem_cons_self) (by simp)
  | k :: ks, l, hnd, hcov => by
    rw [List.flatMap_cons]
    have hrest : (ks.flatMap fun k' => l.filter fun a => key a = k')
        = ks.flatMap fun k' =>
            (l.filter fun a => ¬(key a = k)).filter fun a => key a = k' := by
      refine flatMap_congr' fun k' hk' => ?_
      rw [List.filter_filter]
      refine (List.filter_congr fun a _ => ?_).symm
      have hne : k' ≠ k := by
        rintro rfl
        exact (List.nodup_cons.mp hnd).1 hk'
      by_cases he : key a = k'
      · simp [he, hne]
      · simp [he]
    rw [hrest]
    have hih := partition_flatMap_perm key ks
      (l.filter fun a => ¬(key a = k)) (List.nodup_cons.mp hnd).2
      (fun a ha => by
        have hm := List.mem_filter.mp ha
        have hk := hcov a hm.1
        rcases List.mem_cons.mp hk with he | hm2
        · exact absurd (by simpa using hm.2) (by simp [he])
        · exact hm2)
    refine ((hih.append_left (l.filter fun a => key a = k)).trans ?_)
    simpa using List.filter_append_perm (fun a => key a = k) l

/-- The index-keyed form: responses keyed positionally (the wire ids),
groups taken at matching positions. -/
theorem zip_partition_perm {α κ : Type} [DecidableEq κ] [Inhabited α]
    (ks : List κ) (pairs : List α) (keys : List κ)
    (hnd : keys.Nodup) (hcov : ∀ k ∈ ks, k ∈ keys)
    (hlen : ks.length = pairs.length) :
    (keys.flatMap fun k =>
        ((ks.zip pairs).filter fun p => p.1 = k).map Prod.snd).Perm pairs := by
  have hperm := partition_flatMap_perm (Prod.fst : κ × α → κ) keys
    (ks.zip pairs) hnd (fun p hp => hcov p.1 (List.of_mem_zip hp).1)
  have hmap := hperm.map (Prod.snd : κ × α → α)
  rw [List.map_flatMap] at hmap
  refine hmap.trans ?_
  rw [List.map_snd_zip (show pairs.length ≤ ks.length by omega)]

/-! ### The circuit statement's four trees -/

theorem treesPairs_cons (step : PointF) (rc : QM31) (pow : QM31) (fc : ℕ)
    (T : List (List PointQ) × List (List QM31) × List Nat)
    (rest : List (List (List PointQ) × List (List QM31) × List Nat)) :
    treesPairs step rc pow fc (T :: rest)
      = ((treePairs step rc pow fc (T.1.zip (T.2.1.zip T.2.2))).1
          ++ (treesPairs step rc
              (treePairs step rc pow fc (T.1.zip (T.2.1.zip T.2.2))).2.1
              (treePairs step rc pow fc (T.1.zip (T.2.1.zip T.2.2))).2.2
              rest).1,
         (treesPairs step rc
           (treePairs step rc pow fc (T.1.zip (T.2.1.zip T.2.2))).2.1
           (treePairs step rc pow fc (T.1.zip (T.2.1.zip T.2.2))).2.2
           rest).2) := rfl

/-- The full circuit-statement pair list: the preprocessed and trace
trees (single samples at `pt`), the interaction tree, the composition
tree — one global power chain. -/
noncomputable def circuitPairs (step : PointF) (rc : QM31) (pt prevPt : PointQ)
    (ppVals traceVals : List QM31)
    (comps : List (List QM31 × List (QM31 × QM31) × Nat))
    (compVals : List QM31) (pow : QM31) (fc : ℕ) :
    List (PointQ × NumeratorData) × QM31 × ℕ :=
  let t0 := singlesPairs rc pt ppVals pow fc
  let t1 := singlesPairs rc pt traceVals t0.2.1 t0.2.2
  let t2 := interTreePairs step rc pt prevPt comps t1.2.1 t1.2.2
  let t3 := singlesPairs rc pt compVals t2.2.1 t2.2.2
  (t0.1 ++ (t1.1 ++ (t2.1 ++ t3.1)), t3.2)

/-- **`treesPairs` for the circuit statement's tree shapes** is
`circuitPairs`: the spec's push order is the emitter's response order,
tree by tree. -/
theorem treesPairs_circuit (step : PointF) (rc : QM31) (pt prevPt : PointQ)
    (ppVals traceVals compVals : List QM31)
    (ppLogs traceLogs compLogs : List Nat)
    (comps : List (List QM31 × List (QM31 × QM31) × Nat))
    (hpp : ppVals.length ≤ ppLogs.length)
    (htr : traceVals.length ≤ traceLogs.length)
    (hcp : compVals.length ≤ compLogs.length) (pow : QM31) (fc : ℕ) :
    treesPairs step rc pow fc
      [(List.replicate ppVals.length [pt], ppVals.map fun v => [v], ppLogs),
       (List.replicate traceVals.length [pt],
        traceVals.map fun v => [v], traceLogs),
       (comps.flatMap fun c => List.replicate c.1.length [pt]
          ++ List.replicate c.2.1.length [prevPt, pt],
        comps.flatMap fun c => (c.1.map fun v => [v])
          ++ c.2.1.map fun p => [p.1, p.2],
        comps.flatMap fun c => List.replicate c.1.length c.2.2
          ++ List.replicate c.2.1.length c.2.2),
       (List.replicate compVals.length [pt], compVals.map fun v => [v],
        compLogs)]
      = circuitPairs step rc pt prevPt ppVals traceVals comps compVals pow fc
    := by
  rw [treesPairs_cons, treesPairs_cons, treesPairs_cons, treesPairs_cons]
  dsimp only
  rw [treePairs_singles step rc pt ppVals ppLogs pow fc hpp,
    treePairs_singles step rc pt traceVals traceLogs _ _ htr,
    treePairs_interTree,
    treePairs_singles step rc pt compVals compLogs _ _ hcp]
  rw [show ∀ (p : QM31) (f : ℕ), treesPairs step rc p f [] = ([], p, f)
    from fun _ _ => rfl]
  dsimp only
  rw [List.append_nil]
  rfl

end StwoVerifier.Quotients
