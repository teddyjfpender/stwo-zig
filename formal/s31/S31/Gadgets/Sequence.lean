import S31.Gadgets.Field
import S31.Semantics.Node

namespace S31.Gadgets.Sequence

theorem pointwise_sound_complete {α β : Type} (f : α → β) (relation : α → β → Prop)
    (correct : ∀ x y, relation x y ↔ y = f x) (xs : List α) (ys : List β) :
    List.Forall₂ relation xs ys ↔ ys = xs.map f := by
  induction xs generalizing ys with
  | nil => cases ys <;> simp
  | cons x xs ih =>
    cases ys with
    | nil => simp
    | cons y ys => simp [List.forall₂_cons, correct, ih, eq_comm]

inductive SumAccepts : List M31 → M31 → M31 → Prop where
  | nil (acc) : SumAccepts [] acc acc
  | cons {x xs acc next result} : next - (acc + x) = 0 →
      SumAccepts xs next result → SumAccepts (x :: xs) acc result

theorem sum_sound {xs acc result} (h : SumAccepts xs acc result) :
    result = xs.foldl (· + ·) acc := by
  induction h with
  | nil => rfl
  | cons hlocal htail ih =>
    have heq := (RiscvRefinement.M31.sub_eq_zero_iff _ _).mp hlocal
    simpa only [List.foldl_cons, heq] using ih

theorem sum_complete (xs : List M31) (acc : M31) : SumAccepts xs acc (xs.foldl (· + ·) acc) := by
  induction xs generalizing acc with
  | nil => exact .nil acc
  | cons x xs ih => exact .cons (RiscvRefinement.M31.sub_self _) (ih _)

theorem sum_sound_complete (xs : List M31) (acc result : M31) :
    SumAccepts xs acc result ↔ result = xs.foldl (· + ·) acc :=
  ⟨sum_sound, fun h => h ▸ sum_complete xs acc⟩

def StepAccepts (step : Step) (xs ys : List M31) : Prop :=
  match step with
  | .square => List.Forall₂ (fun x y => y - x * x = 0) xs ys
  | .add_const c => List.Forall₂ (fun x y => y - (x + c) = 0) xs ys
  | .mul_const c => List.Forall₂ (fun x y => y - x * c = 0) xs ys
  | .mix4 => ∃ total, SumAccepts xs 0 total ∧
      List.Forall₂ (fun x y => y - (x + total) = 0) xs ys

theorem step_sound_complete (step : Step) (xs ys : List M31) :
    StepAccepts step xs ys ↔ ys = applyStep xs step := by
  cases step with
  | square =>
    exact pointwise_sound_complete (fun x : M31 => x * x) (fun x y => y - x * x = 0)
      (fun x y => RiscvRefinement.M31.sub_eq_zero_iff y (x * x)) xs ys
  | add_const c =>
    exact pointwise_sound_complete (fun x : M31 => x + c) (fun x y => y - (x + c) = 0)
      (fun x y => RiscvRefinement.M31.sub_eq_zero_iff y (x + c)) xs ys
  | mul_const c =>
    exact pointwise_sound_complete (fun x : M31 => x * c) (fun x y => y - x * c = 0)
      (fun x y => RiscvRefinement.M31.sub_eq_zero_iff y (x * c)) xs ys
  | mix4 =>
    constructor
    · rintro ⟨total, hsum, h⟩
      have ht := sum_sound hsum
      rw [ht] at h
      exact (pointwise_sound_complete (fun x : M31 => x + xs.foldl (· + ·) 0) _
        (fun x y => RiscvRefinement.M31.sub_eq_zero_iff y (x + xs.foldl (· + ·) 0)) xs ys).mp h
    · intro h
      exact ⟨_, sum_complete xs 0,
        (pointwise_sound_complete (fun x : M31 => x + xs.foldl (· + ·) 0) _
          (fun x y => RiscvRefinement.M31.sub_eq_zero_iff y (x + xs.foldl (· + ·) 0)) xs ys).mpr h⟩

inductive BodyAccepts : List Step → List M31 → List M31 → Prop where
  | nil (xs) : BodyAccepts [] xs xs
  | cons {step steps xs mid ys} : StepAccepts step xs mid →
      BodyAccepts steps mid ys → BodyAccepts (step :: steps) xs ys

theorem body_sound {body xs ys} (h : BodyAccepts body xs ys) : ys = applyBody body xs := by
  induction h with
  | nil => rfl
  | cons hstep htail ih =>
    have heq := (step_sound_complete _ _ _).mp hstep
    simpa only [applyBody, List.foldl_cons, heq] using ih

theorem body_complete (body : List Step) (xs : List M31) : BodyAccepts body xs (applyBody body xs) := by
  induction body generalizing xs with
  | nil => exact .nil xs
  | cons step body ih => exact .cons ((step_sound_complete _ _ _).mpr rfl) (ih _)

inductive RepeatAccepts (body : List Step) : Nat → List M31 → List M31 → Prop where
  | zero (xs) : RepeatAccepts body 0 xs xs
  | succ {n xs mid ys} : BodyAccepts body xs mid →
      RepeatAccepts body n mid ys → RepeatAccepts body (n + 1) xs ys

theorem repeat_sound {body n xs ys} (h : RepeatAccepts body n xs ys) :
    ys = repeatBody body n xs := by
  induction h with
  | zero => rfl
  | succ hbody htail ih => simpa only [repeatBody, body_sound hbody] using ih

theorem repeat_complete (body : List Step) (n : Nat) (xs : List M31) :
    RepeatAccepts body n xs (repeatBody body n xs) := by
  induction n generalizing xs with
  | zero => exact .zero xs
  | succ n ih => exact .succ (body_complete body xs) (ih _)

theorem repeat_sound_complete (body : List Step) (n : Nat) (xs ys : List M31) :
    RepeatAccepts body n xs ys ↔ ys = repeatBody body n xs :=
  ⟨repeat_sound, fun h => h ▸ repeat_complete body n xs⟩

end S31.Gadgets.Sequence
