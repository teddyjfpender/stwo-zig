import Lake
open Lake DSL

package StwoVerifier where
  leanOptions := #[⟨`autoImplicit, false⟩, ⟨`relaxedAutoImplicit, false⟩]

require "leanprover-community" / "mathlib" @ git "v4.33.1"

@[default_target]
lean_lib StwoVerifier

lean_exe diffcheck where
  root := `DiffCheck

lean_exe aircheck where
  root := `AirCheck

lean_exe circuitcheck where
  root := `CircuitCheck
