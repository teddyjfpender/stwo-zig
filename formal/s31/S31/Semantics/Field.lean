import S31.Semantics.Types
import Mathlib.Data.ZMod.Basic

namespace S31.Field

/-- Reuse the repository's canonical representatives; ZMod supplies algebraic
structure and the executable Euclidean inverse, rather than duplicating M31. -/
abbrev F := ZMod 2147483647

def toZMod (x : M31) : F := x.val
def fromZMod (x : F) : M31 := RiscvRefinement.M31.reduce x.val
def inverse (x : M31) : M31 := fromZMod (toZMod x)⁻¹

end S31.Field
