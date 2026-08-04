import RiscvRefinement.Publication.TeamB.MulhDiv.Division.Air
import RiscvRefinement.Publication.TeamB.MulhDiv.Division.Semantics

/-!
# Publication bridge for DIV, DIVU, REM, and REMU

The exact generated-AIR extraction lives in `Division/Air.lean`; bounded-field
interpretation and architectural retirement live in `Division/Semantics.lean`.
This facade keeps downstream imports stable.
-/
