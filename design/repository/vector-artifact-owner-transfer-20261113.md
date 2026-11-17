# Circuit artifact owner transfer

Issue #362, decision6857631521. Three artifacts that are not produced by the
circuit-oracle fixture generator now live with their actual line owners:

| Artifact | Active location | Invariant owner |
|---|---|---|
| Bounded circuit composition metallib | `vectors/metal/circuit/circuit_air_composition_bounded.metallib` | `cairo-metal-integration` |
| Historical metallib provenance | `vectors/metal/circuit/circuit_air_composition_bounded.provenance.json` | `cairo-metal-integration` |
| Production recursion registry | `vectors/recursion/registries/production.json` | `circuit-recursion` |

All three moves preserve byte length and SHA256 exactly. Every earlier vector
blob pin is unchanged. All live native/tool/documentation consumers use the new
locations. The manifest remains a complete inventory of574 files, now35 groups.
The existing circuit-artifact admission still requires the exact same digest,
length and label, and still rejects a different library.

The metallib provenance is historical and byte-identical. Its original
`artifact.path`, source hash, recipe, compiler and date describe the original
build; they have not been restamped to claim a new build. The active artifact
locator is the native admission owner's `circuit_bounded_path`; the active
inventory path is in `vectors/MANIFEST.json`.

The metallib's historical regeneration recipe uses the pinned circuit AIR
program and `metal-eval-source`, then the recorded Apple Metal compiler.
Metallib bytes are not reproducible across arbitrary Xcode versions; changed
bytes require a real new artifact admission, not a digest substitution.
The registry's historical generation command/definition remains recorded in
`vectors/circuit/provenance.json`; its numeric configuration and circuit roots
are unchanged by the move.

This transaction does not refresh the circuit-oracle generation. Its existing
source-digest and artifact-set refusals remain visible. The obsolete production
registry entry in that historical provenance is deliberately not hand-edited;
a genuine generator run must establish its complete replacement. The strict
oracle namespace and its validator have not been weakened or given exceptions.

The transfer test authenticates the three original blob identities and actual
new owners independently of oracle replay. CPU-only execution of the existing
circuit metallib admission test covers the real native locator and rejection.
Neither test executes GPU kernels or claims full oracle/protocol qualification.
