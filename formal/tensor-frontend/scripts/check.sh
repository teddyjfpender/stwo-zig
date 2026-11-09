#!/usr/bin/env bash
# Build the tensor-frontend Lean development, audit axioms, run the
# executable security cross-check. Run from anywhere; wrap in memguard on
# shared hosts:  ~/Coding/ge-ops/bin/memguard run --gb 6 -- formal/tensor-frontend/scripts/check.sh
set -euo pipefail
cd "$(dirname "$0")/.."
LAKE="${LAKE:-lake}"
"$LAKE" build
"$LAKE" build tensor-security-check
out="$("$LAKE" env lean Audit.lean)"
echo "$out"
bad="$(echo "$out" | grep -v "does not depend on any axioms" | grep -vE "depends on axioms: \[((propext|Classical\.choice|Quot\.sound)(, )?)+\]$" || true)"
if [ -n "$bad" ]; then
  echo "AXIOM AUDIT FAILED:" >&2; echo "$bad" >&2; exit 1
fi
n=$(echo "$out" | grep -c "depends on axioms\|does not depend on any axioms" || true)
echo "axiom audit: $n theorems, only standard axioms"
# source scan: sorry/admit, axiom declarations with any modifiers or
# indentation, native_decide, and escape hatches that bypass the kernel
if grep -rn --include='*.lean' -E '\bsorry\b|\badmit\b|(^|[[:space:]])axiom[[:space:]]|native_decide|implemented_by|@\[extern|\bunsafe\b|ofReduceBool|trustCompiler' TensorFrontend Main.lean Audit.lean; then
  echo "sorry / admit / axiom / native_decide / unsafe escape hatch found" >&2; exit 1
fi
"$LAKE" exe tensor-security-check
