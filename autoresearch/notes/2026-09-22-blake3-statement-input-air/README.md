# BLAKE3 statement input AIR and direct witness schedule

The BLAKE3 profile now admits the complete 525-word Span layout. All 224 digest
limbs per scope are classified as u16 by the canonical Span format owner. The
existing typed input AIR reconstructs integer values from low/high bytes and
requests the shared range_check_8_8 table; no redundant bit-decomposition graph
was introduced. Four scopes retain 896 full-digest limb coordinates.

Legacy and BLAKE3 witness generation share one implementation. The public profile
types, witness-binding domain and preprocessed schedule domain are separate.
The BLAKE3 binding digest is pinned to
`0d552af92946799a55a52aedcce564c0529c467b5bdaf1a2f603be3259775d10`.
Legacy binding seals and integer classification pass their existing tests.
The old handwritten integer-coordinate list was removed in favor of the same
format owner used by native serialization. BLAKE3 rejects the legacy Ethereum
clock/continuation extension until its authority is migrated.

Qualification command:

```
python3 scripts/zig_serial_build.py --cwd . test-riscv-statement-codecs -Doptimize=ReleaseSafe --summary all
```

Passed; final outer build reported 11 s and 825 MB peak RSS. The focused gate now
has a 23-named-test floor and includes legacy input AIR checks as well as five
new BLAKE3 input tests. New evidence covers all digest coordinates, out-of-range
limbs, changed integer metadata, format-separated preprocessing authority, and
an arithmetic constraint failure for a forged value/decomposition after bypassing
the native witness validator. Direct final-column generation agrees with logical
rows, zeros padding and rejects a bad final limb before writing any column.
The byte-range table and typed arithmetic component are reused unchanged.

This qualifies the input AIR/witness layer, not a complete recursive proof.
The full statement-semantics circuit contract still selects legacy Span and row11
modules and pins the 412-word geometry. Next: parameterize its contract, tracked
builder and graph builder by the admitted format; use all sixteen edge limbs,
constrain the explicit format version, seal the resulting graph identity and
geometry, and qualify distinct-child folds plus malicious-input rejection through
both the graph and this new input schedule. Then migrate statement providers,
BLAKE3 identity hash bindings, artifact/key admission and production capture.
No default-suite promotion or recursion speedup is claimed.
