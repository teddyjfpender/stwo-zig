# Reliable runtime rebuilds before further recursion experiments

Previous goal turn: verified progress, generic covered-batch quotient dispatch
reduced the measured tree median 41.054 to 39.049 seconds. This checkpoint fixes
an observed development-loop hazard; it claims **no additional prover speedup**.

## Problem and implementation

In the prior experiment, changing `runtime/quotients.m` alone reused an enclosing
Zig test executable. A top-level `runtime.m` edit forced the intended rebuild.
The product identity also used a manually maintained list of Objective-C units;
that list omitted current imports including quotient planning/completion,
framework interaction, proof of work and object-model declarations.

`build_runtime_source.zig` now hashes the actual recursive quoted-include closure,
with length-delimited contents, first-visit deduplication and cycle handling.
Identical source checkouts have identical digests regardless of absolute directory.
Missing dependencies and unsupported macro/continued include syntax fail closed.
System angle-bracket headers remain under the existing SDK/toolchain identity.
Both the compilation flags and root product runtime identity consume this digest.
Thus an imported implementation/header change alters Zig's outer compilation key,
while an unchanged closure can reuse its artifact. This does not alter shader ABI,
proof protocol or runtime calculations. Host product identities intentionally change.

The backend module explicitly owns its runtime source; downstream consumers no
longer rely on constructing a backend test to attach it. Cairo's redundant direct
runtime attachment is removed. The shared helper is exported through the backend's
build module, avoiding duplicate Zig source ownership across build packages.

## Evidence

- `unit.log`: two ReleaseSafe checks cover recursive mutation, repeated imports,
  cycles, missing dependencies and rejected unresolved include syntax.
- `check-cache.py`, `cache-results.json`, `cache-{0,1,2}.log`: real Zig build fixture.
  Only a twice-nested header changes, from VALUE=1 to VALUE=2; top-level C/ObjC and
  Zig files remain identical. Executable behavior and digest change. A third
  unchanged build reuses the identical executable and reports a cached compile.
- `canonical.log`: ReleaseFast authenticated Metal canonical tree, 7/7 passing.
  Three independent aggregate verifications at q70/PoW26, existing ABI-24 bundle.
- `cairo-compile.log`: Cairo Metal integration compile target passes (not proof execution).
- `root-help.log`: root build graph configures with the shared helper.
- `local-target.log`: maintained `test-runtime-source-closure` target.

No full suite or new timing claim is warranted for this build-input change.
The parser deliberately covers current literal quoted includes; adding a macro or
continued project include requires an explicit supported dependency mechanism.

## Next larger target from pinned peer source

Pinned Proofman d485fac207679076958b502554fb595568c2f954 has a concrete boundary
reconstruction implementation in `gate_bands_blake3.hpp`: a 56-row block holds
parallel lanes, and setup supplies two boundary rows per lane. `expand_block`
reconstructs interior witness values; its CPU driver uses private lookup counters
and reduces them after expansion. CPU and CUDA instantiate shared arithmetic.
The recursion band uses 59 columns per lane plus shared columns; this is distinct
from the earlier standalone/shared-circuit column census. We must not conflate them.

Our lookup counting already uses bounded private worker counters, so that pattern
is present. The larger remaining opportunity is boundary-driven final-layout
emission, potentially on the device, instead of materializing and joining complete
host child traces. A valid implementation must preserve typed M31 limb constraints,
fixed metadata, namespace binding, lookup multiplicities and next-level verification.
No peer hash-proof benchmark or speedup from boundary reconstruction is established
here. Source digests for this follow-up are in `peer-followup-sources.json`.
