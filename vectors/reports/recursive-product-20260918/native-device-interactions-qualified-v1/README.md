# Native device interaction integration

All six native lookup tables now use admitted AOT fraction and prefix-scan kernels
in the recursive-framework profile. CPU and other Metal profiles retain their
existing writers. Device errors propagate, including the native denominator-pole
error; there is no recomputation fallback after device admission.

The complete four-segment CPU/Metal/AOT command passes 384 cases. All 21 tracked
artifacts match the canonical baseline. Each Metal native child requires 24
successful interaction dispatches: 96 in this four-segment run. The maintained
complete-proof controller enforces that requirement. Source snapshot and patch
record the exact qualified source before the later documentation update.

Focused admitted-AOT tests compare every column and claim for all six full table
geometries, reject malformed shape and poles, and verify recovery. Existing direct
resident checks also cover selector rejection. All 14 ownership checks pass.
AOT regeneration changed only the native-table pipeline coverage flag; the shader
source and export inventory are byte-identical to their predecessor.

Metal leaf production was 26.081s versus 25.879s previously; parent production was
26.035s versus 26.090s. Peak process RSS was 4.388GB versus 4.389GB. These are single
observations, not evidence of speedup or reproducible slowdown. `measurements.json`
retains both CPU and Metal observations and their scope.

The bridge currently stages canonical host columns into device buffers and copies
results back to the existing commitment-column ABI. Removing redundant staging is
a measured optimization candidate. Recursive-parent typed interaction writers
remain on CPU; this checkpoint qualifies the six native tables, not an entirely
GPU-resident prover or production-security profile.
