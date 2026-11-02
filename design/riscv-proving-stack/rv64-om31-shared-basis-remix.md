# Shared OM31 basis reconstruction

The existing native degree-eight reconstruction now lives once in
`core.fields.om31.Quadratic(F,Ops).fromPartialEvals`. Native OM31, circuit OM31,
packed OM31 and the RV64 native OODS helper delegate to it. QM31 remains the
same quartic field with the same APIs and operations.

For the eight extension-valued coordinate polynomial evaluations, split their
inner coordinates into four quartic blocks: lower0, lower1, upper0, upper1.
The result is `(Q(lower0) + u*Q(upper1), Q(lower1) + Q(upper0))`, where each Q is
the existing four-coordinate partial-evaluation map and `u` is the fixed inner
nonresidue. This preserves the original eight-coordinate serialization order.
It avoids eight general outer-extension basis multiplications in the circuit
and packed helpers. Supplied circuit coordinates remain actual guessed wires.

| Actual circuit fixture | Prior basis-product oracle | Shared four-remix map |
|---|---:|---:|
| QM31 operation gates emitted before finalization | 54 | 27 |
| Full graph QM31 operation gates | 394 | 367 |
| Full graph variables | 394 | 367 |
| Equality gates | 2 | 2 |

Both graphs use the same sixteen guessed QM31 inputs and the same independently
known output fixture. Full graph counts include common guess/constant
finalization, so they differ from arithmetic emission counts. These are actual
builder counters, not a total proving-time or leaf speedup measurement.

The reference graph deliberately uses the former sum of eight basis products
as a slow mathematical oracle. The shared graph agrees and rejects each of
64 individual input-base-coordinate mutations. Distinct polynomials across all
sixteen packed rows also agree with an independent basis-product sum. The
allocation-failure sweep now includes reconstruction. Existing real OM31 ALU
STARK/fresh receiver, actual GKR circuit, service/global kernel and legacy QM31
SIMD controls remain in the focused Safe/Fast gates. No production profile,
security claim, proof layout or sampler is changed by this arithmetic slice.
