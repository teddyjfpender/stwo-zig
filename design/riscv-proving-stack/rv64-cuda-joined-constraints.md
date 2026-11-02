# Native joined constraints and secure OODS on CUDA

This slice moves the device lane from MAIN-only equations to recording complete
CPU-shard role equations. It does not yet generate an accepting Ethereum proof.
The production CUDA dispatch remains closed.

`constraint_authority.zig` is a read-only adapter over the existing equation
emitters. `joined_codegen.zig` records the MAIN residuals, three local terminal
binding residuals and every global RAM/KIO/Wire residual, in native emission
order. The 47 local source layouts include compact decode, U8 pairs, sponge,
D64, bulk, all service bridges and shared tables. INIT and TEARDOWN are also
recorded, with their original 20 MAIN constraints and three global constraints;
they have no local GKR argument or fabricated Eq/prefix columns.

The external symbolic lane implements the existing verifier lane contract.
Counts, nonempty flags, public words, claims and challenges become independently
named wires. Equal or zero invocation values do not decide parameter aliasing.
Cold semantic parameter slots are retained separately from live parameter
values and enter the executable identity. Polynomial recording rejects inverse
operations instead of silently recording a non-polynomial AIR.

Sponge MAIN now accepts the same typed row-count representation already used
by bulk MAIN. Its native u32 path is unchanged. Global sponge projection accepts
a typed first permutation ID and delegates to the original tuple emitter.
The integer wrappers remain available to existing native consumers.

The final ten input columns in the joined domain recorder are **uncommitted
public Eq auxiliaries**, not PCS tree columns: two anchors followed by eight
carry coordinate polynomials. The proof controller must construct and evaluate
them from the admitted GKR point and folded role domain. Passing arbitrary
auxiliaries or using the generated kernel as a standalone acceptance check is
not valid. Current masks, previous prefixes and the Eq +2 mask preserve the
native signed global-circle offset semantics.

`composition_codegen.emitOods` lowers authenticated masks as full OM31 values.
It does not reuse the base-field domain input sorts. It retains native reverse
RLC powers and multiplies by a secure vanishing inverse. The fixture exporter
checks all nine native MAIN authorities at arbitrary extension-field masks and
also generates a synthetic mixed-offset/repeated-root case. The CUDA smoke
driver launches multiple blocks deliberately; only the first thread may write
the single-point output. This is numerical qualification, not PCS authentication.

## Evidence at this checkpoint

- ReleaseSafe and ReleaseFast integration suites: 56 tests pass, including real
  CUDA FFI compilation.
- All 47 local joined DAGs have degree at most three at every emitted root.
- INIT/TEARDOWN have 16 interaction columns and 23 residuals, with no local Eq.
- Executable tests bind descriptor labels and semantic parameter maps while
  allowing invocation values to change.
- Sponge call and permutation MAIN match native OM31 residuals at arbitrary
  extension-field rows for public counts 0, 1 and 17.
- Native physical Keccak sponge suite passes after the typed-public refactor.
- RTX5090 OODS: all ten cases match native OM31, with zero errors from
  memcheck, racecheck, initcheck and synccheck. Domain regression passes all
  20 cases and 12,446 signed mask positions; the ten domain kernel bodies are
  byte-identical to their earlier qualified versions.
- Sharing a noinline multiply body for single-point OODS bounds AOT code size.
  The revised build took 66 seconds. The superseded fully inlined build was
  still active after more than fourteen minutes and was stopped after the new
  implementation passed. This is compile-time evidence, not a prover speedup.

Remaining: native-versus-recorded complete joined residual parity, generation
and device qualification of the joined role kernels, typed runtime metadata
framing and Eq/prefix witnesses, classic truth interactions, PCS/OODS/DEEP/FRI
controller and openings, serialized proof framing, complete manifest closure,
and an independently accepted GPU-generated Ethereum bundle. No new security
profile or block performance claim is made by this slice.
