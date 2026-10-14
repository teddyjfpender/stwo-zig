# CAS05 production admission boundary

The draft CAS05 verifier accepts a separate `S31CAS05` wire with outer version
6. The production PCS still uses `CommitmentSchemeProof(H)` with one legacy
`FriProof(H)`, and `CommitmentSchemeVerifier.verifyValuesImpl` builds quotient
FRI answers for `FriVerifier`. The production prover still builds a lazy
quotient provider and commits with `FriProver`. The new in-memory tagged
container admits only the legacy path; no serialized CAS05 proof or production
CAS05 prover/verifier exists.

| Boundary | Current behavior |
| --- | --- |
| Trusted verifier profile | `proof_preflight.Shape`, `Shape5`, and `ShapeFor(N)` carry a `proof_mode`; the default is `legacy_postcard` so existing callers retain their format. The profile must come from the verified statement, never proof bytes. |
| Legacy postcard preflight | Rejects the reserved `S31CAS05` prefix before reading a config or length. Otherwise runs the unchanged allocation-free structural parser. Passing preflight is not proof verification. |
| CAS05-selected profile | Checks the magic, exact outer version 6, reserved field, declared byte count, and maximum length without allocating; then returns `Cas05NotProduction`. A legacy proof, outer version 5, a truncated header, and a wrong declared length all fail separately. |
| Experimental verifier | `paired_sparse_cascade_wire.verifyAgainstStatement` remains separate. Its decoder and statement-bound verifier are not called by production PCS. |

The reserved-prefix check changes no released S31 proof bytes: the current
trusted postcard profiles begin with their configured PoW and FRI varints,
not `S31CAS05`. A future legacy profile whose valid postcard bytes could
begin with that prefix would require a new format decision before admission.

This gate prevents an accidental parser switch. It does **not** make CAS05 a
production PCS. Activation requires a serialized key and proof-container binding,
a prover and verifier dispatch with the full CAS05 transcript and source/line
commitments, an exact statement/claims binding, an end-to-end correspondence
test, and a proved conservative native soundness profile. Until then every
CAS05-selected production preflight fails closed.

## In-memory verifier dispatch slice

`VersionedStarkProof(H)` is an owned tagged union: it carries either the
unchanged legacy `StarkProof(H)` or owned CAS05 wire bytes. It is **not** a new
serialized artifact format. `CommitmentSchemeVerifier.init` still selects the
legacy mode; `initWithTrustedMode` records a mode supplied by a verified key.
`core.verifier.verifySelected` checks the tag against that mode before calling
the legacy verifier. A CAS05-selected verifier rejects the legacy `commit`
and every old `verifyValues` entry point before transcript mutation. A
matching CAS05 wire still stops at `Cas05NotProduction` after its header is
checked. The Native wide-Fibonacci honest proof now passes through the new
legacy dispatch; hostile tests cover swapped modes, outer version 5, and
unchanged channel state on rejection.

The next production slice must define a **serialized** tagged proof artifact
and an authenticated key binding, then connect independently supplied CAS05
statements, source and line commitments, claims, channel replay, and the
complete CAS05 verifier to that tag. The current legacy `StarkProof(H)`
serialization stays byte exact.
Only after the native correspondence and conservative soundness proof can a
CAS05 key become admissible.

## Installed Native artifact binding

The Native CPU `verify --artifact` path now constructs an `InstalledKey` from
the binary's pinned v1 schema, exchange mode, upstream revision, and requested
security policy. `InstalledKey` is caller-supplied in this slice; the Native
product currently installs only this legacy wrapper. It does not authenticate
an S31 serialized verification key. The Native key selects `legacy_postcard`
before the artifact is decoded. The serialized artifact must match the key's
schema/exchange tuple;
the receiver rejects a `pcs_mode` JSON field as unknown, and checks the proof
bytes against the selected format before the legacy proof decoder runs.
The existing v1 artifact writer and bytes are unchanged.

For testing the boundary, schema 2 plus
`proof_exchange_cas05_candidate_v1` is a **reserved candidate** tuple. A
separately supplied CAS05 key can inspect the outer wire magic and version,
but every matching candidate still returns `Cas05NotProduction`. The Native
product never constructs that key. A forged installed-key tuple, mismatched
artifact metadata, mode injection, and version 5 are covered by serialized
artifact tests. This is an envelope admission check, not a CAS05 artifact
standard or an installed S31 verification key.

S31's source-bound embedded key and statement reconstruction live in the
separate `s31` repository. A future engine update must bind its key profile to
this mode and to a final CAS05 artifact schema before any S31 verifier uses
the new route. The CAS05 public statement, commitments, prover, native
verifier, correspondence proof, and conservative soundness profile remain
unimplemented in production.

## Experimental S31 transcript context

The opt-in `proveForS31Statement` and `verifyAgainstS31Statement` wrappers
apply the same typed Blake2s prelude **before** CAS05's `S31CAS06` version tag.
They mix, in fixed order, `S31PRL01`, `S31KEY01` plus the whole installed-key
SHA-256, `S31PUB01` plus eight ABI-reconstructed public words, and `S31RST01`
plus a compiler-owned source-to-AIR roster SHA-256. Every tag is a `mixU64`;
the two digests are eight little-endian `u32` words under `mixU32s`, and the
public words are mixed as eight `u32`s. The CAS05 core then binds its profile,
source commitment root, OOD claims, line roots, terminal coefficients, and
queries in its existing order. The source root comes from the independent
`ExpectedStatement`, not from proof authority.

The focused test compares the prelude digest with an independent Python
`hashlib.blake2s` byte fixture, proves and verifies one candidate wire under
matching context, and rejects changed key, public words, roster digest, and
an unbound proof without advancing the verifier channel. This is a
**conditional transcript contract**: the API accepts a caller-supplied roster
digest and cannot establish that it came from S31's compiler. S31 still needs
to generate an ordered mapping for every preprocessed, base, and interaction
AIR column and OOD claim into the XDM04 hierarchy, then have its installed
verifier reconstruct that mapping. The experimental host can prove arbitrary
degree-bounded source columns, including columns unrelated to any S31 AIR.
No production dispatcher calls these wrappers, and this section makes no
PCS/FRI soundness claim.

Focused check:

```sh
zig build --build-file src/prover/build.zig test-cas05-s31-prelude -j2 -Doptimize=ReleaseSafe
```

Focused checks:

```sh
zig test src/core/pcs_test_root.zig --test-filter 'trusted mode keeps legacy' -O ReleaseSafe
zig test --dep stwo_core -Mroot=src/interop/postcard/proof_preflight.zig -Mstwo_core=src/core/mod.zig -O ReleaseSafe
zig test src/core/verifier.zig --test-filter 'selected verifier rejects' -O ReleaseSafe
zig build test-native-cpu-product -j2 -Doptimize=ReleaseSafe
```
