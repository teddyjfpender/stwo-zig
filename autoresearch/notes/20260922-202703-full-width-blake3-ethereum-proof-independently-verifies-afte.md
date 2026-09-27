---
title: Full-width BLAKE3 Ethereum proof independently verifies after witness destruction
author: Teddy Pender
created_utc: 2026-09-22T20:27:03Z
---

# Full-width BLAKE3 Ethereum proof integration

The explicit Ethereum proof API now joins native execution, full-width BLAKE3
program/memory components, and the existing fourteen Ethereum extension AIRs.
B3EH/1 transcript and B3HK/1 key domains distinguish this profile from base B3EX
and the existing Ethereum outer-suite migration. Native opcode authority,
public execution, external-retirement geometry, provider schedules, hash AIR
semantic digests, coefficient admission and the independently derived fixed
root all enter admission. Proof claims cannot select their own verifier key.

Persistent verifier preparation owns public I/O and commitment schedules, derives
all three PCS column-log arrays independently, retains the admitted fixed root,
and releases preprocessing columns after deriving it. Proving checks the owner
against the caller-pinned key before consuming its interaction phase. Verification
consumes its proof on success and failure and compares the final transcript.

The Ethereum coefficient certificate now derives native demand plus conservative
BLAKE3 provider bounds from the admitted physical hash domains; every physical
LogUp batch contributes at most two event slots. Memory bounds include external
callers, clock rows, ordinary memory boundaries, register boundaries and exact
public I/O terms. All arithmetic is checked and bounds must stay below M31.
The certificate must be recomputed from verifier-derived provider geometry.

Legacy and new paths share extension main-column extraction, selector generation,
interaction generation, and concrete AIR constructors. The new placement follows
native components and the BLAKE3 roster. No scalar-root compatibility statement
or legacy memory/Poseidon component is used to admit this profile.

Qualification command:

```sh
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments -Driscv-test-filter='Ethereum full proof independently' -Doptimize=ReleaseSafe --summary all
```

The fixture executes one signer recovery and one Keccak call. It uses diagnostic
q8/PoW0 on CPU and tests wrong-key admission, coefficient-certificate mutation,
prover-witness destruction and independence from subsequently mutated source
public-I/O storage. A successful run is not canonical CSP or Metal qualification.

Artifact codec, recursive extension capture, canonical/Metal qualification,
production routing and removal of production Poseidon paths remain unfinished.
No end-to-end speedup or complete migration is claimed.

## Full-proof result

Passed: the CPU proof and independent verifier agree on the final transcript
after the execution witness is destroyed and caller public-I/O storage is
mutated. Wrong-key proving fails before interaction generation; modifying the
admitted memory coefficient certificate fails admission. The complete gate
reported 10 minutes / 30 GiB peak RSS with four proof workers, q8/PoW0, one
signer recovery and one Keccak call. This includes construction and verification
and is not a stage-isolated benchmark or speedup comparison.

The first compile exposed distinct anonymous enum types in the shared PCS
column-log helper. A named ColumnTree type is now shared by both call paths.

The separate witness regression also passes in 4 minutes / 12 GiB with the new
admission certificate. Its closure helper uses the caller's existing worker
pool rather than attempting a nested ScopedPoolBinding. This change affects
only the witness-only branch, not the already-qualified full-proof branch.

The existing canonical CSP ECDSA path passes 1/1 tests after the shared main,
selector and assembly refactors (ReleaseSafe, q70/PoW26). The gate reports
1 minute compilation / 4 GiB and 2 seconds execution / 1 GiB. Its serialized
proof remains 3,748,258 bytes. This regression still uses the existing public
memory contract with BLAKE3 PCS/transcript, not the new B3EH full-width path.

```sh
STWO_CSP_FIXTURE_ROOT=/Users/theodorepender/code/cryptography/stwo-zig/vectors/riscv_csp python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-csp-ecdsa -Doptimize=ReleaseSafe --summary all
```
