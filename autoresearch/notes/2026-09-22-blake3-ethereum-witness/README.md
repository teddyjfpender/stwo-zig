# Full-width BLAKE3 Ethereum witness integration

The Ethereum preparation owner builds BLAKE3 program and memory commitments
from native, Keccak and signer-recovery retirement tapes. It reuses the existing
precompile witness generators and validates their independently retained call
and retirement records. Native geometry accounts for external retirements
explicitly; the base-only verifier continues to require zero external steps.
All native, clock, extension-caller and BLAKE3-provider lookup demand enters one
census before table columns are finalized. No legacy program/memory/Poseidon
commitment witness is constructed in this path.

The Ethereum interaction generator is now independently reusable and owns its
output columns. Legacy orchestration invokes this same implementation, with
explicit ownership transfer into its existing commit API. Extension challenge
drawing can append its 26 challenges to an already drawn native relation set,
so native BLAKE3 providers and external callers share the same base challenges.
The legacy draw schedule is unchanged.

The new test executes both a signer recovery and a Keccak call, checks complete
program-fetch inclusion, explicit external-retirement accounting and rejection
by the base-only protocol. It then generates all interaction columns and checks
global LogUp closure with the extension claims; removing those claims must fail
closure. This validates witness/bus integration, not a STARK proof.

Extension-specific statement/key/transcript admission, component assembly, proof
codec, recursive capture and production routing remain unfinished. No speedup
or completed precompile migration is claimed.

The first fixture run failed with OutputAddressNotAccessed because it did not
publish an output length. The self-loop Ethereum fixture now explicitly stores
an empty output length; the original ECALL fixture is unchanged.

A subsequent fixture omitted the output-length word from `output_words`, even
though empty output still publishes that memory access. Its global relation
sum was nonzero. The fixture now copies all runner output words and clocks.
The preparation owner additionally checks input bytes/padding, output geometry,
all output words/clocks and completion against the runner before allocation of
extension witnesses. A missing output-length word is a focused rejection case.

## Qualification results

```sh
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments -Driscv-test-filter='Ethereum external witness census' -Doptimize=ReleaseSafe --summary all
```

Passed in 4 minutes / 12 GiB peak RSS for the build/test gate. The executed
fixture contains one signer recovery and one Keccak call, with two explicitly accounted
external retirements in the runner trace. Full interaction generation closes
the native + BLAKE3 provider + Ethereum relation sum; removing the extension
claims does not close it. No legacy commitment components are present.
This timing is not a proving benchmark.

```sh
STWO_CSP_FIXTURE_ROOT=/Users/theodorepender/code/cryptography/stwo-zig/vectors/riscv_csp python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-csp-ecdsa -Doptimize=ReleaseSafe --summary all
```

The existing canonical ECDSA proof path passes 1/1 tests after the shared
interaction-generator extraction, with independent verification and tamper
rejection at q70/PoW26. This remains the existing memory contract with BLAKE3
PCS/transcript, not the new full-width witness path. One ReleaseSafe CPU sample
reported execution 832,166 ns, proving 1,442,694,542 ns and verification
229,014,833 ns, 1,828 cycles and 3,748,258 proof bytes. It is a regression check,
not a replacement for the ReleaseFast CSP benchmark matrix. The initial command
omitted STWO_CSP_FIXTURE_ROOT and failed before executing the proof; rerunning
with the documented fixture path passed using the cached binary.
