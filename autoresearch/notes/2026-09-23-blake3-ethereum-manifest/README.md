# Full-width Ethereum admission manifest

The B3EHADM1 wrapper authenticates the extension statement and native admission
metadata under one externally supplied identity, before extension decoding or
schedule allocation. It reuses the existing bounded typed statement/plan codec.
A profile context validates external retirement counts and binds the Ethereum
protocol transcript, including coefficient admission and extension semantics.
The unchanged base entry points retain base-only validation and wire format.

Hash trace geometry can now be derived from an admitted plan without allocating
fixed/main columns or typed definitions. Both the witness owner and this manifest
use the same count-to-domain sizing rule. Source admission explicitly supports
base and Ethereum profiles with exact ELF-note/release-ABI validation and actual
full-width program/initial-memory root reconstruction.

The existing signer/Keccak fixture now carries a full release ABI and reconstructs
its PreparedVerifier from decoded metadata, releasing that metadata before proof
generation. It checks wrong source, pre-allocation rejection of altered extension
metadata, base-profile rejection of Ethereum metadata, and geometry parity.

Qualification pending:

    python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments '-Driscv-test-filter=BLAKE3 execution commitment Ethereum full proof independently verifies' -Doptimize=ReleaseSafe --summary all
    python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments '-Driscv-test-filter=BLAKE3 execution commitment real runner proves' -Doptimize=ReleaseSafe --summary all

Logs: /tmp/blake3-ethereum-manifest-canonical-proof.log and
/tmp/blake3-shared-manifest-base-regression.log. The first is canonical q70/26;
the second preserves the qualified base artifact contract after shared-code
extraction. No full-width Ethereum product artifact or default promotion is
claimed yet. This supports existing signer/Keccak functionality, not expanded
Ethereum block proving.


## Canonical manifest proof passed

The q70/26 Ethereum signer/Keccak gate passed: witness released, independently
admitted key reconstructed from decoded manifest, proof codec round-trip and
capture mutation checks succeeded. Log: canonical-manifest-proof-pass.log.
This run predates the complete B3EVART1 outer artifact and product routing.
