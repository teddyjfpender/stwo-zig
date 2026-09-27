# Native BLAKE3 terminal coefficient encoding

FRI terminal coefficient input bindings now connect to their canonical transcript
felt payload through scalar-source, QM31-pack and field-byte AIR rows. The adapter
validates the FRI graph/evaluation and transcript plan, derives coefficient nodes
from semantic graph bindings, and requires exactly one matching trusted/live
receipt with exact source, operation and word counts. Each graph coordinate must
match the corresponding transcript value. Missing or changed payloads reject.

Common row construction now lives in blake3_scalar_payload_rows. Both the native
claim/sample adapter and the terminal adapter use it. It emits each scalar with
graph use count plus one pack consumer, packs once, and emits encoded words with
the exact transcript read counts. All fixed witness cells remain zero. The native
transcript exposes its terminal source constant to avoid duplicated namespace
assignments. No new AIR, hash primitive or protocol framing was introduced.

The native integration gate checks terminal value/encoding parity and fixed
schedules, rejects a missing receipt and altered coefficient payload, and retains
all earlier native claim/sample tests against the shared implementation.

Serial command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment -Doptimize=ReleaseSafe --summary all
```

Terminal exit 0: 4/4 steps and 3/3 tests passed. This profile has one terminal
coefficient, fully linked across its four scalar coordinates. Compile 59 s /
4 GiB; tests 20 s / 1 GiB. Formatting and git diff --check pass. No broad suite
ran and no live build remains. This is a q1/PoW0 native
qualification case, not a canonical CSP result or a speedup measurement.

Scope: row preparation; the complete native parent still needs to include these
rows, shared query/path connections and public-boundary authority. Production key
admission, statement-independent preprocessing, Metal and parent-of-parent
qualification remain open. Existing guest/state Poseidon semantics are unchanged.
