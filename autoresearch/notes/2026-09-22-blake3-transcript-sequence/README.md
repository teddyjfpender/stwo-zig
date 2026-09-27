# Native BLAKE3 transcript sequencing — 2026-09-22

The previous turn proved absorption into a private-state draw. This turn removes
caller-selected counters and state links for supported operation sequences.

`blake3_transcript_witness.zig` compiles integer absorption and secure draws into
existing typed hash, challenge and routing components. The native pinned initial
digest supplies initial boundary words. Each absorption creates a new private
state producer and resets the draw counter to zero. Draws preserve that producer
and advance the counter by their exact rejection-prefix length. Producer copy
counts accumulate across draws and the next absorption. All namespaces are
allocated from operation order and checked before building the witness.

Trusted preprocessing follows the same operation graph without evaluating
private state hashes. Initial state bytes, integer payloads, expected scalar
outputs and the operation schedule are public in this gate. Intermediate states
remain outside the public statement; that is not a zero-knowledge claim.

Focused command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-transcript-sequence -Doptimize=ReleaseSafe --summary all
```

The test sequence is mixU64(198), drawSecureFelt, drawSecureFelt, mixU64(42),
drawSecureFelt. Native output parity and counter reset are checked, as are exact
fixed columns across all five AIRs, changed post-reset outputs, zero attempts,
namespace overflow and every backing allocation failure for absorption plus draw.
The complete proof uses this same builder and real table providers, with trusted
preprocessing rebuilt independently. It includes changed-output and substituted
preprocessing-root rejection checks.

Scope remains explicit: integer absorption and secure draws are supported. Root,
word and secure-field absorption, raw query draws, PoW, private payload encoding,
production transcript/source admission, protocol/key identities and CPU/Metal
parent-of-parent qualification remain. Development proofs use eight queries,
blowup 1 and zero PoW; no production-security or speed claim is made. Production
still selects Poseidon and the original recursion optimization goal remains active.

Both guarded tests pass, including the complete core-verifier proof. Total test
runtime was approximately 3 seconds, max RSS 357 MiB on M5 Max; compilation took
21 seconds. Formatting and diff checks pass. New source files remain below the
manual source-size ceiling. Source snapshots and terminal test logs are pinned
without altering prior evidence.
