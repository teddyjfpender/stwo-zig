# Bounded BLAKE3 transcript and joined parent

The transcript now offers prepareBounded/trustedBounded with a verifier-owned
retry capacity. Consecutive secure draws consume authenticated private u64 counter
ports. Absorptions reset to a shared public zero counter; PoW preserves the port.
Empty query operations preserve both counter value and producer. Nonempty raw
query blocks use the checked counter-step AIR with increment one, without field
reduction or rejection sampling. Producer read multiplicities come from the next
consumer's frame and counter receipts.

The joined STARK parent fixture uses capacity three, independent of recorded
attempt metadata. Its roster adds the existing retry-control and counter-step
AIRs (16 total). No new constraint identity or native protocol framing is needed.
The legacy ordered-draw API remains a regression oracle. The legacy logs() helpers
cover only their original rows; bounded consumers must also include control and
counter AIRs, as the new complete proof and parent fixture explicitly do.

The main serial ReleaseSafe batch exited zero: 16/16 steps, 5/5 tests. Bounded
transcript: 5 s / 503 MiB (compile 25 s / 1 GiB); query batch: 556 ms / 4 MiB;
legacy transcript: two tests, 4 s / 394 MiB; joined parent: 31 s / 6 GiB
(compile 40 s / 2 GiB). These are qualification-test diagnostics, not matched
performance benchmarks or evidence of a speedup. The parent gate produces and
verifies its original child fixture and the combined parent, not a parent-of-parent.

The final edge-case regression exited zero: 4/4 steps, 1/1 test, 9 s / 504 MiB
(compile 25 s / 1 GiB). It constructs and verifies two complete CPU transcript
proofs with independent trusted preprocessing. The expanded transcript
uses the genuine rejection fixture, consecutive single/bulk draws, an intervening
empty query, absorption resets, a partial multi-block query batch, PoW non-reset,
and raw 0xffffffff extraction followed by a secure draw. All recorded attempt
counts are replaced with zero: live rows must remain identical and trusted fixed
rows must match. Capacity exhaustion and zero capacity are rejected; a wrong
public challenge's preprocessing is rejected by the complete CPU proof gate.

Remaining: verifier-key capacity class/overflow admission, witness-independent
lifted alias consistency, production key/artifact integration, Metal support,
CPU/Metal parent-of-parent qualification and matched end-to-end performance.
An initial expansion of the test appended the pinned rejection seed after an
existing transcript, incorrectly assuming absorption resets its digest. Its
boundary assertion failed. The final test correctly initializes an independent
transcript for the raw-word fixture; absorption only resets the draw counter.
No prover implementation change was needed for that test-fixture correction.

Production still uses Poseidon. Capacity three here is a fixture choice, not a
production availability guarantee or a security-parameter reduction.

Formatting and git diff --check passed. All build sessions reached terminal exit.
Only focused gates ran; repository-wide tests were not rerun.
