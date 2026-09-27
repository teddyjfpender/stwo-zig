# Real full-STARK capture and complete typed verifier transcript

Previous turn: progress; all standalone PCS trace/FRI paths, DEEP/FRI arithmetic
and PCS transcript were joined with private opening values.

The proof harness now offers an opt-in successful-capture observer. It invokes
core.verifyWithProofCapture only for that path, publishing capture data to the
observer only after full native STARK verification succeeds. Other gates retain
the ordinary verification path. The combined PCS proof now uses this observer.

The observer reconstructs the exact full-STARK fixture prefix: statement marker,
preprocessed/main roots, bulk universal-relation challenge draws, claim marker
and values, and interaction root. A reusable appendStarkVerifier helper then
appends core.verifier's composition-randomness draw, composition root, OODS-seed
draw, and existing PCS opening sequence. It preserves transactional append and
explicit ownership of query storage. A substituted composition root is rejected
without modifying caller channel/prefix state.

This transcript is prepared with existing typed BLAKE3 components and verified
in a SECOND complete CPU STARK proof. Its challenges come from an actual native
full-STARK capture, not the standalone fixture's constant OODS seed. Fixed
columns are reconstructed independently and false preprocessing is rejected.
The second proof disables capture observation, so it creates no recursive test
loop. The original joined PCS proof also remains part of the guarded test.

Command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-combined-fri -Doptimize=ReleaseSafe --summary all
```

Final result: four steps succeeded, one guarded test passed (containing both
complete proofs), approximately 11 seconds runtime and 1 GiB max RSS;
compilation 33 seconds on M5 Max. Formatting and diff checks pass. These are
qualification timings, not production performance results.

Boundary: the second proof proves the transcript of a real STARK. It does NOT
recursively prove that STARK's composition/OODS algebra, interactions or entire
verifier. The first combined PCS fixture still uses its explicit sample seed.
The next integration must feed real full-STARK composition/OODS data and masked
samples into the recursive arithmetic, then qualify production trusted keys,
CPU/Metal and parent-of-parent. This is not parent-of-parent qualification.
Production still uses Poseidon. No end-to-end speed or security gain is claimed;
the full active goal remains unfinished.
