---
title: Witness-independent BLAKE3 parent verification and owned capture qualified
author: Teddy Pender
created_utc: 2026-09-22T03:44:27Z
---

# Witness-independent native BLAKE3 parent verifier

The parent now has an owned in-memory proof artifact and a canonical verifier
entrypoint. Verification accepts only that artifact and a verifier-pinned key
admission. It reconstructs typed verifier components, lookup-table verifier
components, parameters and PCS column logs from the canonical roster/key. It
accepts no prover components, witness rows, preprocessing columns or prepared
arithmetic owners. The shared roster implementation moved to
`blake3_component_roster`; standalone gates retain thin compatibility names.

Artifact admission checks the external key pin, exact four-commitment shape,
trusted preprocessing root, canonical public claim coordinates and global
claim cancellation. Verification replays the dedicated BLAKE3 transcript and
calls core verification with capture. The artifact proof is consumed on every
success/error path. Successful output owns a verified capture, final channel,
key identity and public claims, suitable for the next recursion handoff.

A parent-specific claims domain changes the transcript, so the native-parent
protocol is explicitly version 2 with a new identity domain. Version-1 keys
reject; there is no legacy fallback. Observed diagnostic version-2 key:
`f76d51b30dce850ad74060c42808bed2f4dd5bee6cc5705673f00b4754d3c976`.
This is test evidence, not a production trust pin.

The real parent proof is verified through this entrypoint. Tests check:

- Wrong artifact key, root and non-cancelling claims reject admission.
- A decoded proof copy with the wrong key is consumed on early rejection.
- Another copy changes two claims by opposite amounts, preserving global
  cancellation. Admission passes, core verification rejects with OodsNotMatching,
  and the rejected proof is consumed.
- The valid proof is consumed and returns a capture with four commitments and
  eight outer queries. The independent verifier's final channel matches proving.

Proof copies use existing postcard serialization/decoding; failure tests do not
regenerate proofs. An external parent artifact envelope/codec is still pending.

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment test-blake3-combined-fri -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment -Doptimize=ReleaseSafe --summary all
```

Initial batch: terminal exit 0, 8/8 steps and 4/4 tests. The version bump and
stronger ownership/claim tests then passed the final native gate: terminal exit
0, 4/4 steps and 3/3 tests, 37 s / 2 GiB, compile 1 min / 5 GiB. Combined-FRI
passed in the initial batch (32 s / 7 GiB) and was not repeated after native-only
changes. Formatting and git diff --check pass. No build remains live.

Still diagnostic: q1/PoW0 child and q8/PoW0 parent. Production defaults and old
Poseidon artifacts remain unchanged. Remaining: bounded external artifact
codec, standalone producer/API integration, stronger security-profile
qualification, statement-independent keys, Metal, binary aggregation and
parent-of-parent qualification. No speedup is claimed from these proof gates.
