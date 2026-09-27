---
title: Native BLAKE3 root and nonce source joins qualified
author: Teddy Pender
created_utc: 2026-09-22T02:46:03Z
---

# Native BLAKE3 root and PoW nonce word producers

The adapter admits the concrete verified native BLAKE3 capture and statement,
checks their public-wire and authority identities, and independently calls the
native statement-derived preprocessing-root verifier. Root zero becomes eight
fixed boundary words; it is not admitted merely because the proof supplied it.
Other trace/FRI roots use bounded private-word rows. Each root word emits for its
exact transcript reads plus one path-root check per query. Canonical root slots
and operation values must agree with the capture and trusted/live read schedules.

Both interaction and PCS PoW nonces use the same bounded-word AIR. Each must have
exactly one PoW receipt and one integer-absorption receipt at its designated source
slot, with consistent values. Their word multiplicities are the sum of those two
receipts. The producer retains all 64 nonce bits. No new AIR or hashing was added.

The native integration gate checks fixed-word schedules and expected row counts,
rejects missing root receipts, and rejects changed root and nonce operations.
Earlier native arithmetic, transcript, path and opening-source checks remain.

Serial command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment -Doptimize=ReleaseSafe --summary all
```

Final terminal exit 0: 4/4 build steps, 3/3 tests passed. The capture produces
188 private-word rows (23 private roots and two 64-bit nonces) plus eight fixed
preprocessing-key boundary rows. Compile 1 min / 4 GiB; tests 23 s / 1 GiB.
Formatting and git diff --check pass. No broad suite ran or live build remains.
This remains a tiny q1/PoW0
qualification case, not a canonical CSP or production performance result.

Remaining: public-boundary/native-sum authority and its shared relation challenges,
then include all prepared rows and arithmetic in a complete native recursive
parent STARK. Statement-independent keys, production artifact admission, Metal
and parent-of-parent qualification remain open. Preparing these source rows is
not itself a complete parent proof or proof-speed improvement.
