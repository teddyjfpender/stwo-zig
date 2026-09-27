---
title: Authenticated AOT BLAKE3 canonical ECDSA verifies at 0.882 seconds
author: Teddy Pender
created_utc: 2026-09-22T11:45:55Z
---

# Canonical BLAKE3 ECDSA on authenticated Metal AOT — 2026-09-22

Full guest proof, independent verification and shared negative checks pass with
precompile enabled, 70 queries, 26 PoW bits and 16 workers. One ReleaseFast sample:
execution 0.000743667 s, proving 0.881876417 s, verification 0.085001875 s,
1,828 cycles, 3,748,258 proof bytes. This is approximately the historical 0.882 s
baseline, not a demonstrated improvement or statistical comparison. Runtime/AOT
initialization occurs before the measured proof call.

The freshly built core-v2 bundle binds current source SHA256
c38849ca672c5693733eabe67302037dd34c4630249c95be25193274f9812366, ABI 22,
Metal 3.1 safe math, warnings-as-errors, Xcode 26.6. Authenticated runtime admission
validates the manifest/artifacts; explicitly selected AOT mode cannot switch to
source JIT. Manifest and trust anchor are archived. Generated source/AIR/metallib
remain locally at /tmp/stwo-blake3-core-aot-20260922, and the manifest pins them.

Whole-test telemetry: 128 Metal dispatches, 5 small circle LDE fallbacks, and
25 host composition component placements. The latter are deliberately excluded
from cpuFallbackTotal (see telemetry.zig); the initial diagnostic log labels all
cpu_* fields CSP_METAL_FALLBACK, so that line must not be interpreted as 25
additional fallback events. None of these counters isolate the successful proof
from negative checks. This is a hybrid CPU/Metal proof, not all-device execution.

Commands:

```
python3 scripts/zig_serial_build.py --cwd . metal-core-aot -Doptimize=ReleaseFast --summary all
zig-out/bin/metal-core-aot build --output-dir /tmp/stwo-blake3-core-aot-20260922
STWO_CSP_FIXTURE_ROOT="$PWD/vectors/riscv_csp" STWO_CSP_PROFILE=1 python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal test-blake3-csp-ecdsa-aot -Dmetal-core-aot-bundle=/tmp/stwo-blake3-core-aot-20260922 -Doptimize=ReleaseFast --summary all
```

Tool build 2/2 steps; bundle build exit 0; proof gate 3/3 steps, 1/1 test,
2 s test run / 482 MiB max RSS, compile 1 minute / 4 GiB. Existing JIT and new
AOT targets use the same test binary with explicit runtime-mode environment.
Missing/non-absolute bundle configuration fails the AOT build target.

Remaining: full CSP suite qualification with BLAKE3 CPU/Metal, isolated successful
proof telemetry, captured work receipts, default suite promotion, production
recursion, and remaining prover-owned Poseidon statement identities.
