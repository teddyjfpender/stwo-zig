The old native V2 failure is an authenticated clock-boundary bug already present in commit6084a979, unrelated to the later one-line VerifiedLink lease consolidation. The original proof test uses global-continuous clocks; its resumed final segment covers clocks2–3 with origin1 and local cycle count2. The validator incorrectly required origin0/end2.

An isolated source copy reverted the lease line and reproduced the same failure at `Trace.validateClockRange`: actual origin1, last3, first row2, last row3. The deterministic720-byte ELF, historical source/blame, exact diagnostic source delta, source manifest, executable hash and failed gate log are retained here. The first proof test does not call VerifiedLinkV3.

The fix derives the permitted start/end from the already-authenticated executed span after exact reconstructed-statement equality. It validates both trace clock authority and row endpoints against that span. No trace-supplied origin, clock default, protocol identity or CSP worker policy changed. The original genuine native proof test now also rejects a self-consistent incorrectly rebased trace range and a changed first-row clock.

The exact2-case native proof gate passed, including real nonfinal/final proofs with independent verification and the existing rebased local V3 proof plus lease reuse/mutation checks. The build summary reports1min/4G compilation and10s/1G execution. This is a focused correctness result, not a CSP16-case benchmark promotion.

Command: `python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-riscv-segment-v2-native-proof -Doptimize=ReleaseSafe -Dethereum-proof-strip=true --summary all`.
