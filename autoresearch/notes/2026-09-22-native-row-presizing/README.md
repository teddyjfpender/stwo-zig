# Pre-sized native hash rows reduce preparation retention

A preparation-only census now reports live row bytes, current ArrayList capacities
and retained arena capacity using the canonical assembler. Its baseline found
118,184,432 live bytes and 127,857,280 current buffer bytes inside an arena retaining
461,490,727 bytes. G rows alone account for 96,839,680 live bytes; byte routes
7,999,608 and XOR rows 3,557,376. Most retention was outside current live buffers.

The assembler now reserves exact live/fixed capacities for G, XOR and byte-route
cohorts before population, using checked sums of already prepared transcript/path
lengths. Both cohorts still pass the existing append metadata checks. No extra
value pass, new row copy, protocol change or guessed capacity was introduced.
Other cohorts retain their existing growth strategy.

## Results

| Measurement | Before | After |
| --- | ---: | ---: |
| Final live row bytes | 118,184,432 | 118,184,432 |
| Current buffer capacity bytes | 127,857,280 | 120,791,952 |
| Retained assembler arena bytes | 461,490,727 | 254,204,293 |
| Handoff retained tracked bytes | 461,491,951 | 254,205,405 |
| Preparation peak tracked bytes | 1,242,103,479 | 1,044,442,891 |
| Worker peak tracked bytes | 1,567,077,617 | 1,567,077,617 |
| Artifact bytes | 116,382 | 116,382 |

Handoff retention falls 207,286,546 bytes (44.92%); preparation peak falls
197,660,588 bytes (15.91%). Allocation counts are not total process RSS, and no
controlled timing-speedup comparison was performed. Same key:
`0fa2bf60222d4e62cf05dbed0c8892a8c8ba39a62b960d22abc2e65975f9fc46`.

## Qualification

Both before/after test-blake3-native-arithmetic-census runs passed 1/1 tests,
10 s / 1 GiB. The audit-only path now assembles and releases canonical rows after
its arithmetic census, without proving a parent. The full native gate then passed
3/3 tests, 41 s / 2 GiB: bounded handoff, row parity, canonical serialization,
independent verification, pipeline and ownership after worker destruction.
All commands used scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu,
-Doptimize=ReleaseSafe --summary all. The full target is test-blake3-native-segment.

Production parameters, reusable statement-independent keys, distinct-child and
parent-of-parent recursion, Metal, complete direct final-layout generation and
separately reviewed parameter experiments remain unfinished. The current result
improves memory footprint, not evidence of subsecond or tenfold proving speed.
