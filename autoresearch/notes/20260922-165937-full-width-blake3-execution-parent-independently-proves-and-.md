---
title: Full-width BLAKE3 execution parent independently proves and verifies
author: Teddy Pender
created_utc: 2026-09-22T16:59:37Z
---

# Full-width execution parent assembly and explicit proof API

The execution path now owns a complete preparation from an independently
admitted child capture through composition/public closure, DEEP, FRI, transcript
routing, trace/FRI openings, query projection, terminal coefficients and roots.
The existing parent row assembler accepts both the earlier five-graph native
adapter and the new three-graph execution adapter. Roster storage and input
inventory are shared modules; secure packing rows count as graph-input producers.
Missing/duplicate producers are rejected, with an exception only for genuinely
unused secure composition inputs. No prover-owned Poseidon provider is added.

Preparation reuses the existing hash layout and writes transcript/path witnesses
directly into final main columns. Column ownership transfers only after successful
assembly. The real-proof test removes a secure claim producer, checks rejection
and retained column ownership, restores it, then assembles successfully. All
13,738 inputs are accounted for. Retained rows and columns total 526,596,548 bytes.
Shared arithmetic fusion selects 3,119 dot4 and 10,080 multiply-add matches;
PCS/query fusion removes 5,024 scalar producer rows across 1,256 groups. These
counts are structural observations, not a measured end-to-end speedup.

The explicit execution-parent key has its own BLAKE3 domain and binds the full
child key ID, child parameters, three graph identities, transcript plan identity,
parent geometry, AIR/registry identities and parent preprocessing root. The
existing persistent proving plan, artifact envelope, bounded decoder and
independent verifier accept that protocol authority through shared APIs. The
legacy parent protocol retains its original entrypoint. Artifacts now also
reject a proof configuration that disagrees with admitted parameters.

Qualification uses the real four-instruction child program and diagnostic
q8/PoW0 for both child and parent. This does not qualify canonical security
parameters, multiple recursion levels, continuation/extension orchestration or
production default promotion. The original performance and scheduling goals
remain active; no 10x or subsecond recursion claim is made.

## Verified results

`python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments -Doptimize=ReleaseSafe --summary all`

Passed: the complete real-child-to-parent proof, key substitution rejection,
artifact encode/decode and independent parent capture. The proving plan is
released before verification. The parent artifact is 124,866 bytes. Build/test
time was 2 minutes with 5 GiB peak RSS; this is not isolated proving latency.

`python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-arithmetic-census -Doptimize=ReleaseSafe --summary all`

Passed 1/1 existing native census test (11 seconds runtime / 1 GiB, 1 minute
compile / 4 GiB). That path retains its duplicate/missing producer attacks and
uses the same refactored assembler, inventory, storage and fusion code. No full
repository suite was run. The explicit API is exported as frontend
`prover.blake3_execution_parent` and CPU integration `Blake3ExecutionParent`.
