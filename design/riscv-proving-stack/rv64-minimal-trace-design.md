# RV64 minimal trace and parallel per-segment witness regeneration

Status: design plus measurement. No production code was changed. Every number
comes from [capture-throughput-v1.json](../../vectors/reports/rv64-ethereum-20261101/capture-throughput-v1.json)
(source 9dba9705d, M5 Max, 18 logical cores) unless it is labelled as an
estimate or projection. Related: `rv64-result-advice-tape-proposal.md` (a
smaller result tape that still avoids re-execution), roadmap item 9 in
`rv64-competitive-roadmap.md`, and `rv64-cuda-port.md`.

## 1. Measured baseline (pinned round-five block, 104,253,913 steps)

| Stage | Wall | Throughput | Peak RSS | Threads used |
| --- | ---: | ---: | ---: | ---: |
| Pure execution (`rv64-ethereum-execution`, services v2) | 2.58 s | 40.5 MHz | 25 MB | 1 |
| Execution + 48 B compact tape | 2.97 s | 35.2 MHz | 247 MB | 1 |
| Execution + tape + RAM boundary capture | 3.38 s | 30.9 MHz | 291 MB | 1 |
| `nativeprepare` (above + openings/frontier + 6.28 GB fsynced packets) | 12.96 s | 8.0 MHz | 1.52 GB | 1 |
| Driver capture (`plan`, 3 runs: 9.30 / 9.05 / 9.16 s) | 9.16 s median | 11.4 MHz | 12.26 GB | 1 |

There are two serial passes over the execution today. Capture alone takes
3.5x as long as execution, and none of it runs in parallel: in the sampled
run, all 15 pool workers waited on a futex the whole time.

Where capture time goes (`/usr/bin/sample`, 1 ms, main-thread samples):

| Bucket | Share | What it is |
| --- | ---: | --- |
| Packet read | 37% | SHA-256 content digest over each packet (`word16_execution/packet.zig:36`), ROM admission walk (`:43`), syscalls, tape decode |
| CPU replay and fact routing | 47% | `cpu_source.zig:82-114` tape restore and validation, 56 B metadata, ROM counts; `prepared.zig:105-146` routing, BINARY/ALU dedup hash maps, shift grouping |
| RAM and service ledger | 9% | `services/collector.zig:93-177`: one global `AutoHashMap(address -> State)` lookup per LS event and service word |
| Program setup and other | 7% | |

Comparison, using public claims we have not reproduced: zkDTVM claims about
3 GHz execution and 700 MHz record mode. That is 74x our pure interpreter and
20x our tape mode. Their record mode is about 60x our capture rate, and their
records are GPU-native. ZisK's AOT emulator writes a 47-word chunk header plus
memory-read words every 2^18 steps (`zisk-src/emulator-asm/asm-runner/src/asm_mt.rs:34-44`,
`core/src/zisk_definitions.rs:6-7`). It replays chunks in Rust in parallel,
overlapped with the emulator (`executor/src/execution/asm/emulator.rs:206-220`,
`mt_chunk.rs:72-95`), and replays again for witness fill. ZisK's source prints
MHz at runtime but states no number. The lesson is that ZisK and zkDTVM keep
the serial part to execution plus a thin log. We serialize execution, a 6.3 GB
packet write, a hashed re-read and a single-threaded replay.

## 2. How capture works today

1. `nativeprepare` (`rv64_ethereum_native_prepare.zig:62-110`) runs the
   interpreter. Each step goes through `rv64_ethereum_batch.zig:16-29`: a
   `compact_tape.Step` of 48 B (`compact_tape.zig:16-27`, with lhs, rhs,
   previous_rd, result, next_pc, mem index and flags), an 8 B memory-before
   word per LS (`:118-132`), typed Keccak/secp before/after sidecars, and
   per-segment first/last RAM cells (`boundary_capture.zig`). It writes one
   packet per 2^22-1 steps: 6.28 GB, 60.3 B/step.
2. The driver (`ethereum/main.zig:76`, `ethereum/capture.zig:21-66`)
   processes packets in order. For each one:
   - `Packet.read` checks the digest, admission and boundary.
   - `Prepared.captureForCombinedServicesLEv2` restores every step against
     the ROM (`cpu_source.zig:59-116`). Register clocks are segment-local and
     start at 0. It emits 56 B `Metadata` per step plus FUNCTION facts,
     memory records and service records, then routes and dedups the facts
     into ALU/JALR/BINARY/SHIFT/MUL/DIV (`prepared.zig:81-147`; the dedup
     keeps first-occurrence order, `binary_dedup.zig:16-40`).
   - `collector.append` walks LS and service records together in tick
     order and fills each event's `before` State (value, epoch, tick,
     rights) from the global ledger, recording first touches as INIT cells
     (`collector.zig:93-177`).
3. `collector.finish` sorts INIT by address and reads TEARDOWN from the
   ledger (`word16_global_execution/collector.zig:49-57`). `Plan.cpus/truths`
   (`plan.zig:21-87`) size the ladders. Wide MAIN projection
   (`cpu_source.zig:120-151`), the provider sources, and interactions happen
   later inside `E.produceWithOptions` (`main.zig:107`). That later part
   already uses the pool.

Retained after capture: 12.26 GB RSS. Estimated make-up:

| Item | Estimate |
| --- | ---: |
| CPU metadata, 56 B x 104.25 M | 5.84 GB |
| LS events, about 72 B x 33.46 M | about 2.4 GB |
| Dedup'd facts, ROM counts and histograms | remainder |
| Recycler cache | part of the rest (2.19 GB released at trim in the baseline receipt) |

## 3. Minimal trace for our protocol

The unit is a chunk of 2^18 steps. A proof segment stays 4,194,303 steps.
Chunks never cross segment boundaries, so a segment is 16 chunks, the last one
short by one step.

**Chunk header.** About 432 B, so 0.002 B/step:
- segment index (epoch = index+1)
- step offset within the segment
- pc
- x1..x31
- 32 segment-local register clocks (u32), needed only when the offset is
  not 0
- cursors into the memory-word log and the three service-call streams
- first Keccak/ADD/DOUBLE call ids

**Per-step log.** Nothing for non-memory steps. The re-executor recomputes
ALU, branch and next-pc results from the ROM and the register file.

**Memory log.** One u64 before-word per LS step: the 8-byte-aligned word,
the same value as today's `memory_before`. That is 33,457,230 x 8 B =
268 MB. Loads need it for their value. Stores need it for partial-store
merging and LS `before.value`. A later version can drop the before-word for
full-width stores whose address the same chunk touched earlier, but v1 keeps
one word per LS, for simplicity and to keep tape parity.

**Service log.**
- Keccak: 25 before-words per call, 6.6 MB. The after state is recomputed
  with keccak-f.
- secp ADD/DOUBLE: before words per call. The after state is recomputed, or
  logged in v1 to avoid a CPU secp dependency (under 10 MB either way).

**Per segment (from execution).**
- Final pc, registers and register clocks. These are the public boundary,
  equal to the next segment's header.
- Step count.
- Sorted first/last RAM cells (address, first-before state, last-after
  state, rights), as `boundary_capture.Capture` computes today.
- Counts of Keccak/ADD/DOUBLE calls.

**Size.** About 0.29 GB for the block (2.8 B/step), against 6.28 GB of
packets today (21x) and about 1.1 GB for the result-tape proposal (4x).

**Global, computed serially from per-segment boundaries.**
- INIT cells: the first touch of each address across the execution (1,347,207
  words), with values from the static image.
- TEARDOWN cells: the last state of each address.
- Predecessor state for every segment's first-touch cells: the last state of
  that address in any earlier segment. This is a merge over 2,666,553 summed
  segment cells, not over 34.5 M accesses.
- Service id prefix sums and the manifest/declarations (`plan.zig`).

## 4. Parallel regeneration of one segment's full witness

Inputs are the minimal trace chunks, the segment's predecessor table from the
serial merge, the immutable `Program`, and the image. Each worker owns one
chunk. Merges happen per segment, in chunk order.

| Output | Regeneration | Order or merge rule |
| --- | --- | --- |
| CPU 56 B metadata, ROM multiplicities | Re-execute the chunk from the header registers/clocks using the ROM decode (the `cpu_source.zig:82-114` logic with `restore` replaced by `execute`) | Disjoint rows. ROM counts are summed |
| FUNCTION facts -> ALU, JALR, BINARY, SHIFT, MUL, DIV (+DIV support MULs) | Same pass | Per-chunk first-occurrence maps, merged in chunk order, keeping the earliest index and summing weights. This must match the serial first-occurrence order exactly |
| LS events | Same pass gives the effect. Within a segment, the predecessor is the previous access in the chunk, else the previous chunk's last-state map, else the segment predecessor table | Chronological concatenation; epoch = segment+1, tick = 4*(index+1) |
| Keccak / secp service calls (OWNER, FUNCTION and RAM predecessors) | Before-words from the log; predecessors resolved like LS; after recomputed or logged | Call ids from prefix sums |
| REG boundary | Header and final registers/clocks | None |
| RAM boundary (INIT, TEARDOWN) | Serial merge, section 3 | Sorted by address |
| MAIN projection, range histograms, interactions | Unchanged consumers (`materializeMain`, providers, `cpu_interaction`) | Unchanged |

The cross-chunk predecessor inside a segment needs each chunk's first/last
cell maps. That is a small two-level version of the global merge: run chunk
re-execution in parallel, do a short serial fix-up of first-touch entries,
then emit events. Alternatively, keep chunk = segment for LS and parallelize
only across segments. 25 segments over 16 workers already gives about 12x.

Fail-closed rule: the re-executor must check each chunk's derived end state
against the next header and the segment boundary, and check log
cursor/underflow/overflow. The trace is advice, like today's tape. Nothing it
says gains authority; the AIR, ROM and RAM argument still authenticate every
row.

## 5. Cost model and staged plan

The per-segment numbers below are today's serial costs divided by 25:

| Item | Per segment (measured) |
| --- | ---: |
| Packet read | 0.14 s |
| CPU replay and routing | 0.17 s |
| Ledger | 0.03 s |

**Stage 1a. Parallelize the existing capture. No new format.**
- Change: read packets and run `captureForCombinedServicesLEv2` on the work
  pool, one segment per task. Split `collector.one` into a per-segment local
  pass (in-segment predecessors) and a serial pass over first-touch cells.
- Projection (estimate): (0.14+0.17) x 25 / ~14 effective workers ≈ 0.6 s,
  plus serial merge ≈ 0.1 s, plus setup ≈ 0.15 s. That is about 0.9 s against
  9.16 s, roughly 10x.
- Memory: RSS rises a little with packets in flight.

**Stage 1b. In-process handoff.**
- Change: when producer and capture share a process, skip packet files and
  the SHA-256 re-hash.
- Effect: removes 37% of capture and the 6.28 GB fsync write. Most of
  `nativeprepare`'s 12.96 s, against 3.38 s for execute+tape+boundary, is
  openings and packet I/O.
- Distributed packets keep a digest. It can be a parallel hash over the
  smaller minimal trace.

**Stage 1c. Minimal trace v1.**
- Change: the executor logs headers, memory words, service inputs and
  segment cells. Per-segment regeneration re-executes the chunk.
- Re-execution cost is at most the 40.5 MHz pure rate, which includes the
  memory model the replay does not need: under 0.1 s per segment.
- Two-pass (count, then regenerate just before each segment's prove) lets
  the driver stop retaining the 5.84 GB metadata and about 2.4 GB of LS events
  for all 25 segments.
- Projected retained capture memory: about 0.3 GB trace + about 65 MB
  boundary tables + about 0.35 GB per in-flight segment. That is under 1.5 GB
  with two segments in flight, against about 8-12 GB today. It is the
  largest single step toward the 16 GB host target.
- Cost: the count pass re-executes once more; at about 0.3 s of parallel CPU
  this is negligible.

**Critical path after stage 1 (projection).** Execution plus logging at about
35-40 MHz (2.6-3.0 s). Segment regeneration overlaps execution, so add one
segment (about 0.3 s) and the merge (0.1 s): about 3.1-3.4 s, against
12.96 + 9.16 = 22.1 s today, before any proving. Below that, the executor is
the wall. An AOT/DBT executor (zkDTVM-style) is a separate item.

**Stage 2. GPU.**

Kernels:
1. MAIN projection, bit-reverse scatter and range16/range8 histograms
   (atomics).
2. ROM multiplicity histogram.
3. LS predecessor resolution as radix sort by (address, tick) plus a
   segmented scan, which removes the hash map.
4. Fact dedup as stable sort plus run-length, then reorder by first index to
   keep the serial order.
5. Interaction/LogUp generation, already planned in `rv64-cuda-port.md`.

Re-execution stays on the CPU: it is serial per chunk and branchy, as in
ZisK.

PCIe traffic per segment:

| Data | Size | Time on PCIe 5 x16 (~25 GB/s, projection) |
| --- | ---: | ---: |
| CPU-produced narrow records (56 B metadata) | 235 MB | about 9 ms |
| Or: chunk headers, memory words and (c, next_pc) only | about 90 MB | |
| Global INIT/TEARDOWN tables (once) | about 65 MB | |

Committed columns, LDEs and the MAIN matrix never cross the bus; a MAIN
matrix is 1.2-6.5 GB per segment. Gate: device witness byte-identical to the
CPU witness, then identical proof bytes.

## 6. Proof-byte impact

None intended. Bytes stay identical if the regenerated `Prepared`, LS events,
service calls, INIT/TEARDOWN and declarations are bit-identical to today's.

Things that would change proof bytes and must not move:
- segment size or segment boundaries (`batch_steps` 4,194,303)
- epoch/tick numbering
- ALU/BINARY/SHIFT fact order: first occurrence, so the parallel merge must
  keep the earliest index
- LS chronological order
- service id assignment
- INIT sort order
- ladder planning inputs

Chunk size (2^18) is internal and invisible to the proof.

Qualification:
- byte-identical `plan` output on the complete block
- hash equality of all per-segment sources against the serial path
- identical proof files for at least two segments, including a service-heavy
  one (segment 4)
- corruption tests for header, cursor and log

Security note: the packet SHA-256 protects transport integrity, not
soundness. Dropping it is safe only for in-process handoff.

## 7. Status (2026-11-02, branch codex/rv64-ge-capture)

Implemented (no proof-byte change intended; see the commit messages for receipts):

- **Stage 1a (packets).** `rv64-word16-ethereum produce|plan ... --capture-inflight=N`
  reads and captures up to N packets concurrently; every schedule feeds one
  ordered owner (`capture.Ordered`: `admit` then `accept`), which alone advances
  adjacency, step budget, completion and the global ledger.
- **Stage 1b (in-process handoff).** `produce-direct|plan-direct <config> <out>
  <count> [--capture-inflight=N]` runs the execution walk (`native_prepare.Walk`,
  shared with `nativeprepare`) in the driver process. Each batch goes through
  `Packet.fromNative`: the packet reader's identity, statement wire decode,
  ROM/PC admission (`Admission.checkTape`, the same walk as the file check) and
  tape checks; only file framing, the SHA-256 transport digest and the legacy
  Poseidon frontier are not produced. Captures run on helper threads while
  execution continues.
- **nativeprepare pipeline.** Execution of batch k+1 overlaps the ordered
  publication (frontier graph, packet write+fsync, cache advance, descriptor)
  of batch k. Output bytes are identical to the serial binary.

Measured on block 24,628,607 (26.89 M instructions, 7 batches): nativeprepare
4.6-5.3 s -> 3.5-3.7 s; packet capture 3.0 s -> 1.27 s (N=7); in-process
execute+capture 2.2 s (N=4) against about 8.2 s for nativeprepare plus packet
capture. Execution itself (1.6 s of the 2.2 s) is now the floor.

Not implemented: checkpointed parallel re-execution (stage 1c / per-segment
start states). With the handoff overlapping capture, only execution remains
serial; a checkpoint first pass already costs about 0.67 s at the measured
40 MHz pure rate plus per-segment memory snapshots, so the projected saving on
this block is at most about 0.4 s for roughly +2 GB RSS.
