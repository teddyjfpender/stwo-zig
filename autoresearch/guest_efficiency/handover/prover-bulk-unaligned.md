# Handover: admitted bulk memory, unaligned memcpy + memcmp

## 0. Resumed 2026-11-02 on `codex/rv64-ge-bulk` (worktree `~/Coding/ge-wt/bulk`)

Status at the end of this session (details in the commits; the sections
below 1-6 are the original paused-state handover, kept for history):

- AIR (`bulk_memory/`): the predecessor's ucopy/cdesc/cmp kinds were already
  green. Review found two zero-length forgeries (memcmp `len = 0` claiming a
  difference after reading outside the operands; unaligned memcpy with a
  lead-only run) and closed both (cdesc length inverse column; `start' (1 - c)
  = 0`). New adversarial tests: both zero-length forgeries (close every
  relation, fail exactly the new constraint), forged equal result, body length
  != descriptor length, forged descriptor length. Constraint counts: ucopy
  134, cdesc 117 (MAIN 61), cmp 148. `test-riscv64-word16-bulk-memory` passes.
- Soundness flag (RAM writers): re-established in
  `design/riscv-proving-stack/rv64-ls-joint-write-induction.md` section 11
  (generic W1-W5 obligations + a per-roster-field case table: keccak, the
  shared secp bridge for add/double/sha256/arith256/curves, bulk x6, sponge).
  Only constraints added: the two zero-length rules. Guard
  `joint_write_invariants_test.zig` now pins the roster fields, bridge kinds,
  bulk kinds and sponge kinds by name and references section 11.
- Services lane: six bulk kinds end to end (types, protocol, statement, wire,
  roster, air_components, worker, pipeline, collector, Ethereum plan/role
  cost, prepared whitelist 0x30003). Extension block (`ucopy/cdesc/cmp`) is
  mixed (`0x424d4532` block), committed and serialized (`bulk_ext` claims,
  `ucopy_rows/cmp_calls/cmp_words`) only when present.
  `services/bulk_ext_fixture.zig`: two real CPU STARKs (unaligned memcpy
  shift 3 in epoch 1; memcmp in epoch 2 reading the copy, stopping at word 1;
  LD observes the result), fresh receiver over the wire; wrong source byte and
  wrong compared word rejected as `UnclosedCombinedRam`; forged result refused
  by the prover's `validateCall` (AIR-level rejection in tests.zig); absent
  extension debts, aligned-only keys and changed counts rejected.
- See section 7 for the measured numbers and what was not run.


Branch `codex/rv64-guest-prover-bulk-unaligned` (worktree
`/private/tmp/stwo-rv64-guest-prover-bulk-unaligned`). Base: bulk-memory branch
`1d2f62e8c`, merged with `origin/codex/rv64-guest-prover-v3-integration`
(`b25175ff6`) in commit `9b94eb0d3`. Scratch:
`/private/tmp/claude-501/-Users-theodorepender-code-cryptography-stwo-zig-rv64-frontend/41eff230-75ab-4f11-a53b-7db4dcd5a611/scratchpad/prover-bulk-unaligned/`
(`build_elf.sh`, `run.sh`, `t.sh`, `census-*`, `runs/`, `elf/`).

## 1. Fallback measurement (done)

Census executor (scratch patch `census-exec.patch`, never committed) on the
candidate guest routing every memcpy/memmove/memcmp/bcmp, 15 blocks:

| memcpy+memmove class | calls | bytes |
|---|---:|---:|
| total | 7,912,300 | 681.2 MB |
| len 0 | 16,717 | 0 |
| overlap | 313 (0.004%) | 0.23 MB |
| same alignment, both 8-aligned (admitted already) | 3,320,634 (42.0%) | 449.9 MB (66%) |
| same alignment, both unaligned | 53,549 (0.7%) | 2.2 MB |
| **mismatched alignment** | **4,521,087 (57.1%)** | 228.9 MB (33.6%) |

Mismatched lengths: 32-63 B 3.26M, 16-31 B 0.50M, 1-7 B 0.49M. They hold
26.2M whole destination words and 19.2M edge bytes (~4.2 per call). Shift
r = (src - dst) mod 8 is spread over 1..7 (odd shifts are the majority).
Overlap is negligible: stays refused. memcmp: 1,726,601 calls, 51.8 MB
requested but only 17.5 MB examined (first difference early; 3.31M words in
an aligned-word model), 35% equal, 94% with both operands 8-aligned, lengths
16-31 (338k, 20-byte addresses) and 32-63 (1.35M, 32-byte hashes). bcmp: 0
calls (Rust lowers slice equality to memcmp). Full table:
`scratchpad/prover-bulk-unaligned/census-summary.txt`.

Decision taken from this: destination head/tail stay in the guest (byte
masks would need dst-before byte columns on every row; measure later if the
remaining gap warrants it); the service takes a dst-aligned body with any
source alignment; memcmp takes 8-aligned operands with the `len % 8` tail
compared in the guest.

## 2. Done and verified

- **Executor** (`src/frontends/riscv/rv64/ethereum_services/bulk_memory.zig`):
  memcpy source of any alignment (source words = words holding a source byte,
  `len/8 + 1` when unaligned, disjoint from packet and destination words);
  memcmp tag `0x30003`, packet `a, b, len, result`, a/b 8-aligned, result
  -1/0/1 written to packet word 3, only words up to the first difference
  read (`examined`). Session/tape/boundary capture/report counters updated
  (`bulk_memcpy_unaligned_*`, `bulk_memcmp_calls`, `bulk_memcmp_bytes` =
  8 x examined). `isBulkTag` includes memcmp; `BULK_MAX_TOUCHED_WORDS` = 4 +
  2 x 2^17. Evidence: `zig build test` in `src/frontends/riscv/rv64` 95/95
  (commit `9b94eb0d3`).
- **Rust guest** (`ethereum/rv64/mem`, feature `admitted-bulk`): unaligned
  copies routed (`STWO_ADMITTED_UCOPY_MIN`, default 16), memcmp/bcmp bodies
  routed (`STWO_ADMITTED_CMP_MIN`, default 8). Host tests emulate executor
  admission (all alignments, word aliasing impossible for byte-disjoint
  ranges, compare order): `cargo +nightly-2026-08-08 test --release` 9/9.
- **evmone glue** (`client_evmone/glue/runtime.cpp`, `services.hpp`): same
  routing (`v3_copy` takes mismatched alignment, `v3_compare`). NOT built or
  run yet.
- **Rust guest basket, full v3 features** (`keccak-service,secp-lean,
  sha256-service,arith256-service,admitted-mem`), profile
  `ethereum_services_v3`, all 15 blocks, every guard passing, exact outputs:

| guest | instr/gas scored | holdout | all |
|---|---:|---:|---:|
| aligned-only (UCOPY/CMP off) | 11.328 | 9.594 | 10.986 |
| + unaligned memcpy + memcmp (16/8) | 10.776 | 9.123 | 10.450 |

  i.e. **-4.9% instructions/gas** on top of the aligned service. Committed
  bits/gas printed by the bench (134,858 -> 129,324 scored) is NOT valid for
  the new variant: `bench.py` `admitted_usage` costs only memcpy/memset keys,
  so unaligned-copy and memcmp rows are uncharged. Logs:
  `scratchpad/prover-bulk-unaligned/runs/v3-{aligned,ucmp16}.log`.

## 3. In progress (uncommitted before this handover commit; now committed)

AIR, `src/frontends/riscv/rv64/air/delegations/bulk_memory/`:

- `layout.zig`: kinds `desc, copy, set, ucopy, cdesc, cmp` (`kinds` array);
  column maps; fraction/range16/ram counts; constraint counts hard-coded
  (`UCOPY_CONSTRAINTS = 133`, `CDESC = 115`, `CMP = 148`, hand-counted; the
  tests assert the sink count equals them).
- `types.zig`: `Op.cmp`, `TOKEN_CMP`, `TOKEN_CMP_RESULT`, `Call.packet: [4]`,
  `examined`, `result`, `shift()`, `entries()`, `body()`, `descriptor()`,
  `compareWords`, `shifted`, generalized `validateCall`.
- `equations.zig`: ucopy (lead row reads source word 0; row r writes
  destination word r-1 = one-hot-shift combination of previous-row and
  current bytes, materialized `out` limbs, degree 3; dst step
  `8 (1 - start')`; token src = aligned + shift; bytes ranged as lo: 2 U16,
  hi: 1 U16 using the canonical source limb), cdesc (ECALL limb0 = 3, 3
  packet reads + result write, emits TOKEN_CMP, consumes result token), cmp
  (prefix equality, `is_one` gadget forcing the run to end at remaining 1,
  `last` <=> diff or is_one, one-hot first differing limb, `hb`, strict
  byte order via `gap = (1 - 2 lt)(da - db) - 1` ranged U16; last row emits
  `[TOKEN_CMP_RESULT, clock, lt, diff - lt]`).
- `source.zig`: `ucopyRow`, `cdescRow`, `cmpRow`, range values, generalized
  `Source` (row maps for descriptor and body kinds).
- `packed_rows.zig`, `component.zig`: buffers enlarged (cdesc is 131 columns).
- `tests.zig`: World/Witness for six kinds; scenario 2 (three unaligned
  copies incl. chained and read-only source, three memcmp: equal, diff in
  limb 2 high byte a<b, diff at byte 0 a>b); honest closure, known answers,
  adversarial: wrong shift (whole run / one row), wrong written limb, wrong
  source byte, non-canonical byte split, skipped word (a/b), lead row writing,
  destination not advancing, flipped lt, desc result mismatch, later limb
  chosen, hb on low-byte difference, early stop claiming diff, early stop
  claiming 0, skipped differing word, running past length, missing cdesc.

State: `zig build test-riscv64-word16-bulk-memory` compiled and ran; all
earlier failures were fixed; the last run (after fixing the past-length test
fixture) printed no failure lines but its summary line was not captured, so
**AIR test status is UNVERIFIED** — rerun first. Expect possible adjustments
of hand-counted constraint counts or individual adversarial expectations.

Not started: services lane plumbing (types `bulk_kinds`/`BulkCounts`/`Bulk`
logs for six kinds, roster/protocol/statement/wire/air_components/worker/
pipeline/collector replay of unaligned copies and memcmp, mass bounds RAM
`6 desc + 4 copy + 2 set + 4 ucopy + 8 cdesc + 4 cmp` per row, U16 per row
`17/6/3/18/16/13`, OWNER `<= 3` per call), Word16 prepared whitelist
(`word16_execution/prepared.zig` line ~106 add 0x30003), protocol transcript
(mix new kinds only when present so existing v3 bundles stay identical),
fixture proof with a fresh receiver, v2 byte identity check, calibration
entries (`memcpy_unaligned`, `memcmp`) + `bench.py` `admitted_usage` keys,
evmone v3 build and basket run, docs (`rv64-bulk-memory-service.md`,
`soundness_review.md`), threshold sweep.

## 4. Next steps

1. `scratchpad/prover-bulk-unaligned/t.sh test-riscv64-word16-bulk-memory 80`
   (wraps `lockf ... zig build <step> -j3`); fix until green; commit.
2. Measured costs from layouts: ucopy MAIN 56 + INTER 60 = 116 cells/row,
   one extra lead row per call; cdesc 60 + 68 = 128 per call; cmp 59 + 52 =
   111 per examined word. Times 1/ln 2 padding. Add to
   `calibration.json admitted_services` and `bench.py` `ADMITTED` map
   (`bulk_memcpy_unaligned_*`, `bulk_memcmp_*`); rescore the two runs
   (`run.sh v3-aligned`, `run.sh v3-ucmp16`).
3. Services lane plumbing + collector (`bulkCall` must replay unaligned
   copies on `sourceWords` and memcmp up to the first difference, reading
   only ledger values) + fixture (`svc/bulk_test.zig`,
   `test-riscv64-word16-bulk-services -Doptimize=ReleaseSafe`).
4. v2 byte identity: `rv64-word16-combined-services-fixture produce` at base
   vs branch.
5. evmone: `python3 -I client_evmone/build.py --out DIR --profile v3`, run
   `bench.py run --client evmone ... --profile ethereum_services_v3`.
6. Docs and soundness review sections.

## 5. Known issues / risks

- Executor and guests now emit memcmp ECALLs and unaligned memcpy that the
  prover does NOT yet prove end to end (no services-lane support): an
  ELF built with `admitted-mem` from this branch is not provable until step 3
  lands. Do not promote.
- The ucopy byte-range argument (hi byte with one U16 lookup) relies on the
  source limb being canonical (joint write induction, strictly decreasing
  edge as for the aligned copy); it must be written up in the soundness doc.
- cmp words are read only up to the first difference; executor requires the
  full ranges readable and disjoint (a superset of what the AIR needs).
- Hand-counted constraint counts may be off by small numbers.

## 6. Resume

```sh
cd /private/tmp/stwo-rv64-guest-prover-bulk-unaligned
U=/private/tmp/claude-501/-Users-theodorepender-code-cryptography-stwo-zig-rv64-frontend/41eff230-75ab-4f11-a53b-7db4dcd5a611/scratchpad/prover-bulk-unaligned
$U/t.sh test-riscv64-word16-bulk-memory 80          # AIR tests
(cd src/frontends/riscv/rv64 && lockf -k /private/tmp/stwo-rv64-perf-build.lock zig build test -j3)
(cd autoresearch/benchmarks/guest_runtime/ethereum/rv64/mem && cargo +nightly-2026-08-08 test --release -j 3)
$U/build_elf.sh $U/elf/NAME.elf sha256-service,arith256-service,admitted-mem   # STWO_ADMITTED_{COPY,UCOPY,SET,CMP}_MIN env
$U/run.sh NAME                                        # 15 blocks, ethereum_services_v3
```

## 7. Verified on `codex/rv64-ge-bulk` (2026-11-02)

Commands (all ReleaseSafe, through memguard, worktree `~/Coding/ge-wt/bulk`):

| Check | Result |
|---|---|
| `zig build test-riscv64-word16-bulk-memory` | pass |
| `zig build test-riscv64-word16-bulk-services` | pass (aligned fixture + new extension fixture, fresh receiver, mutations) |
| `test-riscv64-word16-memory` | pass (writer guard now an inventory pinned to joint-induction section 11) |
| `test-riscv64-word16-v3-services`, `-word16-combined-services`, `-word16-global-execution`, `-execution`, `-ethereum-chain` | pass |
| v2 byte identity: `rv64-word16-combined-services-fixture produce` | all seven files equal the golden sha256s (`bundle.json` be49c88c...) |
| v3 identity vs base `4e4b38a62`: `produce-v3 sha256`, `produce-v3 all` (aligned bulk) | every file byte-identical |
| `python3 -I autoresearch/guest_efficiency/test_bench.py` | 41 OK |

evmone v3 client with `umem` now default (`build.py --profile v3`, ELF
sha256 9f3509f0...f529), 15 blocks, `--profile ethereum_services_v3`, shared
executor, all guards G1-G6 pass, exact outputs:

| Set | aligned-only v3 (merged head) | + unaligned memcpy + memcmp |
|---|---|---|
| scored instr/gas | 4.778 | **4.525** (-5.3%) |
| scored committed bits/gas | 67,192 | **64,978** (-3.3%) |
| holdout instr/gas, bits/gas | | 3.854, 55,020 |
| all instr/gas, bits/gas | | 4.392, 63,012 |

The bits/gas now charges the new kinds: bench.py `ADMITTED_REPORT_FIELDS`
gains `memcpy_unaligned` (bulk_memcpy_unaligned_calls/bytes) and `memcmp`
(bulk_memcmp_calls, bytes = 8 x examined words); the earlier 64,650 figure left
them uncharged. Basket usage (15 blocks): unaligned memcpy 626,931 calls /
92.8 MB; memcmp 11,675 calls / 149,376 examined bytes (the evmone client
routes far fewer memcmp than the Rust guest census).

Costs in `calibration.json admitted_services` (LAYOUT TIER, from the proven
component widths; no complete-block proof was run, coordinator-scheduled):
memcpy_unaligned 321.6 cells/call (measured desc 154.3 + one 167.35 lead
row) + 20.92/byte; memcmp 186.1/call + 20.02 per examined byte. Replace with
complete-block measurements (roster.json `bulk_ucopy`, `bulk_cdesc`,
`bulk_cmp`) when a v3 block proof with this client is run.

Not done / open:
- Complete-block or prefix proof with the umem client (not allowed for
  agents; the Ethereum plan now assigns ucopy/cdesc/cmp logs, untested at
  block scale).
- Rust guest: `admitted-mem` already routes unaligned copies (UCOPY_MIN 16)
  and memcmp (CMP_MIN 8) by default (not gated); not re-run on the basket this
  session.
- Recursion and `services/gkr_local` do not know the bulk components.
- `ethereum/role_cost.zig` family switch lists only 5 families (pre-existing,
  not compiled by the suites run here).
