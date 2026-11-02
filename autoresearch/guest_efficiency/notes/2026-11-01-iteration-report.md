# Guest efficiency iteration, 2026-11-01

**Validated progress, not ziskethone parity.** The final scored result is
**13.180380280 instructions/gas and 151,694.817 proxy committed bits/gas**.
This is 5.0475% fewer instructions and 4.4282% fewer proxy bits than the frozen
baseline (13.881027266 and 158,723.480). All six guards pass on all 15 blocks.
The three holdout blocks improve by 5.0350% in instructions; all 15 aggregate
to 12.782441315 instructions/gas and 147,128.340 proxy committed bits/gas.
All 15 individual blocks improve. Keccak and secp call counts are unchanged.

This is track C work. It began at head 8f75a38f, before the concurrent
architecture-first update 3e2455379. That update was preserved on integration;
its A-client and B-service track branches already have ownership. Completing
and recording this existing measured change avoids duplicating those tracks.
The updated harness was rerun on all 15 blocks with the admitted profile:
all guards pass, `promotable: true`, and the metrics match the original-harness
receipt exactly. No candidate service is used. The parity and supersede targets remain **unmet**. Relative to this candidate,
2.020 still requires 84.67% fewer instructions and 1.500 requires 88.62% fewer.
Neither the targets, calibration, basket, expected outputs, validator, executor,
linker, target specification nor service ABI was changed.

## Kept code

- Decode MPT nodes into their final storage instead of returning large temporary
  enums through recursive Result values. Maintain exact-input checks, branch
  arity checks, extension-child checks and cache invalidation. Handle canonical
  empty children and 32-byte digest headers directly, retaining bounds checks.
- Bypass memcpy's byte-prologue jump table for already aligned object copies;
  skip empty copy tails. Copy aligned overlapping memmove ranges backwards by
  words. Use equality-only bcmp and find memcmp's first differing byte without
  two RV64IM byte swaps. Existing aligned-only load/store rules remain.
- Write JUMPDEST bitmap backing bytes directly instead of using BitVec's
  general bit-pointer setter.
- Fuse canonical PUSH2+JUMP/JUMPI inside run_plain. Preserve the public step
  method as exactly one opcode. Fall back for gas exhaustion, stack overflow or
  underflow, invalid taken targets, different instructions or custom stacks
  that have not explicitly opted into eliding an unobservable PUSH/POP pair.
  Use the supplied gas table; do not hard-code opcode gas prices.
- Patch only sha2 0.10.9 in the services workspace with an original, narrow
  SHA-256 implementation using a rolling schedule and expanded rounds. No
  third-party implementation was copied. Read its README: this intentionally
  does not implement upstream SHA-224/384/512 APIs and requires dependency and
  cryptographic review. SHA2 0.11 remains independently resolved and unchanged.

The final ELF SHA-256 is
`8cdb3b939ef9f8b9c8fa7ebf80a339f7338b41263cf0db7201e8d61857d23a27`.
A clean rebuild and a subsequent build after the generic-stack opt-in refinement
produced identical ELF bytes. The frozen original baseline is preserved; upstream candidate-profile additions
do not change the admitted-profile coefficients used here. A local
baseline rebuild smoke control differed from the frozen first-block count by
under 0.01%; comparisons and guards still use the frozen baseline.

## Evidence and reproduction

`../ledger/2026-11-01-guest-efficiency/final-all.json` is the updated-harness
receipt; `final-all-original-harness.json` preserves the earlier run. It contains every block,
ELF/executor identities, metrics and all guard results. `../ledger/2026-11-01-iterations.jsonl`
records all experiments, including build failures and rejected probes. The
central `../ledger/attempts.jsonl` preserves its original baseline entry and
appends these entries with track labels. A smoke
probe is not a scored basket result. Partial/trapped executions have no score.
Intermediate receipts retain their requested set; the harness's `metrics.all`
on a scored-only run is only that requested set, not all 15 blocks.
`2026-11-01-final-attribution.json` contains the final sampled-block profile.

```sh
B=autoresearch/guest_efficiency/bench.py
CACHE=/absolute/path/outside/repository
python3 -I "$B" prepare --cache "$CACHE" --fetch
python3 -I "$B" build-exec --out "$CACHE/exec"
python3 -I "$B" build-guest --out "$CACHE/elf"
python3 -I "$B" run --elf "$CACHE/elf/ethereum-rv64-services-v2-lean.elf" \
  --executor "$CACHE/exec/bin/rv64-ethereum-execution" --cache "$CACHE" \
  --out "$CACHE/final" --set all --jobs 4 --keep-profiles
python3 -I autoresearch/guest_efficiency/notes/validate_guest_changes.py \
  --out "$CACHE/units"
python3 -I autoresearch/guest_efficiency/test_bench.py
python3 -I "$B" check-scope --base 3e24553793c22a5ff71df272b8f3aef702b57dd1
```

The pinned nightly occasionally left metadata-only dependencies unavailable to
fat LTO after a small incremental rebuild. Those builds failed rather than
producing measurements. A clean services target rebuild resolved the failures;
no compiler version or harness change was used. `opt-level=s` produced an actual
MisalignedAddress trap and was rejected, regardless of its partial count.

Focused suites cover 45 bytecode tests, 44 interpreter tests, 19 trie tests,
6 memory tests and 2 SHA tests, plus 32 current harness tests. The fusion
suite compares the fused loop with repeated public single steps over 39,600
combinations of targets, conditions, stack heights, gas limits and custom
instruction/gas tables, plus truncated-input and step-API controls. SHA testing
includes published abc/million-a vectors and an independent sha2 0.11 comparison
for lengths 0..4096, varied alignment, six chunk sizes, cloning and reset.
The isolated unit runner copies exact vendored sources and pins test dependencies;
it does not change production workspace membership or production lockfiles.

## Rejected experiments

| Candidate | Observed reason for rejection |
|---|---|
| Box branch tables to shrink Node | Scored instructions increased about 5.4%; extra allocation outweighed smaller moves. |
| Constant-width generic PUSH construction | Sampled instructions increased. |
| Fixed GLV generator tables | Reduced ADD services but increased ordinary instructions and the proxy. |
| Broad direct opcode specialization | Pointer guards and dispatch expansion increased sampled instructions. |
| Exact Keccak-32 memoization | Reduced service calls but worsened the primary metric. |
| Exact SHA compression memoization | Lookup/copy overhead exceeded savings. |
| opt-level=s | MisalignedAddress trap; not a completed execution. |

## Promotion status

This is execution-qualified PR progress, **not a new proving baseline**. The
Word16 prefix proof plus fresh verify-prefix, complete-block proof plus fresh
verify and exact cost.json accounting, dependency/cryptographic review and human
promotion have not been performed. Committed bits here are the frozen linear
proxy, not measured final native committed cells or proof size. No wall-clock
proving speedup is claimed.
