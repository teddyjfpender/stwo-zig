# Proposal: Keccak-256 sponge service

Status: **candidate, measured; pays.** Recommended once a Keccak bridge
rework is planned, because it reuses the Keccak truth AIR. Execution-only
evidence; not promotable.

## Motivation (measured, evmone client, 15-block basket, 2026-11-01)

With the admitted Keccak-f service, the client's sponge glue (absorb with
unaligned word assembly, padding, state set-up, memo) cost 0.43 instr/gas. That
is about 146 instructions per permutation, or 429 per `ethash_keccak256` call.

| Set | instr/gas | Δ instr | bits/gas | Δ bits (low / nominal / high cost) |
|---|---:|---:|---:|---|
| scored | 5.293 | -6.37% | 75,425 | -5.24% / -4.34% / -2.84% |
| holdout | 4.540 | -6.28% | 64,186 | -4.29% nominal |
| all | 5.145 | -6.35% | 73,206 | -4.33% nominal |

All guards pass with exact outputs. Mix-adjusted: -4.54%.

- There were 273,562 sponge calls with 1,173,787 permutations. That is exactly
  the drop in admitted Keccak-f calls (1,279,412 to 105,625; the ≤ 64-byte
  memoized path keeps Keccak-f).
- 155.4M instructions were saved. The keccak glue bucket fell from 0.432 to
  0.082 instr/gas.
- Cells: Keccak-f cost fell by 84.7G and the sponge added 86.4G (2.9G of
  per-call cost plus 83.5G per permutation). The CPU saved 24.1G. The service
  side is slightly more expensive per permutation than the calibrated Keccak-f
  call (71,053 + 10,700/call vs 72,159), so the whole gain comes from the
  instructions removed.

## ABI

Tag `0x0003_0130`, packet `{state, in, len, flags}`:

- rate 136; `in` may have any alignment;
- `flags` bit0 = finalize (Keccak 0x01/0x80 padding), bit1 = fresh (zero
  state);
- without finalize, `len` must be a multiple of 136;
- writes the 25 lanes; `bytes` = 136 × permutations.

The guest pads only by asking the service to finalize. `keccak_stwo.cpp` makes
one fresh+finalize call for inputs over 64 bytes and keeps the memoized
admitted path below that.

## AIR sketch

The admitted Keccak truth AIR, with three additions:

1. An absorb stage per permutation: 17 input words from RAM, byte realignment
   for unaligned input, input bits XORed into the rate lanes.
2. In-AIR chaining of the state between the permutations of one call.
3. A final-block padding row: a one-hot over the remainder position, with
   0x01 and 0x80.

The state crosses the bridge only once per call: out, plus in for non-fresh
calls. Estimate 10,700 cells per call plus 71,053 per permutation.

## Expected effect

About -6.4% instructions and -4.3% committed bits. The result is the most
sensitive of the three to the cost estimate (-2.8% at the high end).

Refinement: a digest-only flag (write lanes 0..3 only) would cut about 5,700
cells per call, worth about 0.9% of service cells here. Absorbing into a
caller-held state (non-fresh) would serve incremental hashing but is not
needed by this client.

## Prover work

- Extend the Keccak AIR with the absorb/chain/pad stages, or add a sponge
  front-end that feeds the existing permutation slots.
- A byte-addressed input bridge (shared with the bulk-memory DMA work).
- Services lane and receiver, and recursion support.
- Adversarial tests: unaligned tails, `len` at block boundaries, flags.
