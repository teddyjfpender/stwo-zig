# RV64 Ethereum guest efficiency program

**Goal:** get the guest's work per unit of gas down to ZisK's level and below:
from **13.88** instructions/gas (158,723 committed bits/gas) on the scored
basket to **2.02** (ziskethone parity) and then **1.5**.

That is a 7-9x reduction. It does not come from a greedy loop over the current
guest. It comes from three architectural moves, each measured with the same
harness, followed by tuning. Read [CONTEXT.md](CONTEXT.md) first.

## The three moves

### Move A: replace the client (largest single jump)

The 4x gap between ZisK's own reth guest (6.21) and its C++/evmone guest (2.02)
on identical blocks shows the client design dominates. Our reth/revm guest is
the same design as ZisK's slower one.

- **Reference:** ziskethone, a C++ stateless verifier with evmone v0.24, its own
  state DB and MPT and zero-parse input. Public output is the EIP-8025
  `new_payload_request_root`, the same value our guest commits.
- **Port:** build for RV64IM (`zig c++` or Homebrew clang with an RV64 target),
  our `linker-wide.ld`, our entrypoint, halt and 43-byte output. Replace ZisK
  CSR precompiles with our Keccak and secp services; everything else software
  at first.
- **Input:** either read our canonical SSZ, or add a converter from the ZisK
  reth fixtures to its binary format and extend host validation to cover it.
  The public output must not change.
- **Correctness gates:** the 15-block basket (exact output), EEST, and
  differential runs against the reth guest.
- **Licence:** ziskethone is Apache-2.0/MIT; evmone is Apache-2.0 (confirm).
  Until legal signs off, keep the client as a pinned fetch plus our patches
  rather than copying third-party sources into the repository.
- **Expected:** about 3-4 instructions/gas without new services (no DMA, no Zbb).

### Move B: add the services the client actually needs

ZisK reaches 2.02 with single-step memcpy/memset/memcmp, 256-bit arithmetic and
SHA-256 among its precompiles. Measure each as a **candidate service** in the
execution-only profile (CONTEXT.md) on both clients, with an estimated cost per
call, before any prover work. Adopt a service into the prover only when its
measured committed-bits saving clearly exceeds its estimated cost, and write the
proposal with that evidence.

Priority by expected value: bulk memory (20% of today's instructions), SHA-256
compression for the SSZ root (11%), 256-bit arithmetic for EVM `MUL`/`MULMOD`/
`ADDMOD`/`EXP` and modexp, then curve operations for EVM precompiles (BN254)
if blocks use them.

### Move C: guest hygiene on whichever client wins

Batch inversion and fixed-base tables for secp recovery, zero-copy decoding,
no re-hashing, witness pre-indexing, opcode dispatch, `U256` fast paths,
compiler settings. This is where the greedy loop is effective, and it applies
to both clients.

## Expected landing points (estimates, to be replaced by measurements)

| Step | instructions/gas | committed bits/gas |
|---|---:|---:|
| today | 13.9 | 158,700 |
| C on current client, admitted services only | ~10.5-11 | ~120,000 |
| A: evmone-class client, admitted services only | ~3-4 | ~35,000-45,000 |
| A + B: client plus candidate memory, SHA-256, arith256 | ~2-2.5 | ~25,000-30,000 incl. service cost |
| A + B + C tuned | <= 1.5 | <= 17,000 |

ZisK's production block commits about 95,000 bits/gas, so move A alone would
already commit about 2-3x fewer bits per gas than ZisK.

## Tracks and ownership

| Track | Branch prefix | Editable (scope.json tier) | Output |
|---|---|---|---|
| A client | `codex/rv64-guest-client-*` | C_new_client | client build recipe, basket result, EEST and differential evidence |
| B services | `codex/rv64-guest-candidate-*` | E_candidate_executor + guest code | executor candidate services, cost entries with derivations, basket results on both clients, proposals |
| C hygiene | `codex/rv64-guest-*` | A_guest_code | basket results, ledger entries |

Tracks run in parallel. Each reports with `bench.py run --set all` and appends
to `ledger/attempts.jsonl`. Combining A+B+C is a separate integration step.

## Gates before a guest is adopted for proving

1. `bench.py run --set all`: all guards pass and `promotable` is true (admitted
   profile only).
2. `bench.py check-scope --base <base>`: only editable paths changed.
3. For a new client: EEST and differential evidence, licence sign-off.
4. Word16 prefix proof of block 24,628,607 with the new ELF plus a fresh
   `verify-prefix`; then a complete-block proof and fresh `verify` with exact
   committed cells from `cost.json` replacing the proxy.
5. Any candidate service becomes admissible only after its prover work
   (CONTEXT.md) is qualified; until then results using it are evidence, not
   promotion.
