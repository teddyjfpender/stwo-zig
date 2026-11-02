# Candidate services: ABI clarifications and how to reproduce (2026-11-01)

CONTEXT.md fixes the candidate ABI. These are the choices made where it leaves
room; the executor (`src/frontends/riscv/rv64/ethereum_services/candidate_services.zig`)
and the guest wrappers follow them exactly.

## Common rules

- `a0` = packet pointer, must be 8-byte aligned (else `MisalignedAddress` trap);
  `a7` = tag; all registers preserved; one retired instruction (ECALL) per call.
- The packet is read with `read` permission over all of its words; output words
  also need `write` permission. Every permission/range check happens before any
  byte changes, so a trapping call leaves memory, PC, retirement count and
  counters untouched.
- Unknown tags in `0x0003_xxxx` trap `UnsupportedService`, like any unknown tag.
- Admitted tags (Keccak, secp v2) are dispatched first and behave exactly as in
  `ethereum_services_v2`; candidate dispatch only sees tags they decline.

## Bulk memory (`memcpy` 0x0003_0001, `memset` 0x0003_0002, `memcmp` 0x0003_0003)

- `dst`, `src`, `a`, `b` have no alignment requirement.
- `len == 0`: no memory is touched and no mapping is needed (pointers may be
  anything); the call still counts (calls += 1, bytes += 0).
- `len` is capped at 256 MiB per call (the mapped-memory ceiling); larger traps
  `CandidateLengthLimit`.
- `memcpy` snapshots the whole source before writing, so any overlap behaves as
  `memmove`. Source needs `read`, destination `write` over the exact ranges.
- `memset` writes `byte & 0xff`.
- `memcmp` compares unsigned bytes and writes `-1`, `0` or `1` (as i64) to the
  packet's fourth word, which needs `write` permission even when `len == 0`.
- Reported `bytes`: memcpy/memset = `len`; memcmp = bytes examined (index of the
  first difference + 1, or `len` when equal). A memcmp AIR only has to read up
  to the first difference.

## `sha256_compress` (0x0003_0010)

Packet = 12 u64 (96 bytes):

- bytes 0..32: the eight state words H0..H7, each the FIPS 180-4 u32 value
  stored little-endian, H0 at bytes 0..4 (low half of u64[0]), H1 at bytes 4..8
  (high half of u64[0]), ... H7 in the high half of u64[3];
- bytes 32..96: the 64-byte message block exactly as it appears in the message
  stream (SHA-256's big-endian word parse applies to these bytes).

Only bytes 0..32 change. `bytes` = 64 per call. Tests: FIPS 180-4 "abc" one-block
vector and a two-block message checked against `std.crypto` SHA-256.

## `arith256` (0x0003_0020) and `arith256_mod` (0x0003_0021)

Each 256-bit value is four little-endian u64 limbs (limb 0 least significant).

- `arith256`: packet `a[4] b[4] c[4] lo[4] hi[4]` (160 bytes); writes `lo`, `hi`
  with `hi:lo = a*b + c` (never overflows 512 bits). `a`, `b`, `c` unchanged.
- `arith256_mod`: packet `a[4] b[4] c[4] m[4] r[4]`; writes `r = (a*b + c) mod m`,
  `r = 0` when `m = 0`. Inputs unchanged. `bytes` = 0 for both.

## Profile

`execution_profile = "ethereum_services_v3_candidate"` in the execution config.
The tool rejects it with `compact_capture_batch_steps`, `census_batch_steps` or
`capture_ram_boundaries` (`CandidateProfileIsExecutionOnly`); nothing the prover
reads (compact tape, boundary capture, admitted profiles) knows about it. The
report gains `candidate_service_calls: {memcpy|memset|memcmp|sha256_compress|
arith256|arith256_mod: {calls, bytes}}` (null on other profiles).

## Guest side

Cargo features in `rv64/services/Cargo.toml`, all off by default:

| Feature | Effect |
|---|---|
| `candidate-mem` | `stwo-rv64-mem/candidate-services`: `memcpy`, `memmove` (both tag memcpy), `memset`, `memcmp`/`bcmp` go to the services. Thresholds `STWO_CANDIDATE_{COPY,SET,CMP}_MIN=<bytes>\|off` at build time; default 0 (every call, no length test). |
| `candidate-sha256` | vendored `sha2 0.10.9` (`vendor/sha2`, pin `vendor/sha2-source.json`) feature `stwo-candidate-sha256`: `compress256` issues one ECALL per block. |
| `candidate-arith` | vendored `revm-interpreter` feature `stwo-candidate-arith`: MUL (unless both operands < 2^64), MULMOD, ADDMOD (as `a*1 + b mod n`) and EXP (square-and-multiply on `arith256`). |
| `candidate-services` | all three. |

Build (equivalent to `build.py --guest-profile ethereum-services-v2-lean
--input-window-mib 16` plus features; `build.py` is locked):

```sh
cd autoresearch/benchmarks/guest_runtime/ethereum/rv64/services
RUSTFLAGS="-C link-arg=-Tlinker-wide.ld" cargo +nightly-2026-08-08 build --locked --release -j 4 \
  --features keccak-service,secp-lean,candidate-services --target riscv64i-stwo.json \
  -Z json-target-spec -Z build-std=core,alloc -Z build-std-features=compiler-builtins-mem
# ELF: target/riscv64i-stwo/release/stwo-ethereum-rv64-guest
```

With no candidate feature this command reproduces `build.py`'s ELF byte for
byte (both `cdfa884a…`). That ELF differs from the frozen baseline
(`37fbf8fd…`) because `sha2` is now a patched path dependency. Instruction counts
move by -283k to +25k per block (scored -0.01%, holdout +0.002%; all guards pass
on the admitted profile). All deltas below use this same-tree build as the
reference.

Scoring with estimated costs (calibration.json is locked): a wrapper imports
`bench.py` and swaps `candidate_services` for
`proposals/candidate-service-costs.json` in memory:

```sh
python3 -I <scratch>/bench_with_costs.py run --elf <elf> --executor <exec> --cache <cache> \
  --out <out> --set all --jobs 4 --profile ethereum_services_v3_candidate
```

## `jumpdest_bitmap` (0x0003_0040), added 2026-11-02

Packet = 3 u64 `code, len, bitmap`. `code` 64-byte aligned, `bitmap` 8-byte
aligned, `len` a nonzero multiple of 8 up to 2^20 (else `MisalignedAddress` /
`CandidateLengthLimit`); code words, bitmap words and packet pairwise disjoint
(else `CandidateAliasing`). Reads the `len/8` code words, writes exactly
`ceil(len/64)` bitmap words (bit `i%64` of word `i/64` = byte `i` is a JUMPDEST
outside PUSH data; data past `len` cut off). `bytes` = `len`. Reported in
`candidate_service_calls` only once called (like the curve candidates), so
existing reports and cost files are unchanged. Executor:
`ethereum_services/candidate_jumpdest.zig`. Client: `build.py --profile v3
--candidate-jumpdest`. Proposal: `proposals/jumpdest-bitmap.md`.
