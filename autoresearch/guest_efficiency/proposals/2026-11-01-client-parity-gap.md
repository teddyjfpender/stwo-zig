# Remaining parity gap: client and service portability

The completed guest iteration reaches 13.180 instructions/gas, not 2.020. This
proposal preserves that target; it does not lower it or change scoring.

Inspected the exact reference commit already pinned in basket.json:
[ziskethone 1c3e8d1737c0269a50af24a6fdb26091a6eaee27](https://github.com/0xPolygonHermez/ziskethone/tree/1c3e8d1737c0269a50af24a6fdb26091a6eaee27).
In particular, cpp-guest/zisk/CMakeLists.txt, toolchain.cmake,
cpp-guest/patches and cpp-guest/zisk/evm/fused_dispatch.inl are useful primary
sources. The reference was inspected outside this repository; no client or
patch source was imported.

## What must be measured before extrapolating 2.020

The reference is not simply an unmodified evmone interpreter with Keccak and
point-add/double services. Its build selects wrappers for full secp recovery,
SHA-256, modular arithmetic, BN254, P-256 and other precompiles; patches route
U256 operations and JUMPDEST analysis through ZisK-specific interfaces. Its
runtime lowers bulk memory operations through its memory ABI, and its target
uses bit-manipulation extensions unavailable to our RV64IM executor. It also
uses guest-specific client structures and fused dispatch. Actual savings from
each feature require a controlled ablation, not an inferred multiplicative
speedup. The cited commit is the pinned reference, not an unreviewed newer head.

For the final sampled block, interpreter self-attribution is still 35,622,304
of 98,800,238 instructions; MPT/RLP 17,343,936; memory/allocation 18,117,528;
SHA-256 10,425,954; secp setup 11,242,490. These are one block's self-counts,
not whole-basket fractions or an aggregate lower bound. They explain why small
kernel hygiene alone has not closed an 84.7% remaining instruction gap.

## Concrete next experiment

1. Follow the concurrent architecture-first update: a pinned fetch plus our
   patches is now explicitly permitted before legal sign-off. Record the
   licences and pin the complete source graph; obtain legal sign-off before
   vendoring third-party implementation source. The existing client track
   `codex/rv64-guest-client-evmone` owns this work.
2. Pin the full C++ dependency and compiler graph. Build a freestanding RV64IM
   LP64 control without Zbb/Zbs, DMA, ZisK CSRs or unimplemented accelerators.
   Check ELF instructions before executing; a reference ZisK ELF is not a
   drop-in ELF for our executor.
3. Keep canonical SSZ as the first private-input format. The existing reference
   ZEG0 parser does not establish equivalence to our request; implementing that
   adapter and recomputing the exact SSZ request root is part of the client.
   Do not trust a host-supplied root or claimed EVM result.
4. Map Keccak-f and projective add/double to existing ECALL packets; supply
   ordinary verified software implementations for every other required crypto
   operation. Never reinterpret a full recovery or U256 accelerator as an
   already-supported service.
5. Run software-control and service-enabled variants on the unchanged 15-block
   basket. Add EEST and differential invalid/valid-block tests before claiming
   correctness for a replacement client. Only completed, exact-output runs count.
6. Attribute the remaining software paths. The existing B track
   `codex/rv64-guest-candidate-services` owns execution-only candidate services
   under the newly specified ABI. Coordinate with it for SHA, DMA and U256
   measurements; keep candidate estimates distinct from admitted AIR costs.
   Admission still requires AIR and CPU/RAM bridge design, soundness review,
   real committed-cell costs and explicit baseline epochs.

## Proposed ablation receipt

Keep one row per ELF with compiler flags, dependency SHAs, allowed ISA, input
identity, outputs, instruction count, each service count, all basket guards and
an EEST/differential receipt. Compare software-only, existing-services-only and
any separately admitted new services. This distinguishes client gains from
accelerator gains and prevents the score from being moved by a new calibration.

This iteration implements the existing-client hygiene track. It does not
claim to implement the replacement client or candidate services. The concurrent
architecture-first update allows the pinned-fetch client path to proceed now;
legal review is a gate on vendoring/adoption, not a blocker on that work.
