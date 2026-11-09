# Kona guest work: measured pairing reuse

[LRU census and qualification](lru-census.json) records the full selected guest's
380,167,068 instructions with zero excluded PCs. The old 2 MiB profile missed
part of its executable text. Use `scripts/riscv64_ethereum_profile.py` on a
full-range execution census; local assembler labels are not function owners.

The heavy block has 84 unique pairing requests: 252 unique one-shot pairs and
one pair repeated 84 times. Three G2 points repeat each call. FIFO discarded
their prepared owners, and retaining old computed factor candidates could
starve a new recurring pair. Bounded recency now preserves hot owners and
admits new hot factors without trusting host answers or increasing capacity.

Heavy execution falls **380,167,068 → 361,804,837 instructions** (−4.83%),
Fp2 calls **678,888 → 619,553** (−8.74%), and service RAM word transitions
**28,053,166 → 26,347,061** (−6.08%). Native execution and Unicorn agree on
all registers, terminal PC, exact steps, output and service counts on three
blocks. ROM log remains 20. These are execution/representation savings,
**not a measured physical proving speedup**.

Host-only exact public input/cache census:

```sh
cargo +nightly-2026-08-08 run --release --locked \
  --manifest-path opstack/kona/Cargo.toml --features host,pairing-hints \
  --bin stwo-kona-host -- pairing-census INPUT.opx OUT.json
```

The census runs the real native execution and retains request bytes and
cache observations; none is a proof authority or a trusted guest result.
Raw run outputs and frozen ELFs remain in
`rv64-proof-artifacts/20261108/opstack-cpu/` outside Git. The receipt pins
their hashes. Major remaining work is genuine variable pairing arithmetic;
full-request memoization is not a path to the 10× target.

## Miller-line client prototype (admission closed)

[Client ABI and gates](sparse-client-prototype.json) pin the explicit
`canonical-glv-hinted-sparse` build. It uses **0x0004_0001** in the new OP
namespace, never the existing Keccak sponge tag. The inline640-byte packet
contains 12 accumulator, six raw line and two G1 point Fq coordinates, with only
the first384 bytes overwritten. The service includes c0*y and c3*x point
scaling before sparse034, removing four separate arith256 calls per line. Serialization names each coordinate; it does not cast
Ark object layout. RV64 requires the canonical BN254 client; native reference
execution retains the original software path.

The old `ethereum_services_v3` VM refuses the actual new ELF at the first new
call with `UnsupportedService`. The independent Python interpreter only admits
this tag under `ethereum_services_op_v1` and uses schoolbook ring reduction.
Fifteen host tests and 43 OP Python tests pass. The OP native/provider/RAM/wire
and physical-proof joins must qualify before production admission; neither
execution completion nor proving speedup is claimed from this prototype.

The earlier576-byte client was a closed control and is superseded before any
OPv1 admission. There is one current variant, one OP profile, and one new tag.

The final640-byte guest now completes **three real blocks** under the prototype
OP VM. Native execution and independent Unicorn agree on exact instructions,
43-byte output, all registers, terminal PC and all service counts. Heavy
121065789 uses **253,185,635 instructions**, **22,185 Miller-line calls**,
331,163 legacy Fp2 calls and33,117 arith256 calls. That removes exactly
**4 × 22,185** arith256 crossings versus the LRU guest. Service RAM word
transitions fall **26,347,061 → 20,423,872**. Smaller cases use796,313 and
5,927,325 instructions. These execution gains do not qualify native proving
speed or production proof admission; physical provider/RAM/receiver gates
remain open. The complete post-fusion census is pinned in the receipt.


## Caller-owned packet initialization

[Qualified initialization receipt](caller-owned-packet.json) removes the full
640-byte aggregate copy on every line call. A fully initialized zeroed buffer
still emitted 22,185 replacement memset calls, so the final path writes all
20 named coordinates into caller-owned `MaybeUninit<Packet>` storage before
creating any Packet reference. There are no reads or references to partially
initialized storage and no Ark object-layout casts.

Heavy retirements fall **253,185,635 → 252,009,830**. Service RAM word
transitions fall **20,423,872 → 16,807,717** (−17.7%); all 22,185 full-packet
memcpy calls disappear without replacement zero-fill calls. Text is 20 bytes
smaller and ROM remains log 20. Fifteen host tests and exact native/Unicorn
agreement on all three fixtures pass. This preserves the 640-byte ABI and
its still-closed physical proof admission. It does not establish a wall-time
proving speedup.

The rejected targeted Fp2 Add/Sub inlining experiment increased instructions
by 599,008 and was reverted. The [Miller program design](../../../../design/riscv-proving-stack/op-bn254-miller-program.md)
costs the next arithmetic boundary; it emits no new service.


## Canonical Fp2 scalar arithmetic

[Scalar-path qualification](canonical-fp2-scalar.json) specializes each
scalar-only operand case to two necessary base-field products. The previous
fallback evaluated redundant zero products and field add/sub scaffolding.
General Fp2 service packets and all arithmetic service counts are unchanged.
Heavy retirements fall **252,009,830 → 247,343,716** (another 1.85%) and text
shrinks by 42,220 bytes, retaining ROM log 20. Canonical-field differential
tests cover both scalar positions, zero, one and minus one against ordinary
Montgomery arithmetic. Three real fixtures have exact native/Unicorn agreement.
This is an execution saving, not a qualified proving-time speedup.


## Wordwise field-zero checks

[Zero-check qualification](wordwise-field-zero.json) replaces small-array
memcmp calls with a wordwise OR of XOR differences against the configured zero
representation under the existing selected RV64 feature. Heavy instructions
fall **247,343,716 → 240,511,227** and service RAM transitions
**16,807,677 → 15,867,083**. Bulk memcmp calls fall from 206,985 to 53,770.
Text grows by 35,496 bytes, keeping ROM log 20. Three real fixtures retain
exact native/Unicorn agreement. The simple equality identity preserves all
limbs and does not assume a particular zero representation.

A separate forced Fp6-multiply inlining experiment was rejected: it saved only
0.37% of instructions while expanding text past 4 MiB and doubling ROM size.


## Canonical output authority

[Direct output qualification](canonical-line-output.json) binds the next
client cut to the narrow provider's physical canonical writers: each final
Fq has range-checked bytes, a modulus-distance equation, Boolean borrows and
no final carry. With that authority, the explicitly gated OP client writes
each result coordinate directly without repeating twelve modulus checks.
RV64 asserts canonical field representation; host tests retain checked
conversion into their ordinary Montgomery representation.

Heavy instructions fall **240,511,227 → 238,226,172**, with identical service
RAM and call counts. Fifteen host tests and three real-block native/Unicorn
agreements pass. A returned Fq12 variant regressed through aggregate copies and
was rejected. Complete CPU/RAM/receiver qualification is still required before
OP-profile admission; none of these guest receipts admits unproved host advice.


## Further experiments rejected

[Follow-up costs](followup-codegen-costs.json) retain the actual native
instruction/RAM counts for three additional compiler/arithmetic experiments.
Borrow-first canonical subtraction increased instructions by 6.16M and RAM
transitions by 1.10M. Isolated AddAssign inlining increased instructions by
729,002. An in-place square-temporary rewrite saved only 0.23% of instructions
with slightly more RAM; it was not independently qualified or retained.
All these experimental sources were restored. The qualified baseline remains
238,226,172 retirements, 15,867,083 service RAM transitions and ROM log 20.

The refreshed full-text census still attributes 32.73M self instructions to
Fp6 multiplication and 23.32M to Fp2 addition. Those costs do not disappear
through blanket inlining. A bounded local field microprogram that removes
repeated canonicalization and global RAM crossings remains the structural
next step, with explicit range bounds and the semantic gates in the Miller
design. These negative results prevent repeating low-yield compiler tweaks.
