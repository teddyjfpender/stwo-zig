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
