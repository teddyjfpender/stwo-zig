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

## Sparse034 client prototype (admission closed)

[Client ABI and gates](sparse-client-prototype.json) pin the explicit
`canonical-glv-hinted-sparse` build. It uses **0x0004_0001** in the new OP
namespace, never the existing Keccak sponge tag. The inline576-byte packet
contains 12 accumulator and six sparse-line Fq coordinates, with only the first
384 bytes overwritten. Serialization names each coordinate; it does not cast
Ark object layout. RV64 requires the canonical BN254 client; native reference
execution retains the original software path.

The old `ethereum_services_v3` VM refuses the actual new ELF at the first new
call with `UnsupportedService`. The independent Python interpreter only admits
this tag under `ethereum_services_op_v1` and uses schoolbook ring reduction.
Fifteen host tests and 42 OP Python tests pass. The OP native/provider/RAM/wire
and physical-proof joins must qualify before production admission; neither
execution completion nor proving speedup is claimed from this prototype.
