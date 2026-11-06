# Precompile provider integration

The `precompiles` guest variant installs an explicit provider through pinned
Revm's `Crypto` interface before any EVM executes. OP Revm still owns fork
activation, gas, input padding and EVM error handling. Installation failure traps;
it does not silently switch to another provider. The reference host is unchanged.

| Operation | Implementation | Boundary |
|---|---|---|
| SHA-256 | Existing admitted compression service | All input/padding lengths |
| Modexp | Existing admitted `(a*b+c) mod m` relation | Base and modulus up to 256 bits, arbitrary exponent byte length; even moduli supported |
| Larger modexp | Pinned software implementation | No truncation or odd-modulus assumption |
| BN254 G1 add | Existing admitted affine add/double services | Canonical on-curve input validation; infinity, doubling and inverse points handled in guest |
| BN254 G1 multiply | Same services, four-bit window | Validates point before zero-scalar shortcut; reduces scalar modulo group order |
| Pairing, P256, RIPEMD, Blake2, BLS/KZG | Pinned provider defaults | Full software semantics; not replaced by unchecked hints |

The BN254 window follows the existing evmone integration. Packet construction
avoids zero-then-fill memory-service calls. Partial affine service preconditions
are discharged explicitly before every call. These operations reuse the existing
native and recursive service roster; no new AIR, transcript or tag is introduced.

Native differential tests cover zero/one/even moduli, leading zeros, exponents
longer than 256 bits, wider fallback, malformed/noncanonical points, infinity,
inverse points, order-boundary scalars, randomized multiplication and SHA padding.
The first checkpoint also replays five mainnet blocks against native Kona and
Unicorn. Those blocks do not exercise BN254 G1 or modexp, so that execution
checkpoint does not qualify their RV64 service paths or physical proof cost.
The default guest remains unchanged until explicit service-path and complete
proof/receiver receipts justify promotion.
