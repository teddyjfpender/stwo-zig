# Owned dependency deltas

The reference host and RV64 guest share the pinned Kona version. These small
forks have separate ownership; upstream files and licenses remain recognizable.
Every fork records original file SHA-256 identities in `UPSTREAM.json`.

| Crate | Consumers | Maintained delta |
|---|---|---|
| `kona-mpt` | Optimized RV64 guest only | Capped reference sizing and bounded branch/extension encoding. The native host retains upstream MPT. |
| `op-revm` | Host and all guests | Gate the operator fee recipient at Isthmus. Upstream Revm loads an account even for a zero balance increment; pre-Isthmus blocks must not request this future vault. L1/base fees and post-activation zero/nonzero operator payouts are preserved. |
| `ark-bn254` | Optimized guest only | Optional `stwo-montgomery-service` Fq configuration; original field identity/default behavior stays available. BN254 radix-2^256 operands use the existing radix-2^384 admitted service by shifting the first operand 128 bits. |

The BN254 adapter is an explicit experiment, not the default. Its instruction
counts do not establish a lower full proof time: field service calls and RAM
transitions must be included. Native feature tests use upstream Ark multiplication
as the reference; RV64 output must independently match the mainnet block hash and
Python big-integer oracle. Only the adapter's single documented RV64 ECALL
function permits unsafe code. The rest of the crate retains its unsafe-code ban.

Standalone manifests/locks support repeatable upstream property tests. Do not
format or rewrite the imported source wholesale. Keep new tests separate and
record changes to existing files explicitly in each upstream manifest.
