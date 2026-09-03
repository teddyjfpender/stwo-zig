# Stwo Revm ECRECOVER candidate v1

Status: non-production, unimported, activation disabled.

This candidate routes only the successful Revm ECRECOVER operation through
the existing authenticated `stwo.secp256k1.recover-signer@1` instruction. It
does not alter the 168-byte recovery record, the runner, or the AIR. Ethereum's
address Keccak remains on the existing authenticated Keccak route.

## Retained prefix authority

- Evidence: `/private/tmp/stwo-pc-hotspot-allocator-v2-prefix64.NwBj6g/evidence.json`
- Evidence file SHA-256: `c1b815575c0f2714cd60a312795ed07c9e47544dd8b7758b347cd4dcd74af982`
- Raw observation: `/private/tmp/stwo-pc-hotspot-allocator-v2-prefix64.NwBj6g/evidence.stdout.json`
- Raw observation content SHA-256: `aaadf04b731db70cb98394332cd6362d25bf41d05272efab71b8e80303dae153`
- ELF: `/private/tmp/stwo-guest-allocator-v1.Bf0b4z/candidate-exact-v2.elf`
- ELF SHA-256: `2414c39ed5387531ed94cccc8a3ee90abb30de38ad6d32d05d2df59ce63a647b`
- Scope: segments 0 through 63 of 72, with no extrapolation.
- Retired rows: 268,411,310.

The Revm `DefaultCrypto::secp256k1_ecrecover` entry executed exactly 12
times. Exactly 11 calls completed encoded-public-key and native-Keccak address
generation inside the retained prefix. The twelfth call was still executing at
the segment-63 cutoff: the boundary PC `0x70514` is inside k256's field
multiplication routine. The compiled identity/error branch fell through 12
times, its error block executed zero times, and only 11 returns were observed
before the cutoff. This evidence therefore contains 11 completed successes and
one in-flight call; it does not demonstrate an invalid ECRECOVER input.

An exact-entry dynamic symbol graph, with smallest-enclosing-symbol ownership,
attributes 124,346,467 rows to the recovery-only subtree. Nodes with any
outside caller, and every descendant of such a shared node, are excluded. In
particular, this projection excludes 20,205,437 native-Keccak rows, 40,580,928
compiler-memcpy rows, 2,136,214 memset rows, and 507,558 generic-memcpy rows.
The Revm precompile wrapper itself contributes 3,850 local rows and remains in
both profiles. Therefore 124,346,467 rows is the gross replaceable recovery
projection, not a claimed net speedup; a retained candidate execution must
subtract the new adapter and custom-instruction rows.

## Sound integration boundary

The Rust source is intended to be a child of the existing guest
`crypto::stwo` module. It imports that module's private `RecoveryRecord`,
`execute_recovery`, and success constant, so there is one ABI definition. It
overrides only Revm's ECRECOVER method; every other `Crypto` method retains the
trait default.

Promotion is blocked because the current instruction handler aborts before it
publishes a record when recovery is invalid. Revm instead requires
`Secp256k1RecoverFailed`, which its precompile maps to empty output. The
retained prefix does not exercise this distinction, so production activation
must remain false until a fresh execution demonstrates all of the following:

1. every completed ECRECOVER output matches the software backend byte-for-byte;
2. adversarial invalid calls emit no successful recovery event and return empty;
3. every successful call emits exactly one authenticated recovery event;
4. every successful address hash retains exact Keccak input/output parity;
5. the full guest output and execution boundary identities are unchanged.

The existing success AIR cannot soundly be widened with a prover-selected
status bit. General invalid recovery has three certificate classes. Zero or
out-of-range `r`/`s` admits a byte-comparison certificate. A canonical `r`
whose `r^3 + 7` has no curve square root needs a Legendre/non-residue product
certificate. A valid recovery point whose double-scalar result is the identity
needs the existing scalar-program relation to admit and authenticate an
infinity result. The latter two relations do not exist today. A scalar-only V2
would let the prover self-label other valid inputs invalid, so no partial
invalid-result AIR is included in this candidate.

After those certificates exist, the guest integration patch needs a direct
`revm` dependency, a child module declaration under `crypto::stwo`, and an
explicitly non-production installer. None is present in this tranche.
