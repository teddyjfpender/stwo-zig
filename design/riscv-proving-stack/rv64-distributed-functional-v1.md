# Experimental distributed functional lookup v1

This namespace qualifies **public Word16 truth facts**, not RV64 execution. It
is separate from the qualified root-chain work packet protocol. No existing CPU,
RAM, Ethereum receipt, or chain receiver selects it.

`rv64_distributed_v1/functional.zig` contains an actual two-proof receiver. The
first proof consumes an independently expected public roster of 32 possible
Word16 questions; the second proves BINARY truth and canonical byte-AND table
membership. The diagnostic fixture asks AND, OR, and XOR questions. Both workers
use the existing component equations and q70/P26 PCS configuration. The BINARY
worker reuses the existing native fixture builder and interaction authority. The
proof-producing harness instantiates two retained workers in one process; its
receiver is independently exercised in a fresh process. Receipt/Manifest codecs
provide the transport representation, but no distributed worker scheduler or
parallel speedup is claimed.

## Commitment barrier

1. Each worker starts its own transcript with the exact protocol, request and
   program identities, immutable schema, public statement digest, geometry, and
   role. Every u64 identity is mixed as canonical bytes/words without M31
   truncation.
2. Each commits its actual fixed tree and main tree. Main contains every
   functional tuple and multiplicity. The BINARY main tree also contains the AND
   table multiplicities. The exported `Receipt` contains the **actual PCS roots**.
3. The coordinator validates a complete ordered receiver-derived inventory and
   all receipts, then seals the canonical Manifest. It does not receive worker
   trace values, expand witnesses, or choose an alpha.
4. Each retained worker rechecks its actual committed roots against the
   Manifest. Both independently derive typed ALU/BINARY/SHIFT challenges from
   the same complete Manifest; only BINARY is used by this fixture. Local AND
   challenges are separately tagged and drawn from the worker transcript after
   the Manifest binding.
5. Every physical function/AND claim enters the corresponding local transcript
   **before** the interaction commitment and constraint coefficients. A worker
   cannot submit an unbound rational target in place of an interaction proof.
6. The receiver reconstructs expected schemas, public roster digest, and fixed
   roots independently. It replays the Manifest binding using roots observed in
   each actual proof, runs both complete AIR/FRI verifiers, and only then closes
   the function and AND claims. Root comparison alone never accepts a proof.

The public consumer has fixed34 = first/last plus 32 immutable row selectors,
main14 = payload13 plus Boolean weight, and interaction8. Its 14 binding
constraints compare committed main coordinates with independently expected
public coefficients; one Boolean constraint and the shared three function-bus
constraints complete its 18 residuals. Changing public facts preserves the fixed
root and changes the statement digest, main root, Manifest, and transcript.
There are no duplicate public fact columns in preprocessing.

The BINARY proof has fixed2/main42/interaction28 at log5, plus a canonical AND
provider with fixed5/main1/interaction8 at log16. These independently sized
components share its PCS proof. Provider weights are committed before the
challenge. The aggregate admits the conservative consumer capacity of 32,
including padding, below M31 characteristic; the local AND positive mass is
8*32 = 256. The actual diagnostic consumer weight is three. Transport request
spans are identity metadata and do not claim a physical event bijection.

## Adversarial qualification

The actual-proof tests cover a fresh receiver, a balanced pair of altered
physical claims that still sums to zero, peer-root replay while the consumer's
own root is unchanged, a changed full-width request identity, and a changed
public roster under the same fixed geometry. The false-roster test generates two
valid local proofs and requires the receiver to reject their final function
closure. Constructor allocation failures preserve the borrowed public roster.
Separate commitment/codec tests cover omitted, reordered, duplicated, stale,
wrong-geometry, truncated, oversized, and mutated manifests. An intentionally
invalid empty proof shell demonstrates why observed-root matching is not proof
verification.

## Remaining boundaries

The actual aggregate receiver accepts exactly the public-consumer/BINARY+AND
inventory. It does not accept the metadata model's CPU, ALU, or SHIFT roles.
Those need their own physical proof integrations and complete receiver gates.
RAM profiles, init/teardown, memory origin/clock delegation, terminal output,
and local register endpoints are unsupported. In particular, a native packet
SHA or native RAM root cannot replace a stage-one PCS commitment. Unrelated
BYTE lookups remain local; their full-execution mass exceeds M31 characteristic.
Global RAM cannot remove the current local register clock cap by itself.

The proposed future RAM schema remains inactive: packed rights, full64 time as
four u16 limbs, authenticated owner/local-time origin, strict limb-wise order,
physically unique initialization and teardown addresses, canonical expected
initial image, and independently expected output/terminal bindings all need
physical AIR proofs. The existing root-chain execution receiver remains the
control until that complete aggregate is independently qualified.
