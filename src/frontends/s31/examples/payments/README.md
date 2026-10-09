# Hash-based Tongo-style payments in S31

This is a **payment-validity research prototype**, not a confidential-token
deployment. It replaces [Tongo's EC/ElGamal encrypted accounts](https://docs.tongo.cash/protocol/encryption.html) with hash-committed
notes. One S31 relation spends one note and creates a recipient note and change.
No EC operations, new AIR, or new proof protocol are introduced.

This example declares `blinded circuit` and uses the full gate profile with
fresh random-row blinding. [Proof privacy](../../docs/proof-privacy.md) explains
the mode and verifier binding. **This remains experimental: neither `private`
nor the new blinding mode establishes a reviewed, general zero-knowledge
guarantee. Do not publish real payment witnesses or use this example for real
funds.**

## Contract before implementation

- Amounts and the public fee are unsigned 64-bit integers represented by four
  range-checked little-endian u16 limbs. Checked integer additions enforce
  `input = recipient + change + fee`, without field or integer wraparound.
- An eight-word secret derives the spending owner with a domain-separated hash.
  Each note commits to its owner, amount, eight-word random salt, and context.
  The context identifies protocol version, chain, ledger, asset and verifier.
- A depth-three Merkle path proves membership in an accepted note root.
  The nullifier hashes the spending secret and input commitment. A ledger must
  reject a nullifier already spent, including a spend against a historical root.
- The recipient is positive; change may be zero. Change belongs to the sender.
- The eight-word public output is a receipt committing to the entire public
  envelope: context, anchor, nullifier, both outputs, fee and delivery hash.
  **The verifier must receive the receipt recomputed by the ledger**, rather
  than a statement supplied by the prover. This accommodates S31's eight-word
  public ABI without leaving the transaction fields unbound.
- The reference ledger is bounded to eight leaves. It verifies before committing
  state and rejects duplicate commitments, unknown roots, wrong contexts,
  capacity exhaustion and replay. Its initial notes represent trusted funded
  state; deposit and withdrawal correctness are not implemented.
- The separate reference delivery channel uses a pre-shared, 32-byte invoice
  key, HMAC-SHA256 stream masking, and encrypt-then-MAC. It authenticates the
  context and recipient commitment. The invoice key needs a private channel;
  publishing it makes the note readable. Arbitrary public-address delivery
  would require a separate public-key primitive, such as ML-KEM.

All circuit hashes use the existing pinned M31 Poseidon2 leaf/pair encoding.
Hash roles have distinct v1 tags. The Python value model uses the independent
Poseidon oracle and standard-library HMAC, not the circuit evaluator. Transport
code is an educational construction, not an audited encryption protocol.
Encrypted memo correctness is checked by the receiving wallet; the circuit
binds its hash but does not prove that its plaintext opens the output note.

The native verifier uses the existing full circuit AIR and PCS with a distinct
blinded profile/key and source-bound blinding geometry. Sparse-wide lowering
is rejected for this source. The FRI settings stay at 70 queries, log blowup 1,
PoW 26 and fold step 1. There is no new full-proof Rust interoperability or
post-quantum security-level claim.

## Files and validation

- [tongo_transfer.s31](tongo_transfer.s31): the complete payment relation.
- [tongo_transfer.s31.json](tongo_transfer.s31.json): generated normalized relation,
  checked against the text frontend in the unit tests.
- [reference.py](reference.py): note/receipt encoding, independent fixture
  calculations and atomic bounded reference ledger.
- [delivery.py](delivery.py): shared-invoice hash-only note delivery.
- [tongo_transfer.valid.json](tongo_transfer.valid.json): public, deliberately
  non-secret example witness: `1000 = 375 + 620 + 5`.
- [unit tests](../../tests/python/test_tongo.py): boundary amounts, adversarial
  witnesses, context binding, delivery integrity and ledger failures.
- [proof acceptance](../../tests/acceptance/acceptance_tongo_transfer.py): two
  successive native-verified transfers, changed envelope/proof rejection and
  invalid-witness rejection, with machine-readable diagnostic costs.

From the repository root, with Zig 0.15.2 on PATH:

```sh
python3 -m unittest discover -s src/frontends/s31/tests/python -p 'test_tongo.py' -v
python3 src/frontends/s31/tests/acceptance/acceptance_tongo_transfer.py
```

The acceptance driver retains its packages, proof receipts and report under
`zig-out/s31/tongo-acceptance/`. It uses synthetic witnesses only. Local proof
times and sizes are diagnostics, not an apples-to-apples Tongo benchmark.

## Required next slices

1. Establish a reviewed zero-knowledge argument for the complete blinded proof
   transcript and complete pinned Rust proof interoperability evidence.
2. Audit commitment, nullifier, receipt and hash parameters, including quantum
   margins. Eight M31 words are about 248 output bits; that alone does not imply
   128-bit quantum collision security.
3. Implement a Starknet vault/ledger that computes the expected receipt, pins
   the verifier/key, authenticates funded roots, applies state atomically and
   enforces asset conservation across deposits and withdrawals.
4. Specify invoice establishment, note discovery, recovery and optional auditor
   delivery. Keep shared-secret and ML-KEM variants explicit.
5. Scale Merkle depth and note arity, then optimize the hash AIR and measure the
   complete verified payment path against Tongo at matched security assumptions.
