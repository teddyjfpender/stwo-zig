# Current qualification update

The proposed bridge is now implemented in the guest. Host tests passed and the
full real block executes with 78 native recoveries and the exact output oracle.
See evm-execution-summary.json. The first actual EVM recovery segment now proves and independently verifies
at q70/PoW26 (evm-first-recovery-leaf.json). Recursive wrapping of this new path
and a complete block proof remain pending; the collector is not proof authority.

The following design notes predate implementation and retain useful constraints.

# Measured next acceleration target: EVM recovery

Full-block PC profile execution verified canonical43-byte oracle;253,646,998cycles.
40.85275% of base instructions are in containing k256 symbols; memcpy18.95753%;
SHA compression4.47743%. The named native transaction recovery entry has66visits;
NativeTransactionRecovery::verify_and_compute_signer_unchecked hasZEROvisits;
Revm DefaultCrypto::secp256k1_ecrecover and ecrecover_precompile each have12visits.
Thus optimizing the unused supplied-key callback cannot help this fixture.
Do not confuse containing-symbol instruction counts with inclusive host timing.

Current guest: autoresearch/benchmarks/guest_runtime/ethereum/src/main.rs.
Pinned stateless a134a62 recover_block.rs already uses recover_signer, not the
supplied-key callback. Revm remains DefaultCrypto. Installed revm-precompile42.0.1
interface.rs has install_crypto and Crypto trait with defaults. Implementing only
secp256k1_ecrecover leaves all other operations on their existing correct defaults.
It returns Result<[u8;32],PrecompileHalt>; EVM consumes failure as empty output.

## Correctness requirement

Do NOT route all EVM calls into the existing successful-only native precompile.
Invalid r/s, nonresidue R, or an infinity result must preserve EVM failure behavior.
High-s signatures are valid for EVM: normalize s and flip parity before using any
low-s-only native path, checking exact equality with Revm's backend.
Existing transaction recovery rejects on failure; this is not a fallible EVM API.

## A feasible bridge using existing proved recovery (NOT IMPLEMENTED)

Prover-supplied hint bits can select a SUCCESSFUL native path versus the existing
complete software path. Hints must never assert a result:
- hint=1: execute the already-proved native recovery; a false success hint makes
  proof construction fail, never returns a fabricated successful/failed result.
- hint=0 or absent: run DefaultCrypto, preserving valid AND invalid semantics.
- Native output is actually proved and hashed to the same32-byte EVM return value.
  No public key/address from a host hint may be accepted as an oracle.
- A false negative hint only costs performance. This provides all old behavior,
  while accelerating successful calls without yet proving invalid-case arithmetic.

Use a versioned optional footer after the existing [u32 SSZ length][SSZ] input;
stateless guest still receives EXACT canonical SSZ prefix. Hint bytes participate
in public input commitment. A receiver must separately pin the canonical SSZ
payload; the footer is prover-chosen optimization data, not consensus authority.
If footer present, enforce bounded parsing and exact consumed hint count. Absence
must preserve software fallback for arbitrary blocks. This changes guest/input
identities, not native opcode semantics. Do not silently reuse old input hashes.

Generate hints with an explicitly marked software-observation guest build:
Revm Crypto wrapper calls DefaultCrypto and records whether each recovery succeeds.
After computing/verifying the normal43-byte block result, a collector-only feature
appends a versioned bit vector to its output. A bounded execution-only tool checks
the43-byte oracle prefix and emits the augmented prover input. The collector is
NOT a proof and its output is NOT trusted for cryptographic correctness; fast proof
execution independently checks every selected native result. Normal guest output
must remain EXACTLY43bytes, and wrong hints must never bypass verification.

Tests required: valid low/high-s agreement with DefaultCrypto; invalid scalar and
nonresidue cases use software failure; absence/false-negative hints preserve results;
forged positive hint fails rather than yielding an accepted incorrect result;
malformed/footer bounds/count; full real block output and increased proved native
recovery calls, followed by recursive proof tests of the new guest path.

Alternative: implement a fully fallible native recovery AIR. This is the final
cleaner long-term interface, but needs authenticated invalid-case witnesses
(range failures, nonresidue proof and infinity cases), not just a status bit.

Bulk memcpy is the next substantial remaining guest target. SHA remains required
by the full objective, but current measured SHA contribution is4.48%, so it cannot
by itself solve the block's total execution/proving cost.
