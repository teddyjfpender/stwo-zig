# Shared private PoW nonce bytes

Task: PoW hashing and subsequent integer absorption must read the same private
u64 nonce. Reuse the canonical frame writer's word callback for the two LE u32
halves, preserving all protocol bytes. Extend existing authenticated payload
routing to nonce/integer roles; two bounded private-word producers supply exact
combined read counts. No new AIR or identity; retain public wrapper behavior.
This is exact sparse dataflow / weighted multiset equality, as in previous
stages (https://eprint.iacr.org/2022/1530). No external code copied.

Inputs: native verified nonce, exact per-operation read receipts, fixed PoW bit
requirement and source namespace. O(1) source rows and receipt aggregation;
PoW and absorb hashing costs unchanged. Reject source collisions and invalid
word count/role. Keep PoW zero-test public and fixed, and integer domain/counter
reset semantics unchanged. Test byte parity against manual native encoding,
fixed-column independence across 64-bit nonce values, routed proof with nonzero
PoW, existing public protocol/framing regression and complete parent proof.
Remaining rejection schedules, lifted alias consistency and production key/
backend qualification are not resolved by this stage. No speed claim.
