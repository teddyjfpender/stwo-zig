# Shared commitment roots for BLAKE3 recursion

Task: connect transcript root absorption and all authentication paths to one
canonical bounded 32-byte root source per trace tree / FRI layer. Retain the
preprocessed-tree root as a public trusted-key anchor. Other commitment values
must leave fixed columns. Preserve framing, full digest widths and path geometry.

Canonical match: weighted multiset equality / sparse dataflow, using existing
byte_route and private_word AIRs. An identity byte route consumes a computed
hash output and emits with multiplicity p-1 at the canonical root wire; this
consumes the canonical root too. Its producer emits the number of paths plus
transcript reads. Four affine equality constraints preserve the exact bytes.
No new AIR identities or equations; no external implementation copied.
Reference mechanism: https://eprint.iacr.org/2022/1530 (previous stage research).
Alternative new equality AIR is redundant; public copies retain per-proof keys.

Inputs: native verified capture, fixed per-tree/layer root slots, canonical
transcript read receipts, and all existing path schedules. O(8*(roots+paths))
new wiring rows, bounded fixed multiplicities below M31 modulus (derived).
Counterexample: removing the preprocessed-root anchor would admit a substituted
verification key. Keep it explicitly anchored; production admission still pending.

Falsifier: full joined parent proof fails, root bytes remain in non-key fixed
columns, or a changed root is accepted by the equality relation. Check fixed
invariance, exact root tuple conservation / tamper mismatch, public API regression,
and complete parent proof with focused serial targets. No speed claim. Dynamic
query/nonces/rejection schedules and parent-of-parent remain later work.
