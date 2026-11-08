# Resident OM31 transcript on RTX 5090

The native channel keeps raw Blake2s digests and reduces only drawn challenge
words modulo M31. It imports a nine-word native checkpoint (eight digest words
and a draw counter); initialization deliberately does not mix the profile tag a
second time. Profile/statement binding belongs to the authenticated controller.
The existing 64-byte device transcript state and Blake primitive are reused.

Batched draws hash independent counters in parallel in one CTA. The counter and
schedule cursor advance once after the complete batch. Absorbs support empty
inputs and exact Blake block boundaries. Canonical-field validation occurs
before digest mutation. Order, chain, field and seed errors are sticky; failed
draws clear their output. The Zig owner validates the final status/cursor/chain
before publication. This remains a primitive: callers must join and actually
check that terminal snapshot, and independently bind their launch schedule.

One hundred GPU cases pass, including 1/2/3/9/257/1024 draws, empty/partial/multiple
hash blocks, padding canaries, alias/alignment rejection and four poison cases.
All four Compute Sanitizer tools pass. Sixty reference cases independently agree
with the real Zig `Om31Channel`, and Safe/Fast integration each pass 35 tests.
Numeric challenges and transcript feedback remain on the GPU between commands;
only setup ingress and terminal validation copies occur in this test harness.

No full Ethereum GPU proof, GKR batch integration or whole-prover performance
claim follows from these tests. FRI/DEEP/composition controllers and mixed-instance
GKR remain necessary before production readiness can change.
