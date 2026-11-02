# Ethereum completion over authenticated terminal RAM

A valid execution prefix is not a completed Ethereum guest execution. The
receiver must separately require its independently pinned absorbing terminal
PC, halt flag1, output length43 and expected43-byte result. The new terminal
helper checks these values in the execution proof's already authenticated RAM
boundary, rather than replaying execution or accepting a producer's output file.
Image.Owner retains the validated ABI symbols and absorbing PC alongside its
pinned ELF/input identity. Existing loading already checks that PC's immutable
instruction is JAL x0,0 and that the output region has the expected policy.

The helper is a terminal predicate, not a proof verifier. The accepting block
receiver must first verify every physical CPU/provider proof, the complete
manifest, CPU adjacency, genesis authority and global RAM/service closures.
Only then may it apply this predicate to the last proved CPU state and terminal
RAM list. A missing output word is rejected; no mutable-memory fallback supplies
an unproved terminal value. The lookup reads at most the ABI's fixed output size
and performs binary searches over the validated sorted RAM list.

The integrated test proves five actual programs from independently loaded
pristine images. Every proof freshly verifies as an ordinary execution prefix.
The honest program meets the predicate. Four valid prefixes are rejected for
wrong halt value, wrong length, wrong output, or stopping before the pinned
terminal PC. Thus rejection comes from independently expected completion, not
from a failed native constructor or an invalid execution proof. Safe/Fast gates
pass. This qualifies the predicate and its use after a closed proof; the complete
mixed-service block receiver/driver and real-block run remain separate gates.
