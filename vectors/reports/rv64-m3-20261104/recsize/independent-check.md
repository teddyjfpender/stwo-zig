# recsize independent adversarial check (2026-11-04)

Checked at 532f773e6. CPU-only, no GPU job run.

- Soundness re-derivation [D]: conjectured query+PoW bits r1 1*108+20=128, m3 b4 2*51+26=128, b8 3*34+26=128,
  the same ethSTARK convention as native (log_blowup*queries+pow). The in-circuit verifier takes PoW bits (26 fits the
  32-bit two-limb check), query count, blowup and the config mix from `Outer.protocol.targetConfig()`, so a fold
  enforces the m3 parameters; it does not keep r1 constants. Under the Johnson-bound regime: r1 74, m3 77 bits.
- Fold arity [D, plus a Python replay of Plan.initArity]: 17 leaves at arity 4 give folds of 4,4,4,4,4,2, so 22 child
  verifications. The design note said 24, and that is now fixed. 11 leaves (26235156) give 4 folds (4,4,3,3), not the 3
  in the implementer's integration note. Every child of a fold gets its own guessed proof, V.verify and FIXED-root equality.
  The fold digest binds the child identities and outputs in order. Ordering, adjacency and coverage come from the
  receiver's own plan, which it never reads from the producer. The fold circuit itself does no execution adjacency
  check, as in r1. That remains the application receiver's job.
- Fused Blake2s gadget: not implemented in this stream (stated), so there was nothing to check.
- Fresh receiver: the accept/reject receipt is in-process, on synthetic children, CPU (as stated). No separate-process
  real-block receiver at m3 exists yet.
- Fixed (fail-closed): an env value that is set but unreadable (longer than the lookup buffer) used to fall back silently
  to r1 / the default arity. It now panics (profile) or returns InvalidRecursiveFoldArity (arity). Probe [M]: arity
  "3" gives 3, a 23-digit value gives an error, an empty value gives an error, unset gives the default 4.
- Re-run [M]: test-circuit-om31 (includes the protocol.zig profile test) 17/17 pass, before and after the fix;
  ready_dag.zig 7/7 pass.
