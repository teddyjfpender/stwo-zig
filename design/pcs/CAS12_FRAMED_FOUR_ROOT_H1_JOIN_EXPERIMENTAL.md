# CAS12: framed H1 source and query join

**Status:** experimental proof control. No production selector, security bits,
or P05 discharge.

CAS12 combines three separately reviewable candidates in an isolated engine
branch: CAS11's four production-profile **plain** source Merkle roots and
separate original/own-quotient H1 degree checks, P07's versioned framed
transcript channel, and P08's exact-uniform raw-word query sampler. The
focused test builds 1 fixed, 1 main, 1 interaction and 8 composition columns
over 32 rows. It commits the four roots, draws challenges in the candidate
fixed/main/interaction/composition/OOD/FRI order, folds each degree track,
absorbs both terminal vectors, then samples 16 raw query positions only
after two accepted PoW barriers. The four source openings use those sampled
positions. Recommitting the same columns after the queries must reproduce
the four roots that entered the transcript.
For this one-scalar-per-stage fixture, the first QM31 from each exact
eight-limb challenge block is used and the second is discarded. The final
query frame is verifier schedule event 22.

The test uses difficulty zero, synthetic roots/statement digests for the
circuit identity and line profile, and a synthetic interaction claim. It
does not verify a real Gate AIR relation, bind a sealed S31 key, select a
line-tree Merkle profile, or put all subproofs into one complete wire format.
The test synthesizes the roots and query positions and passes them into the
source-opening `Expected` value. A real verifier must derive `Expected` roots,
column logs and raw positions from its trusted statement, accepted root
frames and terminal query draw; it must never take those values from an
unauthenticated proof payload. No installed verifier performs this join yet.
The H1 slice has one OOD claim per column and no nonterminal line layer;
the reviewed Gate key has seven occupied heights and many mask claims.
`FramedBcsChannelV2` enforces byte roles, event numbering and the two PoW
barriers, but does not yet enforce this entire Gate event schedule as a
typed state machine. The test exhibits one matching schedule, not a complete
native-to-paper BCS or PCS theorem.

The current conservative paper target remains blocked independently of this
test. The source-bound Gate roster contains a 193-column source-log-4 bucket.
If its functions map uncompressed to a published same-domain batch at
`N=2^20`, `B=2`, the necessary QM31 batching term exceeds the selected
T64/96 work-factor target. A smaller actual key, different ensemble mapping,
or proved and affordable partition may change that feasibility result;
CAS12 certifies none of those alternatives.

Run the focused control with:

```sh
zig build --build-file src/prover/build.zig test-four-root-framed-h1 -j4 -Doptimize=Debug
zig build --build-file src/prover/build.zig test-four-root-framed-h1 -j4 -Doptimize=ReleaseSafe
```
