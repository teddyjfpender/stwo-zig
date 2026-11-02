# CPU / global RAM / homogeneous secp arithmetic prefix

This explicit LE-word protocol joins one CPU proof per shard to independently
sized ADD and DOUBLE arithmetic truth proofs. It does not change existing plain,
Keccak, BE-packet or software execution routes. The current bounded harness is
not a full Ethereum block, halt/output certificate or scalable fanout driver.

Each CPU proof contains the canonical Word16 core plus two service bridges. A
bridge row holds one 32-byte coordinate and four distinct RAM words: six rows
per ADD, three per DOUBLE. The geometry-only fixed key does not depend on actual
call count, pointer, values, clocks or starting call ID. MAIN has134 columns;
INTER has244, comprising RAM20 +OWNER8 +Wire8 +U16(26 queries)56 +U8(73 queries)152.
The439 constraints share one scalar/packed-base authority, degree at most3 and a
native2n composition. Strict RAM chronology and permissions reuse the existing
RAM28 local equations, once for each affine virtual word view. No RAM word is
replicated at CPU height. The same native source supports owned/borrowed MAIN;
copied narrow packets and predecessors survive release for interaction work.

OWNER19 binds the real ECALL, a0's full64-bit pointer, IMM0, a7's exact LE service
tag0x20011/0x20012, C0, public CPU epoch and actual4*local instruction timestamp.
One unit negative owner term occurs at the first coordinate of each call. The
CPU supplies the matching positive term. The pointer is32-byte aligned. Four
U16 additions bind pointer+32*coordinate, with Boolean carries and no final
carry; alignment then makes base+8*lane canonical and nonwrapping for all four
words. Every word is readable; the three output coordinates must also be
writable. ADD's second operand is read-only and keeps its value while acquiring
the new authenticated timestamp. All before epochs/ticks/gaps are ranged.

Wire35 is unchanged: `(program kind,call ID,wire ID,32 LE bytes)`. Before input
coordinates contribute positively and after output coordinates negatively.
The RCB product/linear providers consume/produce exactly these tuples using the
existing byte arithmetic and program topology. Their independently sized
proofs remain degree4/native4n, with a local BYTE provider. The CPU/core bridge
proofs stay degree3/native2n. No field-operation, formula, wire ID or tuple
encoding was copied or changed in the arithmetic authorities. Raw coordinates
are reduced once by that existing program; no on-curve/infinity assumption is
introduced, and this service is not an unconstrained ECDSA acceptance oracle.

A strict inverse proves both Wire denominators nonzero. Its prefix is cleared
as `delta*d*e - active*e + active*is_output*d =0`; this keeps the quadratic
fixed-selector output weight cubic. Multiplying the inverse into that weighted
numerator inside an ordinary prefix would instead give degree4. All phase
polynomials remain live at LDE/OODS points. Dense arbitrary-QM31 and packed
16-lane gates check the same residual order.

The coordinator seals ALL actual CPU/bridge and truth fixed/MAIN roots before
common RAM14 and Wire35 challenges. Receiver-owned expected keys/specs bind
program, image, complete CPU coverage, epoch, PC/all-register adjacency, budgets,
role, geometry, call counts and per-kind disjoint call-ID spans. Truth wire IDs
include the ADD/DOUBLE program tag. Each CPU's complete physical claim vector
is mixed before its interaction commitment; all truth claims likewise. The
receiver verifies every STARK and actual root before accepting joint closure.
It checks the separate INIT/TERM RAM claims against independently validated
public boundary arrays, closes CPU local debt excluding ONLY service Wire and
RAM, then checks global RAM and global Wire sums. No native ledger total or
caller-supplied random challenge is an acceptance authority. Future core tail
roles are included through canonical core claim-count and RAM-sum helpers.

Receiver admission bounds local padded U16/U8 masses, all RCB BYTE masses, total
Wire multiplicity and absolute global RAM mass below the characteristic. A call
adds48 RAM terms for ADD or24 for DOUBLE, plus ordinary LS and both boundaries.
Parameters stay q70/P26/blowup1 (nominal configuration96); whole-protocol bits are
not established after rational-degree, multiplicity and union accounting.

The retained four-instruction fixture is SD→ADD /ADDI→DOUBLE over24 cross-page
words. The store deliberately changes a coordinate, so validity of a curve
point is not assumed. Four actual proofs accept with fresh independent keys.
Locally valid false outputs, fabricated epoch0 predecessors, a substituted
pointer and a substituted service kind are rejected by physical Wire/RAM/OWNER
closure. Complete-root, missing-inventory, typed-truth and balanced-claim
mutations are also rejected. A separate-process fixture tool reconstructs all
expected state and keys. Worker1/16 artifacts match exactly. This tiny fixture
is heavily padded and is no evidence of real-packet throughput or device fit.
