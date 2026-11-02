# ALU canonical-input range reduction

This evolves the concrete ALU encoding from v3 to v4. FUNCTION13 operation IDs
0..9 and integer semantics stay unchanged. MAIN remains52; INTER48 becomes32.
The lane-generic polynomial authority remains shared by scalar Q, packed base,
packed secure and Circuit evaluation. There is no representation runtime enum.

## Retained obligations and accounting

`word16_v1/alu.rangeValueFor` retains sum4, difference4, and four doubled low
parts used by the A/B/sum/difference sign decompositions:12 U16 queries per
padded row. Only the eight direct A/B limb memberships are removed. Six strict
pair inverses use24 M31 columns; the strict FUNCTION inverse uses4; the joint
prefix uses4. The total is32, with63 residuals and degree3/native2n. Every
physical range query remains unit weight, including zero-FUNCTION-weight rows.
FUNCTION multiplicity remains separate and cannot disable a strict pole.

Source metadata shrinks70 to54 bytes per padded row: payload13 already retains
all A/B/C coordinates for the FUNCTION tuple, so only12 range indices are needed.
Native fill, serial/parallel interaction generation and histogram admission use
that same query inventory. This is not a reduction in MAIN backing or the
Stage1 MAIN retention floor. Each ALU component removes16 Q opening samples;
its four previous-prefix samples remain. Source INTER falls16*N M31 cells.
No whole-job speedup or peak-RSS claim follows from these counts.

## Noncircular write anchors

The original53 local equations retain their emission order and meaning.
The staged signed predicate is factored into one shared `signedLessFor` helper.

* ADD outputs the independently ranged sum limbs; SUB outputs ranged difference.
* ADDW/SUBW use those same low limbs. Their upper limbs are0 or65535 from Boolean
  signs. Ranged sum[1]/difference[1], the sign equation and doubled-low query make
  the W sign bit exact: all relevant integer expressions have magnitude below p.
* Comparison outputs have zero upper limbs. EQ/NE use the Boolean SUM-zero
  witness with all four difference limbs ranged; their sum is at most262140<p.
  Unsigned comparison uses a Boolean borrow. The staged signed comparison is
  Boolean for all eight Boolean signA/signB/borrow combinations, even before
  input-word canonicality is established.

Consequently every active provider C is canonical independently of the removed
A/B queries. Inactive rows have zero selectors and zero C. Nonzero FUNCTION
multiplicity forces active=1. Negative/large pure-truth multiplicities do not
create support for a false canonical-input tuple: each contributing row still
has the local truth and write anchors. Positive consumer mass is admitted below
M31's characteristic; the usual typed randomized multiset soundness argument
remains required. This is not an individually authenticated range/function
certificate: the merged prefix authenticates only their physical sum.

## Canonical reads and correct integer semantics

The closed CPU REG6 relation starts from receiver-admitted u64 registers. Its
fixed after-clocks and retained gap16/U8 queries establish strict integer
predecessor order. All writers retain independent anchors: this ALU as above,
BINARY/SHIFT lookup truth, DIV/MUL result ranges and immutable ROM links.
LS C and RAM after values use the strict joint REG/RAM time induction in
[rv64-ls-joint-write-induction.md](rv64-ls-joint-write-induction.md), rather
than independent LS C4 queries. Service RAM writes retain byte anchors. Thus
canonical reads follow without presupposing ALU input ranges.
ROM authenticates immediate/PC operands. The CPU commits its effective B mux
before the affine FUNCTION lookup. Exact tuple equality supplies canonical A/B
coordinates to every consumed ALU fact, restoring ordinary bounded-integer
carry/borrow and signed-input semantics.

JALR composite ADD requests also have canonical inputs (REG and ROM immediate);
their ALU SUM result is independently canonical before BINARY clears bit0.
No stateful OWNER or RAM event may use pure-fact multiplicity: those weights
remain Boolean/unit on both sides of their buses.

A doubled-low query alone does **not** range an arbitrary A/B high limb.
For h=(p+1)/2, `2*h=1` in M31. A=B with high limb h can satisfy every local
polynomial and retained query, with ranged sum high=1 and canonical EQ result.
The new tests preserve this counterexample. Such a fact cannot match a canonical
CPU/ROM tuple. This encoding must not be advertised as standalone truth over
arbitrary M31-encoded input words.

## Accepting contexts

The full Word16 genesis/global/service receivers supply the closed REG/ROM and
FUNCTION argument described above. Thin raw46 and indexed40 V2 receivers also
close local REG/ROM/ranges against independently admitted u64 endpoints; their
outputs use the same independent ALU write anchors. Their geometry mass admission
now derives the ALU query count from its encoding. V2 public policy already binds
the ALU encoding identity; both local transcript paths mix it explicitly.

The standalone diagnostic ALU fixture reconstructs its complete public consumer
roster from independently selected native u64 facts. Its verifier accepts no
caller-supplied arbitrary roster. Generic low-level Component verification has
open FUNCTION debt and is not an accepting execution or arbitrary-input truth
verifier. The BINARY-only V1 transcript branch is unchanged. Core materials and
all ALU fixtures bind the concrete v4 encoding identity and actual physical shape;
old ALU proof bytes are intentionally not interchangeable with v4.

## Adversarial and lane qualification

Local tests retain the canonical-input SUM-zero forgery (A=65536,B=1 and false
D0=p-1,D1=1), which must fail physical difference membership. A second forgery
keeps ADD equations valid with low output65536/high0 and false carry; the retained
sum range blocks this noncanonical register write. Boolean predicate tests cover
all sign/borrow cases. Arbitrary-Q finite differences and packed-base/secure
comparisons cover every complete residual, including previous masks.

`word16_execution/alu_read_induction_proof_test.zig` commits a half-field A/B
alias with canonical C, satisfying all local equations and all retained query
values. It updates retained-range multiplicities BEFORE MAIN commitment and checks
that every other debt closes; only the FUNCTION debt changes. It rebuilds
interactions from the actual committed false MAIN, obtains a real full-PCS proof accepted by a fresh physical verifier, and requires the
precise `UnclosedExecutionRelations` rejection from the fresh closed CPU receiver.
This exercises the missing-read authority seam rather than native input checks.
Circuit tests compare every residual using actual builder wires, including
challenge, claim and inverse mutations. Native serial/parallel tests compare
all columns/claims after MAIN retirement and exercise poles, retries, draining
and allocation failures. The report records actual fresh proofs and gates;
this manual source argument is not a machine-checked proof.
