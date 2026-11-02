# LS affine MAIN projection

The concrete CPU-owned LS encoding moves from MAIN79 to MAIN71. INTER48,
12 U16 queries,4 U8 queries, all five physical ledger fields, metadata82B,
D3/native2n/split1 and the canonical-range induction assumptions are unchanged.
Legacy `memory.load_store_v1` keeps its original physical layout and authority.
The new encoding identity is v4; no runtime profile enum is introduced.

## Eight exact affine substitutions

Indices below refer to the legacy logical79 row. `projection.STORED` defines
all71 physical columns in increasing logical-index order. All coefficients are
constants in the base field, and all equations listed were unconditional:

| Logical column | Reconstructed value |
|---|---|
| write1 | sum of the four store opcode flags |
| owner tick3 | after_low12 +65536*after_high13 |
| address low4 |8*quotient68 |
| effective low44 | address low4 + sum(offset_flag60+j *j) |
| effective high45..47 | address high5..7 |
| opcode48 | sum(opcode_flag49+j *raw_opcode_j) |

The source of opcode values and load/store positions is the existing immutable
`memory_constraints.load_specs ++ store_specs`, also used by the shared legacy
arithmetic. There is no second ISA switch. The effective-address additions still
use the original four Boolean carry constraints, preserving full64 wrap and
natural alignment. No address, immediate, clock or value canonicality assumption
is needed to justify substituting these affine equalities.

`expandFor` reconstructs the bounded virtual row, and the original
`load_store_v1.equations.emitLocalFor` evaluates that row. Every old residual is
retained, including the eight now-identically-zero copy equations; this keeps
one arithmetic authority and the complete261-residual order. Padding constraints
are retained too. Inactive offset/opcode flags, clock limbs and quotient therefore
force the derived padding coordinates to zero. Previous MAIN needs only active0;
no removed coordinate introduces a previous-row dependency.

## Relation and degree preservation

OWNER19 still contains raw opcode,A4,I4,B4,C4,after epoch and the recomposed24-bit
tick. RAM14 still contains the same address4,before/after epoch/tick/value and
R/W bits. Selection5 still contains selected limb,offset parity,byte and signs.
The exact same12 U16 and4 U8 semantic coordinates remain. Physical indices are
derived through the projection; metadata cache indices use logical indices.
This distinction is explicit and tested against the original wide-row oracle.

All reconstructed coordinates are affine, including opcode and offset sums at
arbitrary extension-field points. Thus every old local D3 polynomial remains D3
under substitution. RAM denominator pairs remain affine×affine, and local OWNER,
selection and range denominator pairs remain affine×affine. Their strict inverse
residuals remain D3. Numerators, activity, prefix resets and public claims retain
their original degrees and transcript order. No RAM/local-claim redistribution
or lookup-mass reduction is introduced.

## Native ownership and oracle boundaries

Native event validation and `native.logicalRow` retain the original row arithmetic.
`native_fill` writes only the71 stored columns into the final owned or borrowed
MAIN allocation. The79-coordinate row is bounded stack scratch, never a second
wide trace or a retained matrix. Narrow metadata and histograms are populated
from the same logical row. After MAIN release/adoption, interactions reconstruct
relations from unchanged82B metadata; no VM replay or wide source access occurs.

K/secp native bridges explicitly call `native.logicalRow` because their existing
RAM28 views use logical coordinates; their equations and physical layouts do not
change. The independent legacy-matrix expansion helper exists only in integration tests.
It lets the legacy source generate RAM/OWNER/selection claims and inverses as an
oracle. Production ownership and publication paths are unchanged: borrowed input
admission precedes writes; failed submissions drain; successful MAIN detach is
move-only; metadata survives commitment and is retired by the existing phase API.

## Qualification and scope

Native tests cover every LS width and legal offset, negative signed loads,
full64 addresses and wrapping EA arithmetic. The existing permission equations
are unchanged.
Arbitrary secure-field affine-map tests and all-residual finite differences check
polynomial behavior. Scalar, sixteen-lane base/secure and actual Circuit lanes
use the same residual authority. Existing actual false-witness physical proofs
still exercise noncanonical OWNER inputs, before clocks, writes, future epochs,
reversed ticks and orphan RAM cycles; the complete receiver must reject them.
An actual four-worker packed quotient run on256KiB stacks equals serial
accumulation in Safe/Fast; this is not merely FFT-worker coverage. The receipt
records final Safe/Fast and fresh positive proof results.

The current complete operational control has45 LS components and36,798,464
padded LS rows (`/tmp/rv64-ethereum-full-ls48-concurrent-v1/bundle.json`). At the
same geometries, MAIN71 removes294,387,712 source cells (1,177,550,848 bytes of
summed source volume) and360 Q opening samples. The maximum single CPU proof's
LS-source reduction is67,108,864 bytes. Fixed, INTER, query counts and narrow
metadata do not change. These counts establish neither runtime nor peak RSS.
