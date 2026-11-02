# Public GKR auxiliary preparation

The physical CPU/local-role evaluator derives ten uncommitted public columns:
eight M31 coordinates of the carry polynomial and two singleton selectors.
They depend only on the already checked GKR row point. They are not producer
witness authority, do not enter the PCS, and introduce no transcript draw.

The previous construction walked all logical rows separately for each of the
eight coordinates, converted an OM31 value to coordinates on each walk, then
allocated a fresh twiddle tree and a copied coefficient vector for each of ten
interpolations. `public_aux.zig` instead owns ten buffers once, precomputes the
small carry-coordinate table, fills all columns in one physical-row walk and
runs the existing batched/pooled M31 inverse FFT in place with one twiddle tree.
There is no retained cache or second interpolation authority.

## Physical indexing

Let `p` be the physical bit-reversed circle index, `b=bitReverse(p,log)`, and
`N=2^log`. For `b<N/2`, the logical coset index is `2b`; otherwise it is
`2(N-1-b)+1`. The low bit of `p` therefore selects the logical parity. The old
carry index `ctz(~(logical/2))` becomes the number of leading ones of `p` within
`log` bits for even `p`, or leading zeroes for odd `p`. Thus one bounded `clz`
replaces logical division and bit reversal. Its argument is always nonzero:
for even `p`, `(N-1)^p` is odd; for odd `p`, `p` is nonzero. The index is always
strictly below `log`. Logical selector rows0 and1 map to physical rows0 andN-1.

The independent qualification oracle retains the complete previous logical
walk and scalar interpolation. Every coefficient in all ten columns is
compared, including all eight secure coordinates. Coefficient equality also
checks physical row ordering through the invertible interpolation map.

## Ownership and resources

Each returned polynomial owns a separate allocation. Every physical row is
written once in disjoint relative32-row blocks; helpers join before stack
coordinate tables or buffer descriptors expire. One forward and inverse
twiddle array outlive the existing joined in-place transforms, then are freed.
Allocation failures unwind every initialized buffer; a point is never mutated.
The optional pool is explicitly supplied or taken from the current scoped pool,
never discovered globally or constructed here. Held/cooperative leases retain
the existing serial fallback. Worker stacks remain at their existing size.

The requested heap peak is exactly ten coefficient vectors plus two half-size
twiddle arrays: `11*N*sizeof(M31)`. The old peak was twelve vectors, including
its temporary evaluation copy. At log22 this saves one16MiB vector. The fixed
coordinate table is1920 stack bytes; bounded scheduler/FFT stack overhead and
already-owned pool stacks are separate. No N-sized scratch, LDE retention or
process-global cache is added.

## Qualification

`test-riscv64-gkr-public-aux` compares all coefficients against the untouched
scalar construction for logs1 through14, exercises a three-worker log18 inverse
FFT and held-lease fallback, checks independent owners, rejects invalid geometry
before allocation, preserves checked-point rejection of degenerate0/1 inputs,
and exhausts allocation-failure cleanup. A hard requested-heap cap checks the
allocation plan. The complete two-CPU plus Keccak/ADD/DOUBLE services fixture is
also proved and independently freshly verified, including parked/parallel
artifact parity and global closure. Actual real-prefix byte parity/performance
qualification is a separate gate; no speedup is inferred from this source change.
