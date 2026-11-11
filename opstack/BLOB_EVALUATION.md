# Bounded blob evaluation on RV64

The anchored guest now selects radix-2 interpolation for dense EIP-4844
evaluation vectors and the streaming barycentric recurrence for sparse ones.
This changes local field arithmetic only. The blob Fiat–Shamir transcript,
canonical scalar decoding, point admission, KZG equation and trusted setup
remain the same. No service, host hint, AIR or execution profile was added.

Adjacent values in EIP-4844's bit-reversed order correspond to `w` and `-w`.
The even/odd interpolation identity gives

```
2 f_z(w²) = a + b + (z / w) (a - b).
```

Fold at `z²` after every layer, using the public inverse root from the existing
roots table. Twelve unscaled layers introduce a factor of 4096, removed using
a compile-time field constant whose inverse identity is tested. A dense fold
uses at most `2(N-1)` multiplications plus twelve squares, compared with about
`4N` in the previous recurrence. Every scalar is decoded canonically before
any zero-vector or on-domain shortcut. Sparse vectors skip zero terms before
root lookup and bit reversal; their nonzero denominators follow from the
caller's explicit `z^N != 1` check.

The [RV64 diagnostic receipt](../vectors/reports/rv64-opstack-cpu-20261108/blob-evaluation.json)
compares both algorithms in the same ELF. Native Arkworks and the actual RV64
executor must agree with independent Python polynomial or batch-inversion
arithmetic. These counts include root generation and diagnostic I/O:

| Vector | Previous instructions | Adaptive instructions | Reduction |
| --- | ---: | ---: | ---: |
| Dense polynomial | 9,048,344 | 6,608,445 | 27.0% |
| Dense full-width hash values | 9,048,713 | 6,929,722 | 23.4% |
| Half padded | 6,063,883 | 6,061,715 | approximately equal |
| One nonzero value | 3,075,732 | 2,977,590 | 3.2% |
| All zero | 3,076,573 | 2,686,860 | 12.7% |
| On-domain point | 4,156,847 | 3,885,724 | 6.5% |

Existing c-kzg-derived individual and batch sidecars still verify, and altered
blob bytes, commitments, proofs and noncanonical scalars reject. Dense, sparse,
zero and domain-hit cases also agree with the retained original formula. All
38 host tests pass with the transition and precompile features enabled.

This is not a measured full-transition speedup. Batch KZG shares its roots
table across blobs, and interpolation adds a temporary 128 KiB scalar vector.
Instruction savings alone do not establish the resulting memory argument or
proving cost. The previously retained anchored transition input remains missing
locally; its complete replay and physical proof are still open gates.

## Reproduce the isolated diagnostic

From the repository root, with the pinned Rust nightly and Zig 0.15.2:

```sh
python3 opstack/build.py --variant blob-eval-probe --artifacts /tmp/op-blob-build
python3 opstack/tools/blob_evaluation_bench.py \
  --build /tmp/op-blob-build --artifacts /tmp/op-blob-results
```

Both directories must be new. The diagnostic input is `BEV1`, one mode byte,
a canonical 32-byte scalar point and the 131,072-byte blob. Its output has a
`BEV1` marker and `BP` suffix; it cannot be admitted as `OP` or `OD`. The
existing execution runner retains its 43-byte output-size contract. The probe
feature is separate from the transition guest, and enabling both guest programs
is a compile error. No production receiver is relaxed to admit diagnostics.
