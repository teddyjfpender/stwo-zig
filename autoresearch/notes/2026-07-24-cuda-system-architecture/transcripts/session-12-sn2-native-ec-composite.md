# Session 12: SN2 native EC composite

## Scope

Admit Cairo `ec_op_builtin` as an authenticated resident CUDA writer and make
`partial_ec_mul_generic` its ordered consumer. The partial-EC program remains
unavailable through the public standalone recorded-witness path: the native
EC graph is the only producer allowed to bind its 127 input columns.

The evidence boundary is the canonical EC fixture and the Zig-side resident
contract. It does not build or execute the Rust CUDA backend.

## Resident contract

The native writer has one exact ABI and three same-stream launches:

1. one thread owns an EC row and writes the 273 trace columns, 488 lookup
   words per row, 127 projective partial-input columns, and four multiplicity
   slabs;
2. round-major normalization converts the saved projective points to the
   affine inputs consumed by `partial_ec_mul_generic`;
3. padding extends 252 rounds to the exact 256-round power-of-two domain.

Preparation validates every resident range, pointer-table extent, ownership
generation, alias boundary, count capacity, and launch dimension. The hot
launch performs no allocation, host copy, synchronization, fallback, or JIT.

`native_ec.zig` requires the generic consumer's 126 inputs to have the exact
same address, length, owner, and generation as native partial columns 0
through 125. Native column 126 is private padding row-index scratch and is not
an AOT input. The composite launches the native writer before the
authenticated `partial_ec_mul_generic` AOT consumer on the proof stream. The
generic program is deliberately rejected by the standalone
`recorded_witness.prepare` API.

## Authority identities

| authority | SHA-256 |
| --- | --- |
| `vectors/cairo/ec_op_parity.bin` | `dd3e2354adee6779e68b19cd46314e9da54f53ec5ad232948623add38282e53b` |
| `ec_op_witness.cu` | `992f03a616c843f1b180adc397216635c2debb65b3fb4ccbbf9da2ae989a16bc` |
| native EC composite binding | `54c7cc06889e168c425a124a92438ad57ff0c6eb646960b2824861c85d3bd4f3` |
| resident EC contract | `c6445d144476274b66721aa29eb49a2b71ed869ef0f8fa98b7bf591fd8ce7bda` |
| generic AOT source | `48345960c70951f32c5c0c49d16a03c0daab9d4c8a404f5e9bebbe7502a17c61` |
| hardware differential | `02105b3c6bfc6acb93aaa636dad7fcd66adbfc11b6892bf9ac2b5a69e983b66a` |
| Zig SIMD receipt tool | `ae486a89316091af5d6061daae19f0f92ae6cfb8f47352247a7bf91e9cbbcf51` |

The hardware run used the released native archive:

- build identity:
  `72a2dee34a879e6ca76d206b372912a488a0540daef4d34aefd077791fe4f66c`;
- archive SHA-256:
  `bbf7426d3e988dbc35a1e777e9d1855c607936e1ab8a8b490da5c773d49a08c2`;
- AOT pack SHA-256:
  `932708af0fd3f4f1273a9f1e0778d916bd066af0b199b6ed186f1975027e1bc0`.

## RTX 4090 differential

The first run reported:

```text
trace mismatch word=1 column=0 row=1 expected=4 actual=1073741836
```

The fixture serializes trace values as `[row][column]`; resident CUDA columns
are `[column][row]`. The actual value was the canonical row-1 value. The
harness now performs that explicit oracle-boundary transpose, while lookup and
partial sections retain their documented word-major layouts.

The corrected immutable-archive run passed:

```text
native CUDA EC composite passed: rows=64 partial_rows=16384
trace_words=17472 lookup_words=31232 partial_words=2080768
multiplicity_words=11462 launches=3 device_ms=2.569
hot_allocations=0 hot_copies=0 hot_syncs=0 jit=0 fallbacks=0
```

Every trace, lookup, and partial-input word matched the canonical fixture.
Address, big-value, small-value, and range-check-8 multiplicities were
independently derived from the execution tables by the hardware harness and
also matched word for word.

## Partial-EC accounting

The standalone device matrix intentionally excludes
`partial_ec_mul_generic`; recording it there would falsely permit callers to
launch it without the native EC producer. Its product entry is nevertheless
authenticated:

- cache key `d6628b6f40a95659`;
- kernel `stwo_jit_witness_945de91f8879d0ac`;
- recorded-witness ABI schema 2;
- module globals `none`.

The first composite draft incorrectly inferred a Pedersen requirement from
unused helper definitions in the generated source. The canonical witness
program reports no Pedersen deduction, and its kernel body never calls either
Pedersen helper. The local contract gate rejected that over-admission. The AOT
manifest and composite preparation now require `none`; the two actual
Pedersen consumers retain their exact module-global capability.

The same gate found that the native workspace has 127 columns while the
generic program has 126 inputs. Requiring all 127 as consumer inputs made a
complete preparation impossible. The fixed boundary proves the first 126
aliases individually and retains column 126 as native-only scratch.

The two standalone programs that exercise the same authenticated Pedersen
module-global publication path passed the complete device matrix:

- `pedersen_aggregator_window_bits_18`;
- `partial_ec_mul_window_bits_18`.

This separates three claims cleanly: the base native EC writer has complete
device parity, Pedersen AOT module publication has complete device parity, and
the generic partial writer can only be reached through the exact composite
binding.

## Compact generic oracle

The generic consumer would require roughly 130 MiB to store a second
word-for-word fixture. Instead, the checked Zig SIMD receipt executes every
canonical consumer word from the EC fixture and hashes each complete ABI
stream:

```text
rows=16384 inputs=126 outputs=624 lookup_words=990 sub_words=424
outputs_sha256=64a9134cc28a5dd353a86434660c5dfbe8bb7dceb9e510a35a2ed4ce593b4edb
lookup_sha256=946e0c8bd1cca02686ac24d55a06568e317abcda7f20cc0d0ea8f2ffc6d36387
sub_sha256=1ae0d9fa6a593c19a1e3e83c33fe3a02c0cf7dc1a2d581f0bab905adfef3fe79
```

CUDA downloads and hashes the complete column-major output, word-major
lookup, and word-major sub streams after the same-stream native-plus-AOT
launch. A mismatch fails with the expected and observed stream digest; no
large duplicate fixture is checked in.

The RTX 4090 chained differential used an authenticated one-entry carrier
generated by the product packer from the regenerated generic cubin. This
avoided waiting for unrelated Cairo evaluation kernels in the concurrent full
archive build:

- generic cubin and pack SHA-256:
  `67650777f2037f1fd9b100bc5f727991de94dbba124557a2cffe9a2584d2629d`;
- cache key `d6628b6f40a95659`, ABI schema 2, module globals `none`;
- the loader authenticated the cubin digest before `cuModuleLoadData`;
- AOT telemetry reported one load, one launch, zero misses, and zero launch
  failures.

The complete chained result was:

```text
native CUDA EC composite passed: rows=64 partial_rows=16384
trace_words=17472 lookup_words=31232 partial_words=2080768
multiplicity_words=11462 generic_output_words=10223616
generic_lookup_words=16220160 generic_sub_words=6946816
launches=4 device_ms=5.474 hot_allocations=0 hot_copies=0
hot_syncs=0 jit=0 fallbacks=0
```

## Reproduction

```sh
g++ -std=c++17 -O2 \
  -Isrc/backends/cuda/native -I/usr/local/cuda/include \
  tests/cuda/native_ec_op_composite_smoke.cpp \
  /path/to/libstwo_cuda_kernels.a \
  -L/usr/local/cuda/lib64 -lcuda -lcudart -lnvToolsExt -ldl -lpthread \
  -o /tmp/native_ec_op_composite_smoke

/tmp/native_ec_op_composite_smoke vectors/cairo/ec_op_parity.bin
```

Zig SIMD generic receipt:

```sh
zig build cuda-native-ec-composite-oracle \
  --build-file build_support/internal_build.zig \
  -Drepository-root="$PWD" -Dproduct-scope=cuda_tools
```
