# bzip2 1.0.8

This directory contains the minimal libbzip2 compression closure required by
the official Stwo-Cairo binary proof transport.

- Upstream: <https://sourceware.org/bzip2/>
- Version: `1.0.8`
- Imported from: crates.io `bzip2-sys 0.1.13+1.0.8`
- License: BSD-style terms in [`LICENSE`](LICENSE)

Only the library headers and seven implementation units used by
`bzip2-sys` are retained. The command-line tools, decompressor-only utilities,
manuals, samples, and build-system files are omitted.

The Cairo product compiles this closure with `BZ_NO_STDIO` and calls only the
bounded in-memory `BZ2_bzBuffToBuffCompress` API. It does not invoke an external
executable or expose libbzip2 types through a public Zig interface. Removal
requires replacing the official upstream `bincode + bzip2` transport or
supplying an audited, format-compatible Zig compressor.
