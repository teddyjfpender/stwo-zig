# Retained OP Mainnet anchored transition

This is one canonical input for the genuine transition **159321793 → 159321794**
under pinned Ethereum L1 anchor **26378629**. It contains 38,981 authenticated
preimages and 15 standard EIP-4844 sidecars. The official pinned Kona native
client and this repository's independent native transition verifier accepted it.
The unpruned input, KV caches, binaries and logs are deliberately not duplicated.

`manifest.json` pins the entire claim, expected statement and 43-byte OD output,
compressed/raw sizes and SHA-256 hashes, upstream source/patch, native executable,
source inventory, and KZG setup/checker identities. The gzip uses mtime=0 and has
no filename header. Raw OPD: 13,882,081 bytes, SHA-256
`9ee0a1f7b425d90c12d705212502dc135773af8d60f63c494a83500214c14031`.

From the repository root, unpack with a fixed 16 MiB bound and verify both hashes:

```sh
mkdir -p /tmp/op-transition-159321794
python3 opstack/capture_host/unpack_fixture.py \
  --manifest opstack/tests/fixtures/transition-159321794/manifest.json \
  --output /tmp/op-transition-159321794/input.opd
```

For a fresh **native-only** replay, use an independently built trusted native
host. For example, the existing pinned Rust nightly can build only that binary:

```sh
CARGO_TARGET_DIR=/tmp/op-transition-native-build \
  cargo +nightly-2026-08-08 build --manifest-path opstack/kona/Cargo.toml \
  --locked --release --features host,transition-program --bin stwo-kona-host
mkdir -p /tmp/op-transition-159321794-fresh
python3 opstack/capture_host/unpack_fixture.py \
  --manifest opstack/tests/fixtures/transition-159321794/manifest.json \
  --output /tmp/op-transition-159321794-fresh/input.opd \
  --native-host /tmp/op-transition-native-build/release/stwo-kona-host
```

The optional native run has a 180-second bound, records the actual executable
hash, and must reproduce the exact independently pinned statement and OD bytes.
Default tests only check bounded decompression and hashes. They run neither
native execution nor RV64, STARK or recursion proving. This receipt establishes
native anchored derivation, **not a physical proof**; anchor finality remains an
external input. The missing older 159257842 archive remains a separate gate.
