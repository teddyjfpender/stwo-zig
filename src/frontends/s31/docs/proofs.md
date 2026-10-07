# 6. Packages, native verification, and audit

## Build, prove, verify

This sequence starts with a checked-in text program and assignment. Run it
from the repository root:

```sh
python3 src/frontends/s31/s31.py lower src/frontends/s31/examples/math_polynomial4.s31
python3 src/frontends/s31/s31.py build src/frontends/s31/examples/math_polynomial4.s31 --lowering direct-gate --out zig-out/s31/docs-polynomial
python3 src/frontends/s31/s31.py explain zig-out/s31/docs-polynomial
python3 src/frontends/s31/s31.py equations zig-out/s31/docs-polynomial
python3 src/frontends/s31/s31.py inspect zig-out/s31/docs-polynomial
python3 src/frontends/s31/s31.py prove zig-out/s31/docs-polynomial src/frontends/s31/examples/math_polynomial4.valid.json zig-out/s31/docs-polynomial.proof
python3 src/frontends/s31/s31.py verify zig-out/s31/docs-polynomial zig-out/s31/docs-polynomial.proof
```

`build` compiles a prover and a separate native verifier for the selected
source and proof profile. It stages the package and publishes it atomically.
Before publishing, it rechecks the source bytes and compiler fingerprint;
an edit detected during the build aborts instead of stamping the package
with an earlier compiler hash.
Reusing an output directory with a different source, profile, compiler
fingerprint, or artifact hash fails. `prove` reads private and public values
from the assignment and writes a binary proof. The wrapper also writes
`zig-out/s31/docs-polynomial.proof.statement.json`, which contains only
`public_inputs` and `public_outputs`. `verify` uses that statement by default.

The generated verifier can run without the Python wrapper:

```sh
zig-out/s31/docs-polynomial/bin/s31-math_polynomial4-native-verifier \
  zig-out/s31/docs-polynomial.proof \
  zig-out/s31/docs-polynomial.proof.statement.json \
  zig-out/s31/docs-polynomial/verification-key.json
```

It reads no private assignment. It is a **native STARK verifier** that calls
the core Stwo verifier on the program's circuit/AIR components; it does not
execute an in-circuit recursive verifier on the host.

For a fixed-key recursive proof, the
[claim inspector](../inspect_recursive_claim.py) invokes that package's
native top verifier and prints the leaf words, intermediate public digests,
key hashes, counter, and expected fold output as JSON. Its digest
calculation is an independent Python check of the public statement; the
native verifier still decides proof acceptance.

## What is in a package?

| Artifact | Purpose |
| --- | --- |
| `bin/s31-NAME-prover` | Program-specific witness construction and proving. |
| `bin/s31-NAME-native-verifier` | Program-specific native proof checker. |
| `verification-key.json` | Profile, program/canonical-IR hashes, circuit hash, preprocessed root, padded geometry, pinned AIR asset hashes, FRI parameters, optional chip parameters. |
| `recursive-verification-key.json` | For `gate` and `sparse-wide-gate` packages: sealed outer verifier layout, root, hash, child-key digest and pinned AIR asset hashes. Sparse-wide key v3 also binds outer FRI fold step 4; its leaf defaults to step 1 and can be built with step 4. The native verifier embeds this key. |
| `recursive-verification-key-level2.json` | Sealed second wrapper layout and child-key digest for both recursive profiles. |
| `fixed-fold-verification-key.json` | Sealed repeatable fold AIR and root. Gate v3 and sparse-wide v4 use the constrained `u32` counter; the wide key binds the second wrapper key and fourfold FRI schedule. The [worked fold](recursion-wide-fold.md) explains its claim and limits. |
| `public-abi.json` | Named public inputs/outputs, kinds, lengths, eight-slot encoding. |
| `cost-report.json` | Raw/padded component rows, fixed columns/cells, source spans, input packing, public binding, selected profile and chip. |
| `source.s31.json` | Exact normalized relation bytes compiled by Zig. |
| `source.s31`, `source-map.json`, `typed-interface.json` | Text source, source locations, and nominal text types when the input was `.s31`. |
| `stdlib-lock.json` | Text package's pinned `std@1` version, import mode, and library source hashes; its digest is also in the key. |
| `manifest.json` | SHA-256 of every artifact above plus source/compiler identity, Zig version, and any sealed batch-proving capabilities. |

The text parser's qualified library calls disappear into normalized nodes.
The package manifest hashes the original text and standard-library lock;
the generated verifier checks the lock digest embedded in its key. The native verifier's
program identity binds the normalized relation and selected proof profile.
Text spellings or JSON whitespace can change source/package hashes and proof
bytes even when the canonical arithmetic graph and cost geometry agree.
Consequently a cost comparison should use canonical IR, component geometry,
and native-verifier acceptance, not require byte-identical proof files.

Before `prove`, `verify`, or `inspect` uses a package, the Python wrapper
checks its listed artifact hashes and required files, compares the key and
cost report to the manifest, and for a text package re-lowers `source.s31`
to compare the normalized relation, source map, and typed interface. This
detects an internally inconsistent or accidentally edited package. A
manifest can itself be replaced and rehashed; it is **not a signature**.
To decide which program's claim to trust, obtain the native verifier and
verification key through a trusted distribution path and check their
identity. Re-lowering also does not prove that the compiler translated the
source with the semantics the programmer intended.

## What the verifier checks

The verifier is built with the source relation and sealed key. It checks the
provided key and program identity, proof envelope/profile, canonical public
word encodings, preprocessed commitment root and circuit hash, component
geometry, lookup sums and chip endpoints when present, and then the core
STARK proof: commitments, out-of-domain AIR evaluations, openings, FRI, and
proof-of-work. Generic proof envelopes have a 16 MiB input cap and a
bounded 64 MiB decoding arena; the `sha-joint` envelope has a 64 MiB cap.
A key or proof for another program/profile
is rejected; a changed public output changes the transcript and fails.

Profile-specific proof headers are:

| Profile | Header |
| --- | --- |
| `gate` | `S31NAT1` followed by a NUL byte. |
| `chip` | `S31NAT2` followed by a NUL byte. |
| `sparse-gate` / `sparse-chip` | `S31NAT3G` / `S31NAT3C`. |
| `sparse-wide-gate` | `S31NAT5W`. |
| `direct-gate` / `direct-chip` | `S31NAT4G` / `S31NAT4C`. |
| `sha-joint` | `S31NAT6S`, a sealed key digest, interaction nonce, and twelve canonical LogUp sums. |

The envelope contains an interaction proof-of-work nonce, component LogUp
claimed sums, and a postcard-serialized Stwo proof. Circuit and chip
components share the same commitment trees and FRI proof. The verifier does
not trust the prover's host-side `run` result; it verifies the AIR and public
statement.

## Read the cost report correctly

`explain` lists normalized node names, source locations, canonical IDs,
gate-row spans, and source-expression groups. `equations` prints the
source-level M31 field equation for each arithmetic node, along with its
source location, canonical ID, and builder gate counts. For example, the
first multiply in `math_polynomial4` appears as
`_s31_0[j] - x[j] * x[j] = 0`. It labels these as semantic equations, not
expanded AIR terms. `inspect` exposes the backend report. In that report:

| Field | How to read it |
| --- | --- |
| `raw` | Circuit component rows before power-of-two padding; includes wiring, guesses, bindings, and finalization. |
| `padded` | Rows actually used by each committed circuit component. |
| `preprocessed_columns/cells` | Fixed geometry and its total field-cell count; tables can dominate even when source arithmetic is tiny. |
| `input_packing` | Number of source lanes and QM31-packed wires per input. |
| `source_map` | Builder gate spans for each canonical node. They are not additive across shared expressions. |
| `assertion_map`, `public_binding`, `finalization` | Extra gate spans that are not ordinary source nodes. |
| `chip` | Pinned round count, constant, and relation tag when a chip is selected. |
| `fri` | Visible proof-of-work, blowup, query, and fold settings. |

For the checked-in polynomial, the direct arithmetic profile has 329 raw
QM31-operation rows and 512 padded rows. Its eight fixed columns account for
4096 preprocessed cells. The source contains only six arithmetic nodes; the
other rows implement the circuit's inputs, packing, addresses, public
binding, and finalization. The proof size or proving time of another source
cannot be inferred by multiplying six by a gate cost. Proof-of-work time
varies across trials.

## Reproduce the evidence

```sh
python3 -m unittest discover -s src/frontends/s31 -p 'test_text_frontend.py' -q
zig build --build-file src/frontends/s31/build.zig test -Doptimize=ReleaseSafe
python3 src/frontends/s31/acceptance_text_v1.py
```

The acceptance script builds both text and handwritten JSON for the
polynomial, recurrence, and Poseidon2 Merkle path. It compares canonical IR
and cost geometry, produces proofs accepted by each generated native
verifier, rejects changed public outputs, and rejects a non-Boolean path
direction. The hash acceptance suites and other profile tests are listed in
the root [S31 README](../README.md).

## Current audit boundary

The commands above expose source, normalized relation, semantic field
equations, canonical identity, builder gate counts, selected profile,
fixed-cell counts, proof artifacts, and native verification. The equation
exporter does **not** expand the complete instantiated symbolic polynomial
program of the pinned generic circuit AIR, nor map source expressions to
individual polynomial terms or physical AIR rows. The [AIR chapter](air.md)
gives the exact specialized-chip row constraints; the generic AIR bundle
remains a pinned build asset. A symbolic exporter with an identity check
against that asset is still needed for term-by-term audit.

S31 also lacks a private circuit-to-chip boundary for mixed programs,
automatic chip selection, a dedicated Poseidon2 batch chip, and recursive
verifier generation. Current performance records apply to their specified
programs, host, and protocol configurations; row counts alone do not prove
an end-to-end speedup over Cairo.
