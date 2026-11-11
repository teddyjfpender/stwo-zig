# Fixed-source reuse must bind column geometry

The heavy selected OP guest exposed a setup-mode incompatibility while wrapping
its complete D2 native bundle. The independent identity-only receiver accepted
all native proofs, but the legacy committed-source recursion setup refused with
`GlobalGkrManifestExecution`. The manifest identity check stayed closed.

A minimal regression demonstrates the underlying reuse error. Seal two source
trees with the same nonconstant column at log 8 and a zero column at log 5 or
log 6. Their lifted Merkle roots and column counts are identical. Their native
coefficient vectors have different shapes, so their candidate fixed identities
must differ. This does not require a hash collision: every lifted leaf sees the
same zero value. The source root does not authenticate each native column height.

Two fast paths omitted that distinction:

- `fixed_authority.Binding.matchesSource` compared source root, suite and count.
  Ordered-set deduplication could therefore reuse another geometry's candidate
  binding instead of deriving the correct one.
- `fixed_setup.SourceTag` used the same incomplete identity for trusted restored
  sources without coefficients. A root-only source with another height could
  retrieve the existing entry.

Bindings now retain a digest of the ordered source column logs. Internal source
tags include the same geometry, and artifact restoration derives it from the
already authenticated source-log vector. The digest includes a domain separator,
the column count and each little-endian log in order. It is independently derived
metadata; proof bytes cannot select it.

This changes cache admission, not the AIR, transcript framing, candidate fixed
identity formula, commitment parameters or security target. Existing correctly
bound candidate keys keep their identities and roots. A cache entry whose shape
does not match must miss or refuse; no fallback bypasses manifest, source-body or
root checks. Historical bundles depending on an incorrect alias are not promised
compatibility.

The regression first fails on the old binding reuse. It then checks refusal of
a differently shaped restored source, acceptance of the exact original shape,
and refusal of reordered logs. A second test compares mixed-height log-20
streaming source coefficients with independent identity-only interpolation,
including sparse and constant columns, at both candidate commitment rates.
The full fixed-setup/artifact mutation suite passes in ReleaseSafe after repair.
The [physical heavy native receipt](../../vectors/reports/rv64-opstack-cpu-20261108/fixed-source-geometry.json)
confirms acceptance of all 115 native proofs under the repaired committed-source
receiver. The complete recursive setup-mode comparison is recorded separately;
this note alone is not a recursive-root receipt.

Reproduce the focused checks with:

```sh
zig build test-riscv64-wide-fixed-setup -Doptimize=ReleaseSafe -j1
```
