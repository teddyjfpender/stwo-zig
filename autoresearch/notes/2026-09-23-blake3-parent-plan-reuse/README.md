# Reuse authenticated parent structure across compatible keys

The parent worker already owns a persistent pool/workspace and the shared bounded
pipeline already overlaps one preparation thread with proving. Inspection found
that changing the admitted key always reconstructed AIR definitions, fixed-row
metadata and the fixed commitment, even for changes only to query count/PoW.

The new path independently validates the incoming admission, compares geometry
and fixed root, and compares every fixed row through the existing row validator.
Only query count and PoW are excluded from the configuration comparison: these
control sampling/transcript work, not the fixed commitment. All other configuration
fields and log sizes must match. On success the exclusive worker rebinds its plan
to the new admission. The proof still constructs a fresh channel/scheme and mixes
the new key and complete config. Incompatible structure takes the existing rebuild
path; invalid admission leaves the old plan untouched.

Qualification extends the existing diagnostic-to-canonical profile test: require
the exact same plan pointer, independently verify the q70/PoW26 proof, reject the
old key when decoding, and replay its transcript. Wrong-root and wrong-key attempts
must preserve the prior admission. This focused test passed; no latency
improvement or complete goal fulfillment is claimed.

This is process-local structural reuse, not a new PCS profile or a change to
canonical parameters. It does not make statement-dependent fixed tables equal;
those still require rebuilding when their exact content changes.

```sh
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments -Doptimize=ReleaseSafe '-Driscv-test-filter=real runner proves and independently verifies' --summary all
```


The gate verifies diagnostic parents at two recursive levels, then the canonical
parent after re-admission: 748,495-byte artifact, q70/PoW26, same fixed plan
allocation, transcript replay, and verification after worker destruction. The
child remains diagnostic q8/PoW0 in this profile-switch fixture; this is not a
canonical-security claim for the entire chain. Canonical leaf-to-parent security
was qualified separately in the barycentric-context gate.
