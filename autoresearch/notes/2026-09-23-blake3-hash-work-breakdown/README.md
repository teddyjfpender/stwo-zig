# Canonical recursion hash-work breakdown

The prior census found G hashing at 86.3% of the parent roster's padded trace
words. This gate separates actual transcript G rows from leaf/subtree and upper
ancestor rows across all four trace commitments and each FRI commitment.

For each independent root, candidate sharing counts unique opening indices and
unique (level, ancestor-index) nodes. FRI indices are shifted by the authenticated
fold step before counting, matching the real group emitter. The census checks
that the sum of per-group G rows equals the emitted path witness count. It does
not alter witness generation or admit a shared-path circuit.

The candidate assumes exact equality of repeated payloads and consistent child
hashes. A real implementation must enforce all query-coordinate, payload, root,
and multiplicity bindings in the circuit. The estimate is not a proof, runtime
speedup, or authorization to drop duplicate query checks. It keeps commitment
roots independent, including roots with identical digest bytes.

The gate passed. Reproduction:

```sh
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments -Doptimize=ReleaseSafe '-Driscv-test-filter=canonical parent row census' --summary all
```


Measured G-row inventory:

| Work | Rows | Share |
|---|---:|---:|
| Transcript | 62,328 | 2.0% |
| Leaf payloads and opening subtrees | 807,520 | 25.4% |
| Upper Merkle ancestors | 2,304,960 | 72.6% |
| Total | 3,174,808 | 100% |

Per-root repeated-opening and ancestor sharing gives a candidate 2,124,248 G rows,
a 33.1% live-row reduction. Both current and candidate sizes still pad to 2^22.
The candidate exceeds 2^21 by 27,096 rows. Thus sharing alone does not establish
lower G-domain size, let alone an end-to-end speedup. Other row families may still
benefit, and construction work may fall, but those effects require measurement.

The next hash implementation must preserve every query read, direction binding,
root equality and producer-use count. The candidate is a full multiproof-style
sharing estimate, not evidence that the current independent-opening circuit can
simply skip rows. Any circuit/layout changes require independently derived keys
and canonical proof qualification. A further reduction is needed to cross the
G padding boundary in this fixture; this is an engineering target, not a security
parameter change or a claimed achieved result.
