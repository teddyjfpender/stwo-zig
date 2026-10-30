# Historical active-layout V2 evidence

Current default bounded-wire reload tests use the
[active-layout V3 artifacts](../block-v7-active-caller-v3-20261029/README.md).
The original bytes below remain the reference for the recorded storage/kernel
comparisons. V3 independently derives a different caller identity.


# Complete finite execution in one original STARK

A genuine 20,495-cycle RV32 execution, including two SHA calls, one Keccak call,
ordinary RAM operations and the complete 43-byte terminal ABI, now has one
independently verified heterogeneous STARK. Canonical 70-query/26-bit-PoW and
8-query diagnostic gates both passed all 14 tests.

This is a different output contract from the earlier compact recursive root.
It is a closed original proof, without a qualified 15-tree recursion adapter or
final publication wrapper. It is not an Ethereum block proof or a whole-block
memory qualification.

## Contiguous measurements

Apple M5 Max, 64 GiB RAM, four workers, ReleaseSafe. One sample per configuration;
no other active compiler or prover during these measured paths. Proving includes
interaction preparation, the merged fixed commitment and the original STARK.
The timer begins before ELF admission/execution and ends after fresh verification.
It includes destroying every producer, witness, runner and counter owner, and
serializing/decoding the STARK. Test-only hostile replays run after the timer.

| Stage | Diagnostic: 8 queries, 0 PoW | Canonical: 70 queries, 26 PoW |
|---|---:|---:|
| Admission, execution and first commitments | 0.406 s | 0.400 s |
| Union preparation and proving | 3.253 s | 4.036 s |
| Producer destruction | 0.042 s | 0.042 s |
| STARK encoding and decoding | 0.170 s | 0.186 s |
| Fresh independent verification | 1.223 s | 1.354 s |
| **Contiguous execution to verified proof** | **5.094 s** | **6.018 s** |
| Charged peak across that path | 367,193,630 B | 366,664,734 B |
| Proof size | 1,255,910 B | 5,841,554 B |

The canonical standalone test process had a sampled OS peak footprint of
386,565,368 bytes. That process also ran negative checks and the pair-regression
test; the allocator's direct-path peak is the more precisely scoped metric.
The 24 GiB allocator limit remained enforced. The native access trace contained
1,572,864 cells; the explicit fixture cap is 16,777,216 cells. An earlier small
fixture's 1,048,576-cell cap rejected this one-window workload before proving and
was replaced only through a new explicit test-helper sizing argument.

## What was compared and proved

The new route retains every original equation and physical claimed sum. A
canonical fixed-column concatenation, seven unchanged private roots, six
interaction roots and one composition root form the 15-tree proof. The same
original epoch feeds the unchanged 53 relation draws and caller suffix. All
physical claims enter the new transcript before any interaction commitment.

Independent admission reconstructs the ELF, initial memory and registers, exact
execution window, caller provenance, ROM image, lookup demand and terminal ABI.
After the STARK check, original typed algebra closes per-window state/register
relations, ROM fetches, RAM transitions, first-touch initialization, range and
terminal providers, all lookup claims, and natural event/fetch counts.

The qualification runs separately constructed all five original proofs under
that exact epoch and compared every native/access/caller/provider physical claim
and the final independently verified result. The timing runs omit this test-only
oracle; their complete public metadata and physical claims were then checked
against the qualified artifacts and match exactly. This is recorded separately
from running the oracle during the measurement.

Negative cases cover changed native sums; compensated caller, lookup and RAM
sums; changed fixed roots; substituted private and interaction roots; missing
providers; changed memory geometry; changed ELF identity; and changed public
output. The earlier native/caller union proof also remains in the 14-test gate.

## Comparison boundary

The retained earlier run took 62.981 s and produced a 158,878-byte compact
recursive root. Its architecture used two native windows, one active caller,
three separate RAM cohorts and their providers: eleven originals before recursion.
The direct route uses one native window and three RAM shards inside one joint
memory family. Both run the same guest generator and 4,096 loop iterations:
20,495 cycles, 8,293 RAM events and identical expected output. The extra old
segment boundary explains 20,496 versus 20,495 program fetches.

The archived guest-source hash matches the current source exactly:
`a3362f44171eacaeffffda373064bd1e1a54e4a74173f2fa5610228e495bfcdc`.
Both new profiles use ELF SHA-256:
`53be4c1452a40786acf5fafa67aa3cc3372057cfc942f6290e7f1bd68d8afa4d`.

**Do not present the timing ratio as a same-contract 10× compact-root improvement.**
The direct route removes recursive verification and produces a larger original
proof. Its 34,534 OODS values are close to the five originals' 34,598; adding a
wrapper later still has nearly all that column-verification work. Multiwindow
placement, bounded PCS storage, row batching and a qualified aggregation adapter
remain separate engineering requirements.

## Evidence and reproduction

- `results.tsv` contains phase and memory measurements.
- `summary.json` records scope, machine, exact geometry and comparison limits.
- `q8-qualification/` and `q70-qualification/` contain the exact original-proof
  differential gates. Their phase sums are not contiguous end-to-end timers.
- `q8-contiguous/` and `q70-contiguous/` contain the direct measured runs.
- Each directory contains `proof.stark.postcard`, `public-metadata.json`,
  `guest.elf`, `receipt.json` and the test log.
- `source-sha256.json` pins selected implementation files, explicitly not a full
  transitive build snapshot; `artifact-sha256.json` pins the saved evidence.

The STARK postcard is a standard encoding. Its independent public frames and
admission inputs are saved in the JSON sidecar. The subsequent bounded transport
gate adds `q70-contiguous/proof.b7cun`: canonical physical claims plus the original
STARK, with schema and epoch binding. `wire-receipt.json` and
`wire-validation.log` record **11 passing tests**, a 5,887,369-byte envelope and
19,276,266-byte decoding peak. `verifyBytes` charges decoding and full independent
verification to a configurable allocation budget (4 GiB by default).

Trusted ELF/security/expected output and typed proposed source metadata remain
explicit verifier inputs. The JSON importer is test-only; it does not establish
trust or implement an external metadata API. Explicit PCS lifting is rejected
by this finite codec until qualified. This is a single-window original-STARK
transport, not a multiwindow or recursive publication format.

Reproduce bounded transport validation without producing another proof:

```sh
python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v7_complete_union_wire_test_root.zig \
  -OReleaseSafe -fstrip --test-filter union
```

From the repository root, qualification with the original-proof oracle:

```sh
STWO_V7_COMPLETE_UNION_ITERATIONS=4096 \
STWO_V7_COMPLETE_UNION_CANONICAL=1 \
python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v7_complete_union_test_root.zig \
  -OReleaseSafe -fstrip --test-filter union \
  -femit-bin=/tmp/block-v7-complete-union
```

Then, on an otherwise idle machine, run the already-built binary with
`STWO_V7_COMPLETE_UNION_NO_ORACLE=1` to measure the contiguous path. Keep the
iteration and security variables above; set
`STWO_V7_COMPLETE_UNION_ARTIFACT_DIR` to a chosen output directory to retain
proofs and receipts. Omitting the canonical variable selects the diagnostic
configuration. The proof/verifier route remains identical in measurement mode;
only the separate differential oracle is omitted, and hostile checks remain.
