# CSP is the current priority

The user explicitly prioritized restoring CSP performance over further recursion
work. Keep the earlier recursion improvements; the unfinished parallel-interaction
experiment was removed before CSP changes. Do not resume recursion-only research
until the CSP regression has been addressed or characterized across the suite.

Measured ECDSA regression stages (ReleaseFast CPU/Metal): lookup counts ~1.9 s,
hash interactions ~1.6 s, sampled-value evaluation ~2.95 s. ECDSA precompile
witness and interactions themselves are each only ~10-20 ms. Bounded parallel
lookup counts plus retained trace coefficients reduce complete ECDSA to ~7.5 s;
this remains far above the historical ~1 s route. Composition coefficient caching is now measured: complete ECDSA medians are
6.349760 s CPU and 6.790643 s Metal. This does not restore historical performance. All current proofs retain the exact
original full-width proof hash and canonical parameters.

If host scheduling/caching is insufficient, inspect redundant public-data hash
proving before changing the memory contract. Shared-path geometry attributes
4,894/8,738 compression blocks to program memory, 1,736 to initial memory, and
2,108 to final memory. Source validation already independently reconstructs
program and initial-memory roots from ELF/input. A possible architectural route
is authenticated public preprocessing for immutable program data; this is only
a hypothesis, not permission to omit root/lookup bindings. Current prepared keys
accept roots and schedules rather than ELF-derived byte tables. Any such change
must bind program values to independently admitted ELF/input and carry that
identity through keys, codecs, leaf capture, and recursion. No witness-chosen
program table or unbound root is admissible. Do not silently bypass hash AIRs.

Next full-suite measurements must use manifest-v2 canonical inputs, pinned ELF
routes, 70/26, complete proving boundaries, expected outputs, and fresh verification.
Current source is dirty: record source-pinned diagnostic results honestly; do not
bypass the official suite reader's clean-source admission.


Update from the live suite: SHA-256/128 verifies but takes 85 s and approximately
36.6 GiB physical memory. Program schedule has 4,799 words, 4,632 with nonzero
multiplicity; dropping unused instructions is not the answer. Shared hash trace
has 4,997,216 G rows (padded 2^23), of which 3,227,056 are program and 877,296
initial memory. This is a significant architecture-level regression, not only a
host-loop problem. Public-program preprocessing may be promising, but requires
an independently authenticated program-value table and the same root/lookup
binding through prepared keys, artifact decoding, capture and recursion. Merely
trusting witness program values, or omitting their root binding, is invalid.

The suite driver is PID 90063, originally exec session 9148; authoritative output
is /tmp/blake3-csp-current-suite.log and suite/results.json. All 16 CPU cases and
at least three Metal cases have independently verified. A qualification supervisor
(exec session 44775, /tmp/check-blake3-public-program-proofs.py) temporarily stops
the launcher between measured child processes, runs focused tests, then resumes
it in a finally block. Check live process/session state before acting; do not
restart the suite. Installed CPU/Metal binaries remain the pre-architecture
baseline. Do not replace them while the suite is running.

A shared public-program preprocessing implementation is now in the worktree:
../2026-09-23-blake3-public-program/README.md records design, source overlays,
qualification logs and remaining work. Plan format is v3 and the complete decoded
program is root-authenticated before publishing fixed lookup tuples. This removes
program G rows for every execution profile, not only CSP. Focused admission,
joined-column integration, base execution/recursion and canonical Ethereum-leaf
proof checks have passed. Canonical extension leaf and parent qualification passed at 70/26;
the supervisor exited successfully and resumed the baseline launcher.
Do not report end-to-end recovery: current installed binaries do not include this
change, and canonical CPU/Metal CSP timing is still required. The next structural
candidate is word-granularity memory commitments, not implemented yet.


## Required scope: shared BLAKE3 row reduction

The user explicitly requires a repository-wide fix, not a CSP- or ECDSA-specific
shortcut. Implement reductions in the canonical hash planning, authenticated
commitment, and witness machinery used by all consumers. CSP is the first
performance acceptance gate; base RISC-V execution, extension profiles, segment
continuations, and recursive verification must retain compatible authentication.

Audit three distinct sources of cost before selecting changes:
- Repeated computation of immutable, publicly authenticated program data.
- Tree geometry and framing: current byte-tree internal nodes encode 108 bytes
  and therefore consume two BLAKE3 compressions (112 G rows) per binary node.
- Repeated authenticated paths and generic hash DAG work in recursion.

Do not conflate these: removing public program hash work alone does not fix
private memory or recursive Merkle hashing. Any public preprocessing must bind
values to the admitted root and key. Any framing/tree change requires an explicit
protocol version and matching host hashing, typed AIR, codecs, prepared keys,
capture and recursive verifier updates. Preserve BLAKE3 rounds and full digest
width. Never select weaker circuits or parameters by benchmark identity.

Acceptance requires row counts (including padded domains), complete verified
CPU/Metal CSP results at 70/26, and focused positive/negative coverage of changed
bindings through execution and recursion. No repository-wide performance claim
from one ECDSA sample or from row counts alone. The current suite remains the
pre-architecture baseline; keep its binaries stable until it finishes.


## Current authoritative checkpoint: word-memory qualification

The old full suite is terminal and all 32 cases verified. See BASELINE_RESULTS.md
and vectors/riscv_csp/README.md. PID 90063 must not be restarted. Baseline products
are preserved in baseline-products/ (including the matching Metal AOT bundle).

Shared public-program preprocessing and full-word memory are implemented together
in the current source. The canonical tree module is blake3_state_tree.zig; the old
blake3_byte_tree.zig was removed. Plan version 4, public transcript version 3,
state-tree frame version 2, execution protocol version 4, update-chain and span
binding versions 2 prevent old root reinterpretation. High out-of-range memory
branches are fixed empty digests. Native tuples retain all four byte limbs.

Low-level tree, full-word update/custody, joined-column integration, base execution,
parent-of-parent, and canonical 70/26 extension leaf/parent checks have passed.
The source/evidence directory is ../2026-09-23-blake3-word-memory.

LIVE queued job: exec session 83181, /tmp/qualify-blake3-word-products.py,
log /tmp/blake3-word-products.log. Both proof gates passed and the product build
is running. After it succeeds, the job starts all 32 candidate CSP cases and then
matched ECDSA pairs with the preserved baseline binaries. Do not launch a second
build or benchmark; poll the exact session/process. No candidate timings exist
yet. Do not claim speedup or historical performance recovery from geometry alone.


## Completed measurement checkpoint

Session 83181 is terminal (exit 0). CPU and Metal products built; all 32 word-memory
CSP cases and eight ECDSA paired processes freshly verified. summarize.py was run
after terminal completion; complete results are in the word-memory RESULTS.md and
vectors/riscv_csp/README.md. CPU ECDSA paired median 3.557679 s, Metal 3.822391 s;
SHA-256/128 CPU 6.074877 s and Metal 5.447985 s. Do not claim the historical
0.88-second ECDSA route has been restored. Canonical CPU extension leaf/parent
70/26 qualification passed, but recursion speedup/10x is still unproven.

No benchmark/build job remains live. Current installed binaries are the qualified
word-memory candidate; preserved versions are in word-memory/candidate-products/.
All source overlays are pinned and verified against current source. Subsequent
experiments should compare against these preserved products, not restart the old
suite. Read word-memory/stage-medians.json for the measured next bottlenecks.
CPU PoW is 0.854 s (the current BLAKE3 pool loops over scalar streaming-hash copies);
Metal PoW is only 0.027 s, but FRI 0.805 s and sampled evaluation 0.301 s.
Both still spend about 0.4-0.6 s per main/interaction commitment and composition.
Native fixed lookup schemas have domains up to 2^20; audit active geometry before
changing their typed admission. Keep all further improvements shared, not case-specific.
