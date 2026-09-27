# Full-width BLAKE3 release artifact integration

The base envelope carries a caller-pinned admission manifest and bounded proof.
Fresh verification reconstructs its key, validates the actual ELF/input, and does
not require the original execution witness. The CLI verification router recognizes
B3RVART1 and requires the BLAKE3 suite. Production generation/default switching
remain incomplete; this is not a completed migration or performance claim.

The base proof gate failed with MissingReleaseAbiSymbol: its tiny diagnostic ELF
only declared text symbols. buildReleaseProgram now appends the full release ABI
symbol table while preserving the loadable instruction image. Release validation
remains mandatory. The fixture also rejects compatibility ELFs and a substituted
program with the same ABI. Syntax checks passed; real proof rerun is pending:

    python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments '-Driscv-test-filter=BLAKE3 execution commitment real runner proves' -Doptimize=ReleaseSafe --summary all

Log: /tmp/blake3-owned-base-run-proof-v3.log. The product verifier still needs
product compilation and fresh-process CLI qualification.

Other terminal gates captured here:
- Updated owned segment aggregation: PASS, diagnostic q8/0; two recursion levels.
- Legacy statement/artifact and input-byte compatibility target: PASS.
- Metal quotient planner target: PASS, 9/9. Full Metal recursion retry is pending.

Expanded Ethereum block proving remains deferred. No parameter changes, default
switch, tenfold speedup claim, or comparison with ReleaseFast CSP timing is made.


Follow-up implementation: explicit BLAKE3 base prove/bench now use the full-width
request and artifact route. Source snapshots include the request, product report,
and router. The new report schema includes serialization/admission construction
and fresh verification in its total, labels phase profiling explicitly, and
requires Metal proof dispatches while reporting fallbacks. It does not claim the
legacy exact-work profiling contract. Syntax checks passed; CPU product build
queued at /tmp/blake3-artifact-cpu-product-build.log. No runtime qualification yet.


Review follow-up: request uses the existing public blake3_execution API and shared
admitRunForProving completion/public-I/O gate. New product and verify receipts
label release_status experimental_full_width until qualified. CLI profiling help
states that this route currently reports phase timings. Full Metal recursion retry
now passed (see the wide-fragmentation evidence directory); base artifact and CPU
product qualification remain pending.


## Base artifact gate passed

The corrected real-runner gate completed successfully (3-minute ReleaseSafe
wrapper, 6 GiB MaxRSS). It exercised complete-run ownership, typed statement and
plan wire encoding, externally pinned manifest decoding, source/ABI binding,
B3RVART1 encoding and independently reconstructed verification, including wrong
source/statement/authority and allocation-failure cases. Recursive child/parent
and two-level checks in the same test also passed. The canonical-parent subcase
uses q70/26 with a diagnostic q8/0 child; this is not a fully canonical tree claim.
See base-artifact-pass.log. CPU product compilation and fresh-process CLI checks
remain pending; this frontend gate does not prove those integrations.


## CPU product and separate-process CLI qualification passed

The CPU product build passed. Explicit `--proof-suite blake3 prove` produced a
B3RVART1 artifact from base-release.elf, and a separate `verify` process accepted
it using the report's externally supplied statement_blake3 identity. Both smoke
and secure policies passed. The canonical artifact's serialized manifest was
checked for 70 queries and 26 PoW bits; its size is 609,851 bytes. Retained proof:
canonical-base.b3proof, with canonical prove/verify receipts alongside it.

Six CLI negative cases rejected: wrong expected statement, changed ELF, wrong
policy, wrong suite, truncated artifact and mutated proof bytes. Exact diagnostics
are in cli-negative-results.json. A profiled smoke benchmark with one warmup and
two samples passed determinism checks, every timing partition summed exactly,
and its final retained artifact freshly verified with matching transcript/hash.

Canonical run was ReleaseSafe on a tiny six-retirement base guest, taking
4.553703917 seconds including encoding/admission and fresh verification. This is
functional integration evidence, not CSP throughput, recursion latency, or a
speedup claim. The initial --experimental invocation was correctly rejected by
the already-promoted product shell; successful commands omit that flag. The new
artifact report retains experimental_full_width status pending wider migration.

Reproduce (choose unused output/report paths):

    zig-out/bin/stwo-zig-riscv-cpu --proof-suite blake3 prove --elf autoresearch/notes/2026-09-23-blake3-release-artifact/base-release.elf --backend cpu --protocol secure --output /tmp/new-base.b3proof --report-out /tmp/new-base.json
    zig-out/bin/stwo-zig-riscv-cpu --proof-suite blake3 verify --artifact /tmp/new-base.b3proof --elf autoresearch/notes/2026-09-23-blake3-release-artifact/base-release.elf --protocol secure --expect-statement-digest <statement_blake3 from new-base.json>

Remaining migration: extension profile/CSP full-width artifacts and routing,
Metal product qualification, default promotion, and obsolete prover-owned
Poseidon removal. Expanded Ethereum block support remains deferred.
