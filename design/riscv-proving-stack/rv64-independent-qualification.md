# RV64 independent qualification and complete-cost measurements

Qualification is split into execution semantics (pinned Sail), native proof
acceptance (pinned Rust Stwo primitives with an explicit RV64 adapter), and CSP
workload execution/proof-window measurements. None substitutes for another.

The first Rust boundary intentionally admits exactly the existing five-instruction
ADDI/ADDI/SD/LD/ADD program, with independently supplied full initial/final state.
The receiver derives fixed rows, compact projection and preprocessing root itself;
it never accepts producer key material, witness rows, constraint evaluations or
free relation claims. All 5,513 logical constraints retain their order. The unused
shift/product equations are identically zero under the independently derived
projection; their powers in the composition accumulation are still consumed.
The scalar Rust field implementation evaluates the live arithmetic, memory,
range and state equations. The adapter uses pinned Stwo PCS/FRI and the same
four-way composition coefficient reconstruction. Stock pinned `verify` hard-codes
two-way splitting, so acceptance is attributed to this explicit adapter, not to
an unmodified stock top-level verifier. Other programs fail closed at admission.

The immutable Rust setup is reconstructed once per expected program/path identity
and reused across separate request transcripts. Benchmark decode, independent
setup, warm verification and complete request separately. Authenticate every
opening through upstream PCS; no host execution result can replace acceptance.

Sail builds from the formal ledger's exact model/compiler pins. RV64 configuration
is separate from the existing RV32 override. Use one long-lived simulator batch
where the upstream interface supports it; retain per-retirement comparisons,
source/binary/configuration hashes, negative outcomes and timing scope. Never
use a changed or unpinned model while labelling the result pinned qualification.

CSP execution is rebuilt from manifest-bound sources for both architectures and
checked against independent outputs/instruction counts. Authenticated proof
windows remain partial execution until a receiver checks whole-program input,
output, coverage, adjacency and RAM closure. Sampling windows must use actual
retirements, construct hints once, retain narrow state metadata, and report all
committed cells, openings, padding, setup, proof/verification time and caller
allocation peak. Raising all component heights or extrapolating native steps/s
into a block-proving claim is not an accepted benchmark.

## Public-support evaluation hypothesis

The compact projection already forces every always-disabled word/carry/clock
column to literal zero. If the public program/path contains no shifts or no
multiplication/division, the corresponding projected polynomial constraints are
identically zero at every extension-field point, not merely on valid rows.

Keep the same 5,513 ordered constraints, physical layout, security parameters
and transcript. Replace only those evaluations with zero runs. For an OODS run
of k zeros, Horner accumulation is exactly `acc * alpha^k`; prove this against
the core recurrence. Domain evaluation writes zero residuals at the same
indices. One shared evaluator chooses the public-support guard; there is no
second arithmetic evaluator or witness-derived plan. Predict lower constraint
CPU work without a proof-size or committed-cell claim. Reject if arbitrary
projected extension-field evaluations disagree or complete serialized proofs
differ from the retained reference; measure fresh independently verified runs.
This does not address the still-expensive bit encoding or mixed-family width.

## Sparse immutable program aperture

Measured ECDSA windows fail dense program admission even with only 256 executed
instructions: far-separated PCs unnecessarily include intervening code. Add a
canonical ordered address array alongside program words. An empty array retains
the exact version-2 dense transcript. A nonempty array must match word count,
be strictly increasing and aligned, and start at program_base; it uses a distinct
version-3 transcript with every address bound. Lookups binary-search exact PCs.
RAM must not overlap any actual instruction word, while gaps may contain data.
The native receiver independently reconstructs preprocessing from this expected
mapping. No virtual-PC rewrite, producer-supplied program root, or execution
receipt replaces the proof.

Execution retains its existing loader; sampled captures derive one canonical
PC/word map from actual retirements, build hints once and transfer owned storage.
This removes code-gap amplification without changing trace height or weakening
program identity. Dense fixture proof parity and its independent Rust acceptance
must remain exact. Sparse qualification needs native proof/verification and
address/substitution/overlap rejection; the first Rust fixture remains explicitly
dense-only rather than silently claiming coverage of the new transcript.
