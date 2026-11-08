# Prover-only GPU commitment of original circuit FIXED columns

The completed 25229951 run has115 `CUDA_OUTER_PREPROCESS` records:58leaves and
57folds. Their summed host setup spans are11.117s finalize,66.426s PP column
materialization and178.305s authority construction (255.848s total). This was
functional production under shared workloads, not a quiet A/B. The source log
SHA256 is b154e33e4d3c0fa6246c6e30982a1d5132871bcfe206837e12d06dff109572d2.

Every one of the33 test-block authorities is unique. A cache keyed by whole
per-node authority cannot remove their setup. Existing static PP remains host
materialized even though MAIN/INTER generation is resident. Authority.init then
CPU-interpolates, extends and hashes all45 PP columns, while GPU proving later
requires the same fixed polynomials again.

The explicit default-off factory precommit route commits these original columns
on the same GPU using the established trace transform/Merkle primitive ABI.
Its owned result carries real scoped coefficient columns, their root and an
explicit source-preparation callback. It does not install hidden factory state
as proof authority or fabricate a host commitment tree. The provisional
namespace is local custody only. After MAIN is committed, a single exact fixed
coefficient lease moves to the final statement/fixed/MAIN/ordinal namespace;
context token, generation, count and allocation stay unchanged. All metadata
capacity is admitted before native rebind. Failed rebind preserves old custody.

Authority.initForDeviceProver binds original AIR/layout/profile and the returned
root to the same identity formula. CPU-only proving refuses this authority's
absent host polynomial tree. Device proving admits real FIXED slot0 before
MAIN1/INTER2, validates all45 logs and device column shapes, and retains its
lease through composition/PCS. This is a prover setup constructor, never an
independent receiver admission API. A malicious/wrong returned root still needs
to be rejected against the receiver-derived root.

Cached restores and strict receivers always use unchanged Authority.init and
reconstruct the fixed root independently from the original trusted graph. The
qualification fixture compares GPU precommit root AND authority identity against
that CPU oracle, then checks exact full proof bytes and fresh independent CPU
acceptance. Default factory/CLI selection stays unchanged. Raw precommit
input evaluations retire after commitment; MAIN currently uses its existing
independent raw fixed-forest upload. Avoiding that second ingress is a separate
lifetime optimization. PP materialization remains host work.

There is no new runtime kernel, AIR, transcript, field, proof format or security
claim. The measured178.305s is an opportunity, not an established saving. A real
GPU fixture gate and production A/B are required before enabling this route.

Composition avoids a second immutable-cache copy for ANY complete device-only
FIXED coefficient forest, not just this factory. This is storage policy only:
all scoped token/generation/full-range checks still run before D2D ingress. Mixed
host/device forests retain the prior immutable-cache path. Host tests cover
all-device, mixed, all-host and empty selection. A device-only descriptor is
never accepted as pointer authority merely because this predicate returns true.

Source qualification at this checkpoint: three native OM31 proof/authority
checks passed, including identical original authority identity and refusal of
CPU proving without host FIXED. Fifteen custody/router tests passed, including
failure-atomic rebind and allocation-policy mixtures. GNU recursion, combined
and strict receiver semantic checks passed; the existing joined fixture tool
built with x86_64_v4+sha. Its frozen SHA256 is
cadc3db8e075fbebd8d37eabad8b7a3b9960588f1b2d8b731f4280a38e29a797.
An attempted cross-target test execution was correctly refused by macOS; the
same tests were then executed natively on ARM and passed. No GPU precommit
proof, performance A/B or production enablement is established at this commit.


The first bounded physical gate reached exact CPU/GPU FIXED-root and authority
identity parity, generated original MAIN/INTER on device with zero assignment
upload, then failed `MissingPreprocessedTree`. The core still equated FIXED
presence with a host polynomial tree. No GPU proof was accepted. The follow-up
uses genuine logical slot0 metadata for those guards and preprocessed-column
count, while missing FIXED still rejects and CPU/default counts stay unchanged.
A direct host test covers host-only, device-only, mixed later host storage,
missing, MAIN-only and empty-host-tree cases. The original native proof/fresh
receiver regression still passes. Full physical proof parity remains pending;
this observed partial progress is not a performance result.

Corrected ae02 physical qualification passed on the unchanged2529 runtime: cold
and warm GPU full proofs both match the original CPU control exactly626832B,
SHA256 f5c8c4bb0283cf2788f189e1df2c063cdf8ddf8c68921bd50396323b537d7640.
Both independent fresh CPU receivers accepted, wrong outputs rejected, CPU/GPU
fixed roots and key identities matched, and no host fixed polynomial tree,
CPU assignments or request leases remained. The optional GPU lock held5.824s
across the two proofs plus negative case; this is not a production speed result.

The device FIXED coefficient lease is now live before MAIN/INTER. Previously
those coefficients reached the device later through the immutable forest. A
complete device forest bypasses redundant cloning, but idle kind4 setup cache
can retain a different mix than the old cache-miss eviction path. Worst-shape
peak,28GiB fit and full proof/fresh-receiver parity must be measured before
production enablement. Evicting only unborrowed native-phase setup at a drained
phase boundary is a separate possible optimization; no unchecked free or cache
policy change is included in this correctness checkpoint.

A separate serial resident-batch candidate adds authored manifest bool
recursion_device_fixed_candidate (defaultfalse). It selects the explicit
factoryWithDeviceFixed only for a combined serial request and preserves the
existing single-device guard. Native-only and ready-mode combinations refuse.
Each node's PREPROCESS backend label comes from the actual precommit result;
the combined report derives fixed_setup_backend from the selected factory,
and combined-entry copies that result rather than echoing the requested flag.
The exact original manifest is durably saved as
batch/resident-device-fixed-manifest.json with its hash in combined-entry.
CPU receiver and restore admission remain unchanged. This wiring is now qualified on one complete real block,26235156:11 leaves and10 folds all used actual device_candidate FIXED precommit, with zero CPU assignments and zero request leases after endBlock. All13 native proof files, bundle,22 recursive proof files including root, and ordered tree match the independently accepted original serial control exactly. A fresh independent ARM CPU receiver reconstructed native and outer authority and accepted all proofs; its result SHA256 is2315e8b7efc30bad87f690fe9fe01cafc2006b05ca11ecf4eab589338cd8ffd4.

The observed request wall was126.221s. This is one observation, with different source/runtime/resources from the original control, and establishes no causal speed ratio. It does not qualify worst-shape memory fit or enable the default. The compact receipt is `serial-device-fixed-qualified-v1.json`.

A subsequent single ordered pair used the identical aa526 executable,2529 runtime, request and resources, first with the candidate flag and then with that flag removed. All native/outer/root/tree bytes remained exact. Across21 nodes the observed Authority stage summed1.972s with device precommit and34.759s with CPU precommit; PP column construction remained12.836s and12.873s. Request wall was126.221s and164.769s respectively. This is a single true-then-false observation, not a median or general speed ratio. The FALSE control fresh independent CPU verification is pending in this checkpoint; the TRUE case is independently accepted. `serial-fixed-ordered-pair-v1.json` pins both producer logs and sealed outputs.
