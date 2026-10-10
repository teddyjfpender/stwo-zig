# Original recursive fixed-shape authority audit

This read-only audit covers the actual WM/v2/version5 child verifier and explains what must be independently reconstructed without original child proof files. It does not classify a field as private-dependent merely because the current API accepts a capture. No proof, compiler or benchmark was run for this audit.

## Already symbolic or geometry-derived

| Data | Actual source/kernel | Fixed status |
| --- | --- | --- |
| Original sampled values, OODS seed, composition/DEEP/FRI randomness, relation draws and interaction claims | `open_parent_composition_v2.prepare` allocates graph inputs before activation; original payload/challenge bridges join them to transcript cells | Main symbolic inputs; original constraints remain mandatory |
| Original current/previous mask inventory, trace widths, component logs and quotient split | Actual admitted component roster; mask validation precedes graph construction | Derived from independent admitted key/geometry, not proposed sample lengths |
| DEEP arithmetic graph | `pcs_deep_circuit.build` from exact admitted column logs, sample layouts, lifting log and configured query count | Profile-derived DAG; actual sample/query values are graph inputs |
| FRI arithmetic graph and fold widths | `blake3_native_fri.prepareMode` derives widths from lifting log and admitted FRI config | Profile-derived DAG; original captures are bound only at input evaluation |
| Secure sampling retry count | `blake3_transcript_witness.build` with explicit bounded capacity; bounded retry/control/counter AIR | Recorded attempts are ignored for fixed shape; selected retry and final counter are proved main state |
| Query values and bit directions | Original transcript query output, `blake3_query_links`, `blake3_path_select` | Query count/domain from config; bits are main values with original routing/equality equations |
| Trace query position array | `core.pcs.utils.prepareTreeQueryPositions` | Preserves raw query count/order; it does **not** deduplicate. Do not invent a sorted/deduplicated shape dependency |
| Merkle opening count, depth, grouping and namespaces | `blake3_stark_paths` and `blake3_native_hash_layout` | Live API reads capture fields, but expected counts/depths follow admitted logs/config. It verifies exact path geometry and total openings against tree count times configured query count |
| Shared root selection | `blake3_shared_root_plan.derive` | Query ordinal0 owns root compression; other query ordinals request it. No private position selects this fixed recipe |
| Two-level frontier selection | `blake3_stark_paths.beginFrontier` and `blake3_two_level_frontier` | Selected by admitted opening count and depth. Branch activity, opaque digests and selected path data are main witness, constrained by original frontier AIR |
| Merkle path index bits when directions exist | `blake3_merkle_group_witness` emits `select.fixedRow(schedule)` | Bit/current/sibling data are main. Fixed endpoints/uses come from admitted original query graph and ordinal plan; no fixed private side bit was found on this selected path |
| Readonly opening sorted values | `blake3_opening_inputs.finish` | Sorts main entries; fixed rank/last/table schedule remains count-derived. This is not permission to drop original readonly consistency equations |

These findings do not yet prove all fixed bytes invariant. The next source gates must compare the exact original fixed tails and Context IDs across independent private values while holding independently admitted geometry/public policy constant. Capture geometry must not select a new key. Earlier hypotheses about private retry-attempt and deduplicated trace-query shape are withdrawn: the actual bounded and query-ordinal kernels already handle those cases.

## Instance values deliberately fixed by the version5 closure

The new boundary suppliers use actual enabled `blake3_boundary.logicalCoordinates`: all four main coordinates equal fixed expected coordinates. That is genuine instance-pinned AIR closure, but makes the key depend on public instance cells. The original expected public values include WM native statement/instance/main-root/open-sum exports, true window register/program compensation cells, carrier root/length/prefix/CVs, node census/full-u64 endpoints and independently expected child key IDs. Some of those public values are proof-produced statements; they are not all derivable from whole-job input before execution.

Those values cannot become invariant fixed key constants. A reusable route must consume them as main public-frame suppliers authenticated to the actual nested child's original transcript/hash coordinates, and export a compact root statement that carries the corresponding expected public fields or independently reconstructible public recipe. Version5 instance keys must remain rejected as a claim of that stronger authority.

## Missing API, rather than missing fabricated proof

The current `State.plan` entrypoint starts with genuine capture validation. Even when its fixed shapes are already geometric, calling it requires private input/evaluation custody. A shape-only setup must not create a dummy `Verified`, synthetic proof, successful receipt or scalar acceptance token to get through this guard.

The concrete factoring seams are:

1. Original open-parent composition compiler: separate original graph construction from capture mask/sample binding. Inputs are exact admitted component/table inventory, canonical sample layout, relation/claim input descriptors and public tuple descriptors. Return circuit and input/source schema only. Live `prepare` keeps all current capture checks/evaluation and uses this one exact compiler; there is no second equation body.
2. Exact transcript operation skeleton: derive frame kinds/lengths/roles and bounded retry/query capacities from admitted config/logs/public policy. Actual private payloads remain distinct witness data and never enter shape admission. `trustedBoundedDirect` already emits compact fixed tails without compression; it needs a typed shape facade that cannot read a private payload accidentally.
3. Exact original path shape emitter: derive original column/FRI geometry, ordinal sharing/frontier, namespaces, query/read weights, readonly ranks and routing endpoints from the admitted DEEP/FRI graph schema. Existing group/frontier trusted emitters can produce the same fixed tails. Avoid a new hash stack or unbounded padded/deduplicated path grammar.
4. Fixed-only parent roster and key: `arithmetic_fusion_rows.materializeFixed` already avoids graph evaluations. Compose its fixed metadata with transcript/path/public rows, canonical G partition and original table preprocessed columns. Return a distinct fixed-setup type with no main columns/capture/claims/prove API. Actual preprocessed commitment still uses the original PCS key kernel; context identities must exactly equal the live path's canonical DAG/transcript/namespace identities.
5. Authentication-preserving reusable suppliers: replace the new instance-fixed boundary coordinates with original authenticated compact public cell requests and in-parent equality constraints. Close the resulting internal recursion_wire terms through genuine AIR. This must preserve full child quotient/DEEP/FRI/Merkle/PoW and exact original channel bytes. Expected key construction alone cannot grant this public-input binding.

The first four steps remove the original proof-file prerequisite for geometry reconstruction where the admitted public policy is sufficient; step5 removes instance-fixed public data from geometry. They are distinct requirements. The original live verifier continues to validate a genuine capture and prove every original equation. Full source/register/program/global compensation and final self-contained block authority remain open throughout.
