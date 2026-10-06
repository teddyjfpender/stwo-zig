# V6 direct-leaf preprocessing provenance

The appended verifier-side writer covers **rows 39–49**. It rebuilds their
eleven physical fixed tables from admitted geometry, the fixed V3 link program,
the descriptor-derived child program, and the native instruction template.
It accepts no leaf capture or witness. Row 42 uses the complete canonical
ProgramV2 template-word schedule: exactly the 16 wire/statement identity words
remain dynamic main values. The writer rejects every other row and refuses a
complete preprocessed root. Production admission remains disabled.

An independent base writer also covers **rows 0–3, 6–10, 12, 33–35**. It
derives row 0's ten columns from the admitted native verifier plan; its rows
match the executed V2 source control tuples. The transcript binding, state,
relation-draw and randomness schedules in rows 2, 3, 8 and 9 are reconstructed
from the admitted native plan and descriptor shape. Their fixed tuples match
the executed V2 source in the focused test. Rows 1, 6 and 7 have no
preprocessed columns; row 10 is explicitly inactive and all zero. Row 34 has
only the canonical provider marker, and row 35 is the pinned 65,536-entry
byte-pair table plus its framework first-row marker. These writers reject
every other base row and cannot issue a complete preprocessed root.
Row 12's 27 publication-header relay selectors and source coordinates are
recompiled from the fixed publication ABI; the publication values stay main.

| Rows | Current preprocessed producer | V6 status | Remaining proof obligation |
| --- | --- | --- | --- |
| 0 | `segment_leaf_template_base_fixed_v6` | Deterministically written | Native-plan control tuples match an executed V2 transcript source; compare two strong captures in the full-root gate. |
| 1–3 | `transcript_fixed_schedule_v6` / `segment_leaf_template_base_fixed_v6` | Deterministically written | Row 1 has zero fixed columns. Rows 2 and 3 match the executed V2 transcript source's binding and state-key fixed tuples; compare complete physical columns across two strong captures in the full-root gate. Frame outputs stay main. |
| 4 | `transcript_word_template_v6` | Schedule qualified, not full root | Exact fixed frame words, padding and Tree0 selector pass two executed-transcript tests. Integrate its expanded geometry into the complete physical tree. |
| 5 | V2 transcript payload writer | Unqualified, separate migration | Classify fixed geometry versus leaf-dependent identity words and bind dynamic words to native source producers. |
| 6–9 | `transcript_fixed_schedule_v6` / `segment_leaf_template_base_fixed_v6` | Deterministically written | Rows 6 and 7 have zero fixed columns. Rows 8 and 9 match the executed V2 relation-draw and randomness fixed tuples; compare complete physical columns across two strong captures in the full-root gate. |
| 10 | `segment_leaf_template_base_fixed_v6` | Deterministically written | The V2 component is explicitly inactive; compare physical zero columns in the full-root gate. |
| 11 | `segment_statement_outer_source_v2` | Unqualified | Its fixed byte-selector layout depends on retained-entry counts and payload offsets in the canonical wire, not merely the total wire-word count. Admit this partition as template shape or version the AIR with selector coordinates in main plus exact source joins. |
| 12 | `segment_leaf_template_base_fixed_v6` | Deterministically written | All 27 header relay source coordinates, masks and default circuit fields derive from the fixed publication ABI. Values remain main. Compare physical columns across genuine captures in the full-root gate. |
| 13–16 | `segment_public_outer_source_v2` | Unqualified | Recompile claim/hash, seal, boundary and challenge relays from independently admitted geometry and graph use counts; prove no identity-bearing constants remain fixed. |
| 17 | `vm_public_logup_control_witness_v2` | Blocked on variable public term count | The frozen V2 witness and AIR fix 70 public terms and 71 active rows. `segment_profile.initPlans(16,16)` admits 102 public terms, so V2 `preflight` returns `InvalidPlanProfile`. A versioned variable-cardinality AIR/source or an independently justified fixed 70-term VM shape is required; do not force the V2 schedule into V6. |
| 18–19, 22–32 | `detached_leaf_cohort_v2` core verifier tables | Unqualified | Rebuild composition, Merkle and FRI coordinate schedules from admitted verifier and PCS shape, without copying positions or proof data from a capture into preprocessing. |
| 20–21 | Query-bit and query-mapping preprocessed references | Profile identity bound; physical columns unqualified | Their selectors derive from the exact VM and recursion lane PCS profiles: query counts, lifting sizes, tree heights and FRI widths. `TemplateManifestV6.build` now takes a verifier-selected, value-owned `CoreProfileV6` and the core query-mapping reference separately, requiring exact agreement. The V6 shape and seal bind the full profile and derived mapping/bit digests. Verifier admission must compare that selected profile against its expected template profile; complete-root qualification must compare physical columns to the core's actual reference. |
| 33 | `segment_leaf_template_base_fixed_v6` | Zero-width fixed row | The Merkle-path AIR declares no preprocessed columns. Main and interaction proof work remain separate. |
| 34–35 | `segment_leaf_template_base_fixed_v6` | Deterministically written | Marker and byte table match the V2 writers' exact committed-row formulas. The six ordered call ranges remain a separate main-trace/lookup obligation. |
| 36–38 | V2 statement boundary, public LogUp and verifier-input provider | Unqualified | Rebuild source selectors/multiplicities and move any leaf-dependent constants to main with exact typed joins. |
| 39–49 | `segment_leaf_template_preprocessed_v6.Writer` | Deterministically written | Validate all columns against the existing V5 cohort for genuine captures; derive the full template preprocessed root and pin it independently. |

The focused appended-row gate changes the V2 transcript manifest identity while
retaining the same shape. The V2 seals differ, while every reconstructed
physical fixed column in rows 39–49 is identical, including padding. It also
checks a dirty destination, an unsupported row and incomplete-root refusal.
This is **not** the pending two-genuine-q193-leaf root-invariance test: that
requires two same-shape verified native captures and all rows 0–49 rebuilt.

The direct V4 Tree0 relation semantics are unchanged. Its fixed row-44
`hash_id` is derived from the independently compiled row-4 frame schedule;
root limbs themselves remain main values. Rows 39–40 come from the exact
versioned link schedule, rows 43/45/46/48/49 from hash chunk schedules, row 47
from descriptor-derived router rows with the obsolete Tree0-forward rows
removed, and row 41 from the four canonical arithmetic operation masks.

`CoreProfileV6` is the template admission boundary for rows 20–21. The
verifier selects its VM and recursion query counts, lifting sizes, trace-tree
heights and FRI fold widths before reading the child proof. `TemplateManifestV6`
stores a bounded value copy of both lanes and recomputes the query-mapping and
query-bit reference digests from that copy. `build` requires the core's
separately built reference to equal this expected profile, and
`validateAgainst` repeats that comparison using verifier-selected inputs.
The test-only frozen profile is a fixture, not the general V6 admission
source. A complete-root gate must still compare the core's actual physical
rows 20–21 against the template writer; this check is unavailable today.
