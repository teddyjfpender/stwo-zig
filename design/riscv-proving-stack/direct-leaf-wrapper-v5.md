# Direct RISC-V leaf wrapper: proof-complete target

## Why the 47-row diagnostic is not publishable

The real q193 native fixture generates all 47 rows of the V4 direct wrapper,
but its relation audit has nonzero `range_check_8_8`,
`recursion_transcript_frame_word`, `recursion_verifier_input_word`, and
`recursion_statement_word` totals. An independently reviewed source audit also
found that row 40 consumes 24 local authority, wire, and receipt identity
tuples with no producer in that roster. Its row-42 ProgramV2 hash currently
reads leaf-dependent preprocessing rather than words proved equal to the
native verifier's executed program. Zeroing totals with host-computed values
would not establish those equalities. V4 remains a diagnostic witness and all
publication entry points stay disabled.

## Versioned 50-row candidate

Retain rows 0–46 as the native verifier, global link, arithmetic, ProgramV2,
Tree0, metadata, and link components, with these **versioned replacements**:

| Row | Change and proof obligation |
| --- | --- |
| 4 | Export the eight Tree0 frame words from the actual transcript-word values with the extra lookup multiplicity required by row 44. |
| 5 | Export canonical native ProgramV2 words from the actual transcript payload; use explicit fixed-word equality for constants and proof-visible joins for dynamic words. |
| 34 | Commit one ordered Poseidon provider over six call ranges: native verifier, metadata, link, ProgramV2, local authority, local receipt. |
| 35 | Recompute byte-table multiplicities including authenticated row-41 arithmetic requests. |
| 42 | Replace the self-consistent word source with the versioned `NPV2`-consuming bridge. |
| 47 | Route native statement/context words to local authority, wire, and receipt identities through the existing typed child-field router. |
| 48–49 | Hash the authority and receipt preimages with typed `vm_public_claim_hash` AIR; produce the exact `LAI1` and `LRI1` tuples consumed by row 40. |

Rows 47–49 are a proposed layout, not yet a committed manifest. The dormant
router/hash AIR already defines the tuple equations; the final manifest must
pin their geometry, schedule ID, semantic digests, ordered call counts, and a
new protocol/key namespace. Row 47 must receive `S2WR`/`S2CX` values from
the *checked native base AIR*. Row 40's 24 `LAI1`/`LWI1`/`LRI1` consumers
must close exactly with the router and hash rows. No second table of host
labels counts as proof authority.
The dormant router also forwards eight Tree0 words to `PPR1`. Direct V4
already emits those words in row 39 and consumes them through row 44, so the
V5 schedule must disable exactly those eight router forwards. Keeping them
would over-emit `PPR1` even if the new identity tuples close.

## Fixed-key and public boundary policy

The V4 ProgramV2 preprocessed words contain per-leaf wire and statement
identities, so its Tree0 root and VPK5 key change with each leaf. The target
is a fixed-key verifier template per admitted shape: opcode schedule, PCS
profile, geometry, and true constants remain in preprocessing; proof roots,
statement identities, and other leaf-dependent values are committed main or
authenticated public data. A template key must be reconstructed or looked up
by the detached verifier and checked by the parent. Accepting a child-carried
key as public input is unsound. Moving values to main alone is insufficient:
the `NPV2` relation must connect row 42's canonical words to the native
verifier components that actually execute them. The canonical ProgramV2 word
coverage audit must fail closed until every active index has exactly one
trusted origin or a semantically constrained fixed value.
The staged native source currently covers 14 words from actual row-5 values
(wire identity and selected PCS payloads). A dormant row-42 bridge constrains
nine fixed format/PCS words in AIR under the pinned profile. On the focused
fixture, its machine-readable coverage audit still reports 46 unlinked words,
including instruction descriptors and identity fields, and `requireComplete()`
rejects it. Neither staged module is selected by the direct cohort yet.

The verifier-owned 24-word `LAS2` boundary consumes row 40's public link,
ProgramV2, and Tree0 words and mixes its expected values and claimed sum
into the transcript on both prover and fresh verifier. Its expected values
must come from admission, never the artifact. The existing V2 public-wire
boundary remains separate. A future public-I/O byte relation (issue #228)
must bind actual guest input/output bytes before an application claim is
published.

## Activation gates

1. A real native q193/PCS-PoW16/interaction-PoW10 proof feeds a complete
   50-row cohort. Every direct AIR constraint and all 47 relation domains
   close, including the V2 wire boundary and LAS2 boundary, with one shared
   challenge draw and no free residual.
2. A canonical 50-row proof is produced, serialized, producer state is
   destroyed, and a separately reconstructed verifier checks its fixed key,
   Tree0, transcript, all claims, and proof bytes. Mutations to each native
   identity, ProgramV2 word class, call range, public boundary, child order,
   position, and completion must fail.
3. A temporal parent recursively verifies two such leaves under an admitted
   key family, constrains adjacent spans and state/sparse-memory joins, and
   yields one freshly verified root. The gate then crosses 2^24 aggregate
   cycles with each leaf under its local cap.

Measure native proof, wrapper witness, wrapper prove/fresh-verify, parent
prove/fresh-verify, proof sizes, and peak resident/device memory separately.
The q193 native-to-39-row outer result is only a redundant diagnostic
baseline; it is not a stage in this direct pipeline.
