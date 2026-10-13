# Native paired FRI input: implementation boundary

The current native PCS prover computes one accumulated DEEP quotient word in `src/prover/pcs/scheme.zig`; its verifier reconstructs that one quotient with `friAnswers` and passes it to FRI. This is not the degree-corrected batch-opening protocol in the [S-two whitepaper, Protocols 3–4 and Theorem 5](https://www.researchgate.net/publication/407022099_S-two_Whitepaper). Protocol 4 extends **every** original word `f_(i,j)` with its own quotient `(f_(i,j)-v_(i,j))/v_Q`. Protocol 3 Eq. 66 batches all words at each height with powers of **one shared challenge** `lambda`, and Eq. 68 inserts each height's batch into its FRI fold. The authors state the two-point conjugate quotient used by the implementation should inherit the analysis, but omit its details. Their Section 4.5 also leaves the list-decoding proof for their actual circle-domain query schedule open.

## Executable slice

`src/core/pcs/paired_ensemble.zig` defines a separately tagged experimental transcript and a uniform-domain shape. Once source commitment roots and OOD claims are in the channel, it draws one batch challenge. Its first FRI word at row `P`, in explicit pair order, is

```text
B(P) = f_0(P) + lambda*q_0(P)
     + lambda²*f_1(P) + lambda³*q_1(P) + ... .
```

Every pair has its own source and quotient column. The module rejects missing or extra columns and wrong domain lengths, and precomputes challenge powers once for a complete first layer. `src/core/pcs/paired_authenticated.zig` provides a verifier-side bridge: it checks the existing compressed Merkle multiproof for **all** source query columns against the committed root, then computes each native two-point quotient from precisely those authenticated values and their claimed OOD values before folding the pairs. It refuses wrong height, wrong column count, or reordered source openings.

The native CPU tests use the actual quotient arithmetic for `f(P)=x(P)`, a nonzero quotient, the production `FriProver` and `FriVerifier`, and a source Merkle commitment/decommitment. The verifier reconstructs and authenticates the source queries, derives its own quotients, combines the pair, and accepts the FRI proof. Changed source values are rejected by Merkle verification before an answer is returned; changed paired answers are rejected by FRI. A separate two-column test confirms source order, pairing, and uniform-height refusal.

`src/core/fri/multidomain_insertion.zig` adds a separate scalar kernel for one Eq. 68 height transition. Given a previous line word on `S_(i-1)` and a new circle batch on `D_i`, it checks that the previous line domain doubles exactly to the new batch's half-coset. It returns the native folds in this order:

```text
G_i = FoldLine(G_(i-1), alpha_i)
    + alpha_i² * FoldCircle(H_i, alpha_i).
```

The existing native inverse butterflies omit the factors of `1/2` displayed in the paper's Eq. 70; theorem refinement must explicitly account for that normalization. The production `foldCircleIntoLine` helper uses the reverse weighting, `alpha² * previous + FoldCircle(inserted)`, so the experimental insertion kernel does not reuse its destination-combination behavior. A CPU test starts at a 16-row circle domain, inserts independent batches at 8 and 4 rows, checks each output row against the native scalar formula using its actual `x` and `y` coordinates, and rejects mismatched height and coset geometry. A second test supplies `x`, `x`, and a constant at those heights and checks that the last layer is the expected constant in the native normalization. The kernel is connected only to the experimental two-height fixture below, not production FRI.

## Experimental multi-height source-opening envelope

`src/core/pcs/paired_envelope.zig` defines a separate binary source-opening envelope with the eight-byte magic `S31PMH01`, a little-endian version and total length, largest-domain size, query count, then one record per strictly descending adjacent height. Each height record includes its domain/degree/count shape, a Blake2s source root, each column's OOD point and claim, source values in projected largest-query order, and a compressed Merkle witness. The decoder checks the magic **before** reading any protocol values; it rejects legacy `STWOPRW1`, unknown versions, reserved flags, trailing/truncated bytes, noncanonical M31, invalid shapes, and bounded-size violations. The verifier's `decodeAndBind` entry point also requires a locally chosen exact geometry/query profile and leaves its channel unchanged on a decoding or profile failure. This is an experimental *source-opening fragment*, not a complete PCS proof wire format.

| Field | Bytes | Meaning |
| --- | ---: | --- |
| Magic, version, reserved, total length | 8 + 2 + 2 + 4 | Select this fragment before transcript replay; reserved must be zero. |
| Largest log size, query count, height count | 4 + 4 + 4 | Verifier compares the first two and all height shapes to its local profile. |
| Per-height log size, degree log, column count, source root | 4 + 4 + 4 + 32 | Height records descend by exactly one and share the blowup ratio. |
| Per-column OOD point `x,y`, claim, queried source words | 16 + 16 + 16 + `4 × query_count` | Every M31 limb is canonical; each source column follows projected largest-query order. |
| Per-height witness count and hashes | 4 + `32 × count` | The production lifted-Merkle verifier checks the compressed witness before quotient arithmetic. |

Every integer is little-endian. The complete encoded fragment is capped at 64 MiB, with explicit limits on query count, columns, and witness hashes. There is no FRI section in `S31PMH01` version 1; the fixed two-height proof below wraps it under a distinct outer magic.

`src/core/pcs/paired_projection.zig` applies the existing bit-reversed circle projection to the largest-domain positions, preserving the conjugate-pair bit and duplicate positions. It verifies the matching source Merkle multiproof before returning each height's paired answers in largest-query order. A native fixture commits `f=x` at 16 and 8 rows, decommits at all largest-domain positions, serializes and decodes the envelope, replays a single domain-separated batch challenge from both roots and OOD claims, authenticates both heights, and inserts their batches into the line fold. It checks that geometric point doubling agrees with projected positions and that changing one duplicated source value is rejected before insertion.

The source-opening-only fixture deliberately opens its entire small domain and does not use a Fiat–Shamir sampled FRI query schedule. The envelope has no multi-height FRI layer commitments or decommitments, and its standalone transcript still binds proof-supplied OOD points/claims before drawing the batch challenge. Neither the fixture nor its wire decoder admits a proof in the production PCS verifier. The complete experimental outer proof below uses a different transcript: after selecting its version, it binds all source roots and geometry, draws one secure-field circle OOD point, requires every encoded column point to equal that draw, then binds the claims and draws the shared batch challenge. A production variant still needs a theorem-matched OOD sampler, all folded layers, and admitted parameters.

`src/core/pcs/paired_two_height_fri.zig` adds a **sampled** two-height relation checker. After the outer version and verifier-chosen profile are selected, the verifier binds source roots, draws and checks the OOD point, binds claims, and draws the batch challenge. It then draws `alpha_0`, mixes the Merkle root of the first folded line layer, draws `alpha_1`, mixes a terminal line polynomial of the configured degree, and only then draws raw largest-domain queries. Each raw query expands to four adjacent bit-reversed source rows and two intermediate-line rows. The verifier authenticates source openings at both projected heights and all four coordinates of each intermediate QM31 line word. It checks the first circle fold against the committed line words and the second line fold plus inserted circle fold against the terminal polynomial at the projected point. A native fixture builds real source and intermediate Merkle trees for 16/8-row `f=x` sources, constructs the quotients through the native quotient implementation, and verifies the sampled relations. Changing an authenticated line coordinate is rejected at its Merkle check; committing an internally consistent but incorrect line tree is rejected by the fold relation. Altering the encoded OOD point while preserving both roots is rejected before the transcript is committed to the caller.

`src/core/pcs/paired_two_height_wire.zig` wraps the source envelope and sampled FRI section under separate outer magic `S31P2F01`. Its binary records contain the inner source-envelope length and bytes, intermediate Merkle root, terminal line coefficients, four coordinate opening arrays, and the intermediate Merkle witness. The outer decoder checks its own version and exact length, then the inner version and canonical fields, before `decodeAndBind` compares the locally chosen profile and touches the transcript. The fixture verifies directly from this complete experimental byte stream and rejects an unknown outer version without changing the channel.

```text
S31P2F01 | version:u16 | reserved:u16 | total_len:u32
source_len:u32 | S31PMH01[source_len]
intermediate_root:[32]u8
terminal_coeff_count:u32 | QM31[terminal_coeff_count]
line_query_count:u32 | M31[4][line_query_count]
witness_count:u32 | hash[32][witness_count]
```

The outer `S31P2F01` version tag is mixed into the channel before its root/OOD/claim transcript. Both wire versions and the verifier's expected profile are checked first, so a rejected mode or malformed proof cannot reuse the source-only challenge stream. The source-envelope magic is parsed and checked but its standalone transcript routine is not replayed by the outer verifier. Rejection of a mismatched encoded OOD point leaves the caller's channel unchanged.

This is still a fixed two-height experimental protocol. Its query schedule and normalization need a theorem-to-code argument. The terminal degree check is structural (only the configured number of coefficients are accepted); sampled fold checks provide no security claim until the query distribution, source/FRI commitment binding, two-point quotient law, and error bounds are proven for this exact protocol.

This is **not** a production PCS opening. The fixed two-height wire proof has no production prover path or admission gate, and its theorem mapping is incomplete. Legacy PCS transcripts and proof acceptance are untouched. No native soundness bit claim follows from these tests.

## Theorem-to-code audit still required

| Published protocol property | Experimental implementation | Work before a security claim |
| --- | --- | --- |
| Protocol 4 quotient `(f-v)/v_Q` over a single sampled point | Native two-point conjugate quotient for every original column | Prove the degree and correlated-agreement reduction for this exact quotient law. |
| Protocol 3 one shared batch challenge | One QM31 challenge across both heights and every source/quotient pair, after root-bound OOD draw and claim binding | Map pair ordering, field, and challenge timing to the theorem's ensemble model. |
| Verifier-selected OOD point after source commitments | The outer verifier draws a secure-field circle point from its channel after all source roots and geometry, and checks every encoded point against it | Prove this native point map, its distribution, exclusion conditions, and Fiat–Shamir schedule match the theorem's point model. The standalone source fragment has a separate proof-supplied-point schedule. |
| Protocol 3 oracle commitment to each batched height | Source roots fixed before the challenge; batches derived from authenticated source openings | Prove this derived-oracle substitution, or commit batches explicitly. |
| Eq. 68 fold with insertion | Both sampled fold relations checked with native inverse butterflies | Account for omitted `1/2` normalization and verify all domain/coset projection identities. |
| Uniform verifier query point on the largest circle domain | Fiat–Shamir raw row draws, expanded to four source rows and two line rows; repeats retained | Prove the sampled distribution and adaptive transcript reduction for this exact expansion and hash channel. |
| Bounded polynomial spaces and terminal degree | Fixed two-height log shapes and a short terminal polynomial | Generalize and enforce all per-height degree, blowup, and Eq. 80 small-table conditions. |
| Abstract oracle authentication | Native lifted Blake2s Merkle roots and compressed multiproofs | State the hash assumption and prove parser, leaf layout, duplicate handling, and query projection correspond to the oracle game. |

The fixture uses four queries for tiny domains to exercise mechanics; it is not a conservative parameter profile. Proven native security bits remain undefined.

## Required production work

1. Generalize the experimental two-height wire proof to a complete PCS/FRI proof for admitted geometry, with a canonical decoder and production entry-point selection before transcript replay. Legacy proofs must never opt into paired verification, and paired proofs must never parse as legacy.
2. Bind source commitments, sampled OOD points and claims, source/quotient pair order, all domain heights and degree bounds, and one shared batch challenge in the theorem-matched transcript schedule. Reject inconsistent or repeated source entries before FRI.
3. On the prover, produce **each** quotient word from the corresponding committed source polynomial and claimed OOD value. Stream the paired first layer into FRI without materializing an unbounded second column set. Verify prover outputs against the scalar reference and query reconstruction.
4. Authenticate all source columns at the exact FRI query positions before quotient arithmetic. The experimental bridge now handles per-height projected positions with duplicates; complete the matching source and FRI query schedule, lifted query maps, and borrowed-proof capture semantics.
5. Generalize the sampled two-height FRI relation checker and Eq. 68 insertion kernel to every admitted height and fold schedule, with a complete versioned proof shape and authenticated FRI query projections. A repeated smaller-height source column on the largest domain is not a substitute for that reduction. Validate each per-height pair's target polynomial space and the small-table condition of Eq. 80; reject profiles outside the admitted theorem envelope.
6. Refine the published interactive theorem to the native two-point quotient, actual query sampler, Merkle layout, Fiat–Shamir channel, field, and proof decoder. Only then calculate conservative native security bits and change release admission.

Until these steps pass, native PCS/FRI proven security remains unknown and proved release admissibility must stay false.
