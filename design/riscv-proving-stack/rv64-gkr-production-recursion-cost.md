# Production-local GKR recursion cost assessment

Read-only source analysis, 2026-11-01. This is not an accepting production GKR circuit or a speedup qualification. It uses the exact schema-6 full-block roster at `/tmp/rv64-wave2-final-complete-v1/roster.json`, SHA256 `3e60060777030f45ea3bea6579e498df0117515bd43cfae84d0ed949f8ad22e8`: 25 CPU proofs and 5 unchanged truth proofs. Reproducer: `/tmp/rv64_gkr_recursion_cost.py`; full per-role output: `/tmp/rv64-gkr-production-recursion-cost.json`.

## Finding

A local GKR argument can save native interaction cells substantially, but Blake-backed recursion does not gain in proportion. Restricting GKR to RANGE/BYTE/FUNCTION is a net hashing regression on plain batches. Including REG/ROM/OWNER improves that result, yet its plain-batch hash saving is small before new field arithmetic and binding constraints. Service-rich batches amortize it much better. Do not promote a production replacement on the standalone mini-AIR timing alone.

The following counts use q=70 control, current circuit Blake authority, unchanged tree heights, and an optimistic shared late-random-combination N/D binding occupying 8 interaction columns per participating component. They exclude additional domain-separation/framing, root-claim binding and carry-quotient arithmetic. Separate N and D prefixes need 12 columns, worsening the result.

| Scope / batch | INTER width old → new | New GKR compressions | Trace-leaf compressions removed | OODS mix blocks removed (approx.) | Net compressions added (approx.) |
|---|---:|---:|---:|---:|---:|
| Strict range/byte/FUNCTION, plain 0 | 616 → 308 | 1,554 | 1,330 | 63 | +162 |
| All proof-local, plain 0 | 616 → 176 | 1,842 | 1,960 | 98 | −215 |
| Strict, service-rich 3 | 1,256 → 412 | 1,767 | 3,710 | 196 | −2,138 |
| All proof-local, service-rich 3 | 1,256 → 272 | 1,992 | 4,340 | 237 | −2,584 |
| Strict, all 25 CPU proofs | 22,404 → 8,772 summed widths | 40,344 | 59,360 | 3,081 | −22,072 |
| All proof-local, all 25 | 22,404 → 5,432 summed widths | 46,725 | 74,620 | 3,996 | −31,866 |

Net includes one additional common late-binding draw per proof. The broad full-block saving is about 2.55M Blake G gates across all 25 leaves; it is not a wall-time estimate. The existing native circuit emits 80 G gates per Blake compression. The model's optimistically simplified sumcheck verifier additionally performs about 313,314 QM31 multiplications, 339,014 adds/subtractions and 6,800 QM31×M31 multiplies for the broad scope, before input-binding/carry work. Literal current generic Horner loops cost more. There is no implemented GKR circuit gate count to compare with this arithmetic model.

## Exact source-derived hash accounting

For instance i, n_i = trace_log_i + ceil(log2(padded fraction lanes_i)); L=max n_i; S=sum n_i. The batch has R=L(L−1)/2 sumcheck rounds, S active claim mixes, S mask mixes, and R+3L challenge draws. Claims are two QM31 values, masks and round polynomials four. With the current Blake channel, these cost respectively 1, 2, 2 and 1 compressions, giving C=3(S+R+L). Mini LS log20 + tail18 at 16 lanes has L24/S46/R276/C1038, matching the prototype's counting channel.

Reducing polynomial encoding from four QM31 coefficients to three does not reduce Blake compressions: digest32+48=80 bytes still crosses the 64-byte boundary. It can save wire/field work; do not advertise a hash-block saving.

The native leaf verifier consumes the 70 unpacked query positions directly. It hashes one trace leaf per tree per query, not 140 leaves because the first FRI fold has size two. Thus removed trace-leaf blocks are exactly 70×(ceil(old_width/16)−ceil(new_width/16)) at unchanged height. OODS transcript savings depend on surrounding block alignment and are reported approximately. Two-point masks add a DEEP periodicity sample; removing committed cells is not identical to removing DEEP entries.

Source authorities: `src/prover/lookups/gkr_verifier.zig`, `sumcheck.zig`; `src/frontends/circuit/native_verifier/{verify,merkle,blake_chain}.zig`; `src/frontends/circuit/builder/blake.zig`; `src/integrations/riscv_cpu/logup_gkr/{protocol,mle_point}.zig`.

## Scope and statement constraints

The requested strict scope keeps REG/ROM/OWNER and global RAM/KIO/Wire classic. CPU40→8 is not possible in that scope: CPU40→32 with optimistic late binding, and its OODS sample count does not decrease. The broad candidate includes proof-local REG/ROM/OWNER, while global RAM, Keccak IO and Wire LogUp remain unchanged. A CPU row has six signed register terms, FUNCTION, ROM, OWNER, three U16 and three U8 terms = 15 fractions padded to16. The model retains small public/table providers where replacing a classic 8-column trace adds no width benefit. Bridge global relation prefixes remain authenticated; no global debt is silently dropped.

The final GKR input claim must authenticate the MLE of actual row numerator/denominator expressions, not multiply independently interpolated operand MLEs. The current CpuClaims.local combined debt can be replaced only with an exact matched local sum; global claims and receiver closure remain separate. This binding, and the late N+beta D random combination after commitments, require soundness review before the 8-column assumption is earned.

For mixed geometry, local AIR point is P.repeatedDouble(global_log−trace_log). Masks remain global offsets: P+k×CanonicCoset(global_log).step(), then PCS lifting/folding maps to local. Eq mask [0,+2], carry prefix [0,−1]; +2 also changes DEEP periodicity/sample planning. Never treat trace_log+lane_log as AIR trace height. Instances of different lane counts use their own suffix of the GKR point and row/lane split. Receiver derives these from admitted protocol geometry, not producer hints.

## Whole-protocol 128-bit target

This q70 model is only a nominal96 control; it does not qualify the requested128-bit production target. A single QM31 challenge lives in roughly124 bits. A rational lookup bound scaling as M/|F| is only about97 bits for M≈2^27 and93 bits near2^31. Hundreds of degree-bounded GKR rounds similarly consume field-error budget. Two lookup challenges combined inside one124-bit GKR sumcheck do not eliminate that GKR ceiling. Raising FRI queries or proof-of-work alone does not repair these algebraic terms, and proof-of-work does not automatically amplify an attack that can select a weak challenge before grinding.

Independent repetitions must cover every weak argument (including unchanged global lookup relations and OODS/DEEP) or an independently justified wider-field construction must replace them. They must be compared against an equally secure baseline. Two independent GKR repetitions alone roughly double its transcript work: the broad control then adds ~93,450 GKR compressions against the same~78,616 leaf+OODS removals, turning its hash-only result into a regression before field arithmetic. Wider M31 degree8 doubles secure-element bytes/binding columns and substantially increases circuit arithmetic; it is a protocol-wide engineering change, not a local GKR switch. Formal whole-protocol bounds remain the production gate.

An algebraic GKR-only subtranscript could avoid thousands of Blake G gates while leaving the PCS unchanged, but no such accepting circuit exists here. Existing Poseidon2-M31 channel width16/rate8/capacity8 and eight-word digest have at most roughly124-bit generic collision strength, so they cannot be stamped128. Any new capacity/rate, framing, squeeze length and security bound require review. Seed it injectively from Blake's raw u32 state (e.g.16-bit limbs, not reduction moduloM31), bind protocol/scope/shape/repetition identities and roots, and mix the terminal algebraic digest and claims back into the Blake parent before committing dependent columns.

The pinned width16 Poseidon2 permutation has142 x^5 S-boxes:426 nonlinear M31 multiplies, plus224 partial-round diagonal multiplies and roughly1418 additions per permutation. Literal reuse of the old sponge would cost7S+6R+6L permutations (mini2122), not one permutation per Blake compression. These are raw operations, not a measured proof cost, and the old sponge profile is insufficient for the target. A designed duplex subtranscript may differ and must be costed independently.

## Recommended next gate

Freeze a formally budgeted128-bit candidate and build a source-level/circuit cost oracle for the exact broad local binding and hash choice before implementing production routes. Keep the standalone prototype additive. Measure one plain and one service-rich complete leaf; compare statement/claims, fresh receiver acceptance, cell/byte counts, native time, circuit gates and recursively proved time. Consider pruning strict SHIFT/JALR conversions that add masks while removing little width. Do not force GKR into production if equally secure recursion is slower.

Expansion reuse remains stopped: checkpoint8b7eac773 in `/private/tmp/stwo-rv64-expansion-reuse`, uncompiled and unqualified. No main or original worktree source was changed for this review.
