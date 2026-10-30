# One parent for a bounded Group and its global RAM closure

The experimental Group join compiles three **original** verifier programs into
one parent STARK: Group execution, the endpoint late bridge, and compact global
memory. It does not produce three recursive child roots first. The legacy Local
join is unchanged; the new Group protocol has separate key/public/proof/claims
and public-value/schedule identities.

`recursion/block_v8_endpoint_group_join_saved_v1.zig` loads the retained three
bodies and reconstructs their statements using the pinned ELF, snapshots and
security profile. Each original is verified/captured once for witness
preparation. The Group-aware `Source` reuses the qualified direct-verifier
compiler and row strategy for every physical tree. `Roster` assembles these
verifiers and the closure circuit under one common parent bus. The parent
receiving key is rebuilt independently; successful native verification is never
an authority for accepting the parent proof.

For N native members (1..32), Group first roots have N native roots and N
endpoint roots, with endpoint i at physical tree N+1+i. The closure equates
**each** eight-word digest to bridge physical tree 1+i. The compact global
transition fraction plus all N bridge fractions vanishes. Host admission also
binds every source identity, local epoch, endpoint count and policy, the common
late epoch, the global-memory entry and the complete ordered ordinal/cycle
coverage. No endpoint-root equality is replaced by an aggregate digest sum.

The Group verifier checks CPU/register/local-RAM residuals separately for every
member before aggregating positive range/ROM/lookup membership demands. Its
composition authenticates N consecutive 416-byte RV32 boundary frames, including
132 byte equalities between adjacent CPU states. The join also reproduces all
adjacency equalities and binds the first/last 132 bytes to the independently
derived global window CPU boundary. No off-circuit summary substitutes for those
public-input constraints.

The saved-input producer returns only parent bytes, serialized physical claims,
Group metadata and public directory data. All decoded original proofs, captures,
profiles and producer keys are already destroyed. The test and benchmark persist
these operands, destroy the returned producer owner too, reload the files, and
reconstruct the three verifier keys before verifying the one parent.

This protocol currently admits exactly one native-only Group, one bridge and one
compact global-memory original, covering a declared nonterminal window. Caller
recursion, terminal execution, multi-Group hierarchies and full Ethereum closure
remain separate obligations. Bounded consolidation changes proof count and
padding; it does not imply an eightfold reduction in hash work.

Implementation: `src/frontends/riscv/recursion/block_v8_endpoint_group_join_{source,public,graph,roster,protocol,pipeline,receiver,saved}_v1.zig`.
Qualification root: `src/frontends/riscv/block_v8_endpoint_group_join_test_root.zig`.
Saved benchmark root: `src/frontends/riscv/block_v8_endpoint_group_join_saved_benchmark_root.zig`.

## Qualification

The canonical q70/26 two-cohort joint gate passed all 11 tests. It generated
a 975,915-byte root, SHA-256
`b5ff39b0779975889454bd4cbf5c5f796df3e97c11a0ae409d5db568645087b6`,
and verified it with the fresh file receiver after destroying every producer
owner. Dropped-member coverage rejects. Independent closure-graph controls
reject changed member roots, opposite changed root words and a CPU byte change;
the Group recursion gate also rejects opposite member RAM residuals despite
an unchanged aggregate. The initial full 489-test suite passed these controls,
with its sole failure the subsequently corrected bridge-loader geometry.

The tiny, nonisolated diagnostic parent core took 33.516 s and retained
2.538 GB of rows. This is not an Ethereum cost rate. The saved real-4M Group
originals are the next measurement; their three bodies are reused unchanged.
The test's temporary proof files were cleaned up; log, source hashes and exact
proof identity remain in
`vectors/reports/riscv-cpu-architecture-20261029/group-single-root-qualification-v1/`.
