# Program-only RV64 ROM

`Setup.init(allocator, Program)` owns exact canonical u64 PCs and independently
decoded reference rows. Dense and equivalent sparse programs have the same
identity. No request PC path, state, step count, or final PC enters this object.
Unreachable illegal/system words remain bound to the executable, with validity
zero; `lookup` rejects their execution. The byte encoding of every u64 remains
injective over M31. The identity is a cache hint, never an accepted verifier key.

`compactFixedColumns` produces 43 columns: a 41-field ROM tuple and local
first/last selectors. The tuple is `(valid, pc[8], opcode, rs1, rs2, rd,
immediate[8], slots[4], increment[8], target[8])`. Effective register indices
are zero for absent accesses. Increment and target use exact wrapping RV64
semantics. Padding tuples are zero. The full 155-field reference profile also
retains four raw bytes and 110 word/carry enables.

`compact.inflateFixed` reconstructs arithmetic decode authority from the tuple
and 65 Boolean opcode selectors. `evaluateSelectors` proves their sum equals
validity and their weighted sum equals the authenticated opcode ID. Word/carry
coefficient masks derive from `operations.zig`, deduplicate at compile time,
and are evaluated as linear expressions. First/last, current ticks and next PC
belong to the execution request and remain the caller's responsibility.

One request owns one fresh multiplicity column and eight interaction columns.
`Request.init` checks every executed PC against the immutable program and never
mutates setup. `generateInteraction` publishes transactionally. The component
proves inverse, prefix, first-row reset and terminal claim equations using one
evaluator at both domain and OODS points. Its independent domain has
`2^max(5,ceil(log2(program_words)))` rows. Shared-tree offsets and the global
composition domain do not enlarge its table.

The integration must perform this transcript order:

1. Bind expected program identity, public request and proof geometry.
2. Commit independently reconstructed preprocessing and all execution/provider
   main columns, including program multiplicities.
3. Draw `compact.draw` challenges once for execution and the ROM provider.
4. Generate interactions and mix component claims into the transcript.
5. Commit interactions, then draw composition randomness and prove one STARK.

The execution contribution is positive and the provider contribution negative.
The receiver must check their claims sum to zero and derive the preprocessing
root from its expected executable. An isolated provider proof is only a test
of this component, not an execution proof. Tests use reduced security settings
explicitly; production settings belong to the integrating profile.

Storage before PCS copies is `620 * program_words + 8 * program_words` bytes
for reference setup, `172 * padded_program_words` bytes for compact fixed
columns, and `36 * padded_program_words` bytes per active request. Setup construction
is O(program words), request construction O(execution steps * log(program words)),
and interaction construction scans 155 fields and multiplies 41 nonzero
coefficients per padded program word with compact challenges.
No program-sized cache grows with the number of distinct paths.
