"""Exact source fragments that bind infrastructure theorems to production."""

from pathlib import Path


PROGRAM_INTERACTION_PATH = Path("src/frontends/riscv/air/program/interaction.zig")
PROGRAM_COMMITMENT_PATH = Path("src/frontends/riscv/air/program/commitment.zig")
MEMORY_INTERACTION_PATH = Path(
    "src/frontends/riscv/air/memory_commitment/interaction.zig"
)
MEMORY_BOUNDARY_PATH = Path(
    "src/frontends/riscv/air/memory_commitment/boundary.zig"
)
MEMORY_LOGUP_PATH = Path("src/frontends/riscv/air/memory_logup.zig")
MERKLE_NODE_PATH = Path(
    "src/frontends/riscv/air/memory_commitment/merkle_node.zig"
)
SPARSE_MERKLE_PATH = Path(
    "src/frontends/riscv/air/memory_commitment/sparse_merkle.zig"
)
CLOCK_INTERACTION_PATH = Path(
    "src/frontends/riscv/air/clock_update_interaction.zig"
)
CLOCK_COMPONENT_PATH = Path(
    "src/frontends/riscv/air/clock_update_component.zig"
)
CLOCK_TRACE_PATH = Path("src/frontends/riscv/infra_trace/clock_update.zig")
STATE_CHAIN_PATH = Path("src/frontends/riscv/runner/state_chain.zig")
PUBLIC_LOGUP_PATH = Path("src/frontends/riscv/air/public_logup.zig")
M31_PATH = Path("src/core/fields/m31.zig")
STATE_COMMON_PATH = Path("src/frontends/riscv/air/semantics/common.zig")
LOOKUP_ENTRY_PATH = Path("src/frontends/riscv/air/lookups/entry.zig")
ACCESS_CLOCK_PATH = Path("src/frontends/riscv/access_clock.zig")
STATEMENT_PATH = Path("src/frontends/riscv/air/statement.zig")
STATEMENT_VALIDATION_PATH = Path(
    "src/frontends/riscv/prover/statement_validation.zig"
)

PRODUCTION_PATHS = (
    M31_PATH,
    PROGRAM_INTERACTION_PATH,
    PROGRAM_COMMITMENT_PATH,
    MEMORY_INTERACTION_PATH,
    MEMORY_BOUNDARY_PATH,
    MEMORY_LOGUP_PATH,
    MERKLE_NODE_PATH,
    SPARSE_MERKLE_PATH,
    CLOCK_INTERACTION_PATH,
    CLOCK_COMPONENT_PATH,
    CLOCK_TRACE_PATH,
    STATE_CHAIN_PATH,
    PUBLIC_LOGUP_PATH,
    STATE_COMMON_PATH,
    LOOKUP_ENTRY_PATH,
    ACCESS_CLOCK_PATH,
    STATEMENT_PATH,
    STATEMENT_VALIDATION_PATH,
)

SOURCE_BINDINGS: tuple[tuple[str, Path, str], ...] = (
    (
        "program active selector",
        PROGRAM_INTERACTION_PATH,
        "result[N_SUMS] = main[0].sub(is_active);",
    ),
    (
        "program padding multiplicity",
        PROGRAM_INTERACTION_PATH,
        "result[N_SUMS + 1] = main[6].mul(QM31.one().sub(is_active));",
    ),
    (
        "program address radix",
        PROGRAM_INTERACTION_PATH,
        "const word_address = main[8].add(main[9].mul(base(@as(u32, 1) << 20)));",
    ),
    (
        "program address recomposition",
        PROGRAM_INTERACTION_PATH,
        "main[1].sub(word_address.mul(base(4)))",
    ),
    (
        "program tuple emission",
        PROGRAM_INTERACTION_PATH,
        "append(&list, .program_access, main[6], .{ addr, values[0], values[1], values[2], values[3] });",
    ),
    (
        "program Merkle leaf depth",
        PROGRAM_INTERACTION_PATH,
        "const depth = base(30);",
    ),
    (
        "program first Merkle leaf",
        PROGRAM_INTERACTION_PATH,
        "append(&list, .merkle, enabler.neg(), .{ addr, depth, values[0], root });",
    ),
    (
        "program second Merkle leaf",
        PROGRAM_INTERACTION_PATH,
        "append(&list, .merkle, enabler.neg(), .{ addr.add(base(1)), depth, values[1], root });",
    ),
    (
        "program third Merkle leaf",
        PROGRAM_INTERACTION_PATH,
        "append(&list, .merkle, enabler.neg(), .{ addr.add(base(2)), depth, values[2], root });",
    ),
    (
        "program fourth Merkle leaf",
        PROGRAM_INTERACTION_PATH,
        "append(&list, .merkle, enabler.neg(), .{ addr.add(base(3)), depth, values[3], root });",
    ),
    (
        "program low address range",
        PROGRAM_INTERACTION_PATH,
        "append(&list, .range_check_20, enabler.neg(), .{main[8]});",
    ),
    (
        "program high address range",
        PROGRAM_INTERACTION_PATH,
        "append(&list, .range_check_8_8, enabler.neg(), .{ main[9], QM31.zero() });",
    ),
    (
        "program builder tree validation",
        PROGRAM_COMMITMENT_PATH,
        "try self.tree.validate(allocator);",
    ),
    (
        "program builder row-to-leaf cardinality",
        PROGRAM_COMMITMENT_PATH,
        "if (self.rows.len * 4 != self.tree.leaves.len) return error.InvalidProgramCommitment;",
    ),
    (
        "program builder common root",
        PROGRAM_COMMITMENT_PATH,
        "if (row.root != self.tree.root) return error.InvalidProgramCommitment;",
    ),
    (
        "program builder leaf binding",
        PROGRAM_COMMITMENT_PATH,
        "if (leaf.index != row.addr + limb or leaf.value != value) return error.InvalidProgramCommitment;",
    ),
    (
        "memory multiplicity square definition",
        MEMORY_INTERACTION_PATH,
        "const multiplicity_squared = multiplicity.square();",
    ),
    (
        "memory signed multiplicity polynomial",
        MEMORY_INTERACTION_PATH,
        "result[N_SUMS] = multiplicity.mul(multiplicity_squared.sub(QM31.one()));",
    ),
    (
        "memory active multiplicity square",
        MEMORY_INTERACTION_PATH,
        "result[N_SUMS + 1] = multiplicity_squared.sub(is_active);",
    ),
    (
        "memory tuple boundary",
        MEMORY_INTERACTION_PATH,
        "append(&list, .memory_access, multiplicity, .{ QM31.one(), addr, clock, values[0], values[1], values[2], values[3], });",
    ),
    (
        "memory first byte range pair",
        MEMORY_INTERACTION_PATH,
        "append(&list, .range_check_8_8, enabler.neg(), .{ values[0], values[1] });",
    ),
    (
        "memory second byte range pair",
        MEMORY_INTERACTION_PATH,
        "append(&list, .range_check_8_8, enabler.neg(), .{ values[2], values[3] });",
    ),
    (
        "memory Merkle leaf depth",
        MEMORY_INTERACTION_PATH,
        "const depth = base(30);",
    ),
    (
        "memory first Merkle leaf",
        MEMORY_INTERACTION_PATH,
        "append(&list, .merkle, enabler.neg(), .{ addr, depth, values[0], root });",
    ),
    (
        "memory second Merkle leaf",
        MEMORY_INTERACTION_PATH,
        "append(&list, .merkle, enabler.neg(), .{ addr.add(base(1)), depth, values[1], root });",
    ),
    (
        "memory third Merkle leaf",
        MEMORY_INTERACTION_PATH,
        "append(&list, .merkle, enabler.neg(), .{ addr.add(base(2)), depth, values[2], root });",
    ),
    (
        "memory fourth Merkle leaf",
        MEMORY_INTERACTION_PATH,
        "append(&list, .merkle, enabler.neg(), .{ addr.add(base(3)), depth, values[3], root });",
    ),
    (
        "memory host tree validation",
        MEMORY_BOUNDARY_PATH,
        "if (self.initial_tree) |tree| try tree.validate(allocator); if (self.final_tree) |tree| try tree.validate(allocator);",
    ),
    (
        "memory host address canonicality",
        MEMORY_BOUNDARY_PATH,
        "if ((row.addr & 3) != 0 or row.addr > sparse_merkle.LEAF_COUNT - 4) return error.InvalidBoundary;",
    ),
    (
        "memory host initial sign",
        MEMORY_BOUNDARY_PATH,
        "const is_initial = row.multiplicity.eql(M31.one());",
    ),
    (
        "memory host final sign",
        MEMORY_BOUNDARY_PATH,
        "const is_final = row.multiplicity.eql(M31.one().neg());",
    ),
    (
        "memory host initial clock",
        MEMORY_BOUNDARY_PATH,
        "if (is_initial and row.clock != 0) return error.InvalidBoundary;",
    ),
    (
        "memory host root binding",
        MEMORY_BOUNDARY_PATH,
        "if (row.root != tree.root) return error.InvalidBoundary;",
    ),
    (
        "memory host initial leaf binding",
        MEMORY_BOUNDARY_PATH,
        "try initial_leaves.append(allocator, leaf);",
    ),
    (
        "memory host final leaf binding",
        MEMORY_BOUNDARY_PATH,
        "try final_leaves.append(allocator, leaf);",
    ),
    (
        "memory host exact initial leaves",
        MEMORY_BOUNDARY_PATH,
        "try matchLeaves(self.initial_tree, initial_leaves.items);",
    ),
    (
        "memory host exact final leaves",
        MEMORY_BOUNDARY_PATH,
        "try matchLeaves(self.final_tree, final_leaves.items);",
    ),
    (
        "offline memory previous tuple",
        MEMORY_LOGUP_PATH,
        "self.addr_space, self.addr, self.previous_clock, self.previous[0], self.previous[1], self.previous[2], self.previous[3],",
    ),
    (
        "offline memory next tuple",
        MEMORY_LOGUP_PATH,
        "self.addr_space, self.addr, self.clock, self.next[0], self.next[1], self.next[2], self.next[3],",
    ),
    (
        "offline memory transition signs",
        MEMORY_LOGUP_PATH,
        "const expected_numerator = pair.enabler.neg().mul(pair.next_denominator) .add(pair.enabler.mul(pair.previous_denominator));",
    ),
    (
        "Merkle active selector",
        MERKLE_NODE_PATH,
        "result[N_SUMS] = enabler.sub(is_active);",
    ),
    (
        "Merkle left multiplicity constraint",
        MERKLE_NODE_PATH,
        "result[N_SUMS + 1] = multiplicityConstraint(main[6]);",
    ),
    (
        "Merkle right multiplicity constraint",
        MERKLE_NODE_PATH,
        "result[N_SUMS + 2] = multiplicityConstraint(main[7]);",
    ),
    (
        "Merkle parent multiplicity constraint",
        MERKLE_NODE_PATH,
        "result[N_SUMS + 3] = multiplicityConstraint(main[8]);",
    ),
    (
        "Merkle multiplicity polynomial",
        MERKLE_NODE_PATH,
        "return value.mul(value.sub(one)).mul(value.sub(two));",
    ),
    (
        "Merkle padding multiplicities",
        MERKLE_NODE_PATH,
        "result[N_SUMS + 4] = main[6].mul(is_padding); result[N_SUMS + 5] = main[7].mul(is_padding); result[N_SUMS + 6] = main[8].mul(is_padding);",
    ),
    (
        "Merkle left child",
        MERKLE_NODE_PATH,
        "append(&list, .merkle, main[6], .{ index, depth, lhs, root });",
    ),
    (
        "Merkle right child",
        MERKLE_NODE_PATH,
        "append(&list, .merkle, main[7], .{ index.add(one), depth, rhs, root });",
    ),
    (
        "Merkle parent",
        MERKLE_NODE_PATH,
        "append(&list, .merkle, main[8].neg(), .{ index.mul(INV2), depth.sub(one), cur, root });",
    ),
    (
        "Merkle Poseidon zero-padded input",
        MERKLE_NODE_PATH,
        "var poseidon_input = [_]QM31{QM31.zero()} ** poseidon2_air.WIDTH; poseidon_input[0] = lhs; poseidon_input[1] = rhs;",
    ),
    (
        "Merkle Poseidon narrow output",
        MERKLE_NODE_PATH,
        "var poseidon_output = [_]QM31{QM31.zero()} ** poseidon2_air.WIDTH; poseidon_output[0] = cur;",
    ),
    (
        "Merkle Poseidon input",
        MERKLE_NODE_PATH,
        "append(&list, .poseidon2, enabler, poseidon_input);",
    ),
    (
        "Merkle Poseidon output",
        MERKLE_NODE_PATH,
        "append(&list, .poseidon2, enabler.neg(), poseidon_output);",
    ),
    (
        "sparse Merkle parent index",
        SPARSE_MERKLE_PATH,
        "try next.put(left_index / 2, parent);",
    ),
    (
        "clock committed row layout",
        CLOCK_INTERACTION_PATH,
        ".enabler = main[0], .addr_space = main[1], .addr = main[2], .clock_prev = main[3], .value = .{ main[4], main[5], main[6], main[7] }, .clock_prev_low20 = main[8], .clock_prev_high6 = main[9],",
    ),
    (
        "clock memory tuple layout",
        CLOCK_INTERACTION_PATH,
        "return .{ .addr_space = row.addr_space, .addr = row.addr, .clock = clock, .limbs = row.value, };",
    ),
    (
        "clock previous tuple",
        CLOCK_INTERACTION_PATH,
        "entry.memory(&result, row.enabler.neg(), memoryTuple(row, row.clock_prev));",
    ),
    (
        "clock next tuple",
        CLOCK_INTERACTION_PATH,
        "memoryTuple(row, row.clock_prev.add(q(state_chain.MAX_CLOCK_DIFF)))",
    ),
    (
        "clock low range",
        CLOCK_INTERACTION_PATH,
        "entry.range20(&result, row.enabler.neg(), row.clock_prev_low20);",
    ),
    (
        "clock high range",
        CLOCK_INTERACTION_PATH,
        ".{ row.clock_prev_high6, row.clock_prev_high6.mul(q(4)) },",
    ),
    (
        "clock boolean enabler",
        CLOCK_COMPONENT_PATH,
        "result.values[interaction.N_SUMS] = row.enabler.mul(QM31.one().sub(row.enabler));",
    ),
    (
        "clock active selector",
        CLOCK_COMPONENT_PATH,
        "result.values[interaction.N_SUMS + 1] = row.enabler.sub(is_active);",
    ),
    (
        "clock direct recomposition",
        CLOCK_COMPONENT_PATH,
        "result.values[interaction.N_SUMS + 2] = row.enabler.mul( row.clock_prev.sub( row.clock_prev_low20.add( row.clock_prev_high6.mul( QM31.fromBase(M31.fromU64( @as(u32, 1) << state_chain.CLOCK_PREV_LOW_BITS, )), ), ), ), );",
    ),
    (
        "clock committed row contents",
        CLOCK_TRACE_PATH,
        "fn placeClockUpdateRow( columns: *[CLOCK_UPDATE_COLS][]M31, row: usize, placement: permutation.BitReversalTable, address_space: u32, update: state_chain.ClockUpdate, ) void { permutation.placeValue(columns[0], row, placement, M31.one()); permutation.placeValue(columns[1], row, placement, M31.fromCanonical(address_space)); permutation.placeValue( columns[2], row, placement, M31.fromCanonical(update.addr & 0x7fff_ffff), ); permutation.placeValue(columns[3], row, placement, M31.fromCanonical(update.clk_prev)); for (update.value_limbs, 0..) |value, limb| { permutation.placeValue(columns[4 + limb], row, placement, value); } permutation.placeValue( columns[8], row, placement, M31.fromCanonical( update.clk_prev & ((@as(u32, 1) << state_chain.CLOCK_PREV_LOW_BITS) - 1), ), ); permutation.placeValue( columns[9], row, placement, M31.fromCanonical(update.clk_prev >> state_chain.CLOCK_PREV_LOW_BITS), ); }",
    ),
    (
        "clock bridge recurrence",
        STATE_CHAIN_PATH,
        "while (clk -| current > MAX_CLOCK_DIFF) { const next = current + MAX_CLOCK_DIFF;",
    ),
    (
        "strict positive opcode access gap",
        STATE_COMMON_PATH,
        "clock_gap = current_clock.sub(access.previous_clock).sub(S.one()),",
    ),
    (
        "opcode access gap table",
        LOOKUP_ENTRY_PATH,
        "Self.range20(list, enabler.neg(), chain.clock_gap);",
    ),
    (
        "Merkle coefficient lift admission",
        STATEMENT_VALIDATION_PATH,
        "try validateMerkleCoefficientLift(program.n_rows, memory_shards, merkle_desc.n_rows);",
    ),
    (
        "Merkle node coefficient bound",
        STATEMENT_VALIDATION_PATH,
        "if (merkle_rows > MAX_MERKLE_ROWS_WITHOUT_COEFFICIENT_WRAP) return types.ProverError.InvalidStatement;",
    ),
    (
        "Merkle all-source coefficient bound",
        STATEMENT_VALIDATION_PATH,
        "var terms_per_side = @as(u64, merkle_rows) * 2 + @as(u64, program_rows) + MAX_PUBLIC_MERKLE_TUPLE_MULTIPLICITY; for (memory_shards) |desc| terms_per_side += @as(u64, desc.n_rows); if (terms_per_side >= m31.Modulus) return types.ProverError.InvalidStatement;",
    ),
    (
        "memory coefficient lift admission",
        STATEMENT_VALIDATION_PATH,
        "try validateMemoryRelationCoefficientLift( statement.total_steps, memory_shards, clock_update.n_rows, );",
    ),
    (
        "memory coefficient side bound",
        STATEMENT_VALIDATION_PATH,
        "var terms_per_side = @as(u64, total_steps) * @as(u64, access_clock.MAX_ACCESSES_PER_INSTRUCTION) + @as(u64, clock_update_rows) + MAX_PUBLIC_MEMORY_TUPLE_MULTIPLICITY; for (memory_shards) |desc| terms_per_side += @as(u64, desc.n_rows); if (terms_per_side >= m31.Modulus) return types.ProverError.InvalidStatement;",
    ),
    (
        "public Merkle root tuple",
        PUBLIC_LOGUP_PATH,
        "M31.zero(), M31.zero(), base(root), base(root),",
    ),
)
