//! Internal shard of binary_fri_outer_source.zig; use the public facade.

pub const std = @import("std");

pub const vm_binary_fri_source = @This();

pub const composition_workspace_mod = @import("binary_fri_outer_source_composition_workspace.zig");

pub const fri_workspace_mod = @import("binary_fri_outer_source_fri_workspace.zig");

pub const arithmetic_workspace_mod = @import("binary_fri_outer_source_arithmetic_workspace.zig");

pub const merkle_workspace_mod = @import("binary_fri_outer_source_merkle_workspace.zig");

pub const relation_workspaces = @import("binary_fri_outer_source_relation_workspaces.zig");

pub const interaction_operations = @import("binary_fri_outer_source_interaction_operations.zig");

pub const merkle_operations = @import("binary_fri_outer_source_merkle_operations.zig");

pub const arithmetic_operations = @import("binary_fri_outer_source_arithmetic_operations.zig");

pub const fri_operations = @import("binary_fri_outer_source_fri_operations.zig");

pub const boundary_operations = @import("binary_fri_outer_source_boundary_operations.zig");

pub const composition_operations = @import("binary_fri_outer_source_composition_operations.zig");

pub const constructors_operations = @import("binary_fri_outer_source_constructors_operations.zig");

pub const stwo_core = @import("stwo_core");

pub const M31 = stwo_core.fields.m31.M31;

pub const QM31 = stwo_core.fields.qm31.QM31;

pub const air_digest = @import("../air/lang/digest.zig");

pub const relation = @import("../air/lang/relation.zig");

pub const binary_authority = @import("binary_pair_authority.zig");

pub const captured_fri = @import("captured_fri.zig");

pub const fixed_profile = @import("fixed_profile.zig");

pub const fixed_wire = @import("fixed_wire.zig");

pub const pair_node = @import("pair_node.zig");

pub const protocol = @import("protocol.zig");

pub const transcript_program = @import("transcript_program.zig");

pub const composition = @import("air/composition_circuit.zig");

pub const composition_input_air = @import("air/vm_air_composition_input.zig");

pub const composition_input_relation = @import("air/vm_air_composition_input_relation.zig");

pub const composition_input_witness = @import("air/vm_air_composition_input_witness.zig");

pub const composition_control_air = @import("air/vm_air_composition_control.zig").Air;

pub const composition_control_witness = @import("air/control_slice_witness.zig");

pub const query_bits_air = @import("air/query_bits.zig");

pub const query_bits_relation = @import("air/query_bits_relation.zig");

pub const query_bits_witness = @import("air/query_bits_witness.zig");

pub const query_mapping_air = @import("air/query_mapping.zig");

pub const query_mapping_relation = @import("air/query_mapping_relation.zig");

pub const query_mapping_witness = @import("air/query_mapping_witness.zig");

pub const merkle_root_air = @import("air/merkle_root.zig");

pub const merkle_root_relation = @import("air/merkle_root_relation.zig");

pub const merkle_root_witness = @import("air/merkle_root_witness.zig");

pub const trace_merkle_air = @import("air/trace_merkle.zig");

pub const trace_merkle_relation = @import("air/trace_merkle_relation.zig");

pub const trace_merkle_witness = @import("air/trace_merkle_witness.zig");

pub const pcs_air = @import("air/pcs_deep_input.zig");

pub const pcs_relation = @import("air/pcs_deep_input_relation.zig");

pub const pcs_witness = @import("air/pcs_deep_input_witness.zig");

pub const fri_leaf_air = @import("air/fri_merkle_leaf.zig");

pub const fri_leaf_relation = @import("air/fri_merkle_leaf_relation.zig");

pub const fri_leaf_witness = @import("air/fri_merkle_leaf_witness.zig");

pub const fri_node_air = @import("air/fri_merkle_node.zig");

pub const fri_node_relation = @import("air/fri_merkle_node_relation.zig");

pub const fri_node_witness = @import("air/fri_merkle_node_witness.zig");

pub const fri_anchor_air = @import("air/fri_merkle_anchor.zig");

pub const fri_anchor_relation = @import("air/fri_merkle_anchor_relation.zig");

pub const fri_anchor_witness = @import("air/fri_merkle_anchor_witness.zig");

pub const fri_control_air = @import("air/fri_verifier_control.zig");

pub const fri_control_relation = @import("air/fri_verifier_control_relation.zig");

pub const fri_control_witness = @import("air/fri_verifier_control_witness.zig");

pub const fri_input_air = @import("air/fri_verifier_input.zig");

pub const fri_input_relation = @import("air/fri_verifier_input_relation.zig");

pub const fri_input_witness = @import("air/fri_verifier_input_witness.zig");

pub const statement_input_air = @import("air/statement_input.zig");

pub const multiply_air = @import("air/qm31_mul_full.zig");

pub const multiply_witness = @import("air/qm31_mul_full_witness.zig");

pub const inverse_air = @import("air/qm31_inv.zig");

pub const inverse_witness = @import("air/qm31_inv_witness.zig");

pub const linear_air = @import("air/linear_ops.zig");

pub const linear_witness = @import("air/linear_ops_witness.zig");

pub const lowering = @import("air/verifier_arithmetic_lowering.zig");

pub const merkle_path_air = @import("air/merkle_path.zig");

pub const merkle_path_relation = @import("air/merkle_path_relation.zig");

pub const merkle_path_witness = @import("air/merkle_path_witness.zig");

pub const merkle_path_poseidon = @import("air/merkle_path_poseidon_bridge.zig");

pub const schedule = @import("air/verifier_schedule.zig");

pub const universal_binding = @import("air/universal_relation_binding.zig");

pub const universal = @import("air/universal_challenges.zig");

pub const universal_roster = @import("air/universal_roster.zig");

pub const framework = @import("air/framework_interaction.zig");

pub const relation_interaction = @import("air/relation_interaction.zig");

pub const CompositionControlRelation = universal_binding.Binding(composition_control_air);

pub const MultiplyRelation = universal_binding.Binding(multiply_air);

pub const InverseRelation = universal_binding.Binding(inverse_air);

pub const LinearRelation = universal_binding.Binding(linear_air);

pub const CompositionInputFramework = framework.Runtime(
    composition_input_relation.Runtime,
);

pub const CompositionControlFramework = framework.Runtime(
    CompositionControlRelation.Runtime,
);

pub const QueryBitsFramework = framework.Runtime(query_bits_relation.Runtime);

pub const QueryMappingFramework = framework.Runtime(query_mapping_relation.Runtime);

pub const MerkleRootFramework = framework.Runtime(merkle_root_relation.Runtime);

pub const TraceMerkleFramework = framework.Runtime(trace_merkle_relation.Runtime);

pub const PcsFramework = framework.Runtime(pcs_relation.Runtime);

pub const FriLeafFramework = framework.Runtime(fri_leaf_relation.Runtime);

pub const FriNodeFramework = framework.Runtime(fri_node_relation.Runtime);

pub const FriAnchorFramework = framework.Runtime(fri_anchor_relation.Runtime);

pub const FriControlFramework = framework.Runtime(fri_control_relation.Runtime);

pub const FriInputFramework = framework.Runtime(fri_input_relation.Runtime);

pub const MultiplyFramework = framework.Runtime(MultiplyRelation.Runtime);

pub const InverseFramework = framework.Runtime(InverseRelation.Runtime);

pub const LinearFramework = framework.Runtime(LinearRelation.Runtime);

pub const MerklePathFramework = framework.Runtime(merkle_path_relation.Runtime);

pub const FORMAT_VERSION: u16 = 1;

pub const FIRST_ROW: usize = 18;

pub const LAST_ROW: usize = 34;

pub const FIRST_FRI_ROW: usize = 20;

pub const LAST_FRI_INPUT_ROW: usize = 29;

pub const CHILD_COUNT: usize = 2;

pub const LEFT_CHILD: usize = 0;

pub const RIGHT_CHILD: usize = 1;

pub const LEFT_RECURSION_VERIFIER_ID: u32 = 1;

pub const RIGHT_RECURSION_VERIFIER_ID: u32 = 2;

pub const SEGMENT_FRI_CIRCUIT_ID: u32 = 401;

pub const LEFT_FRI_CIRCUIT_ID: u32 = 402;

pub const RIGHT_FRI_CIRCUIT_ID: u32 = 403;

pub const SEGMENT_PCS_CIRCUIT_ID: u32 = 411;

pub const LEFT_PCS_CIRCUIT_ID: u32 = 412;

pub const RIGHT_PCS_CIRCUIT_ID: u32 = 413;

pub const SEGMENT_ARITHMETIC_CAPACITY_CIRCUIT_ID: u32 = 421;

pub const VM_COMPOSITION_CAPACITY_CIRCUIT_ID: u32 = 431;

pub const LEFT_COMPOSITION_STATEMENT_SCOPE: u32 =
    statement_input_air.LEFT_STATEMENT_SCOPE;

pub const RIGHT_COMPOSITION_STATEMENT_SCOPE: u32 =
    statement_input_air.RIGHT_STATEMENT_SCOPE;

pub const UNIVERSAL_CLAIMED_SUM_COUNT: usize = UNIVERSAL_ROSTER_ROW_COUNT;

pub const POSEIDON2_ROSTER_ROW: usize = 34;

pub const POSEIDON2_PARTIAL_COUNT: usize = 2;

pub const COMPOSITION_CLAIMED_SUM_COUNT: usize =
    UNIVERSAL_CLAIMED_SUM_COUNT + POSEIDON2_PARTIAL_COUNT;

pub const POSEIDON2_PARTIAL_CLAIM_START: usize = UNIVERSAL_CLAIMED_SUM_COUNT;

pub const POSEIDON2_INTERACTION_COLUMN_COUNT: usize = 8;

pub const POSEIDON2_PROVIDER_SAMPLE_COUNT: usize =
    2 * POSEIDON2_INTERACTION_COLUMN_COUNT;

pub const NO_POSEIDON2_SAMPLE_LAYOUT: u32 = std.math.maxInt(u32);

pub const ROW_COUNT: usize = LAST_ROW - FIRST_ROW + 1;

pub const TYPED_RELATION_ROW_COUNT: usize = 16;

pub const UNIVERSAL_ROSTER_ROW_COUNT: usize = 36;

pub const COMPOSITION_ROW_COUNT: usize = 2;

pub const ROWS_18_19_WORKSPACE_HEAP_ALLOCATIONS: usize = 1;

pub const ROWS_18_19_REUSED_HOT_HEAP_ALLOCATIONS: usize = 0;

pub const ROWS_20_29_WORKSPACE_HEAP_ALLOCATIONS: usize = 1;

pub const ROWS_20_29_REUSED_HOT_HEAP_ALLOCATIONS: usize = 0;

pub const ROWS_30_32_WORKSPACE_HEAP_ALLOCATIONS: usize = 4;

pub const ROWS_30_32_REUSED_HOT_HEAP_ALLOCATIONS: usize = 0;

pub const ROW_33_WORKSPACE_HEAP_ALLOCATIONS: usize = 5;

pub const ROW_33_REUSED_HOT_HEAP_ALLOCATIONS: usize = 0;

pub const RELATION_ROWS_WORKSPACE_HEAP_ALLOCATIONS: usize = 1;

pub const RELATION_ROWS_REUSED_HOT_HEAP_ALLOCATIONS: usize = 0;

pub const RELATION_INTERACTION_WORKSPACE_HEAP_ALLOCATIONS: usize =
    TYPED_RELATION_ROW_COUNT + 1;

pub const RELATION_INTERACTION_REUSED_HOT_HEAP_ALLOCATIONS: usize = 0;

pub const MERKLE_PATH_MAIN_COLUMN_COUNT: usize = merkle_path_witness.MAIN_COLUMN_COUNT;

pub const COMPOSITION_PREPROCESSED_COLUMN_COUNT: usize =
    composition_input_witness.PREPROCESSED_COLUMN_COUNT +
    composition_control_witness.COLUMN_COUNT;

pub const COMPOSITION_MAIN_COLUMN_COUNT: usize =
    composition_input_witness.MAIN_COLUMN_COUNT;

pub const COMPOSITION_PREPROCESSED_COLUMNS_PER_ROW = [COMPOSITION_ROW_COUNT]usize{
    composition_input_witness.PREPROCESSED_COLUMN_COUNT,
    composition_control_witness.COLUMN_COUNT,
};

pub const COMPOSITION_MAIN_COLUMNS_PER_ROW = [COMPOSITION_ROW_COUNT]usize{
    composition_input_witness.MAIN_COLUMN_COUNT,
    0,
};

pub const FriRow = enum(u8) {
    query_bits = 20,
    query_mapping = 21,
    merkle_root = 22,
    trace_merkle = 23,
    pcs_deep = 24,
    fri_leaf = 25,
    fri_node = 26,
    fri_anchor = 27,
    fri_control = 28,
    fri_input = 29,
};

pub const FRI_ROW_COUNT: usize = 10;

pub const ARITHMETIC_ROW_COUNT: usize = 3;

pub const ARITHMETIC_PREPROCESSED_COLUMN_COUNT: usize =
    multiply_witness.PREPROCESSED_COLUMN_COUNT +
    inverse_witness.PREPROCESSED_COLUMN_COUNT +
    linear_witness.PREPROCESSED_COLUMN_COUNT;

pub const ARITHMETIC_MAIN_COLUMN_COUNT: usize =
    multiply_witness.MAIN_COLUMN_COUNT +
    inverse_witness.MAIN_COLUMN_COUNT +
    linear_witness.MAIN_COLUMN_COUNT;

pub const ARITHMETIC_PREPROCESSED_COLUMNS_PER_ROW = [ARITHMETIC_ROW_COUNT]usize{
    multiply_witness.PREPROCESSED_COLUMN_COUNT,
    inverse_witness.PREPROCESSED_COLUMN_COUNT,
    linear_witness.PREPROCESSED_COLUMN_COUNT,
};

pub const ARITHMETIC_MAIN_COLUMNS_PER_ROW = [ARITHMETIC_ROW_COUNT]usize{
    multiply_witness.MAIN_COLUMN_COUNT,
    inverse_witness.MAIN_COLUMN_COUNT,
    linear_witness.MAIN_COLUMN_COUNT,
};

pub const PREPROCESSED_COLUMN_COUNT: usize =
    query_bits_witness.PREPROCESSED_COLUMN_COUNT +
    query_mapping_witness.PREPROCESSED_COLUMN_COUNT +
    merkle_root_witness.PREPROCESSED_COLUMN_COUNT +
    trace_merkle_witness.PREPROCESSED_COLUMN_COUNT +
    pcs_witness.PREPROCESSED_COLUMN_COUNT +
    fri_leaf_witness.PREPROCESSED_COLUMN_COUNT +
    fri_node_witness.PREPROCESSED_COLUMN_COUNT +
    fri_anchor_witness.PREPROCESSED_COLUMN_COUNT +
    fri_control_witness.PREPROCESSED_COLUMN_COUNT +
    fri_input_witness.PREPROCESSED_COLUMN_COUNT;

pub const MAIN_COLUMN_COUNT: usize =
    query_bits_witness.MAIN_COLUMN_COUNT +
    query_mapping_witness.MAIN_COLUMN_COUNT +
    merkle_root_witness.MAIN_COLUMN_COUNT +
    trace_merkle_witness.MAIN_COLUMN_COUNT +
    pcs_witness.MAIN_COLUMN_COUNT +
    fri_leaf_witness.MAIN_COLUMN_COUNT +
    fri_node_witness.MAIN_COLUMN_COUNT +
    fri_anchor_witness.MAIN_COLUMN_COUNT +
    fri_control_witness.MAIN_COLUMN_COUNT +
    fri_input_witness.MAIN_COLUMN_COUNT;

pub const PREPROCESSED_COLUMNS_PER_ROW = [FRI_ROW_COUNT]usize{
    query_bits_witness.PREPROCESSED_COLUMN_COUNT,
    query_mapping_witness.PREPROCESSED_COLUMN_COUNT,
    merkle_root_witness.PREPROCESSED_COLUMN_COUNT,
    trace_merkle_witness.PREPROCESSED_COLUMN_COUNT,
    pcs_witness.PREPROCESSED_COLUMN_COUNT,
    fri_leaf_witness.PREPROCESSED_COLUMN_COUNT,
    fri_node_witness.PREPROCESSED_COLUMN_COUNT,
    fri_anchor_witness.PREPROCESSED_COLUMN_COUNT,
    fri_control_witness.PREPROCESSED_COLUMN_COUNT,
    fri_input_witness.PREPROCESSED_COLUMN_COUNT,
};

pub const MAIN_COLUMNS_PER_ROW = [FRI_ROW_COUNT]usize{
    query_bits_witness.MAIN_COLUMN_COUNT,
    query_mapping_witness.MAIN_COLUMN_COUNT,
    merkle_root_witness.MAIN_COLUMN_COUNT,
    trace_merkle_witness.MAIN_COLUMN_COUNT,
    pcs_witness.MAIN_COLUMN_COUNT,
    fri_leaf_witness.MAIN_COLUMN_COUNT,
    fri_node_witness.MAIN_COLUMN_COUNT,
    fri_anchor_witness.MAIN_COLUMN_COUNT,
    fri_control_witness.MAIN_COLUMN_COUNT,
    fri_input_witness.MAIN_COLUMN_COUNT,
};

pub const TYPED_INTERACTION_COLUMNS_PER_ROW = [TYPED_RELATION_ROW_COUNT]usize{
    composition_input_air.INTERACTION_COLUMN_COUNT,
    composition_control_air.INTERACTION_COLUMN_COUNT,
    query_bits_air.INTERACTION_COLUMN_COUNT,
    query_mapping_air.INTERACTION_COLUMN_COUNT,
    merkle_root_air.INTERACTION_COLUMN_COUNT,
    trace_merkle_air.INTERACTION_COLUMN_COUNT,
    pcs_air.INTERACTION_COLUMN_COUNT,
    fri_leaf_air.INTERACTION_COLUMN_COUNT,
    fri_node_air.INTERACTION_COLUMN_COUNT,
    fri_anchor_air.INTERACTION_COLUMN_COUNT,
    fri_control_air.INTERACTION_COLUMN_COUNT,
    fri_input_air.INTERACTION_COLUMN_COUNT,
    multiply_air.INTERACTION_COLUMN_COUNT,
    inverse_air.INTERACTION_COLUMN_COUNT,
    linear_air.INTERACTION_COLUMN_COUNT,
    merkle_path_air.INTERACTION_COLUMN_COUNT,
};

pub const TYPED_INTERACTION_COLUMN_COUNT: usize = blk: {
    var total: usize = 0;
    for (TYPED_INTERACTION_COLUMNS_PER_ROW) |count| total += count;
    break :blk total;
};

/// Rows 18--33 each have one typed framework claim.  Row 34 intentionally
/// exposes the native provider's two recurrence claims separately: consumers
/// may use their sum for the roster vector, but verifier replay must retain
/// both coordinates.
pub const Claims = struct {
    typed_rows: [TYPED_RELATION_ROW_COUNT]QM31,
    poseidon2_partials: [2]QM31,

    pub fn typedClaim(self: Claims, roster_row: usize) !QM31 {
        if (roster_row < FIRST_ROW or roster_row >= LAST_ROW)
            return error.DestinationShapeMismatch;
        return self.typed_rows[roster_row - FIRST_ROW];
    }

    pub fn poseidon2Total(self: Claims) QM31 {
        return self.poseidon2_partials[0].add(self.poseidon2_partials[1]);
    }

    pub fn asRows18Through34(self: Claims) [ROW_COUNT]QM31 {
        return self.typed_rows ++ .{self.poseidon2Total()};
    }

    pub fn bindIntoRoster(
        self: Claims,
        destination: *[UNIVERSAL_ROSTER_ROW_COUNT]QM31,
    ) void {
        const values = self.asRows18Through34();
        inline for (values, FIRST_ROW..) |value, row| destination[row] = value;
    }
};

pub const Poseidon2DomainAudit = struct {
    poseidon2: QM31,
    poseidon2_io: QM31,
    total: QM31,

    pub fn validate(self: Poseidon2DomainAudit, claims: Claims) !void {
        if (!self.poseidon2.eql(claims.poseidon2_partials[0]) or
            !self.poseidon2_io.eql(claims.poseidon2_partials[1]) or
            !self.total.eql(self.poseidon2.add(self.poseidon2_io)) or
            !self.total.eql(claims.poseidon2Total()))
        {
            return error.SourceAuthorityMismatch;
        }
    }
};

pub const DomainAudits = struct {
    typed_rows: [TYPED_RELATION_ROW_COUNT]relation_interaction.DomainAudit,
    poseidon2: Poseidon2DomainAudit,
};

pub const ColumnOffset = struct {
    pub const query_bits_pp: usize = 0;
    pub const query_mapping_pp: usize = query_bits_pp + query_bits_witness.PREPROCESSED_COLUMN_COUNT;
    pub const merkle_root_pp: usize = query_mapping_pp + query_mapping_witness.PREPROCESSED_COLUMN_COUNT;
    pub const trace_merkle_pp: usize = merkle_root_pp + merkle_root_witness.PREPROCESSED_COLUMN_COUNT;
    pub const pcs_deep_pp: usize = trace_merkle_pp + trace_merkle_witness.PREPROCESSED_COLUMN_COUNT;
    pub const fri_leaf_pp: usize = pcs_deep_pp + pcs_witness.PREPROCESSED_COLUMN_COUNT;
    pub const fri_node_pp: usize = fri_leaf_pp + fri_leaf_witness.PREPROCESSED_COLUMN_COUNT;
    pub const fri_anchor_pp: usize = fri_node_pp + fri_node_witness.PREPROCESSED_COLUMN_COUNT;
    pub const fri_control_pp: usize = fri_anchor_pp + fri_anchor_witness.PREPROCESSED_COLUMN_COUNT;
    pub const fri_input_pp: usize = fri_control_pp + fri_control_witness.PREPROCESSED_COLUMN_COUNT;

    pub const query_bits_main: usize = 0;
    pub const query_mapping_main: usize = query_bits_main + query_bits_witness.MAIN_COLUMN_COUNT;
    pub const merkle_root_main: usize = query_mapping_main + query_mapping_witness.MAIN_COLUMN_COUNT;
    pub const trace_merkle_main: usize = merkle_root_main + merkle_root_witness.MAIN_COLUMN_COUNT;
    pub const pcs_deep_main: usize = trace_merkle_main + trace_merkle_witness.MAIN_COLUMN_COUNT;
    pub const fri_leaf_main: usize = pcs_deep_main + pcs_witness.MAIN_COLUMN_COUNT;
    pub const fri_node_main: usize = fri_leaf_main + fri_leaf_witness.MAIN_COLUMN_COUNT;
    pub const fri_anchor_main: usize = fri_node_main + fri_node_witness.MAIN_COLUMN_COUNT;
    pub const fri_control_main: usize = fri_anchor_main + fri_anchor_witness.MAIN_COLUMN_COUNT;
    pub const fri_input_main: usize = fri_control_main + fri_control_witness.MAIN_COLUMN_COUNT;
};

pub const ArithmeticColumnOffset = struct {
    pub const multiply_pp: usize = 0;
    pub const inverse_pp: usize = multiply_pp + multiply_witness.PREPROCESSED_COLUMN_COUNT;
    pub const linear_pp: usize = inverse_pp + inverse_witness.PREPROCESSED_COLUMN_COUNT;

    pub const multiply_main: usize = 0;
    pub const inverse_main: usize = multiply_main + multiply_witness.MAIN_COLUMN_COUNT;
    pub const linear_main: usize = inverse_main + inverse_witness.MAIN_COLUMN_COUNT;
};

comptime {
    if (ColumnOffset.fri_input_pp + fri_input_witness.PREPROCESSED_COLUMN_COUNT !=
        PREPROCESSED_COLUMN_COUNT or
        ColumnOffset.fri_input_main + fri_input_witness.MAIN_COLUMN_COUNT !=
            MAIN_COLUMN_COUNT)
    {
        @compileError("binary FRI column offsets do not close");
    }
    if (ArithmeticColumnOffset.linear_pp + linear_witness.PREPROCESSED_COLUMN_COUNT !=
        ARITHMETIC_PREPROCESSED_COLUMN_COUNT or
        ArithmeticColumnOffset.linear_main + linear_witness.MAIN_COLUMN_COUNT !=
            ARITHMETIC_MAIN_COLUMN_COUNT)
    {
        @compileError("binary FRI arithmetic column offsets do not close");
    }
}

pub const COMPOSITION_PROFILE_FORMAT_VERSION: u16 = 1;

pub const COMPOSITION_PROFILE_DOMAIN =
    "stwo-zig/typed-air/binary-fri-composition-profile/v1\x00";

pub const COMPOSITION_AUTHORITY_FORMAT_VERSION: u16 = 1;

pub const COMPOSITION_AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/binary-fri-composition-authority/v1\x00";

pub const SOURCE_AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/binary-fri-source-authority/v1\x00";

/// V2 removes the process-local source address that V1 accidentally included
/// in a proof-visible identity. Address equality remains an operational
/// capability check in `PreparedAuthority.validateFor`; the canonical digest
/// is now a pure function of the transitive semantic authority below.
pub const PREPARED_AUTHORITY_FORMAT_VERSION: u16 = 2;

pub const PREPARED_AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/binary-fri-prepared-authority/v2\x00";

pub const Error = error{
    ArithmeticOverflow,
    CaptureCircuitMismatch,
    CaptureTranscriptMismatch,
    CaptureWireMismatch,
    ChildOrderMismatch,
    CompositionAuthorityMismatch,
    CompositionProfileMismatch,
    DuplicateChildProof,
    InvalidCompositionProfile,
    InvalidQuerySchedule,
    MissingCompositionAuthority,
    PairAuthorityMismatch,
    PlanMismatch,
    ProfileMismatch,
    SourceAuthorityMismatch,
    WorkspaceAuthorityMismatch,
    DestinationShapeMismatch,
    DestinationAlias,
};
