//! Internal segment statement outer source authority shard; use segment_statement_outer_source.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");

pub const fields = stwo_core.fields;
pub const M31 = fields.m31.M31;
pub const QM31 = fields.qm31.QM31;
pub const core_utils = stwo_core.utils;

pub const public_data_mod = @import("../air/public_data.zig");
pub const lookup_schema = @import("../air/lookups/tables/schema.zig");
pub const relation = @import("../air/lang/relation.zig");
pub const leaf_owner = @import("segment_leaf_authority.zig");
pub const statement_circuit = @import("statement_semantics_circuit.zig");
pub const range_owner = @import("segment_range_authority.zig");

pub const row10_air = @import("air/statement_input.zig");
pub const row10_relation = @import("air/statement_input_relation.zig");
pub const row10_witness = @import("air/statement_input_witness.zig");
pub const row11_air = @import("air/statement_semantics_input.zig");
pub const row11_relation = @import("air/statement_semantics_input_relation.zig");
pub const row11_witness = @import("air/statement_semantics_input_witness.zig");
pub const range_bridge = @import("air/range_check_8_8_bridge.zig");
pub const graph_mod = @import("air/composition_circuit.zig");
pub const relation_interaction = @import("air/relation_interaction.zig");
pub const lowering = @import("air/verifier_arithmetic_lowering.zig");
pub const manifest_mod = @import("air/universal_adapter_manifest.zig");
pub const roster = @import("air/universal_roster.zig");
pub const shared_provider = @import("air/universal_shared_provider.zig");
pub const typed_component = @import("air/universal_typed_component.zig");
pub const universal = @import("air/universal_challenges.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const STATEMENT_CIRCUIT_ID: u32 = 11;
pub const ROSTER_ROWS = [_]roster.Component{
    .statement_input,
    .statement_semantics_input,
    .range_check_8_8,
};

/// Machine-readable global closure ownership for every relation surface
/// touched by rows 10 and 11. `positive` denotes the emit/provider side of the
/// LogUp scalar and `negative` its consume/request side. A row claim aggregates
/// several such domains, so whole-row claims must never be compared edge by
/// edge; the all-36 driver closes the union of these edges.
pub const ClosureEdge = struct {
    domain: relation.Domain,
    positive: roster.Component,
    negative: roster.Component,
};

pub const GLOBAL_CLOSURE_EDGES = [_]ClosureEdge{
    // Transcript payload is the single source of row 10's verifier input.
    .{ .domain = .recursion_verifier_input_word, .positive = .transcript_payload, .negative = .statement_input },
    // Both active segment and parent scopes are emitted by row 10 and consumed
    // by the exact row-11 circuit input schedule.
    .{ .domain = .recursion_statement_word, .positive = .statement_input, .negative = .statement_semantics_input },
    // Each row-11 graph wire is consumed by exactly one lowering family.
    .{ .domain = .recursion_wire, .positive = .statement_semantics_input, .negative = .qm31_mul },
    .{ .domain = .recursion_wire, .positive = .statement_semantics_input, .negative = .qm31_inv },
    .{ .domain = .recursion_wire, .positive = .statement_semantics_input, .negative = .linear_ops },
    // Row 35 is one complete provider for both segment range-request owners.
    .{ .domain = .range_check_8_8, .positive = .range_check_8_8, .negative = .statement_semantics_input },
    .{ .domain = .range_check_8_8, .positive = .range_check_8_8, .negative = .vm_public_claim_input },
};

pub const StatementInputAdapter = typed_component.Component(
    row10_air,
    row10_relation,
);
pub const StatementSemanticsAdapter = typed_component.Component(
    row11_air,
    row11_relation,
);
pub const RangeCheckAdapter = shared_provider.RangeCheck8x8Adapter;

pub const STATEMENT_INPUT_LOG_SIZE: u32 = 11;
pub const STATEMENT_SEMANTICS_LOG_SIZE: u32 = 11;
pub const RANGE_CHECK_LOG_SIZE: u32 = range_bridge.LOG_SIZE;
pub const STATEMENT_INPUT_TRACE_SIZE: usize = 1 << STATEMENT_INPUT_LOG_SIZE;
pub const STATEMENT_SEMANTICS_TRACE_SIZE: usize =
    1 << STATEMENT_SEMANTICS_LOG_SIZE;
pub const RANGE_CHECK_TRACE_SIZE: usize = range_bridge.TABLE_SIZE;

pub const STATEMENT_INPUT_PARAMETERS = [row10_air.PARAMETER_COUNT]M31{
    M31.one(),
    M31.zero(),
    M31.fromCanonical(row10_air.STATEMENT_INPUT_KIND),
    M31.fromCanonical(row10_air.STATEMENT_INPUT_ITEM),
    M31.fromCanonical(row10_air.VM_CLAIM_STATEMENT_SCOPE),
};
pub const STATEMENT_SEMANTICS_PARAMETERS = [row11_air.PARAMETER_COUNT]M31{
    M31.one(),
    M31.zero(),
    M31.zero(),
    M31.zero(),
};

pub const LogSizes = struct {
    statement_input: u32 = STATEMENT_INPUT_LOG_SIZE,
    statement_semantics: u32 = STATEMENT_SEMANTICS_LOG_SIZE,
    range_check: u32 = RANGE_CHECK_LOG_SIZE,
};

/// The graph-only seal is distinct from the full row-11 circuit identity.
/// It pins the exact wire vocabulary consumed by rows 30--32 after the
/// allocation-free typed conversion performed below.
pub const LOWERING_GRAPH_DIGEST_HEX =
    "7fd141d96e9a49111a465794946387741f0ca7a23a1b7d8b5ab7915d8f94766f";
pub const LOWERING_GRAPH_DIGEST = hexDigest(
    LOWERING_GRAPH_DIGEST_HEX,
    "invalid row-11 lowering graph digest",
);

pub const Error = error{
    AliasedDestination,
    AliasedInput,
    ArithmeticOverflow,
    AuthorityMismatch,
    GraphDigestMismatch,
    InvalidTraceShape,
    NonBaseCircuitInput,
    PrefixClosureMismatch,
    ZeroDenominator,
};

/// Independent audit helper for regenerating the pinned graph-only receipt.
/// Production admission compares the same digest without retaining a second
/// circuit instance.
pub fn computeLoweringGraphDigest(allocator: std.mem.Allocator) ![32]u8 {
    var circuit = try statement_circuit.build(allocator);
    defer circuit.deinit();
    const nodes = try allocator.alloc(graph_mod.Node, circuit.graph().nodes().len);
    defer allocator.free(nodes);
    convertGraphNodes(circuit.graph().nodes(), nodes);
    return graph_mod.computeGraphDigest(nodes, circuit.graph().outputs());
}

/// Final, committed-order Tree-0 destinations. Row 35 includes the native
/// table framework's leading `is_first` column before its two tuple columns.
pub const PreprocessedColumns = struct {
    statement_input: [row10_witness.PREPROCESSED_COLUMN_COUNT][]M31,
    statement_semantics: [row11_witness.PREPROCESSED_COLUMN_COUNT][]M31,
    range_check: [range_bridge.FRAMEWORK_PREPROCESSED_COLUMN_COUNT][]M31,
};

/// Final, committed-order Tree-1 destinations.
pub const MainColumns = struct {
    statement_input: [row10_witness.MAIN_COLUMN_COUNT][]M31,
    statement_semantics: [row11_witness.MAIN_COLUMN_COUNT][]M31,
    range_check: [range_bridge.PHYSICAL_MAIN_COLUMN_COUNT][]M31,
};

/// Final, committed-order Tree-2 destinations.
pub const InteractionColumns = struct {
    statement_input: [row10_air.INTERACTION_COLUMN_COUNT][]M31,
    statement_semantics: [row11_air.INTERACTION_COLUMN_COUNT][]M31,
    range_check: [range_bridge.INTERACTION_COLUMN_COUNT][]M31,
};

/// Proof-visible claimed sums in exact roster order. This is the verifier-side
/// adapter input; it deliberately contains no prover-only ledger diagnostic.
pub const RosterClaims = struct {
    statement_input: QM31,
    statement_semantics: QM31,
    range_check: QM31,

    pub fn rosterValues(self: RosterClaims) [ROSTER_ROWS.len]QM31 {
        return .{
            self.statement_input,
            self.statement_semantics,
            self.range_check,
        };
    }

    pub fn bindInto(
        self: RosterClaims,
        vector: *manifest_mod.ClaimVector,
    ) !void {
        try vector.bind(.statement_input, self.statement_input);
        try vector.bind(.statement_semantics_input, self.statement_semantics);
        try vector.bind(.range_check_8_8, self.range_check);
    }

    /// Independent-verifier reconstruction from the already authenticated
    /// all-36 claim vector.
    pub fn fromVector(
        vector: *const manifest_mod.ClaimVector,
        manifest: *const manifest_mod.Manifest,
    ) !RosterClaims {
        try vector.validate(manifest);
        return .{
            .statement_input = vector.values[
                @intFromEnum(
                    roster.Component.statement_input,
                )
            ],
            .statement_semantics = vector.values[
                @intFromEnum(
                    roster.Component.statement_semantics_input,
                )
            ],
            .range_check = vector.values[
                @intFromEnum(
                    roster.Component.range_check_8_8,
                )
            ],
        };
    }
};

/// The proof-visible roster claims plus the independently signed request side
/// of the complete row-35 ledger. Only `verifyRangeClosure` is local: row 10's
/// verifier-input consume closes against row 5; its two statement-scope emits
/// close against row 11; row 11's wire emits close against rows 30--32; and row
/// 35 closes the combined range requests of rows 11 and 12. Consequently the
/// scalar sum of rows 10, 11, and 35 is intentionally not required to vanish.
pub const Claims = struct {
    statement_input: QM31,
    statement_semantics: QM31,
    range_check: QM31,
    range_requests: QM31,

    pub fn verifyRangeClosure(self: Claims) Error!void {
        if (!self.range_check.add(self.range_requests).isZero())
            return error.PrefixClosureMismatch;
    }

    pub fn rosterClaims(self: Claims) RosterClaims {
        return .{
            .statement_input = self.statement_input,
            .statement_semantics = self.statement_semantics,
            .range_check = self.range_check,
        };
    }

    pub fn rosterValues(self: Claims) [ROSTER_ROWS.len]QM31 {
        return self.rosterClaims().rosterValues();
    }

    /// The request audit is not a fourth component and never enters the proof
    /// claim vector.
    pub fn bindInto(
        self: Claims,
        vector: *manifest_mod.ClaimVector,
    ) !void {
        try self.rosterClaims().bindInto(vector);
    }
};

pub const DomainAudits = struct {
    statement_input: relation_interaction.DomainAudit,
    statement_semantics: relation_interaction.DomainAudit,
    range_check: relation_interaction.DomainAudit,
};

/// Type-stable roster-order component bundle for the all-36 driver.
pub const Components = struct {
    statement_input: StatementInputAdapter,
    statement_semantics: StatementSemanticsAdapter,
    range_check: RangeCheckAdapter,
};

pub fn row10RowsEql(
    lhs: []const row10_witness.Row,
    rhs: []const row10_witness.Row,
) bool {
    if (lhs.len != rhs.len) return false;
    for (lhs, rhs) |a, b| if (!std.meta.eql(a, b)) return false;
    return true;
}

pub fn convertGraphNodes(
    source: []const @import("arithmetic_circuit.zig").Node,
    destination: []graph_mod.Node,
) void {
    std.debug.assert(source.len == destination.len);
    for (source, destination) |node, *target| target.* = .{ .op = switch (node.op) {
        .input => .input,
        .constant => |words| .{ .constant = words },
        .add => |operands| .{ .add = .{ .lhs = operands.lhs, .rhs = operands.rhs } },
        .sub => |operands| .{ .sub = .{ .lhs = operands.lhs, .rhs = operands.rhs } },
        .mul => |operands| .{ .mul = .{ .lhs = operands.lhs, .rhs = operands.rhs } },
        .neg => |operand| .{ .neg = operand },
        .inverse => |operand| .{ .inverse = operand },
    } };
}

pub fn hexDigest(comptime value: []const u8, comptime message: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
