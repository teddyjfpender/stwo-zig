//! Cold-compiled hot evaluator for the degree-five direct polynomial program.
//!
//! The canonical candidate program remains the authority. Preparation first
//! authenticates that candidate, then resolves semantic committed-value IDs to
//! physical columns and narrows already-validated operands once. The quotient
//! row loop consumes only this immutable derived plan; verifier/OODS evaluation
//! continues to replay the canonical checked program.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const candidate_mod = @import("typed_poseidon2_degree_bounded_candidate.zig");
const direct = @import("materialization_cost_direct.zig");
const direct_program = @import("materialization_direct_program.zig");
const poseidon = @import("typed_poseidon2.zig");

pub const node_count: usize = 2_842;
pub const root_count: usize = 224;
pub const main_column_count: usize = 239;

pub const Error = std.mem.Allocator.Error || error{
    InvalidCandidateColumn,
    InvalidDirectNode,
    InvalidProgramShape,
    UnsupportedDirectNode,
};

const PreparedOp = enum(u8) {
    constant,
    column,
    add,
    sub,
    neg,
    mul,
};

const PreparedNode = struct {
    op: PreparedOp,
    lhs: u16 = 0,
    rhs: u16 = 0,
    value: u32 = 0,
};

pub const Program = struct {
    allocator: std.mem.Allocator,
    nodes: []PreparedNode,
    roots: [root_count]u16,
    output_columns: [candidate_mod.WIDTH]u16,
    canonical_program_digest: [32]u8,

    pub fn initValidated(
        allocator: std.mem.Allocator,
        candidate: *const candidate_mod.Candidate,
    ) Error!Program {
        const canonical_nodes = candidate.direct_program.nodes();
        const canonical_roots = candidate.direct_program.roots();
        if (canonical_nodes.len != node_count or canonical_roots.len != root_count or
            candidate.mainColumnCount() != main_column_count)
        {
            return error.InvalidProgramShape;
        }
        const nodes = try allocator.alloc(PreparedNode, canonical_nodes.len);
        errdefer allocator.free(nodes);
        for (canonical_nodes, nodes, 0..) |source, *destination, index| {
            destination.* = switch (source.op) {
                .constant => .{
                    .op = .constant,
                    .value = std.math.cast(u32, source.value) orelse
                        return error.InvalidDirectNode,
                },
                .committed => .{
                    .op = .column,
                    .value = try resolveCommittedColumn(candidate, source.value),
                },
                .fixed_committed => blk: {
                    if (source.lhs != @intFromEnum(direct_program.CommitmentTree.main) or
                        source.value >= main_column_count)
                    {
                        return error.InvalidCandidateColumn;
                    }
                    break :blk .{
                        .op = .column,
                        .value = @intCast(source.value),
                    };
                },
                .row_mask => return error.UnsupportedDirectNode,
                .add => try binaryNode(source, index, .add),
                .sub => try binaryNode(source, index, .sub),
                .neg => blk: {
                    if (source.lhs >= index) return error.InvalidDirectNode;
                    break :blk .{
                        .op = .neg,
                        .lhs = std.math.cast(u16, source.lhs) orelse
                            return error.InvalidDirectNode,
                    };
                },
                .mul => try binaryNode(source, index, .mul),
            };
        }
        var roots: [root_count]u16 = undefined;
        for (canonical_roots, &roots) |source, *destination| {
            if (source.node >= nodes.len) return error.InvalidDirectNode;
            destination.* = std.math.cast(u16, source.node) orelse
                return error.InvalidDirectNode;
        }
        var output_columns: [candidate_mod.WIDTH]u16 = undefined;
        for (poseidon.values(candidate.definition.outputs), &output_columns) |
            output,
            *column,
        | {
            column.* = std.math.cast(
                u16,
                try resolveSemanticColumn(candidate, @intFromEnum(output)),
            ) orelse return error.InvalidCandidateColumn;
        }
        return .{
            .allocator = allocator,
            .nodes = nodes,
            .roots = roots,
            .output_columns = output_columns,
            .canonical_program_digest = candidate.direct_program_digest,
        };
    }

    pub fn deinit(self: *Program) void {
        self.allocator.free(self.nodes);
        self.* = undefined;
    }

    pub fn allocatedBytes(self: *const Program) usize {
        return self.nodes.len * @sizeOf(PreparedNode);
    }

    pub fn evaluate(
        self: *const Program,
        main: *const [main_column_count]QM31,
        scratch: *[node_count]QM31,
    ) [root_count]QM31 {
        for (self.nodes, 0..) |node, index| {
            scratch[index] = switch (node.op) {
                .constant => QM31.fromBase(M31.fromU64(node.value)),
                .column => main[@intCast(node.value)],
                .add => scratch[@intCast(node.lhs)].add(
                    scratch[@intCast(node.rhs)],
                ),
                .sub => scratch[@intCast(node.lhs)].sub(
                    scratch[@intCast(node.rhs)],
                ),
                .neg => scratch[@intCast(node.lhs)].neg(),
                .mul => scratch[@intCast(node.lhs)].mul(
                    scratch[@intCast(node.rhs)],
                ),
            };
        }
        var result: [root_count]QM31 = undefined;
        for (self.roots, &result) |root, *value| {
            value.* = scratch[@intCast(root)];
        }
        return result;
    }

    /// The quotient domain is an M31 circle domain, so the direct polynomial
    /// DAG remains base-field valued until its roots enter the secure random
    /// linear combination. LogUp stays on the separate QM31 path owned by the
    /// component.
    pub fn evaluateBase(
        self: *const Program,
        main: *const [main_column_count]M31,
        scratch: *[node_count]M31,
    ) [root_count]M31 {
        for (self.nodes, 0..) |node, index| {
            scratch[index] = switch (node.op) {
                .constant => M31.fromU64(node.value),
                .column => main[@intCast(node.value)],
                .add => scratch[@intCast(node.lhs)].add(
                    scratch[@intCast(node.rhs)],
                ),
                .sub => scratch[@intCast(node.lhs)].sub(
                    scratch[@intCast(node.rhs)],
                ),
                .neg => scratch[@intCast(node.lhs)].neg(),
                .mul => scratch[@intCast(node.lhs)].mul(
                    scratch[@intCast(node.rhs)],
                ),
            };
        }
        var result: [root_count]M31 = undefined;
        for (self.roots, &result) |root, *value| {
            value.* = scratch[@intCast(root)];
        }
        return result;
    }
};

fn binaryNode(
    source: direct.Node,
    index: usize,
    operation: PreparedOp,
) Error!PreparedNode {
    if (source.lhs >= index or source.rhs >= index)
        return error.InvalidDirectNode;
    return .{
        .op = operation,
        .lhs = std.math.cast(u16, source.lhs) orelse
            return error.InvalidDirectNode,
        .rhs = std.math.cast(u16, source.rhs) orelse
            return error.InvalidDirectNode,
    };
}

fn resolveCommittedColumn(
    candidate: *const candidate_mod.Candidate,
    encoded: u64,
) Error!u32 {
    const materialized_namespace = @as(u64, 1) << 63;
    const value_mask = std.math.maxInt(u32);
    if (encoded & ~(materialized_namespace | value_mask) != 0)
        return error.InvalidCandidateColumn;
    const column = try resolveSemanticColumn(candidate, encoded & value_mask);
    const materialized = encoded & materialized_namespace != 0;
    if (materialized != (column >= candidate_mod.MATERIALIZATION_COLUMN_START and
        column < main_column_count - 2))
    {
        return error.InvalidCandidateColumn;
    }
    return column;
}

fn resolveSemanticColumn(
    candidate: *const candidate_mod.Candidate,
    value: u64,
) Error!u32 {
    const value_index = std.math.cast(usize, value) orelse
        return error.InvalidCandidateColumn;
    if (value_index >= candidate.semantic_columns.len)
        return error.InvalidCandidateColumn;
    const column = candidate.semantic_columns[value_index];
    if (column == std.math.maxInt(u32) or column >= main_column_count)
        return error.InvalidCandidateColumn;
    return column;
}

comptime {
    if (node_count != candidate_mod.Profile.degree5.expected().direct_nodes or
        root_count != candidate_mod.Profile.degree5.expected().direct_constraints or
        main_column_count != candidate_mod.Profile.degree5.expected().main_columns)
    {
        @compileError("degree-five prepared program geometry drifted");
    }
}
