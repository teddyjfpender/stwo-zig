//! Owned canonical direct-polynomial program for one materialization cut.
//!
//! The program is the single lowering authority for the globally hash-consed
//! fixed-prefix, candidate-equality, fixed-suffix DAG measured by the H-009
//! cost model. Node order is first-intern order. Root uses retain their exact
//! fold events, including repeated or late uses of an already-interned node.
//! Candidate mappings make the semantic-value to physical-column boundary
//! explicit without changing the direct-node identity used by H-009.

const std = @import("std");
const direct = @import("materialization_cost_direct.zig");
const expr = @import("expr.zig");
const fixed = @import("materialization_fixed_direct.zig");
const identity = @import("degree3_materializer_identity.zig");
const ir = @import("ir.zig");
const types = @import("types.zig");
const validator = @import("validate.zig");

pub const Digest = [32]u8;
pub const Policy = identity.Policy;
pub const Op = direct.Op;
pub const Node = direct.Node;
pub const RootUse = direct.RootUse;
pub const CommitmentTree = fixed.CommitmentTree;
pub const format_version: u16 = 1;
pub const digest_domain =
    "stwo-zig/typed-air/materialization-direct-program-v1";

pub const Request = struct {
    gate: ?types.ValueId,
    policy: Policy = .{},
    /// Strictly increasing semantic values, in equality evaluation order.
    selected: []const types.ValueId,
    /// Physical start of the contiguous candidate materialization block.
    materialization_column_start: u64,
    fixed_direct_program: ?fixed.Program = null,
};

pub const MaterializedColumn = struct {
    source_value: types.ValueId,
    tree: fixed.CommitmentTree,
    physical_column: u64,
    direct_node: u32,
};

pub const StructuralCounts = struct {
    nodes: u64,
    root_uses: u64,
    additions: u64,
    subtractions: u64,
    negations: u64,
    multiplications: u64,
    unique_committed_column_reads: u64,
    streaming_peak_live_nodes: u64,
};

pub const ValidationError = error{
    CountOverflow,
    FixedColumnAliasesMaterialization,
    InvalidGate,
    InvalidGateType,
    InvalidSelectedValue,
    InvalidSelectedValueType,
    MaterializationColumnStartMismatch,
    MissingDirectOperand,
    MissingFixedGate,
    NonCanonicalSelection,
    ProgramDigestMismatch,
    UnsupportedGateExpression,
};

pub const Error = std.mem.Allocator.Error ||
    validator.Error ||
    direct.Error ||
    fixed.Error ||
    ValidationError;

/// An owned, immutable-after-construction lowering result. The hash-consing
/// table remains owned so `deinit` has one unambiguous allocation owner; only
/// the ordered node view is exposed to evaluators.
pub const Program = struct {
    allocator: std.mem.Allocator,
    direct_arena: direct.Arena,
    root_uses: []direct.RootUse,
    materialized_columns: []MaterializedColumn,
    counts: StructuralCounts,
    digest: Digest,

    pub fn deinit(self: *Program) void {
        self.allocator.free(self.materialized_columns);
        self.allocator.free(self.root_uses);
        self.direct_arena.deinit();
        self.* = undefined;
    }

    /// Canonical first-intern node order. Operand IDs index this slice.
    pub fn nodes(self: *const Program) []const Node {
        return self.direct_arena.nodes.items;
    }

    /// Canonical node birth events. Entries correspond one-for-one to
    /// `nodes()` and include interleaved root folds in their event numbers.
    pub fn creationEvents(self: *const Program) []const usize {
        return self.direct_arena.creation_events.items;
    }

    /// Ordered accumulator-fold events, including duplicate node uses.
    pub fn roots(self: *const Program) []const RootUse {
        return self.root_uses;
    }

    /// Ordered semantic-value to physical-column bindings for candidate
    /// materializations. The direct node is the committed leaf in `nodes()`.
    pub fn selectedColumns(self: *const Program) []const MaterializedColumn {
        return self.materialized_columns;
    }

    pub fn programDigest(self: *const Program) Digest {
        return self.digest;
    }

    /// Recomputes the canonical preimage from the exposed program payload and
    /// compares both it and the construction-time digest to trusted identity.
    pub fn authenticate(
        self: *const Program,
        expected: Digest,
    ) ValidationError!void {
        const recomputed = try computeDigest(
            &self.direct_arena,
            self.root_uses,
            self.materialized_columns,
        );
        if (!std.mem.eql(u8, &recomputed, &self.digest) or
            !std.mem.eql(u8, &recomputed, &expected))
        {
            return error.ProgramDigestMismatch;
        }
    }

    /// Payload bytes required by a retained-node interpreter whose scratch
    /// slot is exactly `EvaluationValue`. This deliberately excludes allocator
    /// metadata and alignment padding outside the contiguous value slice.
    pub fn retainedScratchBytes(
        self: *const Program,
        comptime EvaluationValue: type,
    ) error{CountOverflow}!u64 {
        if (@sizeOf(EvaluationValue) == 0)
            @compileError("direct-program scratch values must have non-zero size");
        return std.math.mul(
            u64,
            self.counts.nodes,
            @as(u64, @sizeOf(EvaluationValue)),
        ) catch error.CountOverflow;
    }
};

/// Validates the semantic arena, then extracts its canonical direct program.
pub fn extract(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    request: Request,
) Error!Program {
    try validator.validate(arena);
    return extractValidated(allocator, arena, request);
}

/// Extraction for callers which have already run the canonical IR validator.
/// This exists so a cost search does not validate the same arena twice per
/// candidate; all lowering and direct-program accounting still live here.
pub fn extractValidated(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    request: Request,
) Error!Program {
    try validateRequest(arena, request);

    var direct_arena = direct.Arena.init(allocator);
    errdefer direct_arena.deinit();

    const mapped = try allocator.alloc(u32, arena.nodeCount());
    defer allocator.free(mapped);
    @memset(mapped, no_direct_node);
    const needed = try allocator.alloc(bool, arena.nodeCount());
    defer allocator.free(needed);

    const fixed_root_count: usize = if (request.fixed_direct_program) |program|
        std.math.cast(usize, try program.fixedRootCount()) orelse
            return error.CountOverflow
    else
        0;
    const total_roots = std.math.add(
        usize,
        request.selected.len,
        fixed_root_count,
    ) catch return error.CountOverflow;
    var roots: std.ArrayList(direct.RootUse) = .empty;
    defer roots.deinit(allocator);
    try roots.ensureTotalCapacity(allocator, total_roots);

    const materialized_columns = try allocator.alloc(
        MaterializedColumn,
        request.selected.len,
    );
    errdefer allocator.free(materialized_columns);
    const materialization_tree: fixed.CommitmentTree = if (request.fixed_direct_program) |program|
        program.materialization_tree
    else
        .main;

    const context = try lowerContext(
        &direct_arena,
        arena,
        request.gate,
        request.policy,
        mapped,
    );
    var fixed_lowering: ?fixed.Lowering = if (request.fixed_direct_program) |program|
        try fixed.Lowering.init(allocator, program, request.selected.len)
    else
        null;
    defer if (fixed_lowering) |*lowering| lowering.deinit();
    var fixed_emitter = FixedEmitter{
        .direct_arena = &direct_arena,
        .gate = if (request.gate) |gate| mapped[types.idIndex(gate)] else null,
    };

    if (fixed_lowering) |*lowering| {
        const lowered_roots = try allocator.alloc(u32, lowering.program.prefix_roots.len);
        defer allocator.free(lowered_roots);
        try lowering.lowerPrefix(&fixed_emitter, lowered_roots);
        for (lowered_roots) |root|
            roots.appendAssumeCapacity(try direct_arena.recordRoot(root));
    }

    for (request.selected, 0..) |value, ordinal| {
        const body = try lowerValue(&direct_arena, arena, value, mapped, needed);
        const column = try direct_arena.committed(value, true);
        const equality = try direct_arena.binary(.sub, column, body);
        const root = if (context) |context_node|
            try direct_arena.binary(.mul, equality, context_node)
        else
            equality;
        roots.appendAssumeCapacity(try direct_arena.recordRoot(root));
        mapped[types.idIndex(value)] = column;

        const physical_column = std.math.add(
            u64,
            request.materialization_column_start,
            std.math.cast(u64, ordinal) orelse return error.CountOverflow,
        ) catch return error.CountOverflow;
        materialized_columns[ordinal] = .{
            .source_value = value,
            .tree = materialization_tree,
            .physical_column = physical_column,
            .direct_node = column,
        };
    }

    if (fixed_lowering) |*lowering| {
        const lowered_roots = try allocator.alloc(u32, lowering.program.suffix_roots.len);
        defer allocator.free(lowered_roots);
        try lowering.lowerSuffix(&fixed_emitter, lowered_roots);
        for (lowered_roots) |root|
            roots.appendAssumeCapacity(try direct_arena.recordRoot(root));
    }

    if (roots.items.len != total_roots) return error.CountOverflow;
    const operation_counts = try direct_arena.operationCounts();
    const counts = StructuralCounts{
        .nodes = std.math.cast(u64, direct_arena.nodeCount()) orelse
            return error.CountOverflow,
        .root_uses = std.math.cast(u64, roots.items.len) orelse
            return error.CountOverflow,
        .additions = operation_counts.additions,
        .subtractions = operation_counts.subtractions,
        .negations = operation_counts.negations,
        .multiplications = operation_counts.multiplications,
        .unique_committed_column_reads = operation_counts.committed,
        .streaming_peak_live_nodes = try direct_arena.peakLiveNodes(
            allocator,
            roots.items,
        ),
    };
    const digest = try computeDigest(
        &direct_arena,
        roots.items,
        materialized_columns,
    );

    const owned_roots = try roots.toOwnedSlice(allocator);
    return .{
        .allocator = allocator,
        .direct_arena = direct_arena,
        .root_uses = owned_roots,
        .materialized_columns = materialized_columns,
        .counts = counts,
        .digest = digest,
    };
}

fn validateRequest(arena: *const ir.Arena, request: Request) Error!void {
    if (request.fixed_direct_program) |program| {
        if (request.materialization_column_start !=
            program.materialization_column_start)
        {
            return error.MaterializationColumnStartMismatch;
        }
        const materialization_end = std.math.add(
            u64,
            request.materialization_column_start,
            std.math.cast(u64, request.selected.len) orelse
                return error.CountOverflow,
        ) catch return error.CountOverflow;
        for (program.columns) |column| {
            if (column.tree != program.materialization_tree) continue;
            const resolved = try column.placement.resolve(request.selected.len);
            if (resolved >= request.materialization_column_start and
                resolved < materialization_end)
            {
                return error.FixedColumnAliasesMaterialization;
            }
        }
    }
    if (request.gate) |gate| {
        const node = arena.node(gate) orelse return error.InvalidGate;
        if (!node.key.ty.isSelector()) return error.InvalidGateType;
        switch (node.key.op) {
            .constant, .input, .hint_output, .call_output => {},
            else => return error.UnsupportedGateExpression,
        }
    }
    var previous: ?usize = null;
    for (request.selected) |value| {
        const index = types.idIndex(value);
        const node = arena.node(value) orelse return error.InvalidSelectedValue;
        if (previous) |prior| if (index <= prior)
            return error.NonCanonicalSelection;
        previous = index;
        if (!node.key.ty.isFieldScalar()) return error.InvalidSelectedValueType;
    }
}

const no_direct_node = std.math.maxInt(u32);

const FixedEmitter = struct {
    direct_arena: *direct.Arena,
    gate: ?u32,

    pub fn constant(self: *FixedEmitter, value: u32) Error!u32 {
        return self.direct_arena.intern(.{ .op = .constant, .value = value });
    }

    pub fn column(
        self: *FixedEmitter,
        namespace_digest: *const fixed.Digest,
        column_value: *const fixed.Column,
        resolved: u64,
    ) Error!u32 {
        return switch (column_value.binding) {
            .gate => self.gate orelse error.MissingFixedGate,
            .component => self.direct_arena.fixedCommitted(
                namespace_digest.*,
                column_value.tree,
                resolved,
            ),
        };
    }

    pub fn binary(
        self: *FixedEmitter,
        op: fixed.BinaryOp,
        lhs: u32,
        rhs: u32,
    ) Error!u32 {
        return self.direct_arena.binary(switch (op) {
            .add => .add,
            .sub => .sub,
            .mul => .mul,
        }, lhs, rhs);
    }

    pub fn neg(self: *FixedEmitter, value: u32) Error!u32 {
        return self.direct_arena.intern(.{ .op = .neg, .lhs = value });
    }
};

fn lowerContext(
    direct_arena: *direct.Arena,
    arena: *const ir.Arena,
    gate: ?types.ValueId,
    policy: Policy,
    mapped: []u32,
) Error!?u32 {
    var context: ?u32 = null;
    if (gate) |value| {
        const node = arena.node(value) orelse return error.InvalidGate;
        const lowered = switch (node.key.op) {
            .constant => |constant| try direct_arena.intern(.{
                .op = .constant,
                .value = constantValue(constant),
            }),
            .input, .hint_output, .call_output => try direct_arena.committed(value, false),
            else => return error.UnsupportedGateExpression,
        };
        mapped[types.idIndex(value)] = lowered;
        context = lowered;
    }
    if (policy.row_mask_degree != 0) {
        const mask = try direct_arena.intern(.{
            .op = .row_mask,
            .value = policy.row_mask_degree,
        });
        context = if (context) |prior|
            try direct_arena.binary(.mul, prior, mask)
        else
            mask;
    }
    return context;
}

fn lowerValue(
    direct_arena: *direct.Arena,
    arena: *const ir.Arena,
    root: types.ValueId,
    mapped: []u32,
    needed: []bool,
) Error!u32 {
    const root_index = types.idIndex(root);
    if (mapped[root_index] != no_direct_node) return mapped[root_index];
    @memset(needed, false);
    needed[root_index] = true;
    const root_end = std.math.add(usize, root_index, 1) catch
        return error.CountOverflow;
    var reverse = root_end;
    while (reverse > 0) {
        reverse -= 1;
        if (!needed[reverse] or mapped[reverse] != no_direct_node) continue;
        markOperands(needed, arena.nodesView()[reverse].key.op);
    }

    for (arena.nodesView()[0..root_end], 0..) |node, index| {
        if (!needed[index] or mapped[index] != no_direct_node) continue;
        mapped[index] = switch (node.key.op) {
            .constant => |constant| try direct_arena.intern(.{
                .op = .constant,
                .value = constantValue(constant),
            }),
            .input, .hint_output, .call_output => try direct_arena.committed(
                @enumFromInt(index),
                false,
            ),
            .add => |binary| try direct_arena.binary(
                .add,
                try directOperand(mapped, binary.lhs),
                try directOperand(mapped, binary.rhs),
            ),
            .sub => |binary| try direct_arena.binary(
                .sub,
                try directOperand(mapped, binary.lhs),
                try directOperand(mapped, binary.rhs),
            ),
            .mul => |binary| try direct_arena.binary(
                .mul,
                try directOperand(mapped, binary.lhs),
                try directOperand(mapped, binary.rhs),
            ),
            .neg => |value| try direct_arena.intern(.{
                .op = .neg,
                .lhs = try directOperand(mapped, value),
            }),
            .select => |selection| blk: {
                const selector = try directOperand(mapped, selection.selector);
                const when_true = try directOperand(mapped, selection.when_true);
                const when_false = try directOperand(mapped, selection.when_false);
                const difference = try direct_arena.binary(.sub, when_true, when_false);
                const selected = try direct_arena.binary(.mul, selector, difference);
                break :blk try direct_arena.binary(.add, when_false, selected);
            },
            .machine_derived => |derived| try lowerMachineDerived(
                direct_arena,
                derived,
                mapped,
            ),
        };
    }
    return directOperand(mapped, root);
}

fn markOperands(flags: []bool, op: expr.Op) void {
    switch (op) {
        .constant, .input, .hint_output, .call_output => {},
        .add, .sub, .mul => |binary| {
            flags[types.idIndex(binary.lhs)] = true;
            flags[types.idIndex(binary.rhs)] = true;
        },
        .neg => |value| flags[types.idIndex(value)] = true,
        .select => |selection| {
            flags[types.idIndex(selection.selector)] = true;
            flags[types.idIndex(selection.when_true)] = true;
            flags[types.idIndex(selection.when_false)] = true;
        },
        .machine_derived => |derived| switch (derived) {
            .register_address => |address| flags[types.idIndex(address.index)] = true,
            .access_clock => |clock| flags[types.idIndex(clock.instruction_clock)] = true,
            .strict_clock_gap => |gap| {
                flags[types.idIndex(gap.current_clock)] = true;
                flags[types.idIndex(gap.previous_clock)] = true;
            },
        },
    }
}

fn lowerMachineDerived(
    direct_arena: *direct.Arena,
    derived: expr.MachineDerived,
    mapped: []const u32,
) Error!u32 {
    return switch (derived) {
        .register_address => |address| directOperand(mapped, address.index),
        .access_clock => |clock| blk: {
            const one = try direct_arena.intern(.{ .op = .constant, .value = 1 });
            const four = try direct_arena.intern(.{ .op = .constant, .value = 4 });
            const ordinal = try direct_arena.intern(.{
                .op = .constant,
                .value = @intFromEnum(clock.ordinal),
            });
            const shifted = try direct_arena.binary(
                .sub,
                try directOperand(mapped, clock.instruction_clock),
                one,
            );
            const scaled = try direct_arena.binary(.mul, shifted, four);
            break :blk direct_arena.binary(.add, scaled, ordinal);
        },
        .strict_clock_gap => |gap| blk: {
            const one = try direct_arena.intern(.{ .op = .constant, .value = 1 });
            const delta = try direct_arena.binary(
                .sub,
                try directOperand(mapped, gap.current_clock),
                try directOperand(mapped, gap.previous_clock),
            );
            break :blk direct_arena.binary(.sub, delta, one);
        },
    };
}

fn directOperand(mapped: []const u32, value: types.ValueId) Error!u32 {
    const index = types.idIndex(value);
    if (index >= mapped.len or mapped[index] == no_direct_node)
        return error.MissingDirectOperand;
    return mapped[index];
}

fn constantValue(constant: expr.Constant) u64 {
    return switch (constant) {
        .field => |value| value,
        .unsigned => |value| value,
    };
}

fn computeDigest(
    direct_arena: *const direct.Arena,
    roots: []const direct.RootUse,
    materialized_columns: []const MaterializedColumn,
) ValidationError!Digest {
    if (direct_arena.nodes.items.len != direct_arena.creation_events.items.len)
        return error.CountOverflow;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(digest_domain);
    hashInt(&hash, u16, format_version);
    hashInt(&hash, u32, std.math.cast(u32, direct_arena.nodes.items.len) orelse
        return error.CountOverflow);
    for (direct_arena.nodes.items, direct_arena.creation_events.items) |node, event| {
        hashInt(&hash, u8, @intFromEnum(node.op));
        hashInt(&hash, u32, node.lhs);
        hashInt(&hash, u32, node.rhs);
        hashInt(&hash, u64, node.value);
        hash.update(&node.namespace_digest);
        hashInt(&hash, u64, std.math.cast(u64, event) orelse
            return error.CountOverflow);
    }
    hashInt(&hash, u32, std.math.cast(u32, roots.len) orelse
        return error.CountOverflow);
    for (roots) |root| {
        hashInt(&hash, u32, root.node);
        hashInt(&hash, u64, std.math.cast(u64, root.fold_event) orelse
            return error.CountOverflow);
    }
    hashInt(&hash, u32, std.math.cast(u32, materialized_columns.len) orelse
        return error.CountOverflow);
    for (materialized_columns) |column| {
        hashInt(&hash, u32, @intFromEnum(column.source_value));
        hashInt(&hash, u8, @intFromEnum(column.tree));
        hashInt(&hash, u64, column.physical_column);
        hashInt(&hash, u32, column.direct_node);
    }
    return hash.finalResult();
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}
