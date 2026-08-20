//! Authenticated lowering and allocation-free evaluation for physical typed
//! AIR expressions over current/previous committed-column samples.
//!
//! This is append-only beside frozen logical AIR V1. Compilation binds every
//! shifted read to one validated row-window plan and rejects cross-component
//! arithmetic, dead nodes, duplicate roots, and excess degree. The prepared
//! form contains no maps or pointers; its hot evaluator only performs indexed
//! loads and M31 arithmetic into caller-owned storage.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const compat_layout = @import("compat_layout.zig");
const expr = @import("expr.zig");
const row_window = @import("row_window.zig");
const shadow_program = @import("shadow_program.zig");
const types = @import("types.zig");
const window_ir = @import("window_ir_v2.zig");

pub const FORMAT_ID = "stwo.typed-air.row-window-expression-v2";
pub const FORMAT_VERSION: u16 = 2;
pub const IDENTITY_DOMAIN = FORMAT_ID ++ "\x00";
pub const Digest = [32]u8;
pub const Degree = window_ir.Degree;

pub const Error = window_ir.Error || row_window.Error || error{
    CrossOwnerExpression,
    DegreeLimitExceeded,
    DuplicateRoot,
    EmptyProgram,
    InvalidCompiledNode,
    InvalidExpressionDigest,
    InvalidExpressionFormat,
    InvalidRoot,
    InvalidTraceGeometry,
    NonCanonicalTraceValue,
    OutputAliasesInput,
    OutputAliasesOutput,
    OutputAliasesScratch,
    ScratchAliasesInput,
    UnusedExpression,
};

pub const SampleBinding = struct {
    tree: compat_layout.Tree,
    local_index: u32,
    offset: expr.RowOffset,
};

pub const CompiledNode = struct {
    key: expr.WindowKey,
    owner: ?row_window.Owner,
    degree: Degree,
    sample: ?SampleBinding,
};

/// Pointer-free, map-free executable authority. All slices are owned.
pub const Program = struct {
    allocator: std.mem.Allocator,
    schema_version: u16,
    family: @import("../../runner/trace.zig").OpcodeFamily,
    row_window_plan_digest: Digest,
    degree_cap: Degree,
    maximum_degree: Degree,
    nodes: []CompiledNode,
    roots: []types.WindowValueId,
    program_digest: Digest,

    pub fn deinit(self: *Program) void {
        self.allocator.free(self.roots);
        self.allocator.free(self.nodes);
        self.* = undefined;
    }

    /// Full allocation-free replay of topology, typed ownership, degree, root
    /// liveness, plan custody, and authenticated identity.
    pub fn validate(
        self: *const Program,
        arena: *const window_ir.Arena,
        plan: *const row_window.Plan,
        imported: *const shadow_program.ImportedProgram,
        layout: *const compat_layout.Layout,
    ) Error!void {
        try arena.validate();
        try plan.validate(imported, layout);
        if (self.schema_version != FORMAT_VERSION)
            return error.InvalidExpressionFormat;
        if (self.family != plan.family or
            !std.mem.eql(u8, &self.row_window_plan_digest, &plan.plan_digest) or
            self.nodes.len != arena.nodesView().len or
            self.roots.len == 0 or
            self.degree_cap == 0)
        {
            return error.InvalidExpressionFormat;
        }

        var maximum: Degree = 0;
        for (self.nodes, arena.nodesView(), 0..) |compiled, source_node, index| {
            if (!std.meta.eql(compiled.key, source_node.key))
                return error.InvalidCompiledNode;
            const derived = try deriveNode(self.nodes[0..index], source_node.key, plan);
            if (!std.meta.eql(compiled.owner, derived.owner) or
                compiled.degree != derived.degree or
                !std.meta.eql(compiled.sample, derived.sample))
            {
                return error.InvalidCompiledNode;
            }
            maximum = @max(maximum, compiled.degree);
        }
        try validateRootsAndLiveness(self.nodes, self.roots);
        if (maximum != self.maximum_degree or maximum > self.degree_cap)
            return error.DegreeLimitExceeded;
        const actual = identityDigest(self);
        if (!std.mem.eql(u8, &actual, &self.program_digest))
            return error.InvalidExpressionDigest;
    }
};

pub fn compile(
    allocator: std.mem.Allocator,
    arena: *const window_ir.Arena,
    roots: []const types.WindowValueId,
    degree_cap: Degree,
    plan: *const row_window.Plan,
    imported: *const shadow_program.ImportedProgram,
    layout: *const compat_layout.Layout,
) Error!Program {
    try arena.validate();
    try plan.validate(imported, layout);
    if (arena.nodesView().len == 0 or roots.len == 0 or degree_cap == 0)
        return error.EmptyProgram;

    const nodes = try allocator.alloc(CompiledNode, arena.nodesView().len);
    errdefer allocator.free(nodes);
    var initialized: usize = 0;
    var maximum: Degree = 0;
    for (arena.nodesView(), 0..) |source_node, index| {
        const derived = try deriveNode(nodes[0..initialized], source_node.key, plan);
        if (derived.degree > degree_cap) return error.DegreeLimitExceeded;
        nodes[index] = .{
            .key = source_node.key,
            .owner = derived.owner,
            .degree = derived.degree,
            .sample = derived.sample,
        };
        initialized += 1;
        maximum = @max(maximum, derived.degree);
    }

    const owned_roots = try allocator.dupe(types.WindowValueId, roots);
    errdefer allocator.free(owned_roots);
    try validateRootsAndLiveness(nodes, owned_roots);

    var result = Program{
        .allocator = allocator,
        .schema_version = FORMAT_VERSION,
        .family = plan.family,
        .row_window_plan_digest = plan.plan_digest,
        .degree_cap = degree_cap,
        .maximum_degree = maximum,
        .nodes = nodes,
        .roots = owned_roots,
        .program_digest = .{0} ** 32,
    };
    result.program_digest = identityDigest(&result);
    try result.validate(arena, plan, imported, layout);
    return result;
}

const DerivedNode = struct {
    owner: ?row_window.Owner,
    degree: Degree,
    sample: ?SampleBinding = null,
};

fn deriveNode(
    previous: []const CompiledNode,
    key: expr.WindowKey,
    plan: *const row_window.Plan,
) Error!DerivedNode {
    return switch (key.op) {
        .constant => .{ .owner = null, .degree = 0 },
        .shifted_column => |id| blk: {
            const shifted = plan.shiftedColumn(id) orelse
                return error.InvalidShiftedColumn;
            if (shifted.id != id) return error.InvalidShiftedColumn;
            const column = plan.column(shifted.column) orelse
                return error.InvalidColumn;
            if (column.id != shifted.column or
                !std.meta.eql(column.owner, shifted.owner))
            {
                return error.InvalidColumn;
            }
            break :blk .{
                .owner = shifted.owner,
                .degree = 1,
                .sample = .{
                    .tree = column.reference.tree,
                    .local_index = column.reference.local_index,
                    .offset = shifted.offset,
                },
            };
        },
        .add, .sub => |binary| try deriveBinary(previous, binary, false),
        .mul => |binary| try deriveBinary(previous, binary, true),
        .neg => |id| try operand(previous, id),
    };
}

fn deriveBinary(
    previous: []const CompiledNode,
    binary: expr.WindowBinary,
    multiply: bool,
) Error!DerivedNode {
    const lhs = try operand(previous, binary.lhs);
    const rhs = try operand(previous, binary.rhs);
    return .{
        .owner = try mergeOwners(lhs, rhs),
        .degree = if (multiply)
            std.math.add(Degree, lhs.degree, rhs.degree) catch
                return error.DegreeOverflow
        else
            @max(lhs.degree, rhs.degree),
    };
}

fn operand(
    previous: []const CompiledNode,
    id: types.WindowValueId,
) Error!DerivedNode {
    const index = types.idIndex(id);
    if (index >= previous.len) return error.InvalidOperandOrder;
    return .{
        .owner = previous[index].owner,
        .degree = previous[index].degree,
    };
}

fn mergeOwners(lhs: DerivedNode, rhs: DerivedNode) Error!?row_window.Owner {
    if (lhs.owner) |lhs_owner| {
        if (rhs.owner) |rhs_owner| {
            if (!std.meta.eql(lhs_owner, rhs_owner))
                return error.CrossOwnerExpression;
        }
        return lhs_owner;
    }
    return rhs.owner;
}

fn validateRootsAndLiveness(
    nodes: []const CompiledNode,
    roots: []const types.WindowValueId,
) Error!void {
    if (nodes.len == 0 or roots.len == 0) return error.EmptyProgram;
    for (roots, 0..) |root, root_index| {
        if (types.idIndex(root) >= nodes.len) return error.InvalidRoot;
        for (roots[0..root_index]) |prior| {
            if (prior == root) return error.DuplicateRoot;
        }
    }

    // A topologically ordered finite DAG is live exactly when every node is a
    // root or feeds a later node. This O(n^2) cold check avoids a scratch
    // allocation in validation and makes redundant AIR fail closed.
    for (nodes, 0..) |_, index| {
        const id: types.WindowValueId = @enumFromInt(index);
        var live = false;
        for (roots) |root| {
            if (root == id) {
                live = true;
                break;
            }
        }
        if (live) continue;
        for (nodes[index + 1 ..]) |later| {
            if (references(later.key, id)) {
                live = true;
                break;
            }
        }
        if (!live) return error.UnusedExpression;
    }
}

fn references(key: expr.WindowKey, id: types.WindowValueId) bool {
    return switch (key.op) {
        .constant, .shifted_column => false,
        .add, .sub, .mul => |binary| binary.lhs == id or binary.rhs == id,
        .neg => |value| value == id,
    };
}

pub const TraceColumns = struct {
    preprocessed: []const []const M31,
    main: []const []const M31,
    interaction: []const []const M31,

    pub fn tree(
        self: TraceColumns,
        which: compat_layout.Tree,
    ) []const []const M31 {
        return switch (which) {
            .preprocessed => self.preprocessed,
            .main => self.main,
            .interaction => self.interaction,
        };
    }

    /// Validates exact plan geometry and canonical field representation once,
    /// before a prepared evaluator enters its hot row loop.
    pub fn validate(self: TraceColumns, plan: *const row_window.Plan) Error!usize {
        var row_count: ?usize = null;
        inline for (.{
            compat_layout.Tree.preprocessed,
            compat_layout.Tree.main,
            compat_layout.Tree.interaction,
        }) |which| {
            const columns = self.tree(which);
            if (columns.len != plan.tree_column_counts[@intFromEnum(which)])
                return error.InvalidTraceGeometry;
            for (columns) |column| {
                if (row_count) |count| {
                    if (column.len != count) return error.InvalidTraceGeometry;
                } else {
                    if (column.len == 0) return error.InvalidTraceGeometry;
                    row_count = column.len;
                }
                for (column) |value| {
                    if (value.v >= @import("stwo_core").fields.m31.Modulus)
                        return error.NonCanonicalTraceValue;
                }
            }
        }
        return row_count orelse error.InvalidTraceGeometry;
    }
};

/// Borrowed, zero-allocation hot evaluator. The authenticated program and plan
/// must outlive it; preparation validates all cold structure exactly once.
pub const PreparedEvaluator = struct {
    program: *const Program,
    traces: TraceColumns,
    row_count: usize,

    pub fn init(
        program: *const Program,
        arena: *const window_ir.Arena,
        plan: *const row_window.Plan,
        imported: *const shadow_program.ImportedProgram,
        layout: *const compat_layout.Layout,
        traces: TraceColumns,
    ) Error!PreparedEvaluator {
        try program.validate(arena, plan, imported, layout);
        return .{
            .program = program,
            .traces = traces,
            .row_count = try traces.validate(plan),
        };
    }

    /// Evaluates all nodes and copies roots. Every fallible precondition is
    /// checked before the first caller-owned word is written.
    pub fn evaluateRow(
        self: PreparedEvaluator,
        row: usize,
        scratch: []M31,
        outputs: []M31,
    ) Error!void {
        if (row >= self.row_count or
            scratch.len != self.program.nodes.len or
            outputs.len != self.program.roots.len)
        {
            return error.InvalidTraceGeometry;
        }
        try self.validateWorkingStorage(scratch, outputs);
        self.evaluateRowUnchecked(row, scratch, outputs);
    }

    inline fn evaluateRowUnchecked(
        self: PreparedEvaluator,
        row: usize,
        scratch: []M31,
        outputs: []M31,
    ) void {
        for (self.program.nodes, 0..) |node, index| {
            scratch[index] = switch (node.key.op) {
                .constant => |value| M31.fromCanonical(value),
                .shifted_column => self.sample(node.sample.?, row),
                .add => |binary| scratch[types.idIndex(binary.lhs)].add(
                    scratch[types.idIndex(binary.rhs)],
                ),
                .sub => |binary| scratch[types.idIndex(binary.lhs)].sub(
                    scratch[types.idIndex(binary.rhs)],
                ),
                .mul => |binary| scratch[types.idIndex(binary.lhs)].mul(
                    scratch[types.idIndex(binary.rhs)],
                ),
                .neg => |id| scratch[types.idIndex(id)].neg(),
            };
        }
        for (self.program.roots, outputs) |root, *output| {
            output.* = scratch[types.idIndex(root)];
        }
    }

    /// Column-major materialization for all roots and rows. No allocation,
    /// hashing, map lookup, or search occurs after preflight.
    pub fn materialize(
        self: PreparedEvaluator,
        scratch: []M31,
        row_outputs: []M31,
        output_columns: []const []M31,
    ) Error!void {
        if (scratch.len != self.program.nodes.len or
            row_outputs.len != self.program.roots.len or
            output_columns.len != self.program.roots.len)
        {
            return error.InvalidTraceGeometry;
        }
        try self.validateWorkingStorage(scratch, row_outputs);
        for (output_columns, 0..) |output, index| {
            if (output.len != self.row_count) return error.InvalidTraceGeometry;
            if (overlaps(scratch, output) or overlaps(row_outputs, output))
                return error.OutputAliasesScratch;
            for (output_columns[0..index]) |prior| {
                if (overlaps(prior, output)) return error.OutputAliasesOutput;
            }
            inline for (.{
                compat_layout.Tree.preprocessed,
                compat_layout.Tree.main,
                compat_layout.Tree.interaction,
            }) |which| {
                for (self.traces.tree(which)) |input| {
                    if (overlaps(input, output)) return error.OutputAliasesInput;
                }
            }
        }

        for (0..self.row_count) |row| {
            self.evaluateRowUnchecked(row, scratch, row_outputs);
            for (output_columns, row_outputs) |output, value| output[row] = value;
        }
    }

    fn validateWorkingStorage(
        self: PreparedEvaluator,
        scratch: []M31,
        outputs: []M31,
    ) Error!void {
        if (overlaps(scratch, outputs)) return error.OutputAliasesScratch;
        inline for (.{
            compat_layout.Tree.preprocessed,
            compat_layout.Tree.main,
            compat_layout.Tree.interaction,
        }) |which| {
            for (self.traces.tree(which)) |input| {
                if (overlaps(input, scratch)) return error.ScratchAliasesInput;
                if (overlaps(input, outputs)) return error.OutputAliasesInput;
            }
        }
    }

    inline fn sample(
        self: PreparedEvaluator,
        binding: SampleBinding,
        row: usize,
    ) M31 {
        const columns = self.traces.tree(binding.tree);
        const sample_row = switch (binding.offset) {
            .current => row,
            .previous => if (row == 0) self.row_count - 1 else row - 1,
        };
        return columns[binding.local_index][sample_row];
    }
};

fn overlaps(lhs: []const M31, rhs: []const M31) bool {
    if (lhs.len == 0 or rhs.len == 0) return false;
    const lhs_start = @intFromPtr(lhs.ptr);
    const rhs_start = @intFromPtr(rhs.ptr);
    const lhs_end = lhs_start + lhs.len * @sizeOf(M31);
    const rhs_end = rhs_start + rhs.len * @sizeOf(M31);
    return lhs_start < rhs_end and rhs_start < lhs_end;
}

fn identityDigest(program: *const Program) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(IDENTITY_DOMAIN);
    hashInteger(&hash, u16, program.schema_version);
    hashInteger(&hash, u8, @intFromEnum(program.family));
    hash.update(&program.row_window_plan_digest);
    hashInteger(&hash, Degree, program.degree_cap);
    hashInteger(&hash, Degree, program.maximum_degree);
    hashCount(&hash, program.nodes.len);
    for (program.nodes) |node| {
        hashInteger(&hash, u8, @intFromEnum(std.meta.activeTag(node.key.op)));
        switch (node.key.op) {
            .constant => |value| hashInteger(&hash, u32, value),
            .shifted_column => |id| hashInteger(&hash, u32, @intFromEnum(id)),
            .add, .sub, .mul => |binary| {
                hashInteger(&hash, u32, @intFromEnum(binary.lhs));
                hashInteger(&hash, u32, @intFromEnum(binary.rhs));
            },
            .neg => |id| hashInteger(&hash, u32, @intFromEnum(id)),
        }
        if (node.owner) |owner| {
            hashInteger(&hash, u8, 1);
            hashInteger(&hash, u8, @intFromEnum(owner.family));
            hashInteger(&hash, u8, @intFromEnum(owner.component));
            hashInteger(&hash, u32, owner.instance);
        } else {
            hashInteger(&hash, u8, 0);
        }
        hashInteger(&hash, Degree, node.degree);
        if (node.sample) |sample| {
            hashInteger(&hash, u8, 1);
            hashInteger(&hash, u8, @intFromEnum(sample.tree));
            hashInteger(&hash, u32, sample.local_index);
            hashInteger(&hash, u8, @bitCast(@intFromEnum(sample.offset)));
        } else {
            hashInteger(&hash, u8, 0);
        }
    }
    hashCount(&hash, program.roots.len);
    for (program.roots) |root| hashInteger(&hash, u32, @intFromEnum(root));
    return hash.finalResult();
}

fn hashCount(hash: anytype, value: usize) void {
    hashInteger(hash, u64, std.math.cast(u64, value) orelse
        std.math.maxInt(u64));
}

fn hashInteger(hash: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}
