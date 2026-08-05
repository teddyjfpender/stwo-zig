//! Lossless shadow import of the shipped symbolic polynomial DAG.
//!
//! Production `extract/symbolic.zig` remains the source. This adapter copies
//! its field-only graph into the typed arena, records a source-node-to-value
//! map when canonical interning merges equivalent commutative nodes, and can
//! replay both representations at the same column point for differential
//! evidence. It changes no production consumer.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const ir = @import("ir.zig");
const source_mod = @import("source.zig");
const symbolic = @import("../extract/symbolic.zig");
const types = @import("types.zig");
const validate = @import("validate.zig");

pub const ImportError = error{
    DuplicateSymbolicColumn,
    DuplicateSymbolicColumnName,
    EmptySymbolicColumnName,
    InvalidSymbolicInternTable,
    InvalidSymbolicNode,
    MissingSymbolicColumn,
};

pub const ReplayError = error{
    InvalidColumnCount,
    InvalidReplayBuffer,
    MissingImportedColumn,
    UnsupportedReplayNode,
};

pub const Error = std.mem.Allocator.Error || ir.Error || validate.Error || ImportError;

pub const Imported = struct {
    allocator: std.mem.Allocator,
    arena: ir.Arena,
    source_to_value: []types.ValueId,
    columns: []types.ValueId,
    /// Target node id -> source column index, or `no_column` for non-inputs.
    /// This keeps replay linear without relying on source and target node ids
    /// remaining equal after canonical interning.
    column_for_value: []u32,

    const no_column = std.math.maxInt(u32);

    pub fn deinit(self: *Imported) void {
        self.allocator.free(self.column_for_value);
        self.allocator.free(self.columns);
        self.allocator.free(self.source_to_value);
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn valueForSourceNode(
        self: *const Imported,
        source_node: u32,
    ) ?types.ValueId {
        const index: usize = source_node;
        if (index >= self.source_to_value.len) return null;
        return self.source_to_value[index];
    }

    /// Replays the imported field DAG in one topological pass.
    pub fn replay(
        self: *const Imported,
        column_values: []const m31.M31,
        out: []m31.M31,
    ) ReplayError!void {
        if (column_values.len != self.columns.len)
            return error.InvalidColumnCount;
        if (out.len != self.arena.nodesView().len)
            return error.InvalidReplayBuffer;
        if (self.column_for_value.len != out.len)
            return error.InvalidReplayBuffer;

        for (self.arena.nodesView(), out, 0..) |node, *slot, index| {
            slot.* = switch (node.key.op) {
                .constant => |constant| switch (constant) {
                    .field => |value| m31.M31.fromCanonical(value),
                    .unsigned => |value| m31.M31.fromU64(value),
                },
                .input => blk: {
                    const column_index = self.column_for_value[index];
                    if (column_index == no_column or
                        column_index >= column_values.len)
                    {
                        return error.MissingImportedColumn;
                    }
                    break :blk column_values[column_index];
                },
                .add => |binary| out[types.idIndex(binary.lhs)].add(
                    out[types.idIndex(binary.rhs)],
                ),
                .sub => |binary| out[types.idIndex(binary.lhs)].sub(
                    out[types.idIndex(binary.rhs)],
                ),
                .mul => |binary| out[types.idIndex(binary.lhs)].mul(
                    out[types.idIndex(binary.rhs)],
                ),
                .neg => |value| out[types.idIndex(value)].neg(),
                .select => |selection| blk: {
                    const selector = out[types.idIndex(selection.selector)];
                    const when_true = out[types.idIndex(selection.when_true)];
                    const when_false = out[types.idIndex(selection.when_false)];
                    break :blk when_false.add(
                        selector.mul(when_true.sub(when_false)),
                    );
                },
                .hint_output, .call_output => return error.UnsupportedReplayNode,
            };
        }
    }
};

pub fn import(
    allocator: std.mem.Allocator,
    source: *const symbolic.Arena,
    span: source_mod.SourceSpan,
) Error!Imported {
    try validateSource(source);
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const source_to_value = try allocator.alloc(types.ValueId, source.nodes.items.len);
    errdefer allocator.free(source_to_value);
    const columns = try allocator.alloc(types.ValueId, source.names.items.len);
    errdefer allocator.free(columns);
    const seen_columns = try allocator.alloc(bool, source.names.items.len);
    defer allocator.free(seen_columns);
    @memset(seen_columns, false);

    for (source.nodes.items, source_to_value) |node, *destination| {
        destination.* = switch (node.op) {
            .constant => try arena.constantField(
                m31.M31.fromU64(node.value).toU32(),
                span,
            ),
            .column => blk: {
                const column_index: usize = node.value;
                if (seen_columns[column_index])
                    return error.DuplicateSymbolicColumn;
                const value = try arena.input(
                    source.names.items[column_index],
                    .felt,
                    span,
                );
                seen_columns[column_index] = true;
                columns[column_index] = value;
                break :blk value;
            },
            .add => try arena.add(
                source_to_value[node.lhs],
                source_to_value[node.rhs],
                span,
            ),
            .sub => try arena.sub(
                source_to_value[node.lhs],
                source_to_value[node.rhs],
                span,
            ),
            .mul => try arena.mul(
                source_to_value[node.lhs],
                source_to_value[node.rhs],
                span,
            ),
            .neg => try arena.neg(source_to_value[node.lhs], span),
        };
    }
    for (seen_columns) |seen| {
        if (!seen) return error.MissingSymbolicColumn;
    }
    try validate.validate(&arena);

    const column_for_value = try allocator.alloc(u32, arena.nodeCount());
    errdefer allocator.free(column_for_value);
    @memset(column_for_value, Imported.no_column);
    for (columns, 0..) |column, column_index| {
        const value_index = types.idIndex(column);
        std.debug.assert(value_index < column_for_value.len);
        std.debug.assert(column_for_value[value_index] == Imported.no_column);
        column_for_value[value_index] = std.math.cast(u32, column_index) orelse
            return error.IdOverflow;
    }
    return .{
        .allocator = allocator,
        .arena = arena,
        .source_to_value = source_to_value,
        .columns = columns,
        .column_for_value = column_for_value,
    };
}

fn validateSource(source: *const symbolic.Arena) ImportError!void {
    if (source.interned.count() != source.nodes.items.len)
        return error.InvalidSymbolicInternTable;
    for (source.names.items, 0..) |name, index| {
        if (name.len == 0) return error.EmptySymbolicColumnName;
        for (source.names.items[0..index]) |prior| {
            if (std.mem.eql(u8, name, prior))
                return error.DuplicateSymbolicColumnName;
        }
    }
    for (source.nodes.items, 0..) |node, index| {
        const expected: u32 = std.math.cast(u32, index) orelse
            return error.InvalidSymbolicNode;
        const actual = source.interned.get(node) orelse
            return error.InvalidSymbolicInternTable;
        if (actual != expected) return error.InvalidSymbolicInternTable;
        switch (node.op) {
            .constant => {},
            .column => if (@as(usize, node.value) >= source.names.items.len)
                return error.InvalidSymbolicNode,
            .add, .sub, .mul => if (@as(usize, node.lhs) >= index or
                @as(usize, node.rhs) >= index)
                return error.InvalidSymbolicNode,
            .neg => if (@as(usize, node.lhs) >= index)
                return error.InvalidSymbolicNode,
        }
    }
}
