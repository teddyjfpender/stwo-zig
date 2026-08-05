//! Owned storage for the typed AIR logical program.
//!
//! The arena owns every stable string and source record. No caller-provided
//! slice is retained, and no process-global context is used.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const expr = @import("expr.zig");
const program = @import("program.zig");
const source_mod = @import("source.zig");
const types = @import("types.zig");

pub const ArenaError = error{
    EmptyStableName,
    UnknownSource,
};

pub const NodeError = error{
    BranchTypeMismatch,
    ConstantOutOfRange,
    InputTypeConflict,
    InvalidSelectorType,
    NonCanonicalFieldConstant,
    NonFieldOperand,
    UnknownValue,
    UnsupportedConstantType,
};

pub const ProgramError = error{
    DuplicateAccessOrdinal,
    DuplicateConstraintName,
    EmptyEffectValues,
    InvalidAccessOrdinal,
    InvalidConstraintGate,
    InvalidConstraintRoot,
    InvalidEffectLiveness,
};

pub const NodeCheckpoint = struct {
    len: usize,
};

pub const Error = std.mem.Allocator.Error ||
    types.IdError ||
    types.TypeError ||
    source_mod.SpanError ||
    program.RangeError ||
    ArenaError ||
    NodeError ||
    ProgramError;

pub const Arena = struct {
    allocator: std.mem.Allocator,
    names: std.ArrayList([]const u8),
    names_by_text: std.StringHashMap(types.NameId),
    sources: std.ArrayList(source_mod.Source),
    sources_by_path: std.AutoHashMap(types.NameId, types.SourceId),
    nodes: std.ArrayList(expr.Node),
    interned_nodes: expr.Map,
    constraints: std.ArrayList(program.Constraint),
    hints: std.ArrayList(program.Hint),
    hint_inputs: std.ArrayList(types.ValueId),
    hint_outputs: std.ArrayList(types.ValueId),
    hint_bindings: std.ArrayList(program.HintBinding),
    hint_binding_values: std.ArrayList(types.ValueId),
    effects: std.ArrayList(program.Effect),
    effect_values: std.ArrayList(types.ValueId),
    functions: std.ArrayList(program.Function),
    function_inputs: std.ArrayList(types.ValueId),
    function_outputs: std.ArrayList(types.ValueId),
    calls: std.ArrayList(program.Call),
    call_arguments: std.ArrayList(types.ValueId),
    call_outputs: std.ArrayList(types.ValueId),
    open_function: ?types.FunctionId,

    pub fn init(allocator: std.mem.Allocator) Arena {
        return .{
            .allocator = allocator,
            .names = .empty,
            .names_by_text = std.StringHashMap(types.NameId).init(allocator),
            .sources = .empty,
            .sources_by_path = std.AutoHashMap(types.NameId, types.SourceId).init(allocator),
            .nodes = .empty,
            .interned_nodes = expr.Map.init(allocator),
            .constraints = .empty,
            .hints = .empty,
            .hint_inputs = .empty,
            .hint_outputs = .empty,
            .hint_bindings = .empty,
            .hint_binding_values = .empty,
            .effects = .empty,
            .effect_values = .empty,
            .functions = .empty,
            .function_inputs = .empty,
            .function_outputs = .empty,
            .calls = .empty,
            .call_arguments = .empty,
            .call_outputs = .empty,
            .open_function = null,
        };
    }

    pub fn deinit(self: *Arena) void {
        self.call_outputs.deinit(self.allocator);
        self.call_arguments.deinit(self.allocator);
        self.calls.deinit(self.allocator);
        self.function_outputs.deinit(self.allocator);
        self.function_inputs.deinit(self.allocator);
        self.functions.deinit(self.allocator);
        self.effect_values.deinit(self.allocator);
        self.effects.deinit(self.allocator);
        self.hint_binding_values.deinit(self.allocator);
        self.hint_bindings.deinit(self.allocator);
        self.hint_outputs.deinit(self.allocator);
        self.hint_inputs.deinit(self.allocator);
        self.hints.deinit(self.allocator);
        self.constraints.deinit(self.allocator);
        self.interned_nodes.deinit();
        self.nodes.deinit(self.allocator);
        self.sources_by_path.deinit();
        self.sources.deinit(self.allocator);
        self.names_by_text.deinit();
        for (self.names.items) |stable_name| self.allocator.free(stable_name);
        self.names.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn internName(self: *Arena, text: []const u8) !types.NameId {
        if (text.len == 0) return error.EmptyStableName;
        if (self.names_by_text.get(text)) |existing| return existing;

        const id = try types.idFromIndex(types.NameId, self.names.items.len);
        const owned = try self.allocator.dupe(u8, text);
        errdefer self.allocator.free(owned);
        try self.names.append(self.allocator, owned);
        errdefer _ = self.names.pop();
        try self.names_by_text.put(owned, id);
        return id;
    }

    pub fn name(self: *const Arena, id: types.NameId) ?[]const u8 {
        const index = types.idIndex(id);
        if (index >= self.names.items.len) return null;
        return self.names.items[index];
    }

    pub fn addSource(self: *Arena, path: []const u8) !types.SourceId {
        const path_id = try self.internName(path);
        if (self.sources_by_path.get(path_id)) |existing| return existing;

        const id = try types.idFromIndex(types.SourceId, self.sources.items.len);
        try self.sources.append(self.allocator, .{ .path = path_id });
        errdefer _ = self.sources.pop();
        try self.sources_by_path.put(path_id, id);
        return id;
    }

    pub fn source(self: *const Arena, id: types.SourceId) ?source_mod.Source {
        const index = types.idIndex(id);
        if (index >= self.sources.items.len) return null;
        return self.sources.items[index];
    }

    pub fn sourcePath(self: *const Arena, id: types.SourceId) ?[]const u8 {
        const item = self.source(id) orelse return null;
        return self.name(item.path);
    }

    pub fn validateSpan(
        self: *const Arena,
        span: source_mod.SourceSpan,
    ) !void {
        try span.validate();
        if (span.source) |source_id| {
            if (self.source(source_id) == null) return error.UnknownSource;
        }
    }

    pub fn nodeCount(self: *const Arena) usize {
        return self.nodes.items.len;
    }

    pub fn node(self: *const Arena, id: types.ValueId) ?expr.Node {
        const index = types.idIndex(id);
        if (index >= self.nodes.items.len) return null;
        return self.nodes.items[index];
    }

    /// Borrowed until the next node insertion or `deinit`.
    pub fn nodesView(self: *const Arena) []const expr.Node {
        return self.nodes.items;
    }

    pub fn constraint(self: *const Arena, id: types.ConstraintId) ?program.Constraint {
        const index = types.idIndex(id);
        if (index >= self.constraints.items.len) return null;
        return self.constraints.items[index];
    }

    /// Borrowed until the next constraint insertion or `deinit`.
    pub fn constraintsView(self: *const Arena) []const program.Constraint {
        return self.constraints.items;
    }

    pub fn effect(self: *const Arena, id: types.EffectId) ?program.Effect {
        const index = types.idIndex(id);
        if (index >= self.effects.items.len) return null;
        return self.effects.items[index];
    }

    /// Borrowed until the next effect insertion or `deinit`.
    pub fn effectsView(self: *const Arena) []const program.Effect {
        return self.effects.items;
    }

    pub fn effectValues(self: *const Arena, id: types.EffectId) ?[]const types.ValueId {
        const item = self.effect(id) orelse return null;
        return item.values.slice(self.effect_values.items);
    }

    /// Borrowed until the next effect insertion or `deinit`.
    pub fn effectValuesView(self: *const Arena) []const types.ValueId {
        return self.effect_values.items;
    }

    pub fn input(
        self: *Arena,
        stable_name: []const u8,
        ty: types.Type,
        span: source_mod.SourceSpan,
    ) Error!types.ValueId {
        try ty.validate();
        try self.validateSpan(span);
        const name_id = try self.internName(stable_name);

        for (self.nodes.items, 0..) |existing, index| {
            switch (existing.key.op) {
                .input => |existing_name| {
                    if (existing_name != name_id) continue;
                    if (!std.meta.eql(existing.key.ty, ty))
                        return error.InputTypeConflict;
                    return try types.idFromIndex(types.ValueId, index);
                },
                else => {},
            }
        }
        return self.internNode(.{ .ty = ty, .op = .{ .input = name_id } }, span);
    }

    pub fn constantField(
        self: *Arena,
        canonical: u32,
        span: source_mod.SourceSpan,
    ) Error!types.ValueId {
        if (canonical >= m31.Modulus)
            return error.NonCanonicalFieldConstant;
        return self.internNode(.{
            .ty = .felt,
            .op = .{ .constant = .{ .field = canonical } },
        }, span);
    }

    pub fn constantUnsigned(
        self: *Arena,
        ty: types.Type,
        value: u32,
        span: source_mod.SourceSpan,
    ) Error!types.ValueId {
        try ty.validate();
        const maximum = try maxUnsignedValue(ty);
        if (value > maximum) return error.ConstantOutOfRange;
        return self.internNode(.{
            .ty = ty,
            .op = .{ .constant = .{ .unsigned = value } },
        }, span);
    }

    pub fn add(
        self: *Arena,
        lhs: types.ValueId,
        rhs: types.ValueId,
        span: source_mod.SourceSpan,
    ) Error!types.ValueId {
        return self.fieldBinary(.add, lhs, rhs, span);
    }

    pub fn sub(
        self: *Arena,
        lhs: types.ValueId,
        rhs: types.ValueId,
        span: source_mod.SourceSpan,
    ) Error!types.ValueId {
        return self.fieldBinary(.sub, lhs, rhs, span);
    }

    pub fn mul(
        self: *Arena,
        lhs: types.ValueId,
        rhs: types.ValueId,
        span: source_mod.SourceSpan,
    ) Error!types.ValueId {
        return self.fieldBinary(.mul, lhs, rhs, span);
    }

    pub fn neg(
        self: *Arena,
        value: types.ValueId,
        span: source_mod.SourceSpan,
    ) Error!types.ValueId {
        const node_value = self.node(value) orelse return error.UnknownValue;
        if (!isFieldScalar(node_value.key.ty)) return error.NonFieldOperand;
        return self.internNode(.{
            .ty = .felt,
            .op = .{ .neg = value },
        }, span);
    }

    pub fn select(
        self: *Arena,
        selector: types.ValueId,
        when_true: types.ValueId,
        when_false: types.ValueId,
        span: source_mod.SourceSpan,
    ) Error!types.ValueId {
        const selector_node = self.node(selector) orelse
            return error.UnknownValue;
        switch (selector_node.key.ty) {
            .bit, .selector => {},
            else => return error.InvalidSelectorType,
        }
        const true_node = self.node(when_true) orelse return error.UnknownValue;
        const false_node = self.node(when_false) orelse return error.UnknownValue;
        if (!std.meta.eql(true_node.key.ty, false_node.key.ty))
            return error.BranchTypeMismatch;
        return self.internNode(.{
            .ty = true_node.key.ty,
            .op = .{ .select = .{
                .selector = selector,
                .when_true = when_true,
                .when_false = when_false,
            } },
        }, span);
    }

    pub fn assertZero(
        self: *Arena,
        stable_name: []const u8,
        root: types.ValueId,
        gate: ?types.ValueId,
        category: program.ConstraintCategory,
        span: source_mod.SourceSpan,
    ) Error!types.ConstraintId {
        try self.validateSpan(span);
        const root_node = self.node(root) orelse return error.UnknownValue;
        if (!isFieldScalar(root_node.key.ty))
            return error.InvalidConstraintRoot;
        if (gate) |gate_id| {
            const gate_node = self.node(gate_id) orelse return error.UnknownValue;
            if (!isSelector(gate_node.key.ty))
                return error.InvalidConstraintGate;
        }

        const name_id = try self.internName(stable_name);
        for (self.constraints.items) |existing| {
            if (existing.name == name_id) return error.DuplicateConstraintName;
        }

        const id = try types.idFromIndex(
            types.ConstraintId,
            self.constraints.items.len,
        );
        try self.constraints.append(self.allocator, .{
            .name = name_id,
            .root = root,
            .gate = gate,
            .category = category,
            .source_span = span,
        });
        return id;
    }

    pub fn addEffect(
        self: *Arena,
        kind: program.EffectKind,
        values: []const types.ValueId,
        liveness: ?types.ValueId,
        access_ordinal: ?u8,
        span: source_mod.SourceSpan,
    ) Error!types.EffectId {
        if (values.len == 0) return error.EmptyEffectValues;
        try self.validateSpan(span);
        for (values) |value| {
            if (self.node(value) == null) return error.UnknownValue;
        }
        if (liveness) |liveness_id| {
            const liveness_node = self.node(liveness_id) orelse
                return error.UnknownValue;
            if (!isSelector(liveness_node.key.ty))
                return error.InvalidEffectLiveness;
        }
        if (requiresAccessOrdinal(kind) != (access_ordinal != null))
            return error.InvalidAccessOrdinal;
        if (access_ordinal) |ordinal| {
            for (self.effects.items) |existing| {
                if (existing.access_ordinal == ordinal)
                    return error.DuplicateAccessOrdinal;
            }
        }

        const id = try types.idFromIndex(types.EffectId, self.effects.items.len);
        const value_range = try program.RefRange.init(
            self.effect_values.items.len,
            values.len,
        );
        const value_start = self.effect_values.items.len;
        errdefer self.effect_values.shrinkRetainingCapacity(value_start);
        try self.effect_values.appendSlice(self.allocator, values);
        try self.effects.append(self.allocator, .{
            .kind = kind,
            .values = value_range,
            .liveness = liveness,
            .access_ordinal = access_ordinal,
            .source_span = span,
        });
        return id;
    }

    fn fieldBinary(
        self: *Arena,
        comptime operation: enum { add, sub, mul },
        lhs: types.ValueId,
        rhs: types.ValueId,
        span: source_mod.SourceSpan,
    ) Error!types.ValueId {
        const lhs_node = self.node(lhs) orelse return error.UnknownValue;
        const rhs_node = self.node(rhs) orelse return error.UnknownValue;
        if (!isFieldScalar(lhs_node.key.ty) or !isFieldScalar(rhs_node.key.ty))
            return error.NonFieldOperand;

        var pair = expr.Binary{ .lhs = lhs, .rhs = rhs };
        if ((operation == .add or operation == .mul) and
            types.idIndex(pair.rhs) < types.idIndex(pair.lhs))
        {
            std.mem.swap(types.ValueId, &pair.lhs, &pair.rhs);
        }
        const op = switch (operation) {
            .add => expr.Op{ .add = pair },
            .sub => expr.Op{ .sub = pair },
            .mul => expr.Op{ .mul = pair },
        };
        return self.internNode(.{ .ty = .felt, .op = op }, span);
    }

    fn internNode(
        self: *Arena,
        key: expr.Key,
        span: source_mod.SourceSpan,
    ) Error!types.ValueId {
        try key.ty.validate();
        try self.validateSpan(span);
        if (self.interned_nodes.get(key)) |existing| return existing;

        const id = try types.idFromIndex(types.ValueId, self.nodes.items.len);
        try self.nodes.append(self.allocator, .{
            .key = key,
            .primary_source = span,
        });
        errdefer _ = self.nodes.pop();
        try self.interned_nodes.put(key, id);
        return id;
    }

    /// Package-level transaction support for typed derived-node builders.
    pub fn nodeCheckpoint(self: *const Arena) NodeCheckpoint {
        return .{ .len = self.nodes.items.len };
    }

    pub fn rollbackToNodeCheckpoint(
        self: *Arena,
        checkpoint: NodeCheckpoint,
    ) void {
        std.debug.assert(checkpoint.len <= self.nodes.items.len);
        self.rollbackNodes(checkpoint.len);
    }

    pub fn internCallOutput(
        self: *Arena,
        call_id: types.CallId,
        index: u16,
        ty: types.Type,
        span: source_mod.SourceSpan,
    ) Error!types.ValueId {
        return self.internNode(.{
            .ty = ty,
            .op = .{ .call_output = .{ .call = call_id, .index = index } },
        }, span);
    }

    /// Package-level construction hook for the typed hint builder.
    pub fn internHintOutput(
        self: *Arena,
        hint_id: types.HintId,
        index: u16,
        ty: types.Type,
        span: source_mod.SourceSpan,
    ) Error!types.ValueId {
        return self.internNode(.{
            .ty = ty,
            .op = .{ .hint_output = .{
                .hint = hint_id,
                .index = index,
            } },
        }, span);
    }

    fn rollbackNodes(self: *Arena, starting_len: usize) void {
        while (self.nodes.items.len > starting_len) {
            const removed = self.nodes.pop().?;
            std.debug.assert(self.interned_nodes.remove(removed.key));
        }
    }
};

pub fn isFieldScalar(ty: types.Type) bool {
    return ty.isFieldScalar();
}

pub fn maxUnsignedValue(ty: types.Type) NodeError!u32 {
    return switch (ty) {
        .bit, .selector => 1,
        .byte => std.math.maxInt(u8),
        .uint16 => std.math.maxInt(u16),
        .uint20 => (1 << 20) - 1,
        .register_index => 31,
        .word32, .address, .pc => std.math.maxInt(u32),
        .clock => m31.Modulus - 1,
        .bounded_uint => |bounded| if (bounded.bits == 32)
            std.math.maxInt(u32)
        else
            (@as(u32, 1) << @intCast(bounded.bits)) - 1,
        .felt, .array => error.UnsupportedConstantType,
    };
}

pub fn isSelector(ty: types.Type) bool {
    return ty.isSelector();
}

pub fn requiresAccessOrdinal(kind: program.EffectKind) bool {
    return switch (kind) {
        .register_read,
        .register_write,
        .memory_read,
        .memory_write,
        => true,
        else => false,
    };
}
