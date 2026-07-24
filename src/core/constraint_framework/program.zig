//! Canonical, backend-neutral instruction form for symbolic AIR constraints.
//!
//! Frontends build pointer-based expressions with `ExprEvaluator`. Backends
//! consume this owned, topologically ordered form without retaining an arena,
//! interpreting workload names, or reparsing formatted source.

const std = @import("std");
const evaluator_mod = @import("evaluator.zig");
const expr = @import("expr.zig");
const M31 = @import("../fields/m31.zig").M31;
const QM31 = @import("../fields/qm31.zig").QM31;

pub const Digest = [32]u8;

pub const BinaryOperands = struct {
    lhs: u32,
    rhs: u32,
};

pub const BaseInstruction = union(enum(u8)) {
    column: expr.ColumnExpr,
    constant: M31,
    parameter: u32,
    add: BinaryOperands,
    sub: BinaryOperands,
    mul: BinaryOperands,
    neg: u32,
    inv: u32,
};

pub const SecureColumnOperands = [4]u32;

pub const ExtInstruction = union(enum(u8)) {
    secure_column: SecureColumnOperands,
    constant: QM31,
    parameter: u32,
    add: BinaryOperands,
    sub: BinaryOperands,
    mul: BinaryOperands,
    neg: u32,
};

pub const Error = error{
    CyclicIntermediate,
    DuplicateParameter,
    EmptyConstraintProgram,
    EmptyParameter,
    InvalidBaseInstruction,
    InvalidConstraintRoot,
    InvalidExtInstruction,
    ProgramTooLarge,
} || std.mem.Allocator.Error || expr.EvalError;

pub const Program = struct {
    base: []BaseInstruction,
    extension: []ExtInstruction,
    base_parameters: [][]u8,
    extension_parameters: [][]u8,
    constraint_roots: []u32,

    pub fn deinit(self: *Program, allocator: std.mem.Allocator) void {
        for (self.base_parameters) |name| allocator.free(name);
        for (self.extension_parameters) |name| allocator.free(name);
        allocator.free(self.base_parameters);
        allocator.free(self.extension_parameters);
        allocator.free(self.constraint_roots);
        allocator.free(self.extension);
        allocator.free(self.base);
        self.* = undefined;
    }

    pub fn validate(self: *const Program) Error!void {
        if (self.constraint_roots.len == 0)
            return error.EmptyConstraintProgram;
        try validateParameterNames(self.base_parameters);
        try validateParameterNames(self.extension_parameters);
        for (self.base, 0..) |instruction, index| {
            const limit: u32 = @intCast(index);
            switch (instruction) {
                .column, .constant => {},
                .parameter => |parameter| {
                    if (parameter >= self.base_parameters.len)
                        return error.InvalidBaseInstruction;
                },
                .add, .sub, .mul => |operands| {
                    if (operands.lhs >= limit or operands.rhs >= limit)
                        return error.InvalidBaseInstruction;
                },
                .neg, .inv => |operand| {
                    if (operand >= limit) return error.InvalidBaseInstruction;
                },
            }
        }
        for (self.extension, 0..) |instruction, index| {
            const limit: u32 = @intCast(index);
            switch (instruction) {
                .constant => {},
                .parameter => |parameter| {
                    if (parameter >= self.extension_parameters.len)
                        return error.InvalidExtInstruction;
                },
                .secure_column => |operands| {
                    for (operands) |operand| {
                        if (operand >= self.base.len)
                            return error.InvalidExtInstruction;
                    }
                },
                .add, .sub, .mul => |operands| {
                    if (operands.lhs >= limit or operands.rhs >= limit)
                        return error.InvalidExtInstruction;
                },
                .neg => |operand| {
                    if (operand >= limit) return error.InvalidExtInstruction;
                },
            }
        }
        for (self.constraint_roots) |root| {
            if (root >= self.extension.len)
                return error.InvalidConstraintRoot;
        }
    }

    pub fn semanticDigest(self: *const Program) Error!Digest {
        try self.validate();
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-zig/constraint-program/v1");
        hashNames(&hash, self.base_parameters);
        hashNames(&hash, self.extension_parameters);
        hashU64(&hash, self.base.len);
        for (self.base) |instruction| hashBase(&hash, instruction);
        hashU64(&hash, self.extension.len);
        for (self.extension) |instruction| hashExt(&hash, instruction);
        hashU64(&hash, self.constraint_roots.len);
        for (self.constraint_roots) |root| hashU32(&hash, root);
        return hash.finalResult();
    }

    pub fn evaluate(
        self: *const Program,
        allocator: std.mem.Allocator,
        assignment: *const expr.Assignment,
    ) Error![]QM31 {
        try self.validate();
        const base_values = try allocator.alloc(M31, self.base.len);
        defer allocator.free(base_values);
        for (self.base, 0..) |instruction, index| {
            base_values[index] = switch (instruction) {
                .column => |column| assignment.columns.get(column) orelse
                    return error.MissingColumn,
                .constant => |value| value,
                .parameter => |parameter| assignment.params.get(
                    self.base_parameters[parameter],
                ) orelse return error.MissingParam,
                .add => |operands| base_values[operands.lhs].add(
                    base_values[operands.rhs],
                ),
                .sub => |operands| base_values[operands.lhs].sub(
                    base_values[operands.rhs],
                ),
                .mul => |operands| base_values[operands.lhs].mul(
                    base_values[operands.rhs],
                ),
                .neg => |operand| base_values[operand].neg(),
                .inv => |operand| base_values[operand].inv() catch
                    return error.DivisionByZero,
            };
        }

        const ext_values = try allocator.alloc(QM31, self.extension.len);
        defer allocator.free(ext_values);
        for (self.extension, 0..) |instruction, index| {
            ext_values[index] = switch (instruction) {
                .secure_column => |operands| QM31.fromM31Array(.{
                    base_values[operands[0]],
                    base_values[operands[1]],
                    base_values[operands[2]],
                    base_values[operands[3]],
                }),
                .constant => |value| value,
                .parameter => |parameter| assignment.ext_params.get(
                    self.extension_parameters[parameter],
                ) orelse return error.MissingExtParam,
                .add => |operands| ext_values[operands.lhs].add(
                    ext_values[operands.rhs],
                ),
                .sub => |operands| ext_values[operands.lhs].sub(
                    ext_values[operands.rhs],
                ),
                .mul => |operands| ext_values[operands.lhs].mul(
                    ext_values[operands.rhs],
                ),
                .neg => |operand| ext_values[operand].neg(),
            };
        }

        const result = try allocator.alloc(QM31, self.constraint_roots.len);
        for (self.constraint_roots, result) |root, *value| {
            value.* = ext_values[root];
        }
        return result;
    }
};

pub fn lower(
    allocator: std.mem.Allocator,
    source: *const evaluator_mod.ExprEvaluator,
) Error!Program {
    if (source.constraints.items.len == 0)
        return error.EmptyConstraintProgram;
    var builder = Builder.init(allocator, source);
    defer builder.deinit();

    for (source.constraints.items) |constraint| {
        const root = try builder.lowerExt(constraint);
        try builder.constraint_roots.append(allocator, root);
    }
    var program = try builder.finish();
    errdefer program.deinit(allocator);
    try program.validate();
    return program;
}

const Builder = struct {
    allocator: std.mem.Allocator,
    source: *const evaluator_mod.ExprEvaluator,
    base: std.ArrayList(BaseInstruction),
    extension: std.ArrayList(ExtInstruction),
    base_parameters: std.ArrayList([]u8),
    extension_parameters: std.ArrayList([]u8),
    constraint_roots: std.ArrayList(u32),
    base_nodes: std.AutoHashMap(expr.BaseExpr, u32),
    ext_nodes: std.AutoHashMap(expr.ExtExpr, u32),
    base_parameter_ids: std.StringHashMap(u32),
    ext_parameter_ids: std.StringHashMap(u32),
    active_base_intermediates: std.StringHashMap(void),
    active_ext_intermediates: std.StringHashMap(void),

    fn init(
        allocator: std.mem.Allocator,
        source: *const evaluator_mod.ExprEvaluator,
    ) Builder {
        return .{
            .allocator = allocator,
            .source = source,
            .base = .empty,
            .extension = .empty,
            .base_parameters = .empty,
            .extension_parameters = .empty,
            .constraint_roots = .empty,
            .base_nodes = std.AutoHashMap(expr.BaseExpr, u32).init(allocator),
            .ext_nodes = std.AutoHashMap(expr.ExtExpr, u32).init(allocator),
            .base_parameter_ids = std.StringHashMap(u32).init(allocator),
            .ext_parameter_ids = std.StringHashMap(u32).init(allocator),
            .active_base_intermediates = std.StringHashMap(void).init(allocator),
            .active_ext_intermediates = std.StringHashMap(void).init(allocator),
        };
    }

    fn deinit(self: *Builder) void {
        for (self.base_parameters.items) |name| self.allocator.free(name);
        for (self.extension_parameters.items) |name| self.allocator.free(name);
        self.base_parameters.deinit(self.allocator);
        self.extension_parameters.deinit(self.allocator);
        self.constraint_roots.deinit(self.allocator);
        self.base.deinit(self.allocator);
        self.extension.deinit(self.allocator);
        self.base_nodes.deinit();
        self.ext_nodes.deinit();
        self.base_parameter_ids.deinit();
        self.ext_parameter_ids.deinit();
        self.active_base_intermediates.deinit();
        self.active_ext_intermediates.deinit();
    }

    fn finish(self: *Builder) !Program {
        const base = try self.base.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(base);
        const extension = try self.extension.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(extension);
        const base_parameters = try self.base_parameters.toOwnedSlice(self.allocator);
        errdefer {
            for (base_parameters) |name| self.allocator.free(name);
            self.allocator.free(base_parameters);
        }
        const extension_parameters = try self.extension_parameters.toOwnedSlice(
            self.allocator,
        );
        errdefer {
            for (extension_parameters) |name| self.allocator.free(name);
            self.allocator.free(extension_parameters);
        }
        const constraint_roots = try self.constraint_roots.toOwnedSlice(
            self.allocator,
        );
        return .{
            .base = base,
            .extension = extension,
            .base_parameters = base_parameters,
            .extension_parameters = extension_parameters,
            .constraint_roots = constraint_roots,
        };
    }

    fn appendBase(self: *Builder, instruction: BaseInstruction) Error!u32 {
        if (self.base.items.len >= std.math.maxInt(u32))
            return error.ProgramTooLarge;
        const index: u32 = @intCast(self.base.items.len);
        try self.base.append(self.allocator, instruction);
        return index;
    }

    fn appendExt(self: *Builder, instruction: ExtInstruction) Error!u32 {
        if (self.extension.items.len >= std.math.maxInt(u32))
            return error.ProgramTooLarge;
        const index: u32 = @intCast(self.extension.items.len);
        try self.extension.append(self.allocator, instruction);
        return index;
    }

    fn lowerBase(self: *Builder, node: expr.BaseExpr) Error!u32 {
        if (self.base_nodes.get(node)) |index| return index;
        const instruction: BaseInstruction = switch (node.*) {
            .col => |column| .{ .column = column },
            .constant => |value| .{ .constant = value },
            .param => |name| blk: {
                if (self.source.intermediates.get(name)) |intermediate| {
                    if (self.active_base_intermediates.contains(name))
                        return error.CyclicIntermediate;
                    try self.active_base_intermediates.put(name, {});
                    defer _ = self.active_base_intermediates.remove(name);
                    const index = try self.lowerBase(intermediate);
                    try self.base_nodes.put(node, index);
                    return index;
                }
                break :blk .{ .parameter = try self.baseParameter(name) };
            },
            .add => |operands| .{ .add = .{
                .lhs = try self.lowerBase(operands.lhs),
                .rhs = try self.lowerBase(operands.rhs),
            } },
            .sub => |operands| .{ .sub = .{
                .lhs = try self.lowerBase(operands.lhs),
                .rhs = try self.lowerBase(operands.rhs),
            } },
            .mul => |operands| .{ .mul = .{
                .lhs = try self.lowerBase(operands.lhs),
                .rhs = try self.lowerBase(operands.rhs),
            } },
            .neg => |operand| .{ .neg = try self.lowerBase(operand) },
            .inv => |operand| .{ .inv = try self.lowerBase(operand) },
        };
        const index = try self.appendBase(instruction);
        try self.base_nodes.put(node, index);
        return index;
    }

    fn lowerExt(self: *Builder, node: expr.ExtExpr) Error!u32 {
        if (self.ext_nodes.get(node)) |index| return index;
        const instruction: ExtInstruction = switch (node.*) {
            .secure_col => |operands| .{ .secure_column = .{
                try self.lowerBase(operands[0]),
                try self.lowerBase(operands[1]),
                try self.lowerBase(operands[2]),
                try self.lowerBase(operands[3]),
            } },
            .constant => |value| .{ .constant = value },
            .param => |name| blk: {
                if (self.source.ext_intermediates.get(name)) |intermediate| {
                    if (self.active_ext_intermediates.contains(name))
                        return error.CyclicIntermediate;
                    try self.active_ext_intermediates.put(name, {});
                    defer _ = self.active_ext_intermediates.remove(name);
                    const index = try self.lowerExt(intermediate);
                    try self.ext_nodes.put(node, index);
                    return index;
                }
                break :blk .{ .parameter = try self.extParameter(name) };
            },
            .add => |operands| .{ .add = .{
                .lhs = try self.lowerExt(operands.lhs),
                .rhs = try self.lowerExt(operands.rhs),
            } },
            .sub => |operands| .{ .sub = .{
                .lhs = try self.lowerExt(operands.lhs),
                .rhs = try self.lowerExt(operands.rhs),
            } },
            .mul => |operands| .{ .mul = .{
                .lhs = try self.lowerExt(operands.lhs),
                .rhs = try self.lowerExt(operands.rhs),
            } },
            .neg => |operand| .{ .neg = try self.lowerExt(operand) },
        };
        const index = try self.appendExt(instruction);
        try self.ext_nodes.put(node, index);
        return index;
    }

    fn baseParameter(self: *Builder, name: []const u8) Error!u32 {
        if (name.len == 0) return error.EmptyParameter;
        if (self.base_parameter_ids.get(name)) |index| return index;
        if (self.base_parameters.items.len >= std.math.maxInt(u32))
            return error.ProgramTooLarge;
        const owned = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned);
        const index: u32 = @intCast(self.base_parameters.items.len);
        try self.base_parameters.append(self.allocator, owned);
        errdefer _ = self.base_parameters.pop();
        try self.base_parameter_ids.put(owned, index);
        return index;
    }

    fn extParameter(self: *Builder, name: []const u8) Error!u32 {
        if (name.len == 0) return error.EmptyParameter;
        if (self.ext_parameter_ids.get(name)) |index| return index;
        if (self.extension_parameters.items.len >= std.math.maxInt(u32))
            return error.ProgramTooLarge;
        const owned = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned);
        const index: u32 = @intCast(self.extension_parameters.items.len);
        try self.extension_parameters.append(self.allocator, owned);
        errdefer _ = self.extension_parameters.pop();
        try self.ext_parameter_ids.put(owned, index);
        return index;
    }
};

fn validateParameterNames(names: []const []u8) Error!void {
    for (names, 0..) |name, index| {
        if (name.len == 0) return error.EmptyParameter;
        for (names[0..index]) |prior| {
            if (std.mem.eql(u8, name, prior))
                return error.DuplicateParameter;
        }
    }
}

fn hashNames(hash: anytype, names: []const []u8) void {
    hashU64(hash, names.len);
    for (names) |name| {
        hashU64(hash, name.len);
        hash.update(name);
    }
}

fn hashBase(hash: anytype, instruction: BaseInstruction) void {
    hash.update(&.{@intFromEnum(std.meta.activeTag(instruction))});
    switch (instruction) {
        .column => |column| {
            hashU64(hash, column.interaction);
            hashU64(hash, column.idx);
            hashI64(hash, column.offset);
        },
        .constant => |value| hashU32(hash, value.toU32()),
        .parameter, .neg, .inv => |value| hashU32(hash, value),
        .add, .sub, .mul => |operands| {
            hashU32(hash, operands.lhs);
            hashU32(hash, operands.rhs);
        },
    }
}

fn hashExt(hash: anytype, instruction: ExtInstruction) void {
    hash.update(&.{@intFromEnum(std.meta.activeTag(instruction))});
    switch (instruction) {
        .secure_column => |operands| for (operands) |value| hashU32(hash, value),
        .constant => |value| for (value.toM31Array()) |limb| {
            hashU32(hash, limb.toU32());
        },
        .parameter, .neg => |value| hashU32(hash, value),
        .add, .sub, .mul => |operands| {
            hashU32(hash, operands.lhs);
            hashU32(hash, operands.rhs);
        },
    }
}

fn hashU32(hash: anytype, value: anytype) void {
    var encoded: [4]u8 = undefined;
    std.mem.writeInt(u32, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

fn hashU64(hash: anytype, value: anytype) void {
    var encoded: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

fn hashI64(hash: anytype, value: anytype) void {
    var encoded: [8]u8 = undefined;
    std.mem.writeInt(i64, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}
