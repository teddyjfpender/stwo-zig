//! Bounded secure-field DAG exported from typed Algebra, with explicit shifted
//! PCS inputs. This is executable schema admission, never a proof receipt.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
pub const VERSION: u16 = 1;
pub const MAX_NODES = 65536;
pub const MAX_PARAMETERS = 16384;
pub const MAX_INPUTS = 512; // Canonical lanes require 24+54+9+2*92 = 271.
// Append-only: the legacy executable identities retain their numeric kinds.
pub const Kind = enum(u8) { word_equations_v4, word_fractions_v4, range16_equations_v4, range16_fractions_v4, ram_lanes_equations_v1, ram_lanes_fractions_v1 };
pub const Layout = struct { fixed: u16, main: u16, interaction: u16, roots: u16, expansion_bits: u8 };
pub fn layout(kind: Kind) Layout {
    return switch (kind) {
        .word_equations_v4 => .{ .fixed = 12, .main = 27, .interaction = 68, .roots = 63, .expansion_bits = 2 },
        .word_fractions_v4 => .{ .fixed = 12, .main = 27, .interaction = 0, .roots = 17, .expansion_bits = 0 },
        .range16_equations_v4 => .{ .fixed = 1, .main = 1, .interaction = 8, .roots = 2, .expansion_bits = 1 },
        .range16_fractions_v4 => .{ .fixed = 1, .main = 1, .interaction = 0, .roots = 2, .expansion_bits = 0 },
        .ram_lanes_equations_v1 => .{ .fixed = 24, .main = 54, .interaction = 92, .roots = 117, .expansion_bits = 2 },
        .ram_lanes_fractions_v1 => .{ .fixed = 24, .main = 54, .interaction = 0, .roots = 23, .expansion_bits = 0 },
    };
}
pub const Input = struct { tree: u8, column: u16, previous: bool = false };
pub const Op = enum(u8) { constant, input, parameter, add, sub, mul, neg, fraction, range_fraction };
pub const Node = struct { op: Op, lhs: u32 = 0, rhs: u32 = 0, value: u32 = 0, words: [4]u32 = @splat(0) };
pub fn isFraction(kind: Kind) bool {
    return kind == .word_fractions_v4 or kind == .range16_fractions_v4 or kind == .ram_lanes_fractions_v1;
}
pub fn previousMainAllowed(kind: Kind, column: u16) bool {
    const word_column: u16 = switch (kind) {
        .word_equations_v4, .word_fractions_v4 => column,
        .ram_lanes_equations_v1, .ram_lanes_fractions_v1 => if (column >= 27 and column < 54) column - 27 else return false,
        else => return false,
    };
    return (word_column >= 2 and word_column < 9) or word_column == 25 or word_column == 26;
}
pub const Program = struct {
    a: std.mem.Allocator,
    kind: Kind,
    authority: [32]u8,
    nodes: []Node,
    inputs: []Input,
    roots: []u32,
    parameters: []Q,
    identity: [32]u8,
    pub fn deinit(self: *Program) void {
        self.a.free(self.nodes);
        self.a.free(self.inputs);
        self.a.free(self.roots);
        self.a.free(self.parameters);
        self.* = undefined;
    }
    pub fn validate(self: *const Program) !void {
        const shape = layout(self.kind);
        if (std.mem.allEqual(u8, &self.authority, 0) or self.nodes.len == 0 or self.nodes.len > MAX_NODES or self.inputs.len == 0 or self.inputs.len > MAX_INPUTS or self.parameters.len > MAX_PARAMETERS or self.roots.len != shape.roots) return error.InvalidSecurePolynomialSchema;
        for (self.inputs) |input| {
            const count: usize = switch (input.tree) {
                0 => shape.fixed,
                1 => shape.main,
                2 => shape.interaction,
                else => return error.InvalidSecurePolynomialSchema,
            };
            if (input.column >= count or (input.previous and input.tree == 0)) return error.InvalidSecurePolynomialSchema;
            if (input.previous and input.tree == 1 and !previousMainAllowed(self.kind, input.column)) return error.InvalidSecurePolynomialSchema;
        }
        for (self.nodes, 0..) |node, index| switch (node.op) {
            .constant => for (node.words) |word| {
                if (word >= core.fields.m31.Modulus) return error.InvalidSecurePolynomialSchema;
            },
            .input => if (node.value >= self.inputs.len) return error.InvalidSecurePolynomialSchema,
            .parameter => if (node.value >= self.parameters.len) return error.InvalidSecurePolynomialSchema,
            .add, .sub, .mul, .fraction => {
                if (node.lhs >= index or node.rhs >= index or (node.op == .fraction and !isFraction(self.kind))) return error.InvalidSecurePolynomialSchema;
            },
            .range_fraction => {
                if (!isFraction(self.kind) or node.lhs >= index or node.rhs >= index or node.value >= index or self.nodes[node.value].op != .parameter) return error.InvalidSecurePolynomialSchema;
            },
            .neg => if (node.lhs >= index) return error.InvalidSecurePolynomialSchema,
        };
        for (self.parameters) |value| for (value.toM31Array()) |word| {
            if (word.toU32() >= core.fields.m31.Modulus) return error.InvalidSecurePolynomialSchema;
        };
        for (self.roots) |root| if (root >= self.nodes.len) return error.InvalidSecurePolynomialSchema;
        if (!std.mem.eql(u8, &self.identity, &self.identityDigest())) return error.InvalidSecurePolynomialIdentity;
    }
    /// Identity binds equations, routing, ABI and typed source. Dynamic public
    /// values are invocation data; their ordered schema slots remain fixed.
    pub fn identityDigest(self: *const Program) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo/secure-polynomial-program/v1\x00");
        hash.update(&.{@intFromEnum(self.kind)});
        hash.update(&self.authority);
        hashInt(&hash, u32, @intCast(self.inputs.len));
        for (self.inputs) |input| {
            hash.update(&.{ input.tree, @intFromBool(input.previous) });
            hashInt(&hash, u16, input.column);
        }
        hashInt(&hash, u32, @intCast(self.parameters.len));
        hashInt(&hash, u32, @intCast(self.nodes.len));
        for (self.nodes) |node| {
            hash.update(&.{@intFromEnum(node.op)});
            hashInt(&hash, u32, node.lhs);
            hashInt(&hash, u32, node.rhs);
            hashInt(&hash, u32, node.value);
            for (node.words) |word| hashInt(&hash, u32, word);
        }
        for (self.roots) |root| hashInt(&hash, u32, root);
        return hash.finalResult();
    }
    pub fn invocationDigest(self: *const Program, trace_log: u32) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo/secure-polynomial-invocation/v1\x00");
        hash.update(&self.identity);
        hashInt(&hash, u32, trace_log);
        for (self.parameters) |value| for (value.toM31Array()) |word| hashInt(&hash, u32, word.toU32());
        return hash.finalResult();
    }
    pub fn rangeChallenge(self: *const Program) !?Q {
        try self.validate();
        var result: ?Q = null;
        for (self.nodes) |node| if (node.op == .range_fraction) {
            const z = self.parameters[self.nodes[node.value].value];
            if (result) |prior| {
                if (!prior.eql(z)) return error.SecureRangeChallengeMismatch;
            } else result = z;
        };
        return result;
    }
    pub fn evaluate(self: *const Program, a: std.mem.Allocator, inputs: []const Q) ![]Q {
        try self.validate();
        if (inputs.len != self.inputs.len) return error.InvalidSecurePolynomialInputs;
        const values = try a.alloc(Q, self.nodes.len);
        defer a.free(values);
        for (self.nodes, values) |node, *out| out.* = switch (node.op) {
            .constant => Q.fromU32Unchecked(node.words[0], node.words[1], node.words[2], node.words[3]),
            .input => inputs[node.value],
            .parameter => self.parameters[node.value],
            .add => values[node.lhs].add(values[node.rhs]),
            .sub => values[node.lhs].sub(values[node.rhs]),
            .mul => values[node.lhs].mul(values[node.rhs]),
            .neg => values[node.lhs].neg(),
            .fraction => if (values[node.lhs].isZero()) Q.zero() else values[node.lhs].mul(try values[node.rhs].inv()),
            .range_fraction => blk: {
                if (values[node.lhs].isZero()) break :blk Q.zero();
                const value = values[node.rhs];
                if (!value.isBase() or value.toM31Array()[0].toU32() >= 65536) return error.InvalidSecureRangeValue;
                break :blk values[node.lhs].mul(try value.sub(values[node.value]).inv());
            },
        };
        const result = try a.alloc(Q, self.roots.len);
        for (self.roots, result) |root, *out| out.* = values[root];
        return result;
    }
};
fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}
pub const Builder = struct {
    a: std.mem.Allocator,
    nodes: std.ArrayList(Node) = .empty,
    inputs: std.ArrayList(Input) = .empty,
    parameters: std.ArrayList(Q) = .empty,
    failure: ?anyerror = null,
    pub fn init(a: std.mem.Allocator) Builder {
        return .{ .a = a };
    }
    pub fn deinit(self: *Builder) void {
        self.nodes.deinit(self.a);
        self.inputs.deinit(self.a);
        self.parameters.deinit(self.a);
    }
    fn fail(self: *Builder, err: anyerror) u32 {
        if (self.failure == null) self.failure = err;
        return 0;
    }
    fn record(self: *Builder, node: Node) u32 {
        if (self.failure != null) return 0;
        if (self.nodes.items.len >= MAX_NODES) return self.fail(error.SecurePolynomialNodeCap);
        self.nodes.append(self.a, node) catch |err| return self.fail(err);
        return @intCast(self.nodes.items.len - 1);
    }
    pub fn input(self: *Builder, source: Input) Expr {
        if (self.failure != null) return .{ .owner = self };
        if (self.inputs.items.len >= MAX_INPUTS) return .{ .owner = self, .id = self.fail(error.SecurePolynomialInputCap) };
        const slot: u32 = @intCast(self.inputs.items.len);
        self.inputs.append(self.a, source) catch |err| return .{ .owner = self, .id = self.fail(err) };
        return .{ .owner = self, .id = self.record(.{ .op = .input, .value = slot }) };
    }
    pub fn parameter(self: *Builder, value: Q) Expr {
        return .{ .owner = self, .id = self.resolve(Expr.splat(value)) };
    }
    fn resolve(self: *Builder, expression: Expr) u32 {
        if (self.failure != null) return 0;
        if (expression.owner) |owner| return if (owner == self) expression.id else self.fail(error.ForeignSecurePolynomialExpression);
        if (expression.dynamic) {
            if (self.parameters.items.len >= MAX_PARAMETERS) return self.fail(error.SecurePolynomialParameterCap);
            const slot: u32 = @intCast(self.parameters.items.len);
            self.parameters.append(self.a, expression.literal) catch |err| return self.fail(err);
            return self.record(.{ .op = .parameter, .value = slot });
        }
        var words: [4]u32 = undefined;
        for (expression.literal.toM31Array(), &words) |value, *word| word.* = value.toU32();
        return self.record(.{ .op = .constant, .words = words });
    }
    pub fn finish(self: *Builder, kind: Kind, authority: [32]u8, expressions: []const Expr) !Program {
        const roots = try self.a.alloc(u32, expressions.len);
        errdefer self.a.free(roots);
        for (expressions, roots) |expression, *root| root.* = self.resolve(expression);
        if (self.failure) |err| return err;
        const nodes = try self.nodes.toOwnedSlice(self.a);
        errdefer self.a.free(nodes);
        const inputs = try self.inputs.toOwnedSlice(self.a);
        errdefer self.a.free(inputs);
        const parameters = try self.parameters.toOwnedSlice(self.a);
        errdefer self.a.free(parameters);
        var result = Program{ .a = self.a, .kind = kind, .authority = authority, .nodes = nodes, .inputs = inputs, .roots = roots, .parameters = parameters, .identity = @splat(0) };
        result.identity = result.identityDigest();
        try result.validate();
        return result;
    }
};
pub const Expr = struct {
    owner: ?*Builder = null,
    id: u32 = 0,
    literal: Q = Q.zero(),
    dynamic: bool = false,
    pub fn zero() Expr {
        return .{};
    }
    pub fn one() Expr {
        return .{ .literal = Q.one() };
    }
    /// Typed public/challenge constants become ordered invocation parameters,
    /// never fixed instance literals in a reusable device executable.
    pub fn splat(value: Q) Expr {
        return .{ .literal = value, .dynamic = true };
    }
    /// Public Boolean policy is an invocation slot, even at zero. Choosing a
    /// different shard boundary must never silently select another executable.
    pub fn publicFlag(value: bool) Expr {
        return splat(if (value) Q.one() else Q.zero());
    }
    pub fn exact(value: Q) Expr {
        return .{ .literal = value };
    }
    fn binary(lhs: Expr, rhs: Expr, op: Op) Expr {
        const maybe_owner: ?*Builder = if (lhs.owner) |owner| owner else rhs.owner;
        if (maybe_owner) |owner| {
            const left = owner.resolve(lhs);
            const right = owner.resolve(rhs);
            return .{ .owner = owner, .id = owner.record(.{ .op = op, .lhs = left, .rhs = right }) };
        }
        const value = switch (op) {
            .add => lhs.literal.add(rhs.literal),
            .sub => lhs.literal.sub(rhs.literal),
            .mul => lhs.literal.mul(rhs.literal),
            else => unreachable,
        };
        return .{ .literal = value, .dynamic = lhs.dynamic or rhs.dynamic };
    }
    pub fn add(lhs: Expr, rhs: Expr) Expr {
        return binary(lhs, rhs, .add);
    }
    pub fn sub(lhs: Expr, rhs: Expr) Expr {
        return binary(lhs, rhs, .sub);
    }
    pub fn mul(lhs: Expr, rhs: Expr) Expr {
        return binary(lhs, rhs, .mul);
    }
    pub fn neg(self: Expr) Expr {
        if (self.owner) |owner| return .{ .owner = owner, .id = owner.record(.{ .op = .neg, .lhs = self.id }) };
        return .{ .literal = self.literal.neg(), .dynamic = self.dynamic };
    }
    pub fn fraction(numerator: Expr, denominator: Expr) Expr {
        const owner = numerator.owner orelse denominator.owner orelse unreachable;
        const left = owner.resolve(numerator);
        const right = owner.resolve(denominator);
        return .{ .owner = owner, .id = owner.record(.{ .op = .fraction, .lhs = left, .rhs = right }) };
    }
    /// Explicit arity-one range bus. The challenge must be a bound dynamic
    /// parameter so one authenticated resident table can service every row.
    pub fn rangeFraction(numerator: Expr, value: Expr, z: Expr) Expr {
        const owner = numerator.owner orelse value.owner orelse unreachable;
        const left = owner.resolve(numerator);
        const right = owner.resolve(value);
        const challenge = owner.resolve(z);
        return .{ .owner = owner, .id = owner.record(.{ .op = .range_fraction, .lhs = left, .rhs = right, .value = challenge }) };
    }
    pub fn fromPartialEvals(values: [4]Expr) Expr {
        return values[0].add(values[1].mul(exact(Q.fromU32Unchecked(0, 1, 0, 0)))).add(values[2].mul(exact(Q.fromU32Unchecked(0, 0, 1, 0)))).add(values[3].mul(exact(Q.fromU32Unchecked(0, 0, 0, 1))));
    }
};
