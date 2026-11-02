//! Field-generic secure-polynomial DAG, version 2: the compatible extension of
//! `secure_polynomial_program_v1` for AIRs whose shape is not one of v1's six
//! fixed kinds (RV64 Word16 components, truths and service bridges).
//!
//! What v2 keeps from v1, unchanged:
//!   - the `Op` encoding (v2 reuses `v1.Op`) and the meaning of every
//!     polynomial op (constant, input, parameter, add, sub, mul, neg);
//!   - the topological node order (operands precede their users);
//!   - parameters as ordered invocation data, excluded from the identity;
//!   - roots as the ordered constraint residuals, consumed by the composition
//!     fold with reversed random powers.
//! What v2 adds, because v1 cannot express it:
//!   - signed mask offsets per input (Keccak reads rows -2..+2), not only
//!     `previous`;
//!   - per-program column layout (no fixed `Kind` shape table) and larger caps;
//!   - a secure field chosen at compile time: QM31 (degree 4) today, OM31
//!     (degree 8) on the 128-bit route. Constants live in a degree-sized table.
//! `fromV1` lifts every v1 equations program losslessly; a v1 fraction program
//! is refused because v2 is the composition (quotient) IR only.
//!
//! This module is schema and reference semantics only. It never receives a
//! proof wire and never replaces the native evaluator in proving.
const std = @import("std");
const core = @import("stwo_core");
const v1 = @import("secure_polynomial_program_v1.zig");
const M = core.fields.m31.M31;

pub const VERSION: u16 = 2;
pub const MAX_NODES: usize = 1 << 22;
pub const MAX_INPUTS: usize = 1 << 16;
pub const MAX_PARAMETERS: usize = 1 << 16;
pub const MAX_CONSTANTS: usize = 1 << 16;
pub const MAX_ROOTS: usize = 1 << 16;
pub const MAX_TREES: u8 = 3;
pub const Op = v1.Op;
/// One opened mask: committed tree (0 fixed, 1 main, 2 interaction), the
/// component-local column in that tree, and the row offset in trace steps.
pub const Input = struct { tree: u8, column: u32, offset: i8 = 0 };
/// `value` indexes inputs, constants or parameters for leaf ops.
pub const Node = struct { op: Op, lhs: u32 = 0, rhs: u32 = 0, value: u32 = 0 };
pub const Sort = enum(u1) { base, secure };

pub fn degreeOf(comptime Secure: type) usize {
    return @typeInfo(@TypeOf(Secure.zero().toM31Array())).array.len;
}

fn isPolynomialOp(op: Op) bool {
    return switch (op) {
        .constant, .input, .parameter, .add, .sub, .mul, .neg => true,
        .fraction, .range_fraction => false,
    };
}

pub fn ProgramFor(comptime Secure: type) type {
    const D = degreeOf(Secure);
    return struct {
        const Self = @This();
        pub const Field = Secure;
        pub const DEGREE = D;
        a: std.mem.Allocator,
        authority: [32]u8,
        nodes: []Node,
        inputs: []Input,
        constants: [][D]u32,
        parameters: []Secure,
        roots: []u32,
        identity: [32]u8,

        pub fn deinit(self: *Self) void {
            self.a.free(self.nodes);
            self.a.free(self.inputs);
            self.a.free(self.constants);
            self.a.free(self.parameters);
            self.a.free(self.roots);
            self.* = undefined;
        }
        pub fn validate(self: *const Self) !void {
            if (std.mem.allEqual(u8, &self.authority, 0) or self.nodes.len == 0 or self.nodes.len > MAX_NODES or self.inputs.len > MAX_INPUTS or self.constants.len > MAX_CONSTANTS or self.parameters.len > MAX_PARAMETERS or self.roots.len == 0 or self.roots.len > MAX_ROOTS) return error.InvalidSecurePolynomialSchema;
            for (self.inputs) |input| if (input.tree >= MAX_TREES) return error.InvalidSecurePolynomialSchema;
            for (self.constants) |words| for (words) |word| {
                if (word >= core.fields.m31.Modulus) return error.InvalidSecurePolynomialSchema;
            };
            for (self.parameters) |value| for (value.toM31Array()) |word| {
                if (word.toU32() >= core.fields.m31.Modulus) return error.InvalidSecurePolynomialSchema;
            };
            for (self.nodes, 0..) |node, index| switch (node.op) {
                .constant => if (node.value >= self.constants.len) return error.InvalidSecurePolynomialSchema,
                .input => if (node.value >= self.inputs.len) return error.InvalidSecurePolynomialSchema,
                .parameter => if (node.value >= self.parameters.len) return error.InvalidSecurePolynomialSchema,
                .add, .sub, .mul => if (node.lhs >= index or node.rhs >= index) return error.InvalidSecurePolynomialSchema,
                .neg => if (node.lhs >= index) return error.InvalidSecurePolynomialSchema,
                .fraction, .range_fraction => return error.InvalidSecurePolynomialSchema,
            };
            for (self.roots) |root| if (root >= self.nodes.len) return error.InvalidSecurePolynomialSchema;
            if (!std.mem.eql(u8, &self.identity, &self.identityDigest())) return error.InvalidSecurePolynomialIdentity;
        }
        /// Binds field degree, equations, mask routing and source authority.
        /// Parameter values are invocation data; their ordered slots are fixed.
        pub fn identityDigest(self: *const Self) [32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update("stwo/secure-polynomial-program/v2\x00");
            hash.update(&.{@intCast(D)});
            hash.update(&self.authority);
            hashInt(&hash, u32, @intCast(self.inputs.len));
            for (self.inputs) |input| {
                hash.update(&.{ input.tree, @bitCast(input.offset) });
                hashInt(&hash, u32, input.column);
            }
            hashInt(&hash, u32, @intCast(self.constants.len));
            for (self.constants) |words| for (words) |word| hashInt(&hash, u32, word);
            hashInt(&hash, u32, @intCast(self.parameters.len));
            hashInt(&hash, u32, @intCast(self.nodes.len));
            for (self.nodes) |node| {
                hash.update(&.{@intFromEnum(node.op)});
                hashInt(&hash, u32, node.lhs);
                hashInt(&hash, u32, node.rhs);
                hashInt(&hash, u32, node.value);
            }
            hashInt(&hash, u32, @intCast(self.roots.len));
            for (self.roots) |root| hashInt(&hash, u32, root);
            return hash.finalResult();
        }
        pub fn invocationDigest(self: *const Self, trace_log: u32) [32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update("stwo/secure-polynomial-invocation/v2\x00");
            hash.update(&self.identity);
            hashInt(&hash, u32, trace_log);
            for (self.parameters) |value| for (value.toM31Array()) |word| hashInt(&hash, u32, word.toU32());
            return hash.finalResult();
        }
        pub fn constantValue(self: *const Self, index: u32) Secure {
            var words: [D]M = undefined;
            for (&words, self.constants[index]) |*w, v| w.* = M.fromCanonical(v);
            return Secure.fromM31Array(words);
        }
        /// Reference row interpreter. `values` is scratch of nodes.len; the
        /// program must already be validated. Writes one residual per root.
        pub fn evaluateRow(self: *const Self, values: []Secure, inputs: []const Secure, out: []Secure) void {
            std.debug.assert(values.len == self.nodes.len and inputs.len == self.inputs.len and out.len == self.roots.len);
            for (self.nodes, values) |node, *v| v.* = switch (node.op) {
                .constant => self.constantValue(node.value),
                .input => inputs[node.value],
                .parameter => self.parameters[node.value],
                .add => values[node.lhs].add(values[node.rhs]),
                .sub => values[node.lhs].sub(values[node.rhs]),
                .mul => values[node.lhs].mul(values[node.rhs]),
                .neg => values[node.lhs].neg(),
                .fraction, .range_fraction => unreachable,
            };
            for (self.roots, out) |root, *o| o.* = values[root];
        }
        pub fn evaluate(self: *const Self, a: std.mem.Allocator, inputs: []const Secure) ![]Secure {
            try self.validate();
            if (inputs.len != self.inputs.len) return error.InvalidSecurePolynomialInputs;
            const values = try a.alloc(Secure, self.nodes.len);
            defer a.free(values);
            const out = try a.alloc(Secure, self.roots.len);
            self.evaluateRow(values, inputs, out);
            return out;
        }
        /// Per-node sort: inputs and constants with zero extension coordinates
        /// are base; parameters are secure (FS draws and claims).
        pub fn sorts(self: *const Self, a: std.mem.Allocator) ![]Sort {
            const out = try a.alloc(Sort, self.nodes.len);
            for (self.nodes, out) |node, *s| s.* = switch (node.op) {
                .input => .base,
                .constant => if (std.mem.allEqual(u32, self.constants[node.value][1..], 0)) .base else .secure,
                .parameter => .secure,
                .add, .sub, .mul => if (out[node.lhs] == .secure or out[node.rhs] == .secure) .secure else .base,
                .neg => out[node.lhs],
                .fraction, .range_fraction => unreachable,
            };
            return out;
        }
        pub fn degrees(self: *const Self, a: std.mem.Allocator) ![]u16 {
            const out = try a.alloc(u16, self.nodes.len);
            for (self.nodes, out) |node, *d| d.* = switch (node.op) {
                .input => 1,
                .constant, .parameter => 0,
                .add, .sub => @max(out[node.lhs], out[node.rhs]),
                .mul => out[node.lhs] +| out[node.rhs],
                .neg => out[node.lhs],
                .fraction, .range_fraction => unreachable,
            };
            return out;
        }
        pub fn stats(self: *const Self, a: std.mem.Allocator) !Stats {
            const s = try self.sorts(a);
            defer a.free(s);
            const deg = try self.degrees(a);
            defer a.free(deg);
            var result = Stats{ .constraints = self.roots.len, .nodes = self.nodes.len, .inputs = self.inputs.len, .parameters = self.parameters.len, .constants = self.constants.len };
            for (self.nodes, 0..) |node, i| switch (node.op) {
                .add, .sub => if (s[i] == .base) {
                    result.base_additions += 1;
                } else {
                    result.secure_additions += 1;
                },
                .neg => result.negations += 1,
                .mul => {
                    const l = s[node.lhs];
                    const r = s[node.rhs];
                    if (l == .base and r == .base) {
                        result.base_multiplications += 1;
                    } else if (l == .secure and r == .secure) {
                        result.secure_multiplications += 1;
                    } else result.mixed_multiplications += 1;
                },
                else => {},
            };
            var histogram: [8]usize = @splat(0);
            for (self.roots) |root| {
                result.max_degree = @max(result.max_degree, deg[root]);
                histogram[@min(deg[root], 7)] += 1;
                if (s[root] == .secure) result.secure_roots += 1;
            }
            result.degree_histogram = histogram;
            var trees: [MAX_TREES]std.AutoHashMapUnmanaged(u32, void) = @splat(.{});
            defer for (&trees) |*t| t.deinit(a);
            var min_offset: i8 = 0;
            var max_offset: i8 = 0;
            for (self.inputs) |input| {
                try trees[input.tree].put(a, input.column, {});
                min_offset = @min(min_offset, input.offset);
                max_offset = @max(max_offset, input.offset);
                if (input.offset != 0) result.shifted_inputs += 1;
            }
            for (&trees, 0..) |*t, i| result.columns_read[i] = t.count();
            result.min_offset = min_offset;
            result.max_offset = max_offset;
            return result;
        }
    };
}

pub const Stats = struct {
    constraints: usize,
    nodes: usize,
    inputs: usize,
    parameters: usize,
    constants: usize,
    base_additions: usize = 0,
    secure_additions: usize = 0,
    negations: usize = 0,
    base_multiplications: usize = 0,
    mixed_multiplications: usize = 0,
    secure_multiplications: usize = 0,
    max_degree: u16 = 0,
    degree_histogram: [8]usize = @splat(0),
    secure_roots: usize = 0,
    columns_read: [MAX_TREES]usize = @splat(0),
    shifted_inputs: usize = 0,
    min_offset: i8 = 0,
    max_offset: i8 = 0,
};

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

/// Hash-consing recorder with exact algebraic folding. Every rewrite is a
/// field identity (x+0, x*1, x*0, x-x, neg(neg x), literal folding), so the
/// recorded program computes bit-identical residuals.
pub fn BuilderFor(comptime Secure: type) type {
    const D = degreeOf(Secure);
    const Program = ProgramFor(Secure);
    return struct {
        const Self = @This();
        const Key = struct { op: Op, lhs: u32, rhs: u32, value: u32 };
        a: std.mem.Allocator,
        nodes: std.ArrayList(Node) = .empty,
        literal: std.ArrayList(?Secure) = .empty,
        inputs: std.ArrayList(Input) = .empty,
        constants: std.ArrayList([D]u32) = .empty,
        parameters: std.ArrayList(Secure) = .empty,
        interned: std.AutoHashMapUnmanaged(Key, u32) = .{},
        input_slots: std.AutoHashMapUnmanaged(Input, u32) = .{},
        constant_slots: std.AutoHashMapUnmanaged([D]u32, u32) = .{},
        parameter_slots: std.AutoHashMapUnmanaged([D]u32, u32) = .{},
        failure: ?anyerror = null,
        /// Number of lane operations requested before folding/interning.
        requested: usize = 0,

        pub fn init(a: std.mem.Allocator) Self {
            return .{ .a = a };
        }
        pub fn deinit(self: *Self) void {
            self.nodes.deinit(self.a);
            self.literal.deinit(self.a);
            self.inputs.deinit(self.a);
            self.constants.deinit(self.a);
            self.parameters.deinit(self.a);
            self.interned.deinit(self.a);
            self.input_slots.deinit(self.a);
            self.constant_slots.deinit(self.a);
            self.parameter_slots.deinit(self.a);
        }
        fn fail(self: *Self, err: anyerror) u32 {
            if (self.failure == null) self.failure = err;
            return 0;
        }
        fn words(value: Secure) [D]u32 {
            var out: [D]u32 = undefined;
            for (&out, value.toM31Array()) |*w, v| w.* = v.toU32();
            return out;
        }
        fn intern(self: *Self, node: Node, literal: ?Secure) u32 {
            if (self.failure != null) return 0;
            const key = Key{ .op = node.op, .lhs = node.lhs, .rhs = node.rhs, .value = node.value };
            const entry = self.interned.getOrPut(self.a, key) catch |err| return self.fail(err);
            if (entry.found_existing) return entry.value_ptr.*;
            if (self.nodes.items.len >= MAX_NODES) {
                _ = self.interned.remove(key);
                return self.fail(error.SecurePolynomialNodeCap);
            }
            const id: u32 = @intCast(self.nodes.items.len);
            self.nodes.append(self.a, node) catch |err| return self.fail(err);
            self.literal.append(self.a, literal) catch |err| return self.fail(err);
            entry.value_ptr.* = id;
            return id;
        }
        pub fn constant(self: *Self, value: Secure) u32 {
            if (self.failure != null) return 0;
            const w = words(value);
            const entry = self.constant_slots.getOrPut(self.a, w) catch |err| return self.fail(err);
            if (!entry.found_existing) {
                entry.value_ptr.* = @intCast(self.constants.items.len);
                self.constants.append(self.a, w) catch |err| return self.fail(err);
            }
            return self.intern(.{ .op = .constant, .value = entry.value_ptr.* }, value);
        }
        /// Invocation parameter; equal values share one slot.
        pub fn parameter(self: *Self, value: Secure) u32 {
            if (self.failure != null) return 0;
            const w = words(value);
            const entry = self.parameter_slots.getOrPut(self.a, w) catch |err| return self.fail(err);
            if (!entry.found_existing) {
                entry.value_ptr.* = @intCast(self.parameters.items.len);
                self.parameters.append(self.a, value) catch |err| return self.fail(err);
            }
            return self.intern(.{ .op = .parameter, .value = entry.value_ptr.* }, null);
        }
        pub fn input(self: *Self, source: Input) u32 {
            if (self.failure != null) return 0;
            if (source.tree >= MAX_TREES) return self.fail(error.InvalidSecurePolynomialSchema);
            const entry = self.input_slots.getOrPut(self.a, source) catch |err| return self.fail(err);
            if (!entry.found_existing) {
                entry.value_ptr.* = @intCast(self.inputs.items.len);
                self.inputs.append(self.a, source) catch |err| return self.fail(err);
            }
            return self.intern(.{ .op = .input, .value = entry.value_ptr.* }, null);
        }
        fn lit(self: *const Self, id: u32) ?Secure {
            if (self.failure != null) return null;
            return self.literal.items[id];
        }
        fn isLit(self: *const Self, id: u32, value: Secure) bool {
            return if (self.lit(id)) |v| v.eql(value) else false;
        }
        pub fn add(self: *Self, lhs: u32, rhs: u32) u32 {
            self.requested += 1;
            if (self.failure != null) return 0;
            if (self.lit(lhs)) |l| if (self.lit(rhs)) |r| return self.constant(l.add(r));
            if (self.isLit(lhs, Secure.zero())) return rhs;
            if (self.isLit(rhs, Secure.zero())) return lhs;
            return self.intern(.{ .op = .add, .lhs = @min(lhs, rhs), .rhs = @max(lhs, rhs) }, null);
        }
        pub fn sub(self: *Self, lhs: u32, rhs: u32) u32 {
            self.requested += 1;
            if (self.failure != null) return 0;
            if (self.lit(lhs)) |l| if (self.lit(rhs)) |r| return self.constant(l.sub(r));
            if (self.isLit(rhs, Secure.zero())) return lhs;
            if (lhs == rhs) return self.constant(Secure.zero());
            if (self.isLit(lhs, Secure.zero())) return self.negInner(rhs);
            return self.intern(.{ .op = .sub, .lhs = lhs, .rhs = rhs }, null);
        }
        pub fn mul(self: *Self, lhs: u32, rhs: u32) u32 {
            self.requested += 1;
            if (self.failure != null) return 0;
            if (self.lit(lhs)) |l| if (self.lit(rhs)) |r| return self.constant(l.mul(r));
            if (self.isLit(lhs, Secure.zero()) or self.isLit(rhs, Secure.zero())) return self.constant(Secure.zero());
            if (self.isLit(lhs, Secure.one())) return rhs;
            if (self.isLit(rhs, Secure.one())) return lhs;
            const minus_one = Secure.one().neg();
            if (self.isLit(lhs, minus_one)) return self.negInner(rhs);
            if (self.isLit(rhs, minus_one)) return self.negInner(lhs);
            return self.intern(.{ .op = .mul, .lhs = @min(lhs, rhs), .rhs = @max(lhs, rhs) }, null);
        }
        pub fn neg(self: *Self, value: u32) u32 {
            self.requested += 1;
            return self.negInner(value);
        }
        fn negInner(self: *Self, value: u32) u32 {
            if (self.failure != null) return 0;
            if (self.lit(value)) |v| return self.constant(v.neg());
            const node = self.nodes.items[value];
            if (node.op == .neg) return node.lhs;
            return self.intern(.{ .op = .neg, .lhs = value }, null);
        }
        /// Keeps only nodes reachable from `roots`, preserving order, and
        /// compacts inputs/constants/parameters to the used slots.
        pub fn finish(self: *Self, authority: [32]u8, roots: []const u32) !Program {
            if (self.failure) |err| return err;
            const a = self.a;
            const live = try a.alloc(bool, self.nodes.items.len);
            defer a.free(live);
            @memset(live, false);
            for (roots) |root| live[root] = true;
            var i = self.nodes.items.len;
            while (i > 0) {
                i -= 1;
                if (!live[i]) continue;
                const node = self.nodes.items[i];
                switch (node.op) {
                    .add, .sub, .mul => {
                        live[node.lhs] = true;
                        live[node.rhs] = true;
                    },
                    .neg => live[node.lhs] = true,
                    else => {},
                }
            }
            const remap = try a.alloc(u32, self.nodes.items.len);
            defer a.free(remap);
            const input_map = try a.alloc(?u32, self.inputs.items.len);
            defer a.free(input_map);
            @memset(input_map, null);
            const constant_map = try a.alloc(?u32, self.constants.items.len);
            defer a.free(constant_map);
            @memset(constant_map, null);
            const parameter_map = try a.alloc(?u32, self.parameters.items.len);
            defer a.free(parameter_map);
            @memset(parameter_map, null);
            var nodes: std.ArrayList(Node) = .empty;
            errdefer nodes.deinit(a);
            var inputs: std.ArrayList(Input) = .empty;
            errdefer inputs.deinit(a);
            var constants: std.ArrayList([D]u32) = .empty;
            errdefer constants.deinit(a);
            var parameters: std.ArrayList(Secure) = .empty;
            errdefer parameters.deinit(a);
            for (self.nodes.items, 0..) |node, index| {
                if (!live[index]) continue;
                var out = node;
                switch (node.op) {
                    .input => {
                        if (input_map[node.value] == null) {
                            input_map[node.value] = @intCast(inputs.items.len);
                            try inputs.append(a, self.inputs.items[node.value]);
                        }
                        out.value = input_map[node.value].?;
                    },
                    .constant => {
                        if (constant_map[node.value] == null) {
                            constant_map[node.value] = @intCast(constants.items.len);
                            try constants.append(a, self.constants.items[node.value]);
                        }
                        out.value = constant_map[node.value].?;
                    },
                    .parameter => {
                        if (parameter_map[node.value] == null) {
                            parameter_map[node.value] = @intCast(parameters.items.len);
                            try parameters.append(a, self.parameters.items[node.value]);
                        }
                        out.value = parameter_map[node.value].?;
                    },
                    .add, .sub, .mul => {
                        out.lhs = remap[node.lhs];
                        out.rhs = remap[node.rhs];
                    },
                    .neg => out.lhs = remap[node.lhs],
                    .fraction, .range_fraction => unreachable,
                }
                remap[index] = @intCast(nodes.items.len);
                try nodes.append(a, out);
            }
            const mapped = try a.alloc(u32, roots.len);
            errdefer a.free(mapped);
            for (roots, mapped) |root, *m| m.* = remap[root];
            var program = Program{ .a = a, .authority = authority, .nodes = try nodes.toOwnedSlice(a), .inputs = undefined, .constants = undefined, .parameters = undefined, .roots = mapped, .identity = @splat(0) };
            errdefer a.free(program.nodes);
            program.inputs = try inputs.toOwnedSlice(a);
            errdefer a.free(program.inputs);
            program.constants = try constants.toOwnedSlice(a);
            errdefer a.free(program.constants);
            program.parameters = try parameters.toOwnedSlice(a);
            program.identity = program.identityDigest();
            try program.validate();
            return program;
        }
    };
}

/// Lossless lift of a v1 equations program (fixed/main/interaction trees,
/// `previous` → offset -1). Fraction programs are refused.
pub fn fromV1(a: std.mem.Allocator, source: *const v1.Program) !ProgramFor(core.fields.qm31.QM31) {
    try source.validate();
    if (v1.isFraction(source.kind)) return error.SecurePolynomialFractionNotComposition;
    var builder = BuilderFor(core.fields.qm31.QM31).init(a);
    defer builder.deinit();
    const map = try a.alloc(u32, source.nodes.len);
    defer a.free(map);
    // v1 nodes are replayed through the same builder; folding is exact.
    for (source.nodes, map) |node, *out| out.* = switch (node.op) {
        .constant => builder.constant(core.fields.qm31.QM31.fromU32Unchecked(node.words[0], node.words[1], node.words[2], node.words[3])),
        .input => blk: {
            const input = source.inputs[node.value];
            break :blk builder.input(.{ .tree = input.tree, .column = input.column, .offset = if (input.previous) -1 else 0 });
        },
        .parameter => builder.parameter(source.parameters[node.value]),
        .add => builder.add(map[node.lhs], map[node.rhs]),
        .sub => builder.sub(map[node.lhs], map[node.rhs]),
        .mul => builder.mul(map[node.lhs], map[node.rhs]),
        .neg => builder.neg(map[node.lhs]),
        .fraction, .range_fraction => unreachable,
    };
    const roots = try a.alloc(u32, source.roots.len);
    defer a.free(roots);
    for (source.roots, roots) |root, *r| r.* = map[root];
    return builder.finish(source.authority, roots);
}

test "v2 lifts a v1 equations program and evaluates identically" {
    const Q = core.fields.qm31.QM31;
    const a = std.testing.allocator;
    var b = v1.Builder.init(a);
    defer b.deinit();
    const x = b.input(.{ .tree = 1, .column = 3 });
    const y = b.input(.{ .tree = 1, .column = 4, .previous = true });
    const z = b.parameter(Q.fromU32Unchecked(7, 8, 9, 10));
    const r0 = x.mul(y).sub(z).add(v1.Expr.exact(Q.fromU32Unchecked(5, 0, 0, 1)));
    const r1 = x.mul(x).mul(y).neg();
    var roots: [63]v1.Expr = undefined;
    for (&roots, 0..) |*r, i| r.* = if (i % 2 == 0) r0 else r1;
    var old = try b.finish(.word_equations_v4, @splat(1), &roots);
    defer old.deinit();
    var lifted = try fromV1(a, &old);
    defer lifted.deinit();
    const inputs_v1 = [_]Q{ Q.fromU32Unchecked(11, 0, 0, 0), Q.fromU32Unchecked(13, 0, 0, 0) };
    const expected = try old.evaluate(a, &inputs_v1);
    defer a.free(expected);
    try std.testing.expectEqual(@as(usize, 2), lifted.inputs.len);
    try std.testing.expectEqual(@as(i8, -1), lifted.inputs[1].offset);
    const got = try lifted.evaluate(a, &inputs_v1);
    defer a.free(got);
    for (expected, got) |e, g| try std.testing.expect(e.eql(g));
    var forged = lifted;
    forged.identity[0] ^= 1;
    try std.testing.expectError(error.InvalidSecurePolynomialIdentity, forged.validate());
}

test "v2 builder folds exactly and is degree-generic" {
    inline for (.{ core.fields.qm31.QM31, core.fields.om31.OM31 }) |S| {
        const a = std.testing.allocator;
        var b = BuilderFor(S).init(a);
        defer b.deinit();
        const x = b.input(.{ .tree = 1, .column = 0, .offset = 2 });
        const one = b.constant(S.one());
        const zero = b.constant(S.zero());
        try std.testing.expectEqual(x, b.mul(x, one));
        try std.testing.expectEqual(x, b.add(zero, x));
        try std.testing.expectEqual(zero, b.mul(x, zero));
        try std.testing.expectEqual(zero, b.sub(x, x));
        const p = b.parameter(S.one().add(S.one()));
        const t = b.mul(x, p);
        try std.testing.expectEqual(t, b.mul(p, x));
        var program = try b.finish(@splat(2), &.{ t, b.neg(b.neg(t)) });
        defer program.deinit();
        try std.testing.expectEqual(@as(usize, 3), program.nodes.len);
        const stats = try program.stats(a);
        try std.testing.expectEqual(@as(usize, 1), stats.mixed_multiplications);
        try std.testing.expectEqual(@as(i8, 2), stats.max_offset);
    }
}
