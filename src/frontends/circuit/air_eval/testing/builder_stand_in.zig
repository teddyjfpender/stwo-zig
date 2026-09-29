//! TEMPORARY test-only stand-in for the M2 circuit builder
//! (`src/frontends/circuit/builder/`, branch `recursion/m2`), which had not
//! landed when the evaluator interpreter was written. Delete this file when
//! `recursion/m2` is merged and point the R3 driver at `builder.Context`.
//!
//! It implements exactly the builder surface the in-circuit evaluators call,
//! with Rust's semantics (`crates/circuits/src/{context,ops,circuit}.rs` of
//! https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230):
//!
//! - vars 0, 1, 2 are the interned constants zero, one and `u`; `u` is output;
//! - constants are interned in first-use order;
//! - `add` returns the other operand when either is var 0; `mul` returns var 0
//!   when either is var 0 and the other operand when either is var 1; `sub`
//!   never elides; there is no value folding;
//! - `inv` guesses `1 / b`, then emits `mul(b, b_inv)` and `eq(_, one)`.
//!
//! It also summarizes a circuit with the oracle's gate-list contract
//! (`vectors/circuit/README.md`) and the upstream `Debug` text. Only the gate
//! kinds the evaluators emit are stored; the other kinds hash as empty.

const std = @import("std");
const stwo_core = @import("stwo_core");

const QM31 = stwo_core.fields.qm31.QM31;
const M31 = stwo_core.fields.m31.M31;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// A circuit variable: its index in the value table.
pub const Wire = struct { idx: u32 };

/// Topology mode: no values are carried.
pub const NoValue = struct {};

const Binary = struct { in0: u32, in1: u32, out: u32 };
const EqGate = struct { in0: u32, in1: u32 };

pub fn Context(comptime V: type) type {
    comptime std.debug.assert(V == QM31 or V == NoValue);
    return struct {
        const Self = @This();
        pub const Var = Wire;
        pub const Value = V;

        allocator: std.mem.Allocator,
        n_vars: u32 = 0,
        /// Values exist only in value mode (a zero-sized list is not allowed).
        values: std.ArrayList(QM31) = .empty,
        constants: std.AutoArrayHashMapUnmanaged([4]u32, Self.Var) = .empty,
        add_gates: std.ArrayList(Binary) = .empty,
        sub_gates: std.ArrayList(Binary) = .empty,
        mul_gates: std.ArrayList(Binary) = .empty,
        eq_gates: std.ArrayList(EqGate) = .empty,
        output_gates: std.ArrayList(u32) = .empty,
        guessed: std.ArrayList(u32) = .empty,
        assert_eq_on_eval: bool = false,

        pub fn init(allocator: std.mem.Allocator) !Self {
            var self: Self = .{ .allocator = allocator };
            errdefer self.deinit();
            _ = try self.constant(QM31.zero());
            _ = try self.constant(QM31.one());
            const u = try self.constant(QM31.fromU32Unchecked(0, 0, 1, 0));
            std.debug.assert(u.idx == 2);
            try self.output_gates.append(allocator, u.idx);
            return self;
        }

        pub fn deinit(self: *Self) void {
            self.values.deinit(self.allocator);
            self.constants.deinit(self.allocator);
            self.add_gates.deinit(self.allocator);
            self.sub_gates.deinit(self.allocator);
            self.mul_gates.deinit(self.allocator);
            self.eq_gates.deinit(self.allocator);
            self.output_gates.deinit(self.allocator);
            self.guessed.deinit(self.allocator);
            self.* = undefined;
        }

        pub fn zero(_: *const Self) Self.Var {
            return .{ .idx = 0 };
        }

        pub fn one(_: *const Self) Self.Var {
            return .{ .idx = 1 };
        }

        /// `IValue::from_qm31`.
        pub fn lift(value: QM31) V {
            return if (V == QM31) value else .{};
        }

        fn push(self: *Self, value: V) !Self.Var {
            const idx = self.n_vars;
            if (idx >= std.math.maxInt(i32)) return error.TooManyVars;
            if (V == QM31) try self.values.append(self.allocator, value);
            self.n_vars += 1;
            return .{ .idx = idx };
        }

        pub fn newVar(self: *Self, value: V) !Self.Var {
            return self.push(value);
        }

        pub fn get(self: *const Self, v: Self.Var) V {
            return if (V == QM31) self.values.items[v.idx] else .{};
        }

        pub fn constant(self: *Self, value: QM31) !Self.Var {
            const key = limbs(value);
            if (self.constants.get(key)) |existing| return existing;
            const v = try self.push(lift(value));
            try self.constants.put(self.allocator, key, v);
            return v;
        }

        fn valueOp(comptime op: enum { add, sub, mul }, a: V, b: V) V {
            if (V == NoValue) return .{};
            return switch (op) {
                .add => a.add(b),
                .sub => a.sub(b),
                .mul => a.mul(b),
            };
        }

        pub fn add(self: *Self, a: Self.Var, b: Self.Var) !Self.Var {
            if (a.idx == 0) return b;
            if (b.idx == 0) return a;
            const out = try self.push(valueOp(.add, self.get(a), self.get(b)));
            try self.add_gates.append(self.allocator, .{ .in0 = a.idx, .in1 = b.idx, .out = out.idx });
            return out;
        }

        pub fn sub(self: *Self, a: Self.Var, b: Self.Var) !Self.Var {
            const out = try self.push(valueOp(.sub, self.get(a), self.get(b)));
            try self.sub_gates.append(self.allocator, .{ .in0 = a.idx, .in1 = b.idx, .out = out.idx });
            return out;
        }

        pub fn mul(self: *Self, a: Self.Var, b: Self.Var) !Self.Var {
            if (a.idx == 0 or b.idx == 0) return self.zero();
            if (a.idx == 1) return b;
            if (b.idx == 1) return a;
            const out = try self.push(valueOp(.mul, self.get(a), self.get(b)));
            try self.mul_gates.append(self.allocator, .{ .in0 = a.idx, .in1 = b.idx, .out = out.idx });
            return out;
        }

        pub fn eq(self: *Self, a: Self.Var, b: Self.Var) !void {
            if (V == QM31 and self.assert_eq_on_eval and !self.get(a).eql(self.get(b)))
                return error.EqFailed;
            try self.eq_gates.append(self.allocator, .{ .in0 = a.idx, .in1 = b.idx });
        }

        pub fn inv(self: *Self, b: Self.Var) !Self.Var {
            const value: V = if (V == QM31) try QM31.one().div(self.get(b)) else .{};
            const b_inv = try self.push(value);
            try self.guessed.append(self.allocator, b_inv.idx);
            const product = try self.mul(b, b_inv);
            try self.eq(product, self.one());
            return b_inv;
        }

        /// Per-kind gate counts in `kind_names` order (the oracle's `gate_counts`).
        pub fn gateCounts(self: *const Self) [kind_names.len]usize {
            var counts = [_]usize{0} ** kind_names.len;
            counts[0] = self.add_gates.items.len;
            counts[1] = self.sub_gates.items.len;
            counts[2] = self.mul_gates.items.len;
            counts[4] = self.eq_gates.items.len;
            counts[9] = self.output_gates.items.len;
            return counts;
        }

        /// The oracle's `visit_gates`: every gate of kind `k` from index
        /// `start[k]` on, kind by kind in `kind_names` order, as
        /// `visitor.gate(k, fields)` with the struct fields in declaration order.
        pub fn visitGates(self: *const Self, start: [kind_names.len]usize, visitor: anytype) void {
            for (self.add_gates.items[start[0]..]) |g| visitor.gate(0, &.{ g.in0, g.in1, g.out });
            for (self.sub_gates.items[start[1]..]) |g| visitor.gate(1, &.{ g.in0, g.in1, g.out });
            for (self.mul_gates.items[start[2]..]) |g| visitor.gate(2, &.{ g.in0, g.in1, g.out });
            for (self.eq_gates.items[start[4]..]) |g| visitor.gate(4, &.{ g.in0, g.in1 });
            for (self.output_gates.items[start[9]..]) |in0| visitor.gate(9, &.{in0});
        }

        pub fn summary(self: *const Self) Summary {
            var kinds: [kind_names.len]KindSummary = undefined;
            kinds[0] = binaryKind("add", self.add_gates.items);
            kinds[1] = binaryKind("sub", self.sub_gates.items);
            kinds[2] = binaryKind("mul", self.mul_gates.items);
            kinds[3] = binaryKind("pointwise_mul", &.{});
            var eq_hasher = KindHasher.init("eq");
            for (self.eq_gates.items) |gate| eq_hasher.record(&.{ gate.in0, gate.in1 });
            kinds[4] = eq_hasher.finish();
            for (5..9) |i| {
                var empty = KindHasher.init(kind_names[i]);
                kinds[i] = empty.finish();
            }
            var output_hasher = KindHasher.init("output");
            for (self.output_gates.items) |in0| output_hasher.record(&.{in0});
            kinds[9] = output_hasher.finish();

            var list = Sha256.init(.{});
            list.update("STWO_CIRCUIT_GATE_LIST_V1\x00");
            list.update(&std.mem.toBytes(std.mem.nativeToLittle(u64, self.n_vars)));
            for (kinds) |kind| list.update(&kind.sha256);
            return .{
                .n_vars = self.n_vars,
                .kinds = kinds,
                .gate_list_sha256 = list.finalResult(),
                .debug_text_sha256 = self.debugTextSha256(),
            };
        }

        /// SHA-256 of `format!("{circuit:?}")`: one line per gate, in
        /// `Circuit::all_gates` order (only add, sub, mul, eq, output occur).
        fn debugTextSha256(self: *const Self) [32]u8 {
            var hasher = Sha256.init(.{});
            var line: [96]u8 = undefined;
            for ([_]struct { []const Binary, u8 }{
                .{ self.add_gates.items, '+' },
                .{ self.sub_gates.items, '-' },
                .{ self.mul_gates.items, '*' },
            }) |entry| for (entry[0]) |gate| {
                hasher.update(std.fmt.bufPrint(&line, "[{d}] = [{d}] {c} [{d}]\n", .{ gate.out, gate.in0, entry[1], gate.in1 }) catch unreachable);
            };
            for (self.eq_gates.items) |gate|
                hasher.update(std.fmt.bufPrint(&line, "[{d}] = [{d}]\n", .{ gate.in0, gate.in1 }) catch unreachable);
            for (self.output_gates.items) |in0|
                hasher.update(std.fmt.bufPrint(&line, "output [{d}]\n", .{in0}) catch unreachable);
            return hasher.finalResult();
        }

        /// `SHA-256("STWO_CIRCUIT_VALUES_V1\0" || count:u64 || 4 × u32 per value)`.
        pub fn valuesSha256(self: *const Self) [32]u8 {
            comptime std.debug.assert(V == QM31);
            var hasher = Sha256.init(.{});
            hasher.update("STWO_CIRCUIT_VALUES_V1\x00");
            hasher.update(&std.mem.toBytes(std.mem.nativeToLittle(u64, self.values.items.len)));
            for (self.values.items) |value| {
                for (limbs(value)) |limb| hasher.update(&std.mem.toBytes(std.mem.nativeToLittle(u32, limb)));
            }
            return hasher.finalResult();
        }
    };
}

fn limbs(value: QM31) [4]u32 {
    const m = value.toM31Array();
    return .{ m[0].v, m[1].v, m[2].v, m[3].v };
}

pub const kind_names = [_][]const u8{
    "add", "sub", "mul", "pointwise_mul", "eq", "triple_xor", "m31_to_u32", "blake_g_gate", "permutation", "output",
};

pub const KindSummary = struct { count: u64, sha256: [32]u8 };

pub const Summary = struct {
    n_vars: u32,
    kinds: [kind_names.len]KindSummary,
    gate_list_sha256: [32]u8,
    debug_text_sha256: [32]u8,
};

const KindHasher = struct {
    kind: []const u8,
    count: u64 = 0,
    records: Sha256 = Sha256.init(.{}),

    fn init(kind: []const u8) KindHasher {
        return .{ .kind = kind };
    }

    fn record(self: *KindHasher, fields: []const u32) void {
        self.count += 1;
        for (fields) |field| self.records.update(&std.mem.toBytes(std.mem.nativeToLittle(u32, field)));
    }

    fn finish(self: *KindHasher) KindSummary {
        var outer = Sha256.init(.{});
        outer.update("STWO_CIRCUIT_GATE_KIND_V1\x00");
        outer.update(self.kind);
        outer.update(&.{0});
        outer.update(&std.mem.toBytes(std.mem.nativeToLittle(u64, self.count)));
        outer.update(&self.records.finalResult());
        return .{ .count = self.count, .sha256 = outer.finalResult() };
    }
};

fn binaryKind(kind: []const u8, gates: []const Binary) KindSummary {
    var hasher = KindHasher.init(kind);
    for (gates) |gate| hasher.record(&.{ gate.in0, gate.in1, gate.out });
    return hasher.finish();
}
