//! Finite V7 load/store access export. Every equation is the original shared
//! Algebra.access body; claims and Fiat-Shamir values are invocation inputs.
//! A cold executable plan is not proof admission or an execution receipt.
const std = @import("std");
const core = @import("stwo_core");
const R = @import("../../frontends/riscv/recursion/air/composition_graph_recorder.zig");
const Field = @import("../../frontends/riscv/recursion/air/block_v6_partitioned_composition_v1.zig").Field;
const Access = @import("../../frontends/riscv/prover/block_execution_access_bridge_v2.zig");
const Algebra = @import("../../frontends/riscv/prover/block_v5_native_fused_algebra_v1.zig");
const Integer = @import("../../frontends/riscv/prover/block_execution_integer_algebra_v1.zig");
const Trace = @import("../../frontends/riscv/runner/trace.zig");
const Domain = @import("../../frontends/riscv/air/lang/relation.zig").Domain;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
pub const MAIN_COUNT = Trace.nColumnsForFamily(.load_store);
pub const Kind = enum(u8) { main, witness, current, previous, clock, transition, range, memory, normalized };
pub const Binding = struct { kind: Kind, index: u16 };
pub const Mode = enum(u8) { equations, denominators };
pub const PARAMETER_COUNT = 8 + 12 + 3 + 8 + 10;

pub fn Inputs(comptime S: type) type {
    return struct {
        main: [MAIN_COUNT]S,
        witness: [48]S,
        current: [49]S,
        previous: [49]S,
        clock: [8]S,
        transition: [12]S,
        range: [3]S,
        memory: [8]S,
        /// transition sum, active count, seven range sums, opposite memory sum.
        /// Each is normalized by the independently admitted physical row count.
        normalized: [10]S,
    };
}
fn Element(comptime S: type) type {
    return struct {
        values: []const S,
        pub fn combineSecure(self: @This(), tuple: anytype) !S {
            if (self.values.len != tuple.len + 1) return error.InvalidNativeAccessRelation;
            var result = S.zero();
            const T = @TypeOf(tuple);
            const Child = if (@typeInfo(T) == .pointer) @typeInfo(T).pointer.child else T;
            if (comptime @typeInfo(Child) == .@"struct") {
                inline for (tuple, 0..) |value, i| result = result.add(value.mul(self.values[1 + i]));
            } else for (tuple, self.values[1..]) |value, power| result = result.add(value.mul(power));
            return result.sub(self.values[0]);
        }
    };
}
fn Universal(comptime S: type) type {
    return struct {
        inputs: *const Inputs(S),
        pub fn get(self: @This(), comptime domain: Domain) Element(S) {
            return .{ .values = switch (domain) {
                .range_check_8_8 => &self.inputs.range,
                .memory_access => &self.inputs.memory,
                else => @compileError("finite native access relation"),
            } };
        }
    };
}
fn pairFor(comptime S: type, slot: u8, inputs: *const Inputs(S)) !Access.Pair(S) {
    if (slot != 1 and slot != 2) return error.InvalidNativeAccessSlot;
    const pairs = try Access.fromCommittedMain(S, .load_store, &inputs.main);
    if (slot >= pairs.len) return error.InvalidNativeAccessSlot;
    return Access.rwPairForMode(S, .load_store, slot, pairs.items[slot], 1);
}
pub fn equations(comptime S: type, slot: u8, inputs: *const Inputs(S)) ![68]S {
    return Algebra.Algebra(S).access(try pairFor(S, slot, inputs), inputs.witness, inputs.current, inputs.previous, inputs.clock, Element(S){ .values = &inputs.transition }, Universal(S){ .inputs = inputs }, inputs.normalized[0], inputs.normalized[1], inputs.normalized[2..9].*, inputs.normalized[9]);
}
/// Original seventeen denominators, gated to one on inactive rows, followed
/// by the active numerator. Device inversion must reject an active zero.
pub fn denominators(comptime S: type, slot: u8, inputs: *const Inputs(S)) ![18]S {
    const pair = try pairFor(S, slot, inputs);
    const witness = Integer.Algebra(S).Witness.fromColumns(inputs.witness);
    return denominatorsFromPair(S, pair, witness, &inputs.transition, &inputs.range, &inputs.memory);
}
pub fn denominatorsFromPair(comptime S: type, pair: Access.Pair(S), witness: Integer.Algebra(S).Witness, transition: []const S, range: []const S, memory: []const S) ![18]S {
    const A = Algebra.Algebra(S);
    var out: [18]S = undefined;
    out[0] = try (Element(S){ .values = transition }).combineSecure(A.packedTransition(Integer.Algebra(S).transitionAtPoint(pair, witness)));
    const prior = pair.consume_clock orelse return error.InvalidNativeAccessSlot;
    out[1] = try (Element(S){ .values = memory }).combineSecure(.{ pair.space, pair.source_address, prior } ++ pair.before);
    out[2] = try (Element(S){ .values = memory }).combineSecure(.{ pair.space, pair.source_address, pair.local_clock } ++ pair.after);
    const bytes = A.bytesAtPoint(pair, witness);
    for (0..14) |i| out[3 + i] = try (Element(S){ .values = range }).combineSecure(bytes[2 * i ..][0..2]);
    for (out[0..17]) |*value| value.* = pair.active.mul(value.*).add(S.one().sub(pair.active));
    out[17] = pair.active;
    return out;
}

pub const Owned = struct {
    a: std.mem.Allocator,
    slot: u8,
    mode: Mode,
    circuit: R.Circuit,
    bindings: []Binding,
    identity: [32]u8,
    pub fn init(a: std.mem.Allocator, slot: u8, mode: Mode) !Owned {
        if (slot != 1 and slot != 2) return error.InvalidNativeAccessSlot;
        var builder = R.Builder.init(a);
        defer builder.deinit();
        var bindings: std.ArrayList(Binding) = .empty;
        defer bindings.deinit(a);
        var inputs: Inputs(Field) = undefined;
        inline for (std.meta.fields(Inputs(Field))) |field| {
            for (&@field(inputs, field.name), 0..) |*out, i| {
                out.* = .{ .symbol = (try builder.input()).value };
                try bindings.append(a, .{ .kind = @field(Kind, field.name), .index = @intCast(i) });
            }
        }
        try builder.activate();
        errdefer if (builder.active) builder.deactivate();
        switch (mode) {
            .equations => for (try equations(Field, slot, &inputs)) |root| try builder.constrainZero(root.symbol),
            .denominators => for (try denominators(Field, slot, &inputs)) |root| try builder.constrainZero(root.symbol),
        }
        builder.deactivate();
        var circuit = try builder.finish();
        errdefer circuit.deinit();
        var result = Owned{ .a = a, .slot = slot, .mode = mode, .circuit = circuit, .bindings = try bindings.toOwnedSlice(a), .identity = @splat(0) };
        result.identity = result.identityDigest();
        return result;
    }
    pub fn identityDigest(self: *const Owned) [32]u8 {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("stwo-native-access-row-program-v1");
        h.update(&.{ self.slot, @intFromEnum(self.mode) });
        h.update(&self.circuit.identity_digest);
        inline for (.{ @embedFile("resident_native_access_program_v1.zig"), @embedFile("../../frontends/riscv/prover/block_v5_native_fused_algebra_v1.zig"), @embedFile("../../frontends/riscv/prover/block_execution_access_bridge_v2.zig"), @embedFile("../../frontends/riscv/prover/block_execution_integer_algebra_v1.zig") }) |bytes| h.update(bytes);
        for (self.bindings) |binding| {
            var encoded: [3]u8 = undefined;
            encoded[0] = @intFromEnum(binding.kind);
            std.mem.writeInt(u16, encoded[1..3], binding.index, .little);
            h.update(&encoded);
        }
        return h.finalResult();
    }
    pub fn validate(self: *const Owned) !void {
        try self.circuit.validate();
        if ((self.slot != 1 and self.slot != 2) or self.bindings.len != self.circuit.input_count or
            self.circuit.outputs.len != @as(usize, if (self.mode == .equations) 68 else 18) or
            !std.mem.eql(u8, &self.identity, &self.identityDigest())) return error.InvalidNativeAccessProgram;
    }
    pub fn deinit(self: *Owned) void {
        self.circuit.deinit();
        self.a.free(self.bindings);
        self.* = undefined;
    }
};

test "resident native access graph retains68 equations17 denominators and all10 public claims" {
    const a = std.testing.allocator;
    for ([_]u8{ 1, 2 }) |slot| for ([_]Mode{ .equations, .denominators }) |mode| {
        var p = try Owned.init(a, slot, mode);
        defer p.deinit();
        var input: Inputs(Q) = undefined;
        const flat = try a.alloc(Q, p.bindings.len);
        defer a.free(flat);
        var cursor: usize = 0;
        inline for (std.meta.fields(Inputs(Q))) |field| for (&@field(input, field.name)) |*out| {
            out.* = Q.fromM31Array(.{ M.fromU64(cursor + 7), M.fromU64(cursor * 3 + 11), M.fromU64(cursor * 5 + 13), M.fromU64(cursor * 7 + 17) });
            flat[cursor] = out.*;
            cursor += 1;
        };
        const values = try a.alloc(Q, p.circuit.nodes.len);
        defer a.free(values);
        p.circuit.evaluateInto(flat, values) catch |err| if (err != error.UnsatisfiedCircuit) return err;
        switch (mode) {
            .equations => for (try equations(Q, slot, &input), p.circuit.outputs) |expected, output| try std.testing.expect(expected.eql(values[output])),
            .denominators => for (try denominators(Q, slot, &input), p.circuit.outputs) |expected, output| try std.testing.expect(expected.eql(values[output])),
        }
        if (mode == .equations) {
            var normalized_count: usize = 0;
            for (p.bindings, 0..) |binding, index| if (binding.kind == .normalized) {
                const before = try a.dupe(Q, values);
                defer a.free(before);
                flat[index] = flat[index].add(Q.one());
                p.circuit.evaluateInto(flat, values) catch |err| if (err != error.UnsatisfiedCircuit) return err;
                var changed = false;
                for (p.circuit.outputs) |output| changed = changed or !before[output].eql(values[output]);
                try std.testing.expect(changed);
                flat[index] = flat[index].sub(Q.one());
                p.circuit.evaluateInto(flat, values) catch |err| if (err != error.UnsatisfiedCircuit) return err;
                normalized_count += 1;
            };
            try std.testing.expectEqual(@as(usize, 10), normalized_count);
        }
        if (mode == .denominators) {
            // Independent algebraic extraction from the ORIGINAL 68-equation
            // evaluator: coefficient of each term/prefix is its denominator.
            var baseline = input;
            baseline.current = @splat(Q.zero());
            baseline.previous = @splat(Q.zero());
            baseline.normalized = @splat(Q.zero());
            const ds = try denominators(Q, slot, &baseline);
            const zero = try equations(Q, slot, &baseline);
            for ([_]usize{ 0, 37, 41 }, [_]usize{ 55, 65, 66 }, 0..) |column, equation, i| {
                baseline.current[column] = Q.one();
                const one = try equations(Q, slot, &baseline);
                try std.testing.expect(one[equation].sub(zero[equation]).eql(ds[i]));
                baseline.current[column] = Q.zero();
            }
            for (0..7) |i| {
                baseline.current[9 + 4 * i] = Q.one();
                const one = try equations(Q, slot, &baseline);
                try std.testing.expect(one[58 + i].sub(zero[58 + i]).eql(ds[3 + 2 * i].mul(ds[4 + 2 * i])));
                try std.testing.expect(zero[58 + i].eql(ds[17].mul(ds[3 + 2 * i].add(ds[4 + 2 * i])).neg()));
                baseline.current[9 + 4 * i] = Q.zero();
            }
        }
        try p.validate();
        const old = p.bindings[0];
        p.bindings[0].kind = .normalized;
        try std.testing.expectError(error.InvalidNativeAccessProgram, p.validate());
        p.bindings[0] = old;
        try p.validate();
    };
    try std.testing.expectError(error.InvalidNativeAccessSlot, Owned.init(a, 0, .equations));
}
