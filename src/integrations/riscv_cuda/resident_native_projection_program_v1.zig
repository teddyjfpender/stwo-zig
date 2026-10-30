//! Original physical native projections as secure row programs. The caller
//! must select slots from independently admitted V7/q2 layout; this exporter
//! is not an admission authority. Each slot keeps its own prefix and claim.
const std = @import("std");
const core = @import("stwo_core");
const R = @import("../../frontends/riscv/recursion/air/composition_graph_recorder.zig");
const Field = @import("../../frontends/riscv/recursion/air/block_v6_partitioned_composition_v1.zig").Field;
const Algebra = @import("../../frontends/riscv/prover/block_v5_native_fused_algebra_v1.zig");
pub const Source = @import("../../frontends/riscv/prover/block_v5_native_projection_fused_source_v1.zig");
const Relation = @import("../../frontends/riscv/air/lang/relation.zig");
const Universal = @import("../../frontends/riscv/recursion/air/universal_challenges.zig");
const Q = core.fields.qm31.QM31;
pub const Mode = enum(u8) { fractions, equation };
pub const Kind = enum(u8) { main, current, previous, z, alpha, normalized };
pub const Binding = struct { kind: Kind, index: u16 };
pub fn domain(slot: Source.Slot) Relation.Domain {
    return switch (slot.kind) {
        .program => .program_access,
        .lookup => |lookup| switch (lookup.partition) {
            .register_memory_access, .ordinary_memory_access, .clock_memory_access, .register_clock_memory_access => .memory_access,
            .registers_state => .registers_state,
            .bitwise => .bitwise,
            .range_check_20 => .range_check_20,
            .range_check_8_11 => .range_check_8_11,
            .range_check_8_8_4 => .range_check_8_8_4,
            .range_check_8_8 => .range_check_8_8,
            .range_check_m31 => .range_check_m31,
        },
    };
}
pub fn Relations(comptime S: type) type {
    return struct {
        selected: Relation.Domain,
        z: S,
        alpha: S,
        pub const Element = struct {
            selected: Relation.Domain,
            requested: Relation.Domain,
            arity: u8,
            z: S,
            alpha: S,
            pub fn combineSecure(self: @This(), values: []const S) !S {
                if (self.requested != self.selected or values.len != self.arity) return error.InvalidNativeProjectionRelation;
                var result = S.zero();
                var power = S.one();
                for (values) |value| {
                    result = result.add(value.mul(power));
                    power = power.mul(self.alpha);
                }
                return result.sub(self.z);
            }
        };
        pub fn get(self: @This(), requested: Relation.Domain) Element {
            return .{ .selected = self.selected, .requested = requested, .arity = Relation.universal_descriptors[@intFromEnum(requested)].arity, .z = self.z, .alpha = self.alpha };
        }
    };
}
pub const Owned = struct {
    a: std.mem.Allocator,
    slot: Source.Slot,
    mode: Mode,
    circuit: R.Circuit,
    bindings: []Binding,
    identity: [32]u8,
    pub fn init(a: std.mem.Allocator, slot: Source.Slot, mode: Mode) !Owned {
        if (slot.width == 0 or slot.width > 512 or slot.log_size < 1 or slot.log_size > 27 or slot.n_rows > (@as(u32, 1) << @intCast(slot.log_size))) return error.InvalidNativeProjectionSlot;
        var builder = R.Builder.init(a);
        defer builder.deinit();
        var bindings: std.ArrayList(Binding) = .empty;
        defer bindings.deinit(a);
        const main = try a.alloc(Field, slot.width);
        defer a.free(main);
        for (main, 0..) |*out, i| out.* = try input(&builder, a, &bindings, .main, i);
        var current: [4]Field = undefined;
        var previous: [4]Field = undefined;
        for (&current, 0..) |*out, i| out.* = try input(&builder, a, &bindings, .current, i);
        for (&previous, 0..) |*out, i| out.* = try input(&builder, a, &bindings, .previous, i);
        const z = try input(&builder, a, &bindings, .z, 0);
        const alpha = try input(&builder, a, &bindings, .alpha, 0);
        const normalized = try input(&builder, a, &bindings, .normalized, 0);
        try builder.activate();
        errdefer if (builder.active) builder.deactivate();
        const pair = try Algebra.Algebra(Field).projection(slot, main, Relations(Field){ .selected = domain(slot), .z = z, .alpha = alpha });
        switch (mode) {
            .fractions => {
                try builder.constrainZero(pair.numerator().symbol);
                try builder.constrainZero(pair.denominator().symbol);
            },
            .equation => try builder.constrainZero(Algebra.Algebra(Field).projectionResidual(pair, current, previous, normalized).symbol),
        }
        builder.deactivate();
        var circuit = try builder.finish();
        errdefer circuit.deinit();
        var result = Owned{ .a = a, .slot = slot, .mode = mode, .circuit = circuit, .bindings = try bindings.toOwnedSlice(a), .identity = @splat(0) };
        result.identity = result.identityDigest();
        return result;
    }
    pub fn identityDigest(self: *const Owned) [32]u8 {
        var channel = core.proof_suites.Blake3.Channel{};
        Source.mixSlot(&channel, self.slot);
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-resident-native-physical-projection-v1");
        hash.update(&channel.digestBytes());
        hash.update(&.{@intFromEnum(self.mode)});
        hash.update(&self.circuit.identity_digest);
        hash.update(@embedFile("../../frontends/riscv/prover/block_v5_native_fused_algebra_v1.zig"));
        for (self.bindings) |b| {
            var bytes: [3]u8 = undefined;
            bytes[0] = @intFromEnum(b.kind);
            std.mem.writeInt(u16, bytes[1..3], b.index, .little);
            hash.update(&bytes);
        }
        return hash.finalResult();
    }
    pub fn validate(self: *const Owned) !void {
        try self.circuit.validate();
        if (self.bindings.len != self.circuit.input_count or self.circuit.outputs.len != @as(usize, if (self.mode == .fractions) 2 else 1) or !std.mem.eql(u8, &self.identity, &self.identityDigest())) return error.InvalidNativeProjectionProgram;
    }
    pub fn deinit(self: *Owned) void {
        self.circuit.deinit();
        self.a.free(self.bindings);
        self.* = undefined;
    }
};
fn input(b: *R.Builder, a: std.mem.Allocator, bindings: *std.ArrayList(Binding), kind: Kind, index: usize) !Field {
    try bindings.append(a, .{ .kind = kind, .index = @intCast(index) });
    return .{ .symbol = (try b.input()).value };
}
