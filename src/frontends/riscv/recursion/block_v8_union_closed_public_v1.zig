//! Independently reconstructed V8 operands. The source verifier's physical
//! public claims are reused verbatim; extra metadata words and epoch draws
//! are derived by the receiver, never accepted from a proof envelope.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Original = @import("block_v7_union_public_v1.zig");
const Scoped = @import("block_v5_heterogeneous_scoped_public_bus_v1.zig");
pub const VERSION: u32 = 1;
pub const Wire = union(enum) { original: Original.Wire, closure: Scoped.Wire };
pub const NATIVE_WORDS: usize = 3 + 32 * 3 + 5;
pub const Values = struct {
    allocator: std.mem.Allocator,
    original: Original.Values,
    words: []u32,
    secure: []Q,
    pub fn derive(a: std.mem.Allocator, capsule: *const @import("block_v7_union_compiler_capsule_v1.zig").Capsule) !Values {
        const profile = capsule.profile();
        const i = profile.statement.input;
        if (i.callers.len != 0 or i.natives.len == 0) return error.UnsupportedClosedUnionCaller;
        const window = profile.statement.trusted.window orelse return error.UnsupportedClosedUnionPolicy;
        const word_count = try std.math.add(usize, 4, try std.math.add(usize, try std.math.mul(usize, i.natives.len, NATIVE_WORDS), try std.math.mul(usize, window.changes.len, 3)));
        if (word_count > 1 << 22 or i.program_plan.expected_fetches >= core.fields.m31.Modulus or i.memory_geometry[0].total_events >= core.fields.m31.Modulus) return error.ClosedUnionResourceLimit;
        var original = try capsule.values(a);
        errdefer original.deinit();
        const words = try a.alloc(u32, word_count);
        errdefer a.free(words);
        words[0] = @intCast(i.natives.len);
        words[1] = @intCast(window.changes.len);
        words[2] = @intCast(i.program_plan.expected_fetches);
        words[3] = @intCast(i.memory_geometry[0].total_events);
        for (i.natives, 0..) |pin, index| {
            const data = &pin.shape.public_data;
            const base = 4 + NATIVE_WORDS * index;
            const completion = data.completion orelse return error.MissingCompletion;
            if (completion.kind != .unretired_program_fetch and completion.kind != .unretired_self_loop) return error.UnsupportedClosedUnionCompletion;
            words[base] = data.initial_pc;
            words[base + 1] = data.final_pc;
            words[base + 2] = data.clock;
            @memcpy(words[base + 3 ..][0..32], &data.initial_regs);
            @memcpy(words[base + 35 ..][0..32], &data.final_regs);
            @memcpy(words[base + 67 ..][0..32], &data.reg_last_clock);
            words[base + 99] = completion.address;
            const decoded = try @import("../air/program/decode.zig").decodeProgramWordForProfile(pin.template.execution_profile, completion.value);
            @memcpy(words[base + 100 ..][0..4], &decoded);
        }
        const changes_base = 4 + NATIVE_WORDS * i.natives.len;
        for (window.changes, 0..) |change, index| @memcpy(words[changes_base + 3 * index ..][0..3], &[_]u32{ change.address, change.before, change.after });
        const secure = try a.dupe(Q, &try @import("air/block_v7_memory_joint_inputs_mode_v1.zig").ForMode(true).challenges(a, i.epoch));
        return .{ .allocator = a, .original = original, .words = words, .secure = secure };
    }
    pub fn deinit(self: *Values) void {
        self.original.deinit();
        self.allocator.free(self.words);
        self.allocator.free(self.secure);
        self.* = undefined;
    }
    pub fn validate(self: Values) !void {
        try self.original.validate();
        if (self.words.len < 4 or self.secure.len != 106 or self.words[0] == 0 or self.words[2] >= core.fields.m31.Modulus or self.words[3] >= core.fields.m31.Modulus) return error.InvalidClosedUnionOperands;
        const expected = try std.math.add(usize, 4, try std.math.add(usize, try std.math.mul(usize, self.words[0], NATIVE_WORDS), try std.math.mul(usize, self.words[1], 3)));
        if (expected != self.words.len) return error.InvalidClosedUnionOperands;
        for (self.secure) |value| for (value.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.InvalidClosedUnionOperands;
    }
    pub fn at(self: Values, wire: Wire) ![4]M {
        return switch (wire) {
            .original => |source| self.original.at(source.source, source.coordinate),
            .closure => |source| self.atClosure(source),
        };
    }
    pub fn atClosure(self: Values, wire: Scoped.Wire) ![4]M {
        if (wire.child > 1) return error.InvalidClosedUnionSchedule;
        if (wire.kind == .child_term) {
            if (wire.part != null) return error.InvalidClosedUnionSchedule;
            if (wire.child == 0) return self.original.at(.public_input, wire.coordinate);
            if (wire.coordinate >= self.secure.len) return error.InvalidClosedUnionSchedule;
            return self.secure[wire.coordinate].toM31Array();
        }
        if (wire.kind != .child_cell or wire.child != 1 or wire.coordinate >= self.words.len) return error.InvalidClosedUnionSchedule;
        var bytes: [4]M = undefined;
        for (&bytes, 0..) |*value, part| value.* = M.fromCanonical((self.words[wire.coordinate] >> @as(u5, @intCast(part * 8))) & 255);
        return if (wire.part) |part| .{ bytes[part], M.zero(), M.zero(), M.zero() } else bytes;
    }
    pub fn mix(self: Values, channel: anytype) void {
        channel.mixU32s(&.{ 0x42384356, VERSION, @intCast(self.words.len), @intCast(self.secure.len) });
        self.original.mix(channel);
        channel.mixU32s(self.words);
        channel.mixFelts(self.secure);
    }
};
pub const ClosureView = struct {
    values: Values,
    pub fn at(self: ClosureView, wire: Scoped.Wire) ![4]M {
        return self.values.atClosure(wire);
    }
};
pub fn circuit(wire: Wire) u32 {
    return switch (wire) {
        inline else => |value| value.circuit,
    };
}
pub fn node(wire: Wire) u32 {
    return switch (wire) {
        inline else => |value| value.wire,
    };
}
pub fn scheduleDigest(wires: []const Wire) ![32]u8 {
    if (wires.len == 0 or wires.len > 1 << 22) return error.InvalidClosedUnionSchedule;
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ 0x42384357, VERSION, @intCast(wires.len) });
    for (wires, 0..) |wire, index| {
        if (index != 0 and (circuit(wires[index - 1]) > circuit(wire) or circuit(wires[index - 1]) == circuit(wire) and node(wires[index - 1]) >= node(wire))) return error.InvalidClosedUnionSchedule;
        switch (wire) {
            .original => |w| {
                if (w.uses == 0 or w.circuit >= core.fields.m31.Modulus or w.wire >= core.fields.m31.Modulus) return error.InvalidClosedUnionSchedule;
                channel.mixU32s(&.{ 0, w.circuit, w.wire, w.uses, @intFromEnum(w.source), w.coordinate });
            },
            .closure => |w| {
                if (w.uses == 0 or w.circuit >= core.fields.m31.Modulus or w.wire >= core.fields.m31.Modulus) return error.InvalidClosedUnionSchedule;
                channel.mixU32s(&.{ 1, w.circuit, w.wire, w.uses, @intFromBool(w.negative), @intFromEnum(w.kind), w.child, w.coordinate, if (w.part) |part| part else 4 });
            },
        }
    }
    return channel.digestBytes();
}
pub fn supply(wires: []const Wire, values: Values, relations: @import("air/universal_challenges.zig").UniversalRelations) !Q {
    _ = try scheduleDigest(wires);
    try values.validate();
    const relation = try relations.getExact(.recursion_wire);
    var sum = Q.zero();
    for (wires) |wire| {
        const denominator = try relation.combineBase(&(.{ M.fromCanonical(circuit(wire)), M.fromCanonical(node(wire)) } ++ try values.at(wire)));
        const uses = switch (wire) {
            inline else => |w| w.uses,
        };
        const negative = switch (wire) {
            .original => false,
            .closure => |w| w.negative,
        };
        const term = Q.fromBase(M.fromCanonical(uses)).mul(try denominator.inv());
        sum = if (negative) sum.sub(term) else sum.add(term);
    }
    return sum;
}
