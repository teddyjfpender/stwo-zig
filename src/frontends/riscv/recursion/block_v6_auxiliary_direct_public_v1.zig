//! Original caller and source-PAGE public inputs for a direct mixed verifier.
//! No intermediate wrapper is required. This bus authenticates open equations;
//! the enclosing root must independently admit the complete typed roster,
//! reconstruct original public frames, and close every global relation.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
pub const VERSION: u32 = 1;
pub const MAX_CHILDREN: usize = 16;
pub const Family = enum(u32) { caller_arithmetic = 1, caller_fused = 2, source_raw = 3, source_fold = 4 };
pub fn Definition(comptime family: Family) type {
    return struct {
        pub const Admission = switch (family) {
            .caller_arithmetic => @import("../prover/block_v5_caller_arithmetic_recursive_admission_v1.zig"),
            .caller_fused => @import("../prover/block_v5_caller_fused_recursive_admission_v1.zig"),
            .source_raw, .source_fold => @import("../prover/block_v5_memory_source_page_recursive_admission_v1.zig").ForKind(if (family == .source_raw) .raw else .fold),
        };
        pub const Capture = switch (family) {
            .caller_arithmetic => @import("../prover/block_v5_caller_arithmetic_recursive_capture_v1.zig").VerifiedCapture,
            .caller_fused => @import("../prover/block_v5_caller_fused_recursive_capture_v1.zig").VerifiedCapture,
            .source_raw, .source_fold => @import("../prover/block_v5_memory_source_page_recursive_capture_v1.zig").ForKind(if (family == .source_raw) .raw else .fold).VerifiedCapture,
        };
        pub const Bus = switch (family) {
            .caller_arithmetic => @import("block_v5_caller_arithmetic_recursive_public_bus_v1.zig"),
            .caller_fused => @import("block_v5_caller_fused_recursive_public_bus_v1.zig"),
            .source_raw, .source_fold => @import("block_v5_memory_source_page_recursive_public_bus_v1.zig").ForKind(if (family == .source_raw) .raw else .fold),
        };
    };
}
pub const Value = union(Family) {
    caller_arithmetic: Definition(.caller_arithmetic).Bus.Values,
    caller_fused: Definition(.caller_fused).Bus.Values,
    source_raw: Definition(.source_raw).Bus.Values,
    source_fold: Definition(.source_fold).Bus.Values,
    pub fn deinit(self: *Value) void {
        switch (self.*) {
            .caller_arithmetic => {}, // All statement and physical claims are inline.
            inline else => |*value| value.deinit(),
        }
        self.* = undefined;
    }
    pub fn validate(self: Value) !void {
        switch (self) {
            inline else => |value| try value.validate(),
        }
    }
    pub fn template(self: Value) [32]u8 {
        return switch (self) {
            inline else => |value| value.template,
        };
    }
    pub fn mix(self: Value, channel: anytype) void {
        channel.mixU32s(&.{@intFromEnum(std.meta.activeTag(self))});
        switch (self) {
            inline else => |value| value.mix(channel),
        }
    }
};
/// The index is a typed roster label, not independent source authentication.
/// Root policy must reconstruct each original statement from its admission.
pub const Child = struct {
    index: u32,
    value: Value,
    pub fn expected(self: Child) Expected {
        return .{ .family = std.meta.activeTag(self.value), .index = self.index, .template = self.value.template() };
    }
};
pub const Expected = struct { family: Family, index: u32, template: [32]u8 };
pub fn rosterDigest(expected: []const Expected) ![32]u8 {
    if (expected.len == 0 or expected.len > MAX_CHILDREN) return error.InvalidAuxiliaryDirectCount;
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42364152, VERSION, @intCast(expected.len) });
    for (expected, 0..) |pin, i| {
        if (pin.index >= core.fields.m31.Modulus or std.mem.allEqual(u8, &pin.template, 0)) return error.InvalidAuxiliaryDirectRoster;
        if (i != 0 and (@intFromEnum(expected[i - 1].family) > @intFromEnum(pin.family) or
            (expected[i - 1].family == pin.family and expected[i - 1].index >= pin.index))) return error.InvalidAuxiliaryDirectRoster;
        channel.mixU32s(&.{ @intFromEnum(pin.family), pin.index });
        channel.mixRoot(pin.template);
    }
    return channel.digestBytes();
}
pub const Source = union(Family) {
    caller_arithmetic: Definition(.caller_arithmetic).Bus.Source,
    caller_fused: Definition(.caller_fused).Bus.Source,
    source_raw: Definition(.source_raw).Bus.Source,
    source_fold: Definition(.source_fold).Bus.Source,
};
pub const Wire = struct { circuit: u32, wire: u32, uses: u32, child: u8, source: Source, coordinate: u32 };
pub const Values = struct {
    children: []const Child,
    pub fn validate(self: Values) !void {
        if (self.children.len == 0 or self.children.len > MAX_CHILDREN) return error.InvalidAuxiliaryDirectCount;
        for (self.children, 0..) |child, i| {
            try child.value.validate();
            switch (child.value) {
                .caller_arithmetic => |value| if (child.index != value.binding.execution_index) return error.InvalidAuxiliaryDirectRoster,
                .caller_fused => |value| {
                    const Original = @import("../prover/block_v5_caller_fused_proof_v1.zig");
                    // Original mixFirst begins TAG, VERSION, phase, index.
                    const words = value.statement.words;
                    if (words.len < 4 or words[0] != Original.TAG or words[1] != Original.VERSION or words[2] != 1 or words[3] != child.index) return error.InvalidAuxiliaryDirectRoster;
                },
                .source_raw, .source_fold => {}, // Original PAGE frame reconstruction is root-policy owned.
            }
            const pin = child.expected();
            if (pin.index >= core.fields.m31.Modulus or std.mem.allEqual(u8, &pin.template, 0)) return error.InvalidAuxiliaryDirectRoster;
            if (i != 0) {
                const previous = self.children[i - 1].expected();
                if (@intFromEnum(previous.family) > @intFromEnum(pin.family) or
                    (previous.family == pin.family and previous.index >= pin.index)) return error.InvalidAuxiliaryDirectRoster;
            }
        }
    }
    pub fn requireRoster(self: Values, expected: []const Expected) !void {
        try self.validate();
        if (expected.len != self.children.len) return error.UntrustedAuxiliaryDirectRoster;
        for (self.children, expected) |child, pin| if (!std.meta.eql(child.expected(), pin)) return error.UntrustedAuxiliaryDirectRoster;
    }
    /// Root policy reconstructs original Values from admitted statements and
    /// proposed typed claims. Never deserialize routing offsets as authority:
    /// original values mix data, while at() also depends on their frame layout.
    pub fn requireSameFrame(self: Values, reconstructed: Values) !void {
        try self.validate();
        try reconstructed.validate();
        if (self.children.len != reconstructed.children.len) return error.UntrustedAuxiliaryDirectPublic;
        for (self.children, reconstructed.children) |child, original| if (!std.meta.eql(child.expected(), original.expected())) return error.UntrustedAuxiliaryDirectPublic;
        var actual = core.channel.blake3.Channel{};
        var expected = core.channel.blake3.Channel{};
        self.mix(&actual);
        reconstructed.mix(&expected);
        if (!std.meta.eql(actual.digestBytes(), expected.digestBytes())) return error.UntrustedAuxiliaryDirectPublic;
        for (self.children, reconstructed.children) |child, original| switch (child.value) {
            .caller_arithmetic => {},
            inline else => |value, family| {
                const rebuilt = @field(original.value, @tagName(family));
                if (value.roots_count != rebuilt.roots_count or !std.meta.eql(value.statement.roots_offset, rebuilt.statement.roots_offset)) return error.UntrustedAuxiliaryDirectPublic;
                const frame = if (family == .caller_fused) value.statement else value.statement.frame;
                const expected_frame = if (family == .caller_fused) rebuilt.statement else rebuilt.statement.frame;
                if (frame.sealed_offset != expected_frame.sealed_offset or !std.meta.eql(frame.roots_offset, expected_frame.roots_offset) or
                    frame.first.len != expected_frame.first.len or frame.claims.len != expected_frame.claims.len) return error.UntrustedAuxiliaryDirectPublic;
                for (frame.first, expected_frame.first) |step, expected_step| if (!std.meta.eql(step, expected_step)) return error.UntrustedAuxiliaryDirectPublic;
                for (frame.claims, expected_frame.claims) |step, expected_step| if (!std.meta.eql(step, expected_step)) return error.UntrustedAuxiliaryDirectPublic;
                if (family != .caller_fused and (value.statement.component_claim_first != rebuilt.statement.component_claim_first or
                    !std.meta.eql(value.statement.relations, rebuilt.statement.relations) or
                    !std.meta.eql(value.statement.proof_start, rebuilt.statement.proof_start))) return error.UntrustedAuxiliaryDirectPublic;
            },
        };
    }
    pub fn requireReconstructed(self: Values, reconstructed: Values, wires: []const Wire) !void {
        try self.requireSameFrame(reconstructed);
        _ = try scheduleDigest(wires);
        for (wires) |wire| if (!std.meta.eql(try self.at(wire), try reconstructed.at(wire))) return error.UntrustedAuxiliaryDirectPublic;
    }
    pub fn at(self: Values, wire: Wire) ![4]M {
        if (wire.child >= self.children.len) return error.InvalidAuxiliaryDirectWire;
        const value = self.children[wire.child].value;
        if (std.meta.activeTag(value) != std.meta.activeTag(wire.source)) return error.InvalidAuxiliaryDirectWire;
        return switch (wire.source) {
            inline else => |source, family| @field(value, @tagName(family)).at(source, wire.coordinate),
        };
    }
    pub fn mix(self: Values, channel: anytype) void {
        channel.mixU32s(&.{ 0x42364156, VERSION, @intCast(self.children.len) });
        for (self.children) |child| {
            channel.mixU32s(&.{child.index});
            child.value.mix(channel);
        }
    }
};
pub fn scheduleDigest(wires: []const Wire) ![32]u8 {
    if (wires.len == 0 or wires.len > 1 << 20) return error.InvalidAuxiliaryDirectSchedule;
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42364157, VERSION, @intCast(wires.len) });
    for (wires, 0..) |wire, i| {
        if (wire.child >= MAX_CHILDREN or wire.uses == 0 or wire.uses >= core.fields.m31.Modulus or wire.circuit >= core.fields.m31.Modulus or wire.wire >= core.fields.m31.Modulus) return error.InvalidAuxiliaryDirectSchedule;
        if (i != 0 and (wires[i - 1].circuit > wire.circuit or (wires[i - 1].circuit == wire.circuit and wires[i - 1].wire >= wire.wire))) return error.InvalidAuxiliaryDirectSchedule;
        const source = switch (wire.source) {
            inline else => |source, family| checked: {
                _ = try Definition(family).Bus.scheduleDigest(&.{.{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .source = source, .coordinate = wire.coordinate }});
                break :checked @intFromEnum(source);
            },
        };
        channel.mixU32s(&.{ wire.circuit, wire.wire, wire.uses, wire.child, @intFromEnum(std.meta.activeTag(wire.source)), source, wire.coordinate });
    }
    return channel.digestBytes();
}
pub fn supply(wires: []const Wire, values: Values, relations: @import("air/universal_challenges.zig").UniversalRelations) !Q {
    _ = try scheduleDigest(wires);
    try values.validate();
    const relation = try relations.getExact(.recursion_wire);
    var result = Q.zero();
    for (wires) |wire| {
        const denominator = try relation.combineBase(&(.{ M.fromCanonical(wire.circuit), M.fromCanonical(wire.wire) } ++ try values.at(wire)));
        if (denominator.isZero()) return error.AuxiliaryDirectDenominatorZero;
        result = result.add(Q.fromBase(M.fromCanonical(wire.uses)).mul(try denominator.inv()));
    }
    return result;
}
