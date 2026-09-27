//! Verifier-owned public supply for an instance-independent recursive setup.
//! No rows privately provide these wires. Their opposite claim is recomputed
//! from the independently admitted statement after parent challenges are drawn.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const template = @import("../prover/block_v5_native_template_protocol.zig");
const native_admission = @import("../prover/block_v5_native_recursive_admission_v1.zig");
const native_proof = @import("../prover/block_v5_native_execution_proof_v1.zig");
const universal = @import("air/universal_challenges.zig");
pub const PUBLIC_CIRCUIT: u32 = 4_200_001;
pub const Source = enum(u8) { sealed, template, instance, ordinal_header, fixed_root, main_root, compensation, open_sum };
pub const Wire = struct { circuit: u32, wire: u32, uses: u32, source: Source, coordinate: u8 };
pub const Values = struct {
    sealed: [32]u8,
    template: [32]u8,
    instance: [32]u8,
    roots: [2][32]u8,
    index: u32,
    native_version: u32 = template.VERSION,
    compensation: Q,
    open_sum: Q,
    /// Full canonical public machine statement, including all endpoints/I/O.
    statement_digest: [32]u8,

    pub fn fromNative(a: std.mem.Allocator, admitted: anytype, receipt: anytype) !Values {
        const lightweight = @TypeOf(admitted.pin) == @import("../prover/block_v5_native_public_admission_v1.zig").Admission;
        const Template = if (lightweight) @import("../prover/block_v5_native_template_protocol_v3.zig") else template;
        const NativeProof = if (lightweight) @import("../prover/block_v5_native_execution_proof_v3.zig") else native_proof;
        try admitted.validate(admitted.expected_id);
        if (!std.meta.eql(receipt.template_id, admitted.expected_id) or
            !std.meta.eql(receipt.sealed_digest, admitted.sealed.digest) or
            !std.meta.eql(receipt.first_roots[0], admitted.template.fixed_root) or
            !std.meta.eql(receipt.instance_id, try Template.instanceId(admitted.expected_id, admitted.shape, admitted.pin, receipt.first_roots, admitted.index)))
            return error.UntrustedNativeV5PublicInputs;
        try NativeProof.admitEntry(admitted.index, receipt.first_roots, receipt.instance_id, admitted.sealed, admitted.entries);
        const challenges = try @import("../prover/block_memory_relation_v2.zig").Challenges.draw(a, admitted.sealed);
        const providers = try @import("air/universal_provider_relations.zig").SharedProviderRelations.init(&challenges.universal_prefix);
        const compensation = if (lightweight)
            try @import("../air/public_logup_arithmetic.zig").registersStateSumFor(Q, &admitted.shape.public_data, &providers.native)
        else
            (try @import("../air/public_logup_arithmetic.zig").blake3ScheduledRelationSumsForProfile(
                Q,
                admitted.template.execution_profile,
                &admitted.shape.public_data,
                &providers.native,
                admitted.pin.plan.memories,
            )).total();
        var statement_channel = core.channel.blake3.Channel{};
        statement_channel.mixU32s(&.{ 0x42355053, 1 });
        admitted.shape.public_data.mixInto(&statement_channel);
        const result = Values{ .sealed = admitted.sealed.digest, .template = admitted.expected_id, .instance = receipt.instance_id, .roots = receipt.first_roots, .index = admitted.index, .compensation = compensation, .open_sum = receipt.open_sum, .native_version = Template.VERSION, .statement_digest = statement_channel.digestBytes() };
        try result.validate();
        return result;
    }
    pub fn validate(self: Values) !void {
        if (self.index >= core.fields.m31.Modulus or (self.native_version != 2 and self.native_version != 3)) return error.InvalidRecursivePublicInputs;
        for (self.compensation.toM31Array() ++ self.open_sum.toM31Array()) |v|
            if (v.v >= core.fields.m31.Modulus) return error.InvalidRecursivePublicInputs;
        for ([_][32]u8{ self.sealed, self.template, self.instance, self.statement_digest, self.roots[0], self.roots[1] }) |digest|
            if (std.mem.allEqual(u8, &digest, 0)) return error.InvalidRecursivePublicInputs;
    }
    pub fn at(self: Values, source: Source, coordinate: u8) ![4]M {
        switch (source) {
            .compensation, .open_sum => {
                if (coordinate != 0) return error.InvalidRecursivePublicSchedule;
                return (if (source == .compensation) self.compensation else self.open_sum).toM31Array();
            },
            else => {
                const value: u32 = if (source == .ordinal_header) blk: {
                    if (coordinate >= 3) return error.InvalidRecursivePublicSchedule;
                    break :blk ([_]u32{ template.TAG, self.native_version, self.index })[coordinate];
                } else blk: {
                    if (coordinate >= 8) return error.InvalidRecursivePublicSchedule;
                    const digest = switch (source) {
                        .sealed => self.sealed,
                        .template => self.template,
                        .instance => self.instance,
                        .fixed_root => self.roots[0],
                        .main_root => self.roots[1],
                        else => unreachable,
                    };
                    break :blk std.mem.readInt(u32, digest[4 * @as(usize, coordinate) ..][0..4], .little);
                };
                var bytes: [4]M = undefined;
                for (&bytes, 0..) |*byte, i| byte.* = M.fromCanonical((value >> @as(u5, @intCast(8 * i))) & 255);
                return bytes;
            },
        }
    }
    pub fn mix(self: Values, channel: anytype) void {
        channel.mixU32s(&.{ 0x42355049, 1, self.index });
        for ([_][32]u8{ self.sealed, self.template, self.instance, self.roots[0], self.roots[1], self.statement_digest }) |digest| channel.mixRoot(digest);
        channel.mixFelts(&.{ self.compensation, self.open_sum });
    }
};

pub fn scheduleDigest(wires: []const Wire) ![32]u8 {
    if (wires.len == 0 or wires.len > 128) return error.InvalidRecursivePublicSchedule;
    if (!@import("public_wire_uniqueness_v1.zig").For(Wire, 128).unique(wires)) return error.InvalidRecursivePublicSchedule;
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42355057, 1, @intCast(wires.len) });
    for (wires) |wire| {
        if (wire.uses == 0 or wire.uses >= core.fields.m31.Modulus or wire.circuit >= core.fields.m31.Modulus or wire.wire >= core.fields.m31.Modulus)
            return error.InvalidRecursivePublicSchedule;
        const max: u8 = switch (wire.source) {
            .compensation, .open_sum => 1,
            .ordinal_header => 3,
            else => 8,
        };
        if (wire.coordinate >= max) return error.InvalidRecursivePublicSchedule;
        channel.mixU32s(&.{ wire.circuit, wire.wire, wire.uses, @intFromEnum(wire.source), wire.coordinate });
    }
    return channel.digestBytes();
}
pub fn supply(wires: []const Wire, values: Values, relations: universal.UniversalRelations) !Q {
    _ = try scheduleDigest(wires);
    try values.validate();
    const elements = try relations.getExact(.recursion_wire);
    var total = Q.zero();
    for (wires) |wire| {
        const tuple = .{ M.fromCanonical(wire.circuit), M.fromCanonical(wire.wire) } ++ try values.at(wire.source, wire.coordinate);
        const denominator = try elements.combineBase(&tuple);
        if (denominator.isZero()) return error.RecursivePublicDenominatorZero;
        total = total.add(Q.fromBase(M.fromCanonical(wire.uses)).mul(try denominator.inv()));
    }
    return total;
}

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    recursive: @import("blake3_execution_parent_preparation.zig").Prepared,
    wires: []Wire,
    values: Values,
    pub fn deinit(self: *Prepared) void {
        self.recursive.deinit();
        self.allocator.free(self.wires);
        self.* = undefined;
    }
};
/// Broad reusable route: every changing transcript input and endpoint-dependent
/// compensation is externally supplied; the fixed tree contains schedules only.
pub fn prepare(a: std.mem.Allocator, admitted: anytype, capture: anytype, capacity: u32) !Prepared {
    var dynamic = admitted.*;
    dynamic.reusable_public_inputs = true;
    const values = try Values.fromNative(a, &dynamic, capture.receipt);
    var planned = try @import("blake3_execution_parent_preparation.zig").State.plan(a, &dynamic, capture, admitted.expected_id, capacity);
    defer planned.deinit();
    const state = planned.state.?;
    const transcript = &planned.transcript.?;
    var wires: std.ArrayList(Wire) = .empty;
    errdefer wires.deinit(a);
    const root_circuit = @import("air/blake3_root_sources.zig").CIRCUIT;
    const path_reads: u32 = @intCast(capture.proof.queries.raw.len);
    for (transcript.plan.fixed.root_reads) |receipt| {
        const source: Source = if (receipt.source.circuit == PUBLIC_CIRCUIT) switch (receipt.source.first_wire) {
            0 => .sealed,
            8 => .template,
            16 => .instance,
            else => return error.InvalidRecursivePublicSchedule,
        } else if (receipt.source.circuit == root_circuit and receipt.source.first_wire < 16)
            (if (receipt.source.first_wire == 0) .fixed_root else .main_root)
        else
            continue;
        for (receipt.uses, 0..) |reads, coordinate| {
            const uses = try std.math.add(u32, reads, if (receipt.source.circuit == root_circuit) path_reads else 0);
            try wires.append(a, .{ .circuit = receipt.source.circuit, .wire = receipt.source.first_wire + @as(u32, @intCast(coordinate)), .uses = uses, .source = source, .coordinate = @intCast(coordinate) });
        }
    }
    for (transcript.plan.fixed.payload_reads) |receipt| if (receipt.source.circuit == PUBLIC_CIRCUIT) {
        if (receipt.source.first_wire != 24 or receipt.uses.len != 3) return error.InvalidRecursivePublicSchedule;
        for (receipt.uses, 0..) |uses, coordinate|
            try wires.append(a, .{ .circuit = PUBLIC_CIRCUIT, .wire = 24 + @as(u32, @intCast(coordinate)), .uses = uses, .source = .ordinal_header, .coordinate = @intCast(coordinate) });
    };
    const counts = try a.alloc(u32, state.composition.circuit.nodes.len);
    defer a.free(counts);
    const uses = try @import("air/verifier_arithmetic_lowering.zig").computeUseCountsInto(state.composition.circuit.graph(), counts);
    for (state.composition.sources, 0..) |source, node| if (source == .public_input) {
        if (source.public_input > 1) return error.InvalidRecursivePublicSchedule;
        const kind: Source = if (source.public_input == 0) .compensation else .open_sum;
        if (!std.meta.eql(try values.at(kind, 0), state.composition.inputs[node].toM31Array())) return error.UntrustedNativeV5PublicInputs;
        try wires.append(a, .{ .circuit = 1500, .wire = @intCast(node), .uses = uses[node], .source = kind, .coordinate = 0 });
    };
    _ = try scheduleDigest(wires.items);
    const emitted = try planned.emit();
    defer emitted.deinit();
    var recursive = try emitted.finishReleasingRows();
    errdefer recursive.deinit();
    return .{ .allocator = a, .recursive = recursive, .wires = try wires.toOwnedSlice(a), .values = values };
}
