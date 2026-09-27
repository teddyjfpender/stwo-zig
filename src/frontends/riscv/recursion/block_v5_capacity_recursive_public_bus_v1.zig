//! Versioned B5CT public supply: changing shard counts, roots and instance
//! metadata never enter fixed recursive setup or private producer rows.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const capacity = @import("../prover/block_v5_native_capacity_protocol_v1.zig");
const admitted_mod = @import("../prover/block_v5_native_capacity_recursive_admission_v1.zig");
const native_proof = @import("../prover/block_v5_native_capacity_proof_v1.zig");
const universal = @import("air/universal_challenges.zig");
pub const VERSION: u32 = 1;
pub const PUBLIC_CIRCUIT: u32 = 4_200_004;
pub const MAX_WIRES: usize = 64 + capacity.MAX_SHARDS;
pub const Source = enum(u8) { sealed, template, instance, ordinal_header, fixed_root, main_root, compensation, open_sum, row_count, frame_retirements };
pub const Wire = struct { circuit: u32, wire: u32, uses: u32, source: Source, coordinate: u32 };
pub const Values = struct {
    sealed: [32]u8,
    template: [32]u8,
    instance: [32]u8,
    roots: [2][32]u8,
    index: u32,
    compensation: Q,
    open_sum: Q,
    statement_digest: [32]u8,
    exact_geometry_digest: [32]u8,
    rows: [capacity.MAX_SHARDS]u32 = @splat(0),
    row_count: u32 = 0,
    frame_retirements: u32 = 0,
    pub fn fromCapacity(a: std.mem.Allocator, admitted: *const admitted_mod.Prepared, receipt: native_proof.OpenReceipt) !Values {
        try admitted.validate(admitted.template_id);
        const plan = try capacity.Plan.fromShape(admitted.shape, admitted.external_retirements);
        const exact = try @import("../prover/block_v5_native_template_protocol_v3.zig").geometryDigest(admitted.shape, admitted.external_retirements);
        if (!std.meta.eql(receipt.template_id, admitted.template_id) or
            !std.meta.eql(receipt.sealed_digest, admitted.sealed.digest) or
            !std.meta.eql(receipt.first_roots[0], admitted.template.fixed_root) or
            !std.meta.eql(receipt.exact_geometry_digest, exact) or
            !std.meta.eql(receipt.instance_id, try capacity.instanceId(admitted.template_id, admitted.shape, admitted.external_retirements, admitted.pin, receipt.first_roots, admitted.index))) return error.UntrustedCapacityPublicInputs;
        if (admitted.catalog) |catalog|
            try native_proof.admitWithCatalog(a, admitted.shape, admitted.external_retirements, admitted.pin, admitted.template, admitted.template_id, receipt.instance_id, receipt.first_roots, admitted.index, admitted.sealed, admitted.pins, admitted.entries, catalog)
        else
            try native_proof.admit(a, admitted.shape, admitted.external_retirements, admitted.pin, admitted.template, admitted.template_id, receipt.instance_id, receipt.first_roots, admitted.index, admitted.sealed, admitted.pins, admitted.entries);
        const challenges = try @import("../prover/block_memory_relation_v2.zig").Challenges.draw(a, admitted.sealed);
        const providers = try @import("air/universal_provider_relations.zig").SharedProviderRelations.init(&challenges.universal_prefix);
        const compensation = try @import("../air/public_logup_arithmetic.zig").registersStateSumFor(Q, &admitted.shape.public_data, &providers.native);
        var result = Values{ .sealed = admitted.sealed.digest, .template = admitted.template_id, .instance = receipt.instance_id, .roots = receipt.first_roots, .index = admitted.index, .compensation = compensation, .open_sum = receipt.open_sum, .statement_digest = @import("../prover/block_v5_native_public_admission_v1.zig").publicDigest(&admitted.shape.public_data), .exact_geometry_digest = exact, .row_count = @intCast(plan.len), .frame_retirements = if (plan.len == 0) admitted.external_retirements else 0 };
        for (plan.active(), 0..) |shard, i| result.rows[i] = shard.rows;
        try result.validate();
        return result;
    }
    pub fn validate(self: Values) !void {
        if (self.index >= core.fields.m31.Modulus or self.row_count > capacity.MAX_SHARDS or
            (self.row_count == 0 and (self.frame_retirements == 0 or self.frame_retirements >= core.fields.m31.Modulus)) or
            (self.row_count != 0 and self.frame_retirements != 0)) return error.InvalidCapacityPublicInputs;
        for (self.rows[0..self.row_count]) |rows| if (rows == 0 or rows > 1 << 24) return error.InvalidCapacityPublicInputs;
        for (self.rows[self.row_count..]) |rows| if (rows != 0) return error.InvalidCapacityPublicInputs;
        for (self.compensation.toM31Array() ++ self.open_sum.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.InvalidCapacityPublicInputs;
        for ([_][32]u8{ self.sealed, self.template, self.instance, self.statement_digest, self.exact_geometry_digest, self.roots[0], self.roots[1] }) |digest| if (std.mem.allEqual(u8, &digest, 0)) return error.InvalidCapacityPublicInputs;
    }
    pub fn publicInput(self: Values, index: u32) !struct { source: Source, coordinate: u32 } {
        if (index < 2) return .{ .source = if (index == 0) .compensation else .open_sum, .coordinate = 0 };
        if (self.row_count == 0) {
            if (index != 2) return error.InvalidCapacityPublicSchedule;
            return .{ .source = .frame_retirements, .coordinate = 0 };
        }
        if (index - 2 >= self.row_count) return error.InvalidCapacityPublicSchedule;
        return .{ .source = .row_count, .coordinate = index - 2 };
    }
    pub fn at(self: Values, source: Source, coordinate: u32) ![4]M {
        switch (source) {
            .compensation, .open_sum => {
                if (coordinate != 0) return error.InvalidCapacityPublicSchedule;
                return (if (source == .compensation) self.compensation else self.open_sum).toM31Array();
            },
            .row_count => {
                if (coordinate >= self.row_count) return error.InvalidCapacityPublicSchedule;
                return .{ M.fromCanonical(self.rows[coordinate]), M.zero(), M.zero(), M.zero() };
            },
            .frame_retirements => {
                if (self.row_count != 0 or coordinate != 0) return error.InvalidCapacityPublicSchedule;
                return .{ M.fromCanonical(self.frame_retirements), M.zero(), M.zero(), M.zero() };
            },
            else => {
                const word: u32 = if (source == .ordinal_header) blk: {
                    if (coordinate >= 3) return error.InvalidCapacityPublicSchedule;
                    break :blk ([_]u32{ capacity.TAG, capacity.VERSION, self.index })[coordinate];
                } else blk: {
                    if (coordinate >= 8) return error.InvalidCapacityPublicSchedule;
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
                for (&bytes, 0..) |*byte, i| byte.* = M.fromCanonical((word >> @as(u5, @intCast(8 * i))) & 255);
                return bytes;
            },
        }
    }
    pub fn mix(self: Values, channel: anytype) void {
        channel.mixU32s(&.{ 0x42354349, VERSION, capacity.TAG, capacity.VERSION, self.index, self.row_count, self.frame_retirements });
        for ([_][32]u8{ self.sealed, self.template, self.instance, self.roots[0], self.roots[1], self.statement_digest, self.exact_geometry_digest }) |digest| channel.mixRoot(digest);
        channel.mixU32s(self.rows[0..self.row_count]);
        channel.mixFelts(&.{ self.compensation, self.open_sum });
    }
};

pub fn scheduleDigest(wires: []const Wire) ![32]u8 {
    if (wires.len == 0 or wires.len > MAX_WIRES) return error.InvalidRecursivePublicSchedule;
    if (!@import("public_wire_uniqueness_v1.zig").For(Wire, MAX_WIRES).unique(wires)) return error.InvalidRecursivePublicSchedule;
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42354357, 1, @intCast(wires.len) });
    for (wires) |wire| {
        if (wire.uses == 0 or wire.uses >= core.fields.m31.Modulus or wire.circuit >= core.fields.m31.Modulus or wire.wire >= core.fields.m31.Modulus)
            return error.InvalidRecursivePublicSchedule;
        const max: u32 = switch (wire.source) {
            .compensation, .open_sum, .frame_retirements => 1,
            .row_count => capacity.MAX_SHARDS,
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
pub fn prepare(a: std.mem.Allocator, admitted: *const admitted_mod.Prepared, capture: *const native_proof.VerifiedCapture, transcript_capacity: u32) !Prepared {
    var dynamic = admitted.*;
    dynamic.reusable_public_inputs = true;
    const values = try Values.fromCapacity(a, &dynamic, capture.receipt);
    var planned = try @import("blake3_execution_parent_preparation.zig").State.plan(a, &dynamic, capture, admitted.template_id, transcript_capacity);
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
        const binding = try values.publicInput(source.public_input);
        if (!std.meta.eql(try values.at(binding.source, binding.coordinate), state.composition.inputs[node].toM31Array())) return error.UntrustedCapacityPublicInputs;
        try wires.append(a, .{ .circuit = 1500, .wire = @intCast(node), .uses = uses[node], .source = binding.source, .coordinate = binding.coordinate });
    };
    _ = try scheduleDigest(wires.items);
    const emitted = try planned.emit();
    defer emitted.deinit();
    var recursive = try emitted.finishReleasingRows();
    errdefer recursive.deinit();
    return .{ .allocator = a, .recursive = recursive, .wires = try wires.toOwnedSlice(a), .values = values };
}
