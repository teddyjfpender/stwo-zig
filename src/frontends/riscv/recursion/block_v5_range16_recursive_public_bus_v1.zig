//! External range statement tuples close the actual transcript, root paths and
//! public sum/count graph inputs. Schedules are independently key-pinned.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Native = @import("../prover/block_v5_range16_proof_v1.zig");
const Range = @import("../prover/block_v5_range16_v1.zig");
const Word = @import("../prover/block_v5_word_memory_protocol_v1.zig");
const universal = @import("air/universal_challenges.zig");
pub const VERSION: u32 = 1;
pub const PUBLIC_CIRCUIT: u32 = 4_200_005;
pub const MAX_WIRES: usize = 64;
pub const Source = enum(u8) { sealed, plan, fixed_root, main_root, shard_header, request_count_words, claim_count_words, sum_words, sum, count };
pub const Wire = struct { circuit: u32, wire: u32, uses: u32, source: Source, coordinate: u32 };
pub const Values = struct {
    template: [32]u8,
    sealed: [32]u8,
    plan: [32]u8,
    roots: [2][32]u8,
    shard: Range.Shard,
    sum: Q,
    count: u64,
    pub fn fromRange(admitted: anytype, receipt: Native.OpenReceipt) !Values {
        try admitted.validate(admitted.template_id);
        if (!std.meta.eql(receipt.shard, admitted.shard) or !std.meta.eql(receipt.roots, admitted.roots) or
            !std.meta.eql(receipt.sealed_digest, admitted.sealed.digest)) return error.UntrustedRangePublicInputs;
        const result = Values{ .template = admitted.template_id, .sealed = admitted.sealed.digest, .plan = admitted.plan_digest, .roots = admitted.roots, .shard = admitted.shard, .sum = receipt.claim.sum, .count = receipt.claim.count };
        try result.validate();
        return result;
    }
    pub fn validate(self: Values) !void {
        if (self.shard.index >= core.fields.m31.Modulus or self.shard.first_instance >= core.fields.m31.Modulus or
            self.shard.instance_count == 0 or self.shard.instance_count >= core.fields.m31.Modulus or
            self.shard.request_count == 0 or self.shard.request_count > Range.MAX_REQUESTS or self.count != self.shard.request_count)
            return error.InvalidRangePublicInputs;
        for (self.sum.toM31Array()) |value| if (value.v >= core.fields.m31.Modulus) return error.InvalidRangePublicInputs;
        for ([_][32]u8{ self.template, self.sealed, self.plan, self.roots[0], self.roots[1] }) |digest| if (std.mem.allEqual(u8, &digest, 0)) return error.InvalidRangePublicInputs;
    }
    pub fn at(self: Values, source: Source, coordinate: u32) ![4]M {
        if (source == .sum or source == .count) {
            if (coordinate != 0) return error.InvalidRangePublicSchedule;
            return if (source == .sum) self.sum.toM31Array() else .{ M.fromCanonical(@intCast(self.count)), M.zero(), M.zero(), M.zero() };
        }
        const word: u32 = switch (source) {
            .shard_header => blk: {
                if (coordinate >= 6) return error.InvalidRangePublicSchedule;
                break :blk ([_]u32{ Word.TAG, Word.VERSION, Range.TABLE_LOG, self.shard.index, self.shard.first_instance, self.shard.instance_count })[coordinate];
            },
            .request_count_words, .claim_count_words => blk: {
                if (coordinate >= 2) return error.InvalidRangePublicSchedule;
                const value = if (source == .request_count_words) self.shard.request_count else self.count;
                break :blk @truncate(value >> @as(u6, @intCast(32 * coordinate)));
            },
            .sum_words => blk: {
                if (coordinate >= 4) return error.InvalidRangePublicSchedule;
                break :blk self.sum.toM31Array()[coordinate].toU32();
            },
            .sealed, .plan, .fixed_root, .main_root => blk: {
                if (coordinate >= 8) return error.InvalidRangePublicSchedule;
                const digest = switch (source) {
                    .sealed => self.sealed,
                    .plan => self.plan,
                    .fixed_root => self.roots[0],
                    .main_root => self.roots[1],
                    else => unreachable,
                };
                break :blk std.mem.readInt(u32, digest[4 * @as(usize, coordinate) ..][0..4], .little);
            },
            else => unreachable,
        };
        var bytes: [4]M = undefined;
        for (&bytes, 0..) |*byte, index| byte.* = M.fromCanonical((word >> @as(u5, @intCast(8 * index))) & 255);
        return bytes;
    }
    pub fn mix(self: Values, channel: anytype) void {
        channel.mixU32s(&.{ 0x42355249, VERSION }); // B5RI
        channel.mixRoot(self.template);
        channel.mixRoot(self.sealed);
        Native.mixShard(channel, self.shard, self.plan);
        for (self.roots) |root| channel.mixRoot(root);
        channel.mixU64(self.count);
        channel.mixFelts(&.{self.sum});
    }
};
pub fn scheduleDigest(wires: []const Wire) ![32]u8 {
    if (wires.len == 0 or wires.len > MAX_WIRES) return error.InvalidRangePublicSchedule;
    if (!@import("public_wire_uniqueness_v1.zig").For(Wire, MAX_WIRES).unique(wires)) return error.InvalidRangePublicSchedule;
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ 0x42355257, VERSION, @intCast(wires.len) });
    for (wires) |wire| {
        if (wire.circuit >= core.fields.m31.Modulus or wire.wire >= core.fields.m31.Modulus or wire.uses == 0 or wire.uses >= core.fields.m31.Modulus) return error.InvalidRangePublicSchedule;
        const maximum: u32 = switch (wire.source) {
            .sum, .count => 1,
            .request_count_words, .claim_count_words => 2,
            .sum_words => 4,
            .shard_header => 6,
            else => 8,
        };
        if (wire.coordinate >= maximum) return error.InvalidRangePublicSchedule;
        channel.mixU32s(&.{ wire.circuit, wire.wire, wire.uses, @intFromEnum(wire.source), wire.coordinate });
    }
    return channel.digestBytes();
}
pub fn supply(wires: []const Wire, values: Values, relations: universal.UniversalRelations) !Q {
    _ = try scheduleDigest(wires);
    try values.validate();
    const elements = try relations.getExact(.recursion_wire);
    var sum = Q.zero();
    for (wires) |wire| {
        const denominator = try elements.combineBase(&(.{ M.fromCanonical(wire.circuit), M.fromCanonical(wire.wire) } ++ try values.at(wire.source, wire.coordinate)));
        if (denominator.isZero()) return error.RangePublicDenominatorZero;
        sum = sum.add(Q.fromBase(M.fromCanonical(wire.uses)).mul(try denominator.inv()));
    }
    return sum;
}
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    budget: *@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
    recursive: @import("blake3_execution_parent_preparation.zig").Prepared,
    wires: []Wire,
    values: Values,
    pub fn deinit(self: *Prepared) void {
        self.recursive.deinit();
        self.allocator.free(self.wires);
        self.budget.destroy();
        self.* = undefined;
    }
};
pub fn prepare(a: std.mem.Allocator, admitted: anytype, capture: anytype, capacity: u32) !Prepared {
    const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.createRetainingParent(a, admitted.limits.max_preparation_bytes);
    errdefer budget.destroy();
    const bounded = budget.allocator();
    const values = try Values.fromRange(admitted, capture.receipt);
    var planned = try @import("blake3_execution_parent_preparation.zig").State.plan(bounded, admitted, capture, admitted.template_id, capacity);
    defer planned.deinit();
    const state = planned.state.?;
    const transcript = &planned.transcript.?;
    // Preserve original fresh public-value comparisons before shared routing.
    for (state.composition.sources, 0..) |source, node| if (source == .public_input) {
        if (source.public_input > 1) return error.InvalidRangePublicSchedule;
        const binding: Source = if (source.public_input == 0) .sum else .count;
        if (!std.meta.eql(try values.at(binding, 0), state.composition.inputs[node].toM31Array())) return error.UntrustedRangePublicInputs;
    };
    const path_reads = std.math.cast(u32, capture.proof.queries.raw.len) orelse return error.InvalidRangePublicSchedule;
    const wires = try @import("air/block_v5_word_public_schedule_v1.zig").For(.range16, @This()).collect(bounded, &transcript.plan, &state.composition, path_reads);
    errdefer bounded.free(wires);
    const emitted = try planned.emit();
    defer emitted.deinit();
    var recursive = try emitted.finishReleasingRows();
    errdefer recursive.deinit();
    return .{ .allocator = bounded, .budget = budget, .recursive = recursive, .wires = wires, .values = values };
}
