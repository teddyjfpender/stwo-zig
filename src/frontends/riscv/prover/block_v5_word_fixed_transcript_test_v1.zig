//! Original operation/framing and fixed metadata tests only; no proof receipt.
const std = @import("std");
const core = @import("stwo_core");
const Prefix = @import("../recursion/air/block_v5_word_transcript_prefix_v1.zig");
const Native = @import("../recursion/air/blake3_native_recorder.zig");
const Sink = @import("../recursion/air/blake3_fixed_operation_recorder_v1.zig");
const Schema = @import("../recursion/air/blake3_pcs_operation_schema_v1.zig");
const Plan = @import("../recursion/air/blake3_transcript_plan.zig").Plan;
const Fixed = @import("../recursion/block_v5_word_recursive_fixed_transcript_v1.zig");
const Word = @import("block_v5_word_memory_protocol_v1.zig");
const U = @import("../recursion/air/universal_challenges.zig");
const T = @import("../recursion/air/blake3_transcript_witness.zig");
const Values = struct {
    pub fn root(_: @This(), r: anytype, source: T.Caller, role: Prefix.Root) !void {
        r.mixPublicRoot(source, [_]u8{if (role == .sealed) 71 else 123} ** 32);
        try r.check();
    }
    pub fn integer(_: @This(), r: anytype, source: T.Caller, role: Prefix.Integer) !void {
        r.mixPublicInteger(source, @as(u64, 0xfedc_ba98_7654_3200) + @intFromEnum(role));
        try r.check();
    }
    pub fn limb(_: @This(), r: anytype, source: T.Caller, field: usize, index: usize) !void {
        r.mixPublicWords(source, &.{@as(u32, @intCast(field * 4 + index + 11))});
        try r.check();
    }
    pub fn shard(_: @This(), r: anytype, source: T.Caller) !void {
        r.mixPublicWords(source, &.{ Word.TAG, Word.VERSION, 16, 7, 13, 17 });
        try r.check();
    }
};
// Independent original pre-extraction framing oracle; actual native channel
// runs only protocol absorption/draws, never PCS verification or proving.
fn oracle(comptime family: Prefix.Family, a: std.mem.Allocator, r: *Native.Recorder) !Word.Challenges {
    const universal = @import("block_v5_universal_channel_v1.zig");
    const circuit = if (family == .ram_lanes) @import("../recursion/block_v5_ram_lanes_recursive_public_bus_v1.zig").PUBLIC_CIRCUIT else @import("../recursion/block_v5_range16_recursive_public_bus_v1.zig").PUBLIC_CIRCUIT;
    r.mixU32s(&.{ universal.TAG, universal.VERSION });
    r.mixPublicRoot(.{ .circuit = circuit, .first_wire = 0 }, [_]u8{71} ** 32);
    // Preserve the original bulk universal draw then word-v4 tag/five pairs.
    const universal_draws = try U.UniversalRelations.draw(a, r);
    r.mixU32s(&.{ Word.TAG, Word.VERSION, Word.TRANSITION_ARITY, Word.LINK_ARITY, Word.INITIAL_ARITY, Word.ENDPOINT_ARITY, Word.RANGE_ARITY });
    const draws = try r.drawSecureFelts(a, 10);
    defer a.free(draws);
    const challenges = Word.Challenges{ .transition = .init(draws[0], draws[1]), .link = .init(draws[2], draws[3]), .initial = .init(draws[4], draws[5]), .endpoint = .init(draws[6], draws[7]), .range16 = .init(draws[8], draws[9]), .universal_prefix = universal_draws };
    if (family == .ram_lanes) {
        const Ram = @import("block_v5_ram_lanes_protocol_v1.zig");
        r.mixU32s(&.{ Ram.TAG, Ram.VERSION, 0x50524f46 });
        r.mixStaticRoot(Ram.abiId());
        r.mixPublicRoot(.{ .circuit = circuit, .first_wire = 8 }, [_]u8{123} ** 32);
        r.mixPublicInteger(.{ .circuit = circuit, .first_wire = 16 }, 0xfedc_ba98_7654_3200);
        for (0..21) |i| for (0..4) |j|
            r.mixPublicWords(.{ .circuit = circuit, .first_wire = @intCast(18 + 4 * i + j) }, &.{@as(u32, @intCast(4 * i + j + 11))});
        r.mixPublicInteger(.{ .circuit = circuit, .first_wire = 102 }, 0xfedc_ba98_7654_3201);
        r.mixPublicInteger(.{ .circuit = circuit, .first_wire = 104 }, 0xfedc_ba98_7654_3202);
    } else {
        r.mixPublicWords(.{ .circuit = circuit, .first_wire = 16 }, &.{ Word.TAG, Word.VERSION, 16, 7, 13, 17 });
        r.mixPublicInteger(.{ .circuit = circuit, .first_wire = 22 }, 0xfedc_ba98_7654_3203);
        r.mixPublicRoot(.{ .circuit = circuit, .first_wire = 8 }, [_]u8{123} ** 32);
        r.mixPublicInteger(.{ .circuit = circuit, .first_wire = 24 }, 0xfedc_ba98_7654_3204);
        for (0..4) |j| r.mixPublicWords(.{ .circuit = circuit, .first_wire = @intCast(26 + j) }, &.{@as(u32, @intCast(j + 11))});
    }
    try r.skipCommittedRoots(2);
    try r.check();
    return challenges;
}
test "word fixed transcript: both original live framing channel draws and trusted fixed plans agree" {
    inline for (.{ Prefix.Family.ram_lanes, .range16 }) |family| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var expected = Native.Recorder{ .a = a, .universal_relations = true };
        const old = try oracle(family, a, &expected);
        var actual = Native.Recorder{ .a = a, .universal_relations = true };
        const changed = try Prefix.emit(family, a, &actual, Values{}, Prefix.LiveDraw);
        try std.testing.expectEqualDeep(old, changed);
        try std.testing.expectEqualDeep(expected.native, actual.native);
        try std.testing.expectEqualDeep(expected.operations.items, actual.operations.items);
        try std.testing.expectEqual(@as(usize, 52), actual.relation_count);
        var fixed = Sink.Recorder{ .a = a, .limits = .{} };
        try Prefix.emit(family, a, &fixed, Prefix.FixedValues{}, Prefix.FixedDraw);
        try std.testing.expectEqual(expected.root_count, fixed.skipped_roots);
        try std.testing.expectEqual(expected.operations.items.len, fixed.operations.items.len);
        var live_plan = try Plan.initCompact(std.testing.allocator, .{ .namespace = 1_000_000, .attempt_capacity = 1 }, expected.operations.items);
        defer live_plan.deinit();
        var fixed_plan = try Plan.initCompact(std.testing.allocator, live_plan.config, fixed.operations.items);
        defer fixed_plan.deinit();
        try std.testing.expectEqualDeep(live_plan.id, fixed_plan.id);
        try std.testing.expectEqualDeep(live_plan.fixed.root_reads, fixed_plan.fixed.root_reads);
        try std.testing.expectEqualDeep(live_plan.fixed.draw_outputs, fixed_plan.fixed.draw_outputs);
        try std.testing.expect(fixed_plan.fixed.g_rows.len == 0 and fixed_plan.fixed.xor_rows.len == 0);
        try std.testing.expect(fixed_plan.fixed.nonhash == null);
    }
}
fn config(queries: usize, fold: u32) !core.pcs.PcsConfig {
    var fri = try core.fri.FriConfig.init(0, 1, queries);
    fri.fold_step = fold;
    return .{ .pow_bits = 26, .fri_config = fri };
}
fn shapeFor(comptime family: Prefix.Family, a: std.mem.Allocator, queries: usize, fold: u32) !*Fixed.ForFamily(family).Shape {
    return Fixed.ForFamily(family).Shape.init(a, if (family == .ram_lanes) 4 else 16, try config(queries, fold), .{});
}
test "word fixed transcript: native four-tree PCS suffix retains original slots draws routing and terminal counts" {
    inline for (.{ Prefix.Family.ram_lanes, .range16 }) |family| {
        const a = std.testing.allocator;
        const shape = try shapeFor(family, a, 3, 4);
        defer shape.deinit();
        var operations: std.ArrayList(Schema.Operation) = .empty;
        defer operations.deinit(a);
        try Schema.appendPcsSuffix(a, &operations, shape.config, shape.deepProfile(), shape.friProfile(), 4);
        try std.testing.expectEqual(@as(usize, 9 + 2 * shape.widths.len), operations.items.len);
        try std.testing.expectEqualDeep(Schema.Operation{ .secure = .{ .role = .composition, .consumption = .one } }, operations.items[0]);
        try std.testing.expectEqualDeep(Schema.Operation{ .commitment = .{ .slot = 3, .source = try @import("../recursion/air/blake3_root_sources.zig").caller(3) } }, operations.items[1]);
        try std.testing.expectEqualDeep(Schema.Operation{ .secure = .{ .role = .oods, .consumption = .one } }, operations.items[2]);
        try std.testing.expectEqual(try shape.sampleCount(), operations.items[3].sampled_values.count);
        try std.testing.expectEqualDeep(@import("../recursion/air/blake3_native_transcript.zig").SAMPLE_SOURCE, operations.items[3].sampled_values.source);
        try std.testing.expectEqualDeep(Schema.Operation{ .secure = .{ .role = .deep, .consumption = .one } }, operations.items[4]);
        for (shape.widths, 0..) |_, layer| {
            const root = operations.items[5 + 2 * layer].fri_root;
            try std.testing.expectEqual(layer, root.layer);
            try std.testing.expectEqualDeep(T.Caller{ .circuit = @import("../recursion/air/blake3_root_sources.zig").CIRCUIT, .first_wire = @intCast(32 + 8 * layer) }, root.source);
            try std.testing.expectEqualDeep(Schema.Operation{ .secure = .{ .role = .{ .fri = layer }, .consumption = .one } }, operations.items[6 + 2 * layer]);
        }
        const tail = operations.items[5 + 2 * shape.widths.len ..];
        try std.testing.expectEqual(try shape.friProfile().lastLayerCoefficientCount(), tail[0].terminal_coefficients.count);
        try std.testing.expectEqual(@as(u32, 26), tail[1].pow.bits);
        try std.testing.expectEqualDeep(tail[1].pow.source, tail[2].nonce);
        try std.testing.expectEqual(@as(usize, 3), tail[3].queries.count);
        try std.testing.expectEqual(shape.lifting_log, tail[3].queries.log_domain_size);
    }
}
test "word fixed transcript: changing received geometry cannot append partial PCS operations" {
    const a = std.testing.allocator;
    const shape = try shapeFor(.range16, a, 1, 4);
    defer shape.deinit();
    var ops: std.ArrayList(Schema.Operation) = .empty;
    defer ops.deinit(a);
    try ops.append(a, .{ .nonce = .{ .circuit = 3, .first_wire = 7 } });
    var mismatch = shape.config;
    mismatch.fri_config.n_queries += 1;
    try std.testing.expectError(error.UntrustedFixedPcsOperationGeometry, Schema.appendPcsSuffix(a, &ops, mismatch, shape.deepProfile(), shape.friProfile(), 4));
    mismatch = shape.config;
    mismatch.fri_config.fold_step = 2;
    try std.testing.expectError(error.UntrustedFixedPcsOperationGeometry, Schema.appendPcsSuffix(a, &ops, mismatch, shape.deepProfile(), shape.friProfile(), 4));
    try std.testing.expectError(error.UntrustedFixedPcsOperationGeometry, Schema.appendPcsSuffix(a, &ops, shape.config, shape.deepProfile(), shape.friProfile(), 5));
    try std.testing.expectEqual(@as(usize, 1), ops.items.len);
}
fn suffixAllocation(a: std.mem.Allocator, shape: *const Fixed.ForFamily(.range16).Shape) !void {
    var operations: std.ArrayList(Schema.Operation) = .empty;
    defer operations.deinit(a);
    try operations.append(a, .{ .nonce = .{ .circuit = 3, .first_wire = 7 } });
    Schema.appendPcsSuffix(a, &operations, shape.config, shape.deepProfile(), shape.friProfile(), 4) catch |err| {
        try std.testing.expectEqual(@as(usize, 1), operations.items.len);
        return err;
    };
}
test "word fixed transcript: PCS grammar allocation failures preserve caller prefix" {
    const shape = try shapeFor(.range16, std.testing.allocator, 1, 4);
    defer shape.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, suffixAllocation, .{shape});
}
test "word fixed transcript: genuine native shape records compact plans without MAIN columns or native execution" {
    inline for (.{ Prefix.Family.ram_lanes, .range16 }) |family| {
        const a = std.testing.allocator;
        const shape = try shapeFor(family, a, 1, 4);
        defer shape.deinit();
        var first = try Fixed.ForFamily(family).recordForShape(a, shape, 1, .{});
        defer first.deinit();
        var second = try Fixed.ForFamily(family).recordForShape(a, shape, 1, .{});
        defer second.deinit();
        try first.validate();
        try second.validate();
        try std.testing.expectEqualDeep(first.id, second.id);
        try std.testing.expect(first.fixed.g_rows.len == 0 and first.fixed.xor_rows.len == 0);
        try std.testing.expect(first.fixed.nonhash == null and first.fixed.final_digest == null);
        try std.testing.expectEqual(@as(usize, 52 + 3 + shape.widths.len), first.fixed.draw_outputs.len);
        try std.testing.expectEqual(@as(usize, 1), first.fixed.query_outputs.len);
        try std.testing.expectError(error.InvalidBlake3Transcript, Fixed.ForFamily(family).recordForShape(a, shape, 0, .{}));
        try std.testing.expectError(error.RecursiveParentFixedTranscriptResourceLimit, Fixed.ForFamily(family).recordForShape(a, shape, 1, .{ .max_operations = 1 }));
        try std.testing.expectError(error.RecursiveParentFixedTranscriptResourceLimit, Fixed.ForFamily(family).recordForShape(a, shape, 1, .{ .max_routed_words = 1 }));
    }
}
test "word fixed transcript: sink preserves errors and original skipped-root guards" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var r = Sink.Recorder{ .a = arena.allocator(), .limits = .{ .max_operations = 1 } };
    try std.testing.expectError(error.InvalidNativeBlake3Transcript, r.skipCommittedRoots(2));
    r.mixU32s(&.{7});
    try r.skipCommittedRoots(2);
    try std.testing.expectError(error.InvalidNativeBlake3Transcript, r.skipCommittedRoots(2));
    r.mixU32s(&.{8});
    try std.testing.expectError(error.RecursiveParentFixedTranscriptResourceLimit, r.check());
    r.mixRoot([_]u8{11} ** 32);
    try std.testing.expectError(error.RecursiveParentFixedTranscriptResourceLimit, r.check());
    try std.testing.expectEqual(@as(usize, 1), r.operations.items.len);
}
