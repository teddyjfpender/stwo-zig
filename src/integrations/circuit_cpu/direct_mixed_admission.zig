//! Witness-free admission prototype for a mixed pair/many native roster.
//!
//! This module intentionally exposes no prover, verifier, proof parser, or
//! transcript. It checks a concrete native AIR handle for each source kind;
//! S31 must supply the calls and endpoint addresses from sealed source.
const std = @import("std");
const core = @import("stwo_core");
const pair = @import("private_pair_boundary.zig");
const many = @import("private_many_boundary.zig");
const pair_chip = @import("tagged_pair_chip.zig");
const pair_bridge = @import("tagged_pair_bridge.zig");
const many_chip = @import("tagged_many_chip.zig");
const many_bridge = @import("tagged_many_bridge.zig");

const QM31 = core.fields.qm31.QM31;
const Digest = [32]u8;

pub const policy_version: u32 = 1;
pub const SourceKind = enum(u8) { pair_chip, pair_bridge, many_chip, many_bridge };
pub const Role = enum(u8) { chip, bridge };

const pair_chip_sha256 = parseDigest("cb0fda73f191f74efe4c7ade3fe057c32cc86038db73ab4d53293146bd749e96");
const pair_bridge_sha256 = parseDigest("f87c101304f635ff60bddbea46f2c8e29f10dc4ceff453f450d99cd8e2f2be4f");
const many_chip_sha256 = parseDigest("94a0a4d9203a024209b5e7cdfb2912fe63c33c4c623832712c82e167d4b6efa6");
const many_bridge_sha256 = parseDigest("7a0b9b6c1353f55571ef31a10ebd8f9e4e4422c5ed5a33c8e48e580668a5f466");

pub const Fact = struct {
    kind: SourceKind,
    call_id: u32,
    trace_log_size: u32,
    evaluation_log_size: u32,
    main_columns: usize,
    interaction_columns: usize,
    n_constraints: usize,
    relation_ids: [2]u32,
    relation_count: usize,
    source_sha256: Digest,

    pub fn relationSlice(self: *const Fact) []const u32 {
        return self.relation_ids[0..self.relation_count];
    }
};

/// Fixed policy: calls 0 and 1 use the pair AIRs, later calls use the many
/// AIRs. For N >= 3 this is a genuinely mixed source-kind composition.
pub fn kindForCall(call_id: u32, role: Role) !SourceKind {
    if (call_id >= many.max_calls) return error.UnsupportedMixedCallId;
    return if (call_id < pair.n_calls)
        (if (role == .chip) .pair_chip else .pair_bridge)
    else
        (if (role == .chip) .many_chip else .many_bridge);
}

/// Instantiate the actual registered verifier component and query its degree
/// and trace geometry. This does not show that its lookup formula is sound;
/// the relation list is a reviewed source-kind contract.
pub fn inspectNative(allocator: std.mem.Allocator, kind: SourceKind, call: many.Call) !Fact {
    const expected = try kindForCall(call.call_id, switch (kind) {
        .pair_chip, .many_chip => .chip,
        .pair_bridge, .many_bridge => .bridge,
    });
    if (kind != expected) return error.UnsupportedMixedSourceKind;
    const log_size = try many_chip.validateRounds(call.rounds);
    var pc: pair_chip.Component = undefined;
    var pb: pair_bridge.Component = undefined;
    var mc: many_chip.Component = undefined;
    var mb: many_bridge.Component = undefined;
    const handle: core.air.components.Component = switch (kind) {
        .pair_chip => blk: {
            pc = .{ .log_size = log_size, .call_id = call.call_id, .constant = call.constant, .main_offset = 0, .interaction_offset = 0, .elements = .init(QM31.one(), QM31.one()), .claimed_sum = QM31.zero() };
            break :blk pc.asVerifierComponent();
        },
        .pair_bridge => blk: {
            pb = .{ .main_offset = 0, .interaction_offset = 0, .boundary = call, .elements = .init(QM31.one(), QM31.one()), .claimed_sum = QM31.zero() };
            break :blk pb.asVerifierComponent();
        },
        .many_chip => blk: {
            mc = .{ .log_size = log_size, .call_id = call.call_id, .constant = call.constant, .main_offset = 0, .interaction_offset = 0, .elements = .init(QM31.one(), QM31.one()), .claimed_sum = QM31.zero() };
            break :blk mc.asVerifierComponent();
        },
        .many_bridge => blk: {
            mb = .{ .main_offset = 0, .interaction_offset = 0, .boundary = call, .elements = .init(QM31.one(), QM31.one()), .claimed_sum = QM31.zero() };
            break :blk mb.asVerifierComponent();
        },
    };
    var logs = try handle.traceLogDegreeBounds(allocator);
    defer logs.deinitDeep(allocator);
    if (logs.items.len != 3 or logs.items[0].len != 0)
        return error.UnsupportedMixedHandleGeometry;
    const trace_log = if (kind == .pair_chip or kind == .many_chip) log_size else pair.bridge_log_size;
    for (logs.items[1..]) |columns| for (columns) |column_log|
        if (column_log != trace_log) return error.UnsupportedMixedHandleGeometry;
    const expected_main: usize = if (kind == .pair_chip or kind == .many_chip) 9 else 8;
    const expected_interaction: usize = if (kind == .pair_chip or kind == .many_chip) 8 else 20;
    const expected_constraints: usize = if (kind == .pair_chip or kind == .many_chip) 6 else 13;
    const expected_evaluation = trace_log + if (kind == .pair_chip or kind == .many_chip) @as(u32, 1) else @as(u32, 2);
    const indices = try handle.preprocessedColumnIndices(allocator);
    defer allocator.free(indices);
    if (logs.items[1].len != expected_main or logs.items[2].len != expected_interaction or
        indices.len != 0 or handle.nConstraints() != expected_constraints or
        handle.maxConstraintLogDegreeBound() != expected_evaluation or
        handle.compositionLogSplit() != core.verifier_types.COMPOSITION_LOG_SPLIT)
        return error.UnsupportedMixedHandleGeometry;
    const source = switch (kind) {
        .pair_chip => @embedFile("tagged_pair_chip.zig"),
        .pair_bridge => @embedFile("tagged_pair_bridge.zig"),
        .many_chip => @embedFile("tagged_many_chip.zig"),
        .many_bridge => @embedFile("tagged_many_bridge.zig"),
    };
    const wanted_sha256 = switch (kind) {
        .pair_chip => pair_chip_sha256,
        .pair_bridge => pair_bridge_sha256,
        .many_chip => many_chip_sha256,
        .many_bridge => many_bridge_sha256,
    };
    var actual_sha256: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(source, &actual_sha256, .{});
    if (!std.meta.eql(actual_sha256, wanted_sha256)) return error.UnregisteredMixedAirSource;
    const chip_role = kind == .pair_chip or kind == .many_chip;
    return .{
        .kind = kind,
        .call_id = call.call_id,
        .trace_log_size = trace_log,
        .evaluation_log_size = expected_evaluation,
        .main_columns = logs.items[1].len,
        .interaction_columns = logs.items[2].len,
        .n_constraints = handle.nConstraints(),
        .relation_ids = if (chip_role) .{ many.relation_id, 0 } else .{ @import("stwo_circuit_frontend").common.component_list.GATE_RELATION_ID, many.relation_id },
        .relation_count = if (chip_role) 1 else 2,
        .source_sha256 = actual_sha256,
    };
}

fn parseDigest(comptime hex: []const u8) Digest {
    var result: Digest = undefined;
    _ = std.fmt.hexToBytes(&result, hex) catch unreachable;
    return result;
}

test "mixed native admission instantiates pair and many AIR handles" {
    const M31 = core.fields.m31.M31;
    const a = std.testing.allocator;
    var call: many.Call = .{ .call_id = 0, .rounds = 16, .constant = M31.fromCanonical(7), .input = .{ 3, 4, 5, 6 }, .output = .{ 7, 8, 9, 10 } };
    const first = try inspectNative(a, .pair_chip, call);
    try std.testing.expectEqual(@as(usize, 9), first.main_columns);
    try std.testing.expectEqual(@as(usize, 1), first.relation_count);
    const first_bridge = try inspectNative(a, .pair_bridge, call);
    try std.testing.expectEqual(@as(usize, 2), first_bridge.relation_count);
    call.call_id = 2;
    const later = try inspectNative(a, .many_chip, call);
    try std.testing.expectEqual(@as(u32, 2), later.call_id);
    _ = try inspectNative(a, .many_bridge, call);
    try std.testing.expectError(error.UnsupportedMixedSourceKind, inspectNative(a, .pair_chip, call));
    call.call_id = 7;
    _ = try inspectNative(a, .many_chip, call);
    _ = try inspectNative(a, .many_bridge, call);
    call.call_id = 8;
    try std.testing.expectError(error.UnsupportedMixedCallId, kindForCall(call.call_id, .chip));
}
