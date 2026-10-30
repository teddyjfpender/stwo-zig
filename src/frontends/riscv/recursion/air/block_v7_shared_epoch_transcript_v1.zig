//! Exact original epoch substitution for the opt-in shared mixed verifier.
//! External ports are open obligations. Only a mixed proof containing the
//! original prefix and exact bridges can authenticate these child suffixes.
const std = @import("std");
const E = @import("../../prover/block_v7_execution_epoch_v1.zig");
const T = @import("blake3_transcript_witness.zig");
const Plan = @import("blake3_transcript_plan.zig").Plan;
const Recorder = @import("blake3_fixed_operation_recorder_v1.zig");
const Native = @import("blake3_native_transcript.zig");
pub const STATE_CIRCUIT: u32 = 6_200_001;
pub const CHALLENGE_CIRCUIT: u32 = 6_200_002;
pub const PREFIX_OPERATIONS: usize = 58;
pub const FIELD_COUNT: usize = 106;
pub const WORD_COUNT: usize = 424;
pub fn outputs(caller: bool) [54]T.DrawOutput {
    var out: [54]T.DrawOutput = undefined;
    for (0..52) |i| out[i] = .{ .operation = i, .role = .{ .universal = if (caller and i >= 47) i + 14 else i }, .source = .{ .circuit = CHALLENGE_CIRCUIT, .first_wire = @intCast(8 * i) }, .words = 8 };
    for (0..2) |half| out[52 + half] = .{ .operation = 52 + half, .role = .{ .universal_half = .{ .relation = if (caller) 66 else 52, .half = @intCast(half) } }, .source = .{ .circuit = CHALLENGE_CIRCUIT, .first_wire = @intCast(416 + 4 * half) }, .words = 4 };
    return out;
}
pub fn derive(a: std.mem.Allocator, config: @import("blake3_transcript_plan.zig").Config, operations: []const T.Operation, caller: bool) !Plan {
    try requirePrefix(a, config, operations, caller);
    const exported = outputs(caller);
    return Plan.initBoundaryCompact(a, config, operations[PREFIX_OPERATIONS..], .{ .resume_before_absorb = .{ .source = .{ .circuit = STATE_CIRCUIT, .first_wire = 0 }, .value = @splat(0) }, .external_draw_outputs = &exported });
}
pub fn substitute(a: std.mem.Allocator, transcript: *Native.Planned, epoch: E.Epoch, caller: bool) !void {
    if (transcript.boundary != null) return error.SharedEpochAlreadySubstituted;
    try requirePrefix(a, transcript.plan.config, transcript.operations, caller);
    if (try prefixTag(transcript.operations) != epoch.sharedTag()) return error.UntrustedSharedEpoch;
    if (!std.mem.eql(u8, &transcript.operations[1].routed_root.value, &epoch.digest)) return error.UntrustedSharedEpoch;
    const drawn = try epoch.draw(a);
    const exported = try transcript.arena.allocator().dupe(T.DrawOutput, &outputs(caller));
    const external = try transcript.arena.allocator().alloc(Native.ExternalDraw, exported.len);
    var draw_index: usize = 0;
    for (transcript.operations[0..PREFIX_OPERATIONS]) |operation| if (operation == .secure) {
        const draw = operation.secure;
        if (draw_index >= exported.len or draw.output == null or !std.meta.eql(draw.output.?, exported[draw_index].role) or draw.consumption.words() != exported[draw_index].words) return error.InvalidSharedEpochPrefix;
        external[draw_index] = .{ .output = exported[draw_index], .values = draw.values };
        draw_index += 1;
    };
    if (draw_index != exported.len) return error.InvalidSharedEpochPrefix;
    const ports = T.Boundary{ .resume_before_absorb = .{ .source = .{ .circuit = STATE_CIRCUIT, .first_wire = 0 }, .value = drawn.channel.digestBytes() }, .external_draw_outputs = exported };
    var plan = try Plan.initBoundaryCompact(a, transcript.plan.config, transcript.operations[PREFIX_OPERATIONS..], ports);
    errdefer plan.deinit();
    if (transcript.owns_plan) transcript.plan.deinit();
    transcript.owns_plan = true;
    transcript.plan = plan;
    transcript.operations = transcript.operations[PREFIX_OPERATIONS..];
    transcript.boundary = ports;
    transcript.external_draws = external;
}
fn requirePrefix(a: std.mem.Allocator, config: @import("blake3_transcript_plan.zig").Config, operations: []const T.Operation, caller: bool) !void {
    if (operations.len <= PREFIX_OPERATIONS or operations[1] != .routed_root) return error.InvalidSharedEpochPrefix;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    var recorder = Recorder.Recorder{ .a = temp, .limits = .{} };
    recorder.mixU32s(&.{ try prefixTag(operations), E.VERSION, 2 });
    recorder.mixPublicRoot(operations[1].routed_root.source, @splat(0));
    try @import("block_v7_epoch_transcript_v1.zig").fixed(temp, &recorder);
    if (recorder.operations.items.len != PREFIX_OPERATIONS) return error.InvalidSharedEpochPrefix;
    if (caller) for (recorder.operations.items) |*op| if (op.* == .secure) {
        switch (op.secure.output.?) {
            .universal => |i| if (i >= 47) {
                op.secure.output = .{ .universal = i + 14 };
            },
            .universal_half => |part| op.secure.output = .{ .universal_half = .{ .relation = 66, .half = part.half } },
            else => return error.InvalidSharedEpochPrefix,
        }
    };
    var expected = try Plan.initCompact(a, config, recorder.operations.items);
    defer expected.deinit();
    var actual = try Plan.initCompact(a, config, operations[0..PREFIX_OPERATIONS]);
    defer actual.deinit();
    if (!std.mem.eql(u8, &expected.id, &actual.id)) return error.InvalidSharedEpochPrefix;
}
fn prefixTag(operations: []const T.Operation) !u32 {
    if (operations.len == 0 or operations[0] != .words) return error.InvalidSharedEpochPrefix;
    const words = operations[0].words;
    if (words.len != 3 or words[1] != E.VERSION or words[2] != 2 or
        (words[0] != 0x42374550 and words[0] != 0x42375745)) return error.InvalidSharedEpochPrefix;
    return words[0];
}
