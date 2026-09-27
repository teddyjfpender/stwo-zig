//! The absence of opcode ROM requests is derived from a freshly verified v3
//! zero-opcode shape. Caller fetches and terminal ROM fetches stay mandatory.
const std = @import("std");
const core = @import("stwo_core");
const Request = @import("block_v5_program_request_proof_v1.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Native = @import("block_v5_native_execution_proof_v3.zig");
const Seal = @import("block_v5_source_seal_v1.zig");

pub fn validateShape(shape: *const Shape, external_retirements: u32) !void {
    if (shape.n_components != 0 or external_retirements == 0 or external_retirements != shape.total_steps)
        return error.InvalidV5EmptyProgramShape;
    try shape.validateBlake3ExecutionWithExternal(external_retirements);
}
pub fn entry(template_id: [32]u8, execution: Seal.Entry) !Seal.Entry {
    if (execution.family != .execution) return error.InvalidV5EmptyProgramExecution;
    return .{ .family = .program_request, .index = execution.index, .roots = execution.roots, .instance_id = Request.nativeV5InstanceId(template_id, execution.instance_id, execution.index, &.{}) };
}
pub fn fromFresh(shape: *const Shape, external_retirements: u32, fresh: *const Native.OpenReceipt, index: u32, sealed: Seal.Sealed, pins: Seal.Pins, roster: []const Seal.Entry) !Request.VerifiedReceipt {
    try sealed.require(pins, roster);
    try validateShape(shape, external_retirements);
    if (index >= sealed.execution_instance_count or !std.meta.eql(fresh.sealed_digest, sealed.digest)) return error.UntrustedV5EmptyProgramNative;
    var native_entry: ?Seal.Entry = null;
    var request_entry: ?Seal.Entry = null;
    for (roster) |value| {
        if (value.family == .execution and value.index == index) native_entry = value;
        if (value.family == .program_request and value.index == index) request_entry = value;
    }
    const execution = native_entry orelse return error.MissingV5EmptyProgramExecution;
    if (!std.meta.eql(execution.instance_id, fresh.instance_id) or !std.meta.eql(execution.roots, fresh.first_roots) or
        request_entry == null or !std.meta.eql(try entry(fresh.template_id, execution), request_entry.?)) return error.UntrustedV5EmptyProgramEntry;
    var channel = sealed.programSeal().sharedChannel();
    return .{ .sum = core.fields.qm31.QM31.zero(), .fetch_count = 0, .native_roots = fresh.first_roots, .native_key_id = fresh.template_id, .sealed_channel_digest = channel.digestBytes() };
}
