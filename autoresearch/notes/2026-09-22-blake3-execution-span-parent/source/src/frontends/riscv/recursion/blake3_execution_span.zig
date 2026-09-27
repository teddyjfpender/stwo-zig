//! Specialize an execution leaf's span and memory-custody plans against its
//! admitted key. This is admission metadata; the parent must also prove the
//! child verifier and both conversion witnesses. A binding alone is not a proof.
const std = @import("std");
const core = @import("stwo_core");
const span = @import("span_statement_blake3.zig");
const io = @import("blake3_public_io.zig");
const custody = @import("air/blake3_memory_custody.zig");
const chain = @import("air/blake3_memory_update_chain.zig");
const public = @import("../air/public_data.zig");
const commitment = @import("../prover/blake3_commitment_plan.zig");
pub const VERSION: u32 = 1;
pub const Binding = struct {
    child_key: [32]u8,
    statement: span.SpanStatement,
    conversions: [2][32]u8,
    pub fn identity(self: *const Binding) ![32]u8 {
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x42334553, VERSION });
        const mix = @import("../prover/blake3_execution_protocol.zig").mixDigest;
        mix(&channel, self.child_key);
        mix(&channel, (try span.identity.hash(&try self.statement.canonicalWords(), .statement)).bytes);
        for (self.conversions) |id| mix(&channel, id);
        return channel.digestBytes();
    }
};
/// The protocol pins full memory with no separate mutable I/O frontier. Public
/// I/O is carried by edge claims; the reserved machine I/O digest must be zero.
pub fn protocolIdentity(config: core.pcs.PcsConfig) span.Digest {
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42335345, VERSION, io.VERSION });
    config.mixInto(&channel);
    channel.mixU32s(&.{ @intFromBool(config.lifting_log_size != null), config.lifting_log_size orelse 0 });
    return .{ .bytes = channel.digestBytes() };
}
pub fn bind(a: std.mem.Allocator, admitted: anytype, capture: *const @import("../prover/blake3_execution_capture.zig").Verified, expected: [32]u8, statement: span.SpanStatement, entry: *const chain.Plan, exit: *const chain.Plan) !Binding {
    try capture.validate(admitted, expected);
    try validate(a, statement, &admitted.shape.public_data, admitted.admission(), admitted.config, entry, exit);
    return .{ .child_key = expected, .statement = statement, .conversions = .{ try entry.identity(), try exit.identity() } };
}
pub fn validate(a: std.mem.Allocator, statement: span.SpanStatement, data: *const public.Blake3PublicData, admission: commitment.Admission, config: core.pcs.PcsConfig, entry: *const chain.Plan, exit: *const chain.Plan) !void {
    try statement.validate();
    try admission.validatePublic(data);
    if (statement.slots.height != 0 or statement.body != .executed) return error.InvalidExecutionSpan;
    const executed = statement.body.executed;
    if (executed.segment_count != 1 or executed.cycle_count != data.clock or
        executed.entry.pc != data.initial_pc or executed.exit.pc != data.final_pc or
        !std.meta.eql(executed.entry.registers, data.initial_regs) or !std.meta.eql(executed.exit.registers, data.final_regs) or
        !std.meta.eql(statement.job.complete.program, data.program_root.?) or
        !std.meta.eql(statement.job.complete.protocol_id, protocolIdentity(config))) return error.InvalidExecutionSpan;
    if (!std.mem.allEqual(u8, &executed.entry.public_io_state.bytes, 0) or !std.mem.allEqual(u8, &executed.exit.public_io_state.bytes, 0)) return error.InvalidExecutionIoState;
    if (executed.first_segment == 0) {
        if (!std.meta.eql(executed.input.digest.?, try io.input(data))) return error.InvalidExecutionInput;
    } else if (data.io_entries.input_words.len != 0 or data.io_entries.input_len != 0) return error.InteriorExecutionInput;
    if (executed.endSegment() == statement.job.segment_count) {
        if (data.completion.?.kind == .unretired_program_fetch) return error.IncompleteExecutionSpan;
        if (!std.meta.eql(executed.output.digest.?, try io.output(data))) return error.InvalidExecutionOutput;
    } else if (data.io_entries.output_words.len != 0 or data.io_entries.output_len != 0 or data.completion.?.kind == .halt_flag) return error.InteriorExecutionOutput;
    try custody.admit(entry, .entry, data, admission, a);
    try custody.admit(exit, .exit, data, admission, a);
    if (!std.meta.eql(entry.roots[entry.roots.len - 1], executed.entry.rw_memory) or !std.meta.eql(exit.roots[exit.roots.len - 1], executed.exit.rw_memory)) return error.InvalidExecutionSpanMemory;
}
