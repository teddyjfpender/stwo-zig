//! V5 intermediate span policy carries PC/clock continuity only. Register/RW
//! endpoints are authenticated once by global providers for the whole block.
//! This is a public descriptor; neither construction nor a digest is proof.
const std = @import("std");
const core = @import("stwo_core");
const public = @import("../prover/block_v5_native_public_admission_v1.zig");
const shape_mod = @import("../air/statement.zig");
pub const VERSION: u32 = 1;
pub const Span = struct {
    job_id: [32]u8,
    source_image_digest: [32]u8,
    sealed_digest: [32]u8,
    job_segment_count: u32,
    first_index: u32,
    segment_count: u32,
    first_cycle: u64,
    last_cycle: u64,
    initial_pc: u32,
    final_pc: u32,
    pub fn validate(self: Span) !void {
        if (self.job_segment_count == 0 or self.segment_count == 0 or
            try std.math.add(u32, self.first_index, self.segment_count) > self.job_segment_count or
            self.first_cycle == 0 or self.last_cycle < self.first_cycle or
            self.initial_pc >= 1 << 30 or self.final_pc >= 1 << 30 or
            std.mem.allEqual(u8, &self.job_id, 0) or std.mem.allEqual(u8, &self.source_image_digest, 0) or
            std.mem.allEqual(u8, &self.sealed_digest, 0)) return error.InvalidV5PcClockSpan;
    }
    pub fn identity(self: Span) ![32]u8 {
        try self.validate();
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x42355043, VERSION, self.job_segment_count, self.first_index, self.segment_count, self.initial_pc, self.final_pc });
        channel.mixRoot(self.job_id);
        channel.mixRoot(self.source_image_digest);
        channel.mixRoot(self.sealed_digest);
        channel.mixU64(self.first_cycle);
        channel.mixU64(self.last_cycle);
        return channel.digestBytes();
    }
};
pub fn leaf(pin: public.Admission, shape: *const shape_mod.Blake3ExecutionStatement, sealed_digest: [32]u8, job_segment_count: u32) !Span {
    try pin.validatePublic(&shape.public_data);
    const result = Span{ .job_id = pin.context.job_id, .source_image_digest = pin.context.source_image_digest, .sealed_digest = sealed_digest, .job_segment_count = job_segment_count, .first_index = pin.context.execution_index, .segment_count = 1, .first_cycle = pin.context.first_cycle, .last_cycle = pin.context.last_cycle, .initial_pc = shape.initial_pc, .final_pc = shape.final_pc };
    try result.validate();
    return result;
}
/// Canonical public shape admission for a future constrained fold. Parent AIR
/// must prove the same edges; this host check cannot substitute for equations.
pub fn merge(children: []const Span) !Span {
    if (children.len < 2 or children.len > 4) return error.InvalidV5PcClockFanIn;
    var result = children[0];
    try result.validate();
    for (children[1..]) |right| {
        try right.validate();
        if (!std.meta.eql(result.job_id, right.job_id) or !std.meta.eql(result.source_image_digest, right.source_image_digest) or
            !std.meta.eql(result.sealed_digest, right.sealed_digest) or result.job_segment_count != right.job_segment_count or
            try std.math.add(u32, result.first_index, result.segment_count) != right.first_index or
            try std.math.add(u64, result.last_cycle, 1) != right.first_cycle or result.final_pc != right.initial_pc)
            return error.DiscontinuousV5PcClockSpan;
        result.segment_count = try std.math.add(u32, result.segment_count, right.segment_count);
        result.last_cycle = right.last_cycle;
        result.final_pc = right.final_pc;
    }
    try result.validate();
    return result;
}
