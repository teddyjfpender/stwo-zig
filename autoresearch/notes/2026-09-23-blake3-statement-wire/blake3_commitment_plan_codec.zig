//! Bounded commitment-plan transport under a caller-pinned plan identity.
//! The embedded ID is compared, never used to select admission authority.
const std = @import("std");
const plans = @import("blake3_commitment_plan.zig");
const memory = @import("../recursion/air/blake3_memory_word.zig");
const program = @import("../recursion/air/blake3_program_word.zig");
const wire = @import("guest_precompile/proof_artifact_wire.zig");
pub const MAGIC = "B3CPLAN1";
pub const HEADER_BYTES: usize = 148;
pub const Limits = struct {
    max_bytes: usize = 64 * 1024 * 1024,
    max_memory_words: usize = 1 << 20,
    max_program_words: usize = 1 << 20,
};
fn size(memories: usize, programs: usize, limits: Limits) !usize {
    if (memories > limits.max_memory_words or programs > limits.max_program_words or
        memories > std.math.maxInt(u32) or programs > std.math.maxInt(u32)) return error.CommitmentPlanResourceLimit;
    const bytes = try std.math.add(usize, HEADER_BYTES, try std.math.add(usize, try std.math.mul(usize, memories, 20), try std.math.mul(usize, programs, 12)));
    if (bytes > limits.max_bytes) return error.CommitmentPlanResourceLimit;
    return bytes;
}
pub fn encode(a: std.mem.Allocator, plan: *const plans.Plan, expected: [32]u8, limits: Limits) ![]u8 {
    _ = try plans.Admission.init(plan, expected);
    const raw = try a.alloc(u8, try size(plan.memories.len, plan.programs.len, limits));
    errdefer a.free(raw);
    var stream = std.io.fixedBufferStream(raw);
    const writer = stream.writer();
    try writer.writeAll(MAGIC);
    try wire.writeInt(writer, u32, 1);
    try writer.writeAll(&expected);
    for (plan.roots) |root| try writer.writeAll(&root.bytes);
    try wire.writeInt(writer, u32, @intCast(plan.memories.len));
    try wire.writeInt(writer, u32, @intCast(plan.programs.len));
    for (plan.memories) |item| {
        try wire.writeInt(writer, u32, item.address);
        try wire.writeInt(writer, u32, item.clock);
        try wire.writeInt(writer, u32, if (item.direction == .initial) 0 else 1);
        try wire.writeInt(writer, u32, item.source_circuit);
        try wire.writeInt(writer, u32, item.path_namespace);
    }
    for (plan.programs) |item| {
        try wire.writeInt(writer, u32, item.namespace);
        try wire.writeInt(writer, u32, item.address);
        try wire.writeInt(writer, u32, item.multiplicity);
    }
    std.debug.assert(stream.pos == raw.len);
    return raw;
}
pub fn decode(a: std.mem.Allocator, raw: []const u8, expected: [32]u8, limits: Limits) !plans.Plan {
    if (raw.len > limits.max_bytes) return error.CommitmentPlanResourceLimit;
    if (raw.len < HEADER_BYTES) return error.TruncatedCommitmentPlan;
    if (!std.mem.eql(u8, raw[0..8], MAGIC) or std.mem.readInt(u32, raw[8..12], .little) != 1) return error.InvalidCommitmentPlanVersion;
    if (!std.mem.eql(u8, raw[12..44], &expected)) return error.UntrustedCommitmentPlan;
    var cursor = wire.Cursor.init(raw[44..]);
    var roots: @FieldType(plans.Plan, "roots") = undefined;
    for (&roots) |*root| try cursor.readExact(&root.bytes);
    const memory_count = try cursor.readInt(u32);
    const program_count = try cursor.readInt(u32);
    if (program_count == 0) return error.EmptyProgramCommitment;
    if (try size(memory_count, program_count, limits) != raw.len) return error.InvalidCommitmentPlanLength;
    const memories = try a.alloc(memory.Statement, memory_count);
    errdefer a.free(memories);
    const programs = try a.alloc(program.Statement, program_count);
    errdefer a.free(programs);
    for (memories) |*item| {
        const address = try cursor.readInt(u32);
        const clock = try cursor.readInt(u32);
        const direction: @FieldType(memory.Statement, "direction") = switch (try cursor.readInt(u32)) {
            0 => .initial,
            1 => .final,
            else => return error.InvalidCommitmentSchedule,
        };
        item.* = .{ .address = address, .clock = clock, .direction = direction, .source_circuit = try cursor.readInt(u32), .path_namespace = try cursor.readInt(u32), .root = roots[if (direction == .initial) @as(usize, 1) else 2] };
    }
    for (programs) |*item| item.* = .{
        .namespace = try cursor.readInt(u32),
        .address = try cursor.readInt(u32),
        .multiplicity = try cursor.readInt(u32),
        .root = roots[0],
    };
    try cursor.requireDone();
    const result = plans.Plan{ .allocator = a, .roots = roots, .memories = memories, .programs = programs };
    _ = try plans.Admission.init(&result, expected);
    return result;
}
