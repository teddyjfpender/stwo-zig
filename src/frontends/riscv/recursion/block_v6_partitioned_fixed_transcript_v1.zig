//! Original B6JP-v3 transcript grammar emitted without proof/private values.
const std = @import("std");
const Admission = @import("../prover/block_v6_partitioned_recursive_admission_v1.zig");
const Native = @import("block_v6_partitioned_recursive_fixed_v1.zig");
const Claims = @import("block_v6_partitioned_public_bus_v1.zig").Claims;
const Statement = @import("air/block_v6_partitioned_statement_v1.zig").Statement;
const Prefix = @import("air/block_v6_partitioned_transcript_v1.zig");
const Sink = @import("air/blake3_fixed_operation_recorder_v1.zig");
const Schema = @import("air/blake3_pcs_operation_schema_v1.zig");
const Plan = @import("air/blake3_transcript_plan.zig").Plan;
const Roots = @import("air/blake3_root_sources.zig");
pub const Limits = Sink.Limits;
/// A shape compiler, not admission of a proposed key. Native and statement
/// policy are reconstructed independently before the fixed plan is returned.
pub fn derive(a: std.mem.Allocator, admitted: *const Admission.Prepared, claims: Claims, native: *const Native.Owned, capacity: u32, limits: Limits, native_limits: Native.Limits) !Plan {
    if (capacity == 0 or limits.max_operations == 0 or limits.max_routed_words == 0) return error.InvalidBlake3Transcript;
    try native.validateAgainst(admitted, claims, native_limits);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    var statement = try Statement.initClaims(temp, admitted, claims.projection, claims.memory);
    defer statement.deinit();
    var recorder = Sink.Recorder{ .a = temp, .limits = limits };
    try Prefix.prefixWith(temp, &recorder, admitted, &statement, @import("air/block_v5_word_transcript_prefix_v1.zig").FixedDraw);
    if (recorder.skipped_roots != admitted.tree_count - 1) return error.InvalidPartitionedFixedTranscript;
    try recorder.suffix(.{ .commitment = .{ .slot = @intCast(admitted.tree_count - 1), .source = try Roots.caller(@intCast(admitted.tree_count - 1)) } });
    var suffix: std.ArrayList(Schema.Operation) = .empty;
    try Schema.appendPcsSuffix(temp, &suffix, admitted.config, native.deepProfile(), native.friProfile(), admitted.tree_count + 1);
    for (suffix.items) |operation| try recorder.suffix(operation);
    try recorder.check();
    return Plan.initCompact(a, .{ .namespace = 1_000_000, .attempt_capacity = capacity }, recorder.operations.items);
}
test "partitioned cold transcript compiler codegen" {
    std.mem.doNotOptimizeAway(&derive);
}
