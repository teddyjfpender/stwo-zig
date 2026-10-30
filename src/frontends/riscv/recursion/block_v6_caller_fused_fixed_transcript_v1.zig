//! Original caller B5CF transcript grammar without a private capture.
const std = @import("std");
const Admission = @import("../prover/block_v5_caller_fused_recursive_admission_v1.zig");
const Native = @import("block_v6_caller_fused_fixed_v1.zig");
const Statement = @import("air/block_v5_caller_fused_statement_v1.zig");
const Prefix = @import("air/block_v5_caller_fused_transcript_v1.zig");
const Sink = @import("air/blake3_fixed_operation_recorder_v1.zig");
const Schema = @import("air/blake3_pcs_operation_schema_v1.zig");
const Plan = @import("air/blake3_transcript_plan.zig").Plan;
pub fn derive(a: std.mem.Allocator, admitted: *const Admission.Prepared, claims: Native.Claims, native: *const Native.Owned, capacity: u32, limits: Sink.Limits, native_limits: Native.Limits) !Plan {
    if (capacity == 0 or limits.max_operations == 0 or limits.max_routed_words == 0) return error.InvalidBlake3Transcript;
    try native.validateAgainst(admitted, claims, native_limits);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    var statement = try Statement.initClaims(temp, admitted, claims);
    defer statement.deinit();
    var recorder = Sink.Recorder{ .a = temp, .limits = limits };
    try Prefix.prefixWith(temp, &recorder, admitted, &statement, @import("air/block_v5_word_transcript_prefix_v1.zig").FixedDraw);
    if (recorder.skipped_roots != 3) return error.InvalidCallerFusedFixedTranscript;
    try recorder.suffix(.{ .commitment = .{ .slot = 3, .source = try @import("air/blake3_root_sources.zig").caller(3) } });
    var suffix: std.ArrayList(Schema.Operation) = .empty;
    try Schema.appendPcsSuffix(temp, &suffix, admitted.config, native.shape.deepProfile(), native.shape.friProfile(), 5);
    for (suffix.items) |operation| try recorder.suffix(operation);
    try recorder.check();
    return Plan.initCompact(a, .{ .namespace = 1_000_000, .attempt_capacity = capacity }, recorder.operations.items);
}
