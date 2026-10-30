//! Exact epoch challenge grammar. The interval z and alpha are TWO single
//! draws (two hash blocks), unlike the paired Word/Universal draws before them.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../../prover/block_v7_execution_epoch_v1.zig");
const Word = @import("../../prover/block_v5_word_memory_protocol_v1.zig");
const Universal = @import("universal_challenges.zig");
const Sink = @import("blake3_fixed_operation_recorder_v1.zig");
const Recorder = @import("blake3_native_recorder.zig");
pub const RELATION_PAIRS = 53;
pub fn fixed(a: std.mem.Allocator, r: *Sink.Recorder) !void {
    try Word.Challenges.drawWith(a, r, FixedDraw);
    try intervalFixed(r, 52);
}
pub fn live(a: std.mem.Allocator, r: *Recorder.Recorder) !void {
    if (!r.universal_relations or r.relation_count != 0) return error.InvalidV7EpochTranscript;
    _ = try Word.Challenges.drawFromChannel(a, r);
    try intervalLive(r, 52);
}
/// The caller supplies its independently specified exported relation index;
/// native draw consumption remains exactly two consecutive single draws.
pub fn intervalFixed(r: *Sink.Recorder, relation: usize) !void {
    r.mixU32s(&.{ 0x4237494e, E.VERSION, 6 });
    for (0..2) |half| r.append(.{ .secure = .{ .output = .{ .universal_half = .{ .relation = relation, .half = @intCast(half) } }, .attempts = 0, .consumption = .one, .values = @splat(core.fields.m31.M31.zero()) } });
    try r.check();
}
pub fn intervalLive(r: *Recorder.Recorder, relation: usize) !void {
    if (!r.universal_relations or r.relation_count != relation) return error.InvalidV7EpochTranscript;
    r.mixU32s(&.{ 0x4237494e, E.VERSION, 6 });
    try r.drawSeparateUniversalPair(relation);
}
const FixedDraw = struct {
    pub const Output = void;
    pub fn universal(_: std.mem.Allocator, r: *Sink.Recorder) !void {
        try Universal.requireDrawSchema();
        try r.universalPairs(0, Universal.RELATION_COUNT);
    }
    pub fn extra(_: std.mem.Allocator, r: *Sink.Recorder, _: void) !void {
        try r.universalPairs(47, 5);
    }
};
