const std = @import("std");
const C = @import("stwo_cuda_backend");
const B = C.runtime.stages.blake3;
const Common = C.runtime.stages.common;
fn force(s: *C.runtime.NativeSession, w: Common.WordMatrix, h: B.Hashes, states: B.States, ch: B.Channels, nonce: Common.Nonce) !void {
    const N = B.Native;
    const segment = [_]struct { columns: Common.WordMatrix, source_size: u32 }{.{ .columns = w, .source_size = 8 }};
    try N.contiguousLeaves(s, .trace_commit, 8, w, h);
    try N.mixedLeaves(s, .trace_commit, 8, &segment, h);
    try N.mixedPrefix(s, .trace_commit, 8, &segment, 0, null, states);
    try N.mixedLeavesFromPrefix(s, .trace_commit, 8, &segment, 1, states, h);
    try N.progressiveInit(s, .trace_commit, states);
    try N.progressiveAbsorbLifted(s, .trace_commit, 8, 8, 0, w, states);
    try N.progressiveFinalize(s, .trace_commit, 1, states, h);
    try N.reduceNodes(s, .trace_commit, h, h);
    try N.contiguousTail(s, .trace_commit, h, h, 1);
    try N.friLeaves(s, w, 8, 2, h);
    try N.channel(s, .trace_commit, ch, w.storage, 1, .secure, 32);
    try N.grindRange(s, ch, 8, 0, 1024, nonce);
    try N.grind(s, ch, 8, 1024, 128, nonce);
    try N.drawQueries(s, ch, 20, w.storage);
    try N.sealError(s, ch, w.storage);
}
test "resident BLAKE3 typed dispatch forced code generation" {
    std.mem.doNotOptimizeAway(&force);
}
