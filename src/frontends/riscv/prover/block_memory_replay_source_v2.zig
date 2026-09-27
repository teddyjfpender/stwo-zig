//! Adapter from one admitted block replay to the bounded two-pass producer.
//! Both passes reopen the same immutable external sorted run and first image.
const Replay = @import("block_memory_replay.zig").Replay;
const producer = @import("block_memory_batch_produce_v2.zig");
const transition = @import("../air/block/memory_transition.zig");

pub fn sortedSource(replay: *Replay) producer.SortedSource {
    return .{ .context = replay, .open = reopen };
}

fn reopen(context: *anyopaque) anyerror!transition.Reader {
    const replay: *Replay = @ptrCast(@alignCast(context));
    return replay.reopenSortedTransitions();
}
