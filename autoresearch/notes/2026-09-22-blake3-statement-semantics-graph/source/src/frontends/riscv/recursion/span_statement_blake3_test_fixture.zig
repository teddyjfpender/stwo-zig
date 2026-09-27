//! Shared full-digest statement fixtures for native and arithmetic gates.
const span = @import("span_statement_blake3.zig");

pub fn digest(byte: u8) span.Digest {
    return .{ .bytes = @splat(byte) };
}

pub fn state(pc: u32, byte: u8) !span.MachineState {
    return span.MachineState.init(pc, @splat(0), digest(byte), digest(byte + 1));
}

pub fn job(segments: u32) !span.JobContext {
    return span.JobContext.init(try span.CompleteExecution.init(
        digest(0xff),
        digest(0xfe),
        try state(0, 0x80),
        try state(12, 0x90),
        digest(0xfc),
        digest(0xfd),
        12,
    ), segments);
}

pub fn leaf(context: span.JobContext, index: u32, entry: span.MachineState, exit: span.MachineState) !span.SpanStatement {
    const cycles = 12 / context.segment_count;
    return span.SpanStatement.segmentLeaf(context, index, try span.ExecutedSpan.init(
        index,
        1,
        index * cycles,
        cycles,
        entry,
        exit,
        if (index == 0) try span.EdgeClaim.present(context.complete.public_input) else span.EdgeClaim.absent(),
        if (index + 1 == context.segment_count) try span.EdgeClaim.present(context.complete.public_output) else span.EdgeClaim.absent(),
    ));
}

