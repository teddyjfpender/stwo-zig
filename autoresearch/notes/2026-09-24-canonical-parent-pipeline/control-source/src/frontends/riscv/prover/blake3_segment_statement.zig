//! Construct leaf Span claims from validated runner segments. Construction is
//! not proof admission: the parent pipeline still binds the claim to the
//! independently admitted execution key and ordinary/continuation custody.
const std = @import("std");
const core = @import("stwo_core");
const PublicData = @import("../air/public_data.zig").Blake3PublicData;
const Segment = @import("../runner/result.zig").SegmentResult;
const spans = @import("../recursion/span_statement_blake3.zig");
const snapshot = @import("../recursion/air/blake3_memory_snapshot.zig");
const public = @import("blake3_segment_public.zig");

pub const Boundary = struct {
    entry: spans.MachineState,
    exit: spans.MachineState,
};

/// Retains only two machine states; snapshot projections are released here.
pub fn boundary(a: std.mem.Allocator, segment: *const Segment) !Boundary {
    try public.validateSegment(segment);
    return .{ .entry = try state(a, segment, .entry), .exit = try state(a, segment, .exit) };
}
fn state(a: std.mem.Allocator, segment: *const Segment, side: snapshot.Side) !spans.MachineState {
    var projection = try snapshot.fromSnapshot(a, &segment.rw_memory, side, .continuation);
    defer projection.deinit();
    const cpu = if (side == .entry) segment.entry_cpu else segment.exit_cpu;
    return spans.MachineState.init(cpu.pc, cpu.regs, projection.root, .{ .bytes = @splat(0) });
}

/// The caller supplies the complete job, never a hand-built segment index,
/// cycle offset or memory root. Edge I/O is checked against the execution
/// public data during parent admission.
pub fn leaf(a: std.mem.Allocator, job: spans.JobContext, segment: *const Segment) !spans.SpanStatement {
    try job.validate();
    try public.validateSegment(segment);
    if (segment.segment_index >= job.segment_count or
        segment.segment_role.is_last != (segment.segment_index == job.segment_count - 1)) return error.InvalidBlake3Segment;
    const endpoints = try boundary(a, segment);
    return spans.SpanStatement.segmentLeaf(job, segment.segment_index, try spans.ExecutedSpan.init(
        segment.segment_index,
        1,
        segment.global_first_cycle - 1,
        segment.cycle_count,
        endpoints.entry,
        endpoints.exit,
        .{ .digest = if (segment.segment_role.is_first) job.complete.public_input else null },
        .{ .digest = if (segment.segment_role.is_last) job.complete.public_output else null },
    ));
}

/// Complete-job coordinates come from the actual endpoint segments. Public
/// data must come from the caller's independently admitted execution statement;
/// constructing this value never admits a program or preprocessing key.
pub fn initJob(
    a: std.mem.Allocator,
    config: core.pcs.PcsConfig,
    first: *const Segment,
    last: *const Segment,
    first_data: *const PublicData,
    last_data: *const PublicData,
) !spans.JobContext {
    try public.validateSegment(first);
    try public.validateSegment(last);
    if (!first.segment_role.is_first or !last.segment_role.is_last or
        first.global_first_cycle != 1) return error.InvalidBlake3Segment;
    try @import("blake3_execution_protocol.zig").validateConfig(config);
    try validateEndpoint(a, first, first_data);
    try validateEndpoint(a, last, last_data);
    if (!std.meta.eql(first_data.program_root, last_data.program_root)) return error.SegmentProgramMismatch;
    const count = try std.math.add(u32, last.segment_index, 1);
    const cycles = try std.math.add(u64, last.global_first_cycle - 1, last.cycle_count);
    const io = @import("../recursion/blake3_public_io.zig");
    return spans.JobContext.init(try spans.CompleteExecution.init(
        @import("../recursion/blake3_execution_span.zig").protocolIdentity(config),
        first_data.program_root.?,
        try state(a, first, .entry),
        try state(a, last, .exit),
        try io.input(first_data),
        try io.output(last_data),
        cycles,
    ), count);
}
fn validateEndpoint(a: std.mem.Allocator, segment: *const Segment, data: *const PublicData) !void {
    try data.validate();
    var expected = try public.Owned.init(a, segment);
    defer expected.deinit();
    // Root admission is the proof verifier's responsibility. Every other public
    // field, including all I/O words and clocks, must match the supplied runner.
    expected.data.program_root = data.program_root;
    expected.data.initial_rw_root = data.initial_rw_root;
    expected.data.final_rw_root = data.final_rw_root;
    var actual_channel = core.channel.blake3.Channel{};
    var expected_channel = core.channel.blake3.Channel{};
    data.mixInto(&actual_channel);
    expected.data.mixInto(&expected_channel);
    if (!std.mem.eql(u8, &actual_channel.digestBytes(), &expected_channel.digestBytes())) return error.InvalidBlake3SegmentPublicData;
}
