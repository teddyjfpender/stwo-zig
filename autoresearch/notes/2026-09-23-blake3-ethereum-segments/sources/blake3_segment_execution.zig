//! Own a leaf-local segment's public data and canonical execution witnesses.
//! Global ordering is authenticated by the recursive Span, not local clocks.
const std = @import("std");
const public = @import("../air/public_data.zig");
const Segment = @import("../runner/result.zig").SegmentResult;
const Memory = @import("blake3_commitment_witness.zig");
const Native = @import("blake3_execution_trace.zig").Owner;
const Hashes = @import("blake3_commitment_columns.zig").Owner;
const commitment = @import("blake3_commitment_plan.zig");
pub const Owner = struct {
    allocator: std.mem.Allocator,
    input: []u32,
    output: []public.OutputWord,
    memory: Memory.Witness,
    plan: commitment.Plan,
    native: *Native,
    hashes: *Hashes,
    pub fn init(a: std.mem.Allocator, segment: *const Segment) !Owner {
        var io = try @import("blake3_segment_public.zig").Owned.init(a, segment);
        errdefer io.deinit();
        var data = io.data;
        var memory = try Memory.build(a, @as(@import("../air/program/commitment.zig").DeclaredDecodeAuthority, .base), .{segment.execution_trace.rows.items}, &segment.rw_memory, @import("commitment_program_witness.zig").completionFetch(data.completion), 100);
        errdefer memory.deinit();
        try memory.bindPublic(&data);
        var plan = try memory.plan(a);
        errdefer plan.deinit();
        const pin = try commitment.Admission.init(&plan, try plan.identity());
        const hashes = try Hashes.init(a, pin);
        errdefer hashes.deinit();
        try hashes.prepareMain(&memory);
        const native = try Native.init(a, &segment.execution_trace, data, &segment.state_chain_tracker);
        errdefer native.deinit();
        try native.includeCommitments(hashes);
        return .{ .allocator = a, .input = io.input, .output = io.output, .memory = memory, .plan = plan, .native = native, .hashes = hashes };
    }
    pub fn admission(self: *const Owner) !commitment.Admission {
        return commitment.Admission.init(&self.plan, try self.plan.identity());
    }
    pub fn deinit(self: *Owner) void {
        self.native.deinit();
        self.hashes.deinit();
        self.plan.deinit();
        self.memory.deinit();
        self.allocator.free(self.output);
        self.allocator.free(self.input);
        self.* = undefined;
    }
};
