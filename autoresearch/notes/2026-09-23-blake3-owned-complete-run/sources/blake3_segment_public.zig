//! Shared owned public I/O for complete runs and leaf-local segments.
const std = @import("std");
const public = @import("../air/public_data.zig");
const Segment = @import("../runner/result.zig").SegmentResult;
pub const Owned = struct {
    allocator: std.mem.Allocator,
    input: []u32,
    output: []public.OutputWord,
    data: public.Blake3PublicData,
    pub fn init(a: std.mem.Allocator, segment: *const Segment) !Owned {
        try validateSegment(segment);
        return initMode(true, a, segment);
    }
    pub fn initRun(a: std.mem.Allocator, run: *const @import("../runner/result.zig").RunResult) !Owned {
        return initMode(false, a, run);
    }
    fn initMode(comptime segmented: bool, a: std.mem.Allocator, source: anytype) !Owned {
        const bytes = if (segmented) source.input orelse &.{} else source.input;
        const input = try a.alloc(u32, try std.math.divCeil(usize, bytes.len, 4));
        errdefer a.free(input);
        @memset(input, 0);
        for (bytes, 0..) |byte, i| input[i / 4] |= @as(u32, byte) << @as(u5, @intCast(8 * (i % 4)));
        const output = try a.alloc(public.OutputWord, source.output_words.len);
        errdefer a.free(output);
        for (output, source.output_words) |*target, word| target.* = .{ .addr = word.addr, .value = word.value, .clock = word.clock };
        const data = public.Blake3PublicData{
            .initial_pc = if (segmented) source.entry_cpu.pc else source.initial_pc,
            .final_pc = if (segmented) source.exit_cpu.pc else source.final_pc,
            .clock = std.math.cast(u32, if (segmented) source.cycle_count else source.step_count) orelse return error.InvalidBlake3Segment,
            .initial_regs = if (segmented) source.entry_cpu.regs else source.initial_regs,
            .final_regs = if (segmented) source.exit_cpu.regs else source.final_regs,
            .reg_last_clock = source.state_chain_tracker.reg_last_clk,
            .program_root = null,
            .initial_rw_root = null,
            .final_rw_root = null,
            .completion = if (segmented) try completion(source) else try public.completionFromRun(source.*),
            .io_entries = .{ .input_start = source.input_start, .input_len = std.math.cast(u32, bytes.len) orelse return error.InvalidBlake3Segment, .input_words = input, .output_len = source.output_len, .output_len_addr = source.output_len_addr, .output_data_addr = source.output_data_addr, .output_words = output },
        };
        return .{ .allocator = a, .input = input, .output = output, .data = data };
    }
    pub fn deinit(self: *Owned) void {
        self.allocator.free(self.output);
        self.allocator.free(self.input);
        self.* = undefined;
    }
};
pub fn validateSegment(segment: *const Segment) !void {
    if (segment.clock_frame != .leaf_local or segment.cycle_count == 0 or segment.global_first_cycle == 0 or
        segment.segment_role.is_first != (segment.segment_index == 0) or
        segment.segment_role.is_last != segment.isComplete() or
        segment.segment_role.is_last == (segment.continuation != null) or
        !std.meta.eql(segment.segment_role, segment.rw_memory.segment_role)) return error.InvalidBlake3Segment;
    _ = try std.math.add(u64, segment.global_first_cycle, segment.cycle_count);
    for (segment.entry_access_clocks.register_clocks) |clock| if (clock != 0) return error.InvalidBlake3Segment;
    if (segment.entry_access_clocks.memory_clocks.len != 0) return error.InvalidBlake3Segment;
    if (!segment.segment_role.is_first and segment.input != null) return error.InvalidBlake3Segment;
    if (!segment.segment_role.is_last and (segment.output != null or segment.output_len != 0 or segment.output_words.len != 0)) return error.InvalidBlake3Segment;
    try segment.execution_trace.validateClockAuthority();
}
pub fn completion(segment: *const Segment) !public.Completion {
    if (segment.completion_reason) |reason| return public.completionFromRun(.{
        .completion_reason = reason,
        .completion_address = segment.completion_address,
        .completion_value = segment.completion_value,
        .completion_clock = segment.completion_clock,
    });
    for (segment.rw_memory.program_words) |word| if (word.addr == segment.exit_cpu.pc) {
        if (word.initial_word != word.final_word) return error.ProgramWordChanged;
        return public.Completion.unretiredProgramFetch(word.addr, word.final_word);
    };
    return error.MissingSegmentBoundaryInstruction;
}
