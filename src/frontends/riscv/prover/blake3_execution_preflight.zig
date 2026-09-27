//! Bounded execution planning. Endpoints here are claims, never proof receipts.
//! Replay must independently prove the planned states, I/O and local accesses.
const std = @import("std");
const runner = @import("../runner/mod.zig");
const Segment = @import("../runner/result.zig").SegmentResult;
const statement = @import("blake3_segment_statement.zig");
const snapshot = @import("../recursion/air/blake3_memory_snapshot.zig");
const public = @import("../air/public_data.zig");
const io_hash = @import("../recursion/blake3_public_io.zig");
const Schedule = @import("../runner/balanced_schedule.zig").Schedule;
pub const Planned = struct {
    first: statement.Endpoint,
    last: statement.Endpoint,
    schedule: Schedule,
    required_terminal_cycles: u64,
};

pub fn runEthereum(a: std.mem.Allocator, elf: []const u8, input: []const u8, oracle: []const u8, limit: u32) !Planned {
    return runEthereumForProfile(.rv32im_zkvm_ethereum_v1, a, elf, input, oracle, limit);
}
pub fn runEthereumForProfile(comptime profile: @import("../isa/execution_profile.zig").ExecutionProfile, a: std.mem.Allocator, elf: []const u8, input: []const u8, oracle: []const u8, limit: u32) !Planned {
    const Session = switch (profile) {
        .rv32im_zkvm_ethereum_v1 => runner.EthereumExecutionSession,
        .rv32im_zkvm_ethereum_sha_v1 => runner.EthereumShaExecutionSession,
        else => @compileError("unsupported Ethereum preflight profile"),
    };
    var session = try Session.init(a, elf, .{
        .input = input,
        .strict_completion = true,
        .stop_on_halt_flag = true,
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
        .require_current_output_accesses = false,
    });
    defer session.deinit();
    var current = try session.startSegment(limit);
    var live = true;
    defer if (live) current.deinit();
    const first = try endpointClaim(profile, a, &current.base, .entry);
    var accesses: std.AutoHashMap(u32, u64) = .init(a);
    defer accesses.deinit();
    var cycles: u64 = 0;
    var index: u32 = 0;
    while (true) {
        const segment = &current.base;
        if (segment.segment_index != index or segment.global_first_cycle != cycles + 1) return error.ExecutionDiscontinuity;
        const layout = segment.rw_memory.layout;
        var iterator = segment.state_chain_tracker.mem_last_clk.iterator();
        while (iterator.next()) |entry| {
            const addr = entry.key_ptr.*;
            if (addr == (layout.output_len_addr & ~@as(u32, 3)) or
                (addr >= layout.output_data_addr and addr < layout.output_end) or
                (segment.completion_reason == .halt_flag and addr == (segment.completion_address & ~@as(u32, 3))))
            {
                const access_clock = @import("../access_clock.zig");
                if (!access_clock.isWithinExecution(entry.value_ptr.*, @intCast(segment.cycle_count), false)) return error.InvalidOutputAccessClock;
                const instruction = (entry.value_ptr.* - 1) / access_clock.STRIDE + 1;
                try accesses.put(addr, try std.math.add(u64, cycles, instruction));
            }
        }
        cycles = try std.math.add(u64, cycles, segment.cycle_count);
        if (segment.continuation) |next| {
            current.deinit();
            live = false;
            current = try session.resumeSegment(next, limit);
            live = true;
            index = try std.math.add(u32, index, 1);
        } else {
            if (!segment.isComplete() or !std.mem.eql(u8, segment.output orelse return error.MissingOutput, oracle)) return error.BlockOutputMismatch;
            const words = try outputWords(a, segment);
            defer a.free(words);
            var earliest = cycles;
            for (words) |word| earliest = @min(earliest, accesses.get(word.addr) orelse return error.OutputAddressNotAccessed);
            if (segment.completion_reason == .halt_flag)
                earliest = @min(earliest, accesses.get(segment.completion_address & ~@as(u32, 3)) orelse return error.MissingCompletionAccess);
            const required = cycles - earliest + 1;
            return .{
                .first = first,
                .last = try endpointClaim(profile, a, segment, .exit),
                .schedule = try Schedule.initWithTerminalSuffix(cycles, limit, required),
                .required_terminal_cycles = required,
            };
        }
    }
}

fn endpointClaim(comptime profile: @import("../isa/execution_profile.zig").ExecutionProfile, a: std.mem.Allocator, segment: *const Segment, side: snapshot.Side) !statement.Endpoint {
    try @import("blake3_segment_public.zig").validateSegment(segment);
    if (side == .entry and !segment.segment_role.is_first or side == .exit and !segment.segment_role.is_last) return error.InvalidPreflightEndpoint;
    var memory = try snapshot.fromSnapshot(a, &segment.rw_memory, side, .continuation);
    defer memory.deinit();
    var program = try @import("../air/program/blake3_commitment.zig").buildDeclared(a, @import("../air/program/commitment.zig").DeclaredDecodeAuthority{ .profile = profile }, .{}, segment.rw_memory.program_words, null);
    defer program.deinit();
    const bytes = segment.input orelse &.{};
    const input_words = try a.alloc(u32, try std.math.divCeil(usize, bytes.len, 4));
    defer a.free(input_words);
    @memset(input_words, 0);
    for (bytes, 0..) |byte, i| input_words[i / 4] |= @as(u32, byte) << @as(u5, @intCast(8 * (i % 4)));
    const output_words = if (side == .exit) try outputWords(a, segment) else try a.alloc(public.OutputWord, 0);
    defer a.free(output_words);
    const io = public.IoEntries{
        .input_start = segment.input_start,
        .input_len = @intCast(bytes.len),
        .input_words = input_words,
        .output_len = segment.output_len,
        .output_len_addr = segment.output_len_addr,
        .output_data_addr = segment.output_data_addr,
        .output_words = output_words,
    };
    const cpu = if (side == .entry) segment.entry_cpu else segment.exit_cpu;
    return .{
        .machine = try @import("../recursion/span_statement_blake3.zig").MachineState.init(cpu.pc, cpu.regs, memory.root, .{ .bytes = @splat(0) }),
        .program = program.root,
        .io = if (side == .entry) try io_hash.inputClaim(io) else try io_hash.outputClaim(io),
        .cycle = if (side == .entry) 0 else try std.math.add(u64, segment.global_first_cycle - 1, segment.cycle_count),
        .side = side,
    };
}

fn outputWords(a: std.mem.Allocator, segment: *const Segment) ![]public.OutputWord {
    const count = try std.math.add(usize, 1, try std.math.divCeil(usize, segment.output_len, 4));
    const result = try a.alloc(public.OutputWord, count);
    errdefer a.free(result);
    for (result, 0..) |*out, i| {
        const address = if (i == 0) segment.output_len_addr else try std.math.add(u32, segment.output_data_addr, std.math.cast(u32, (i - 1) * 4) orelse return error.OutputAddressOverflow);
        var low: usize = 0;
        var high = segment.rw_memory.words.len;
        while (low < high) {
            const middle = low + (high - low) / 2;
            if (segment.rw_memory.words[middle].addr < address) low = middle + 1 else high = middle;
        }
        const entry = if (low < segment.rw_memory.words.len and segment.rw_memory.words[low].addr == address) segment.rw_memory.words[low] else return error.MissingOutputSnapshotWord;
        // Zero is a truthful local clock when the last access was in an earlier
        // counting chunk. This is hashed only as an application claim; replay
        // must supply real positive clocks inside its final proof segment.
        out.* = .{ .addr = address, .value = entry.final_word, .clock = entry.final_clock };
    }
    return result;
}

test "preflight reserves terminal publication without weakening proof access checks" {
    try checkTerminalPublication(.rv32im_zkvm_ethereum_v1);
    try checkTerminalPublication(.rv32im_zkvm_ethereum_sha_v1);
}

test "SHA preflight endpoints and terminal suffix do not depend on host chunk size" {
    const a = std.testing.allocator;
    var instructions: [20]u32 = @splat(0x00028393); // ADDI x7,x5,0.
    instructions[0] = 0x001000b7; // LUI x1,0x100: I/O base.
    instructions[1] = 0x2000a103; // LW x2,0x200(x1): public input.
    instructions[12] = 0x0020a423; // SW x2,8(x1): output word.
    instructions[13] = 0x00400193; // ADDI x3,x0,4: output length.
    instructions[14] = 0x0030a223; // SW x3,4(x1): output length.
    instructions[17] = 0x00100193; // ADDI x3,x0,1: halt flag.
    instructions[18] = 0x0030a023; // SW x3,0(x1): publish halt.
    instructions[19] = 0x0000006f;
    var elf = @import("../runner/guest_precompile/test_elf.zig").buildReleaseProgram(instructions.len, &instructions, 1024, .rv32im_zkvm_ethereum_sha_v1);
    // The generic release helper has zero input capacity; reserve one word
    // using the same production-ABI symbols as the real-I/O block fixture.
    const symbols = 640 + instructions.len * 4 + 1024;
    std.mem.writeInt(u32, elf[symbols + 8 * 16 + 4 ..][0..4], 0x0010_0200, .little);
    std.mem.writeInt(u32, elf[symbols + 9 * 16 + 4 ..][0..4], 0x0010_0204, .little);
    const input = [_]u8{ 0x13, 0x57, 0x9b, 0xdf };
    const small = try runEthereumForProfile(.rv32im_zkvm_ethereum_sha_v1, a, &elf, &input, &input, 8);
    const large = try runEthereumForProfile(.rv32im_zkvm_ethereum_sha_v1, a, &elf, &input, &input, 12);
    try std.testing.expect(small.schedule.segments > large.schedule.segments);
    try std.testing.expectEqualDeep(small.first, large.first);
    try std.testing.expectEqualDeep(small.last, large.last);
    try std.testing.expectEqual(small.required_terminal_cycles, large.required_terminal_cycles);
    try std.testing.expectEqual(@as(u64, 7), small.required_terminal_cycles);
}

fn checkTerminalPublication(comptime profile: @import("../isa/execution_profile.zig").ExecutionProfile) !void {
    const Session = if (profile == .rv32im_zkvm_ethereum_sha_v1) runner.EthereumShaExecutionSession else runner.EthereumExecutionSession;
    const a = std.testing.allocator;
    var instructions: [20]u32 = @splat(0x00000013);
    instructions[0] = 0x00100137;
    instructions[1] = 0x00100193;
    instructions[13] = 0x00312223;
    instructions[14] = 0x00312423;
    instructions[17] = 0x00312023; // Publish the release-ABI halt flag.
    instructions[18] = 0x0000006f;
    // Program commitment must decode even unexecuted SHA instructions under the admitted profile.
    if (profile == .rv32im_zkvm_ethereum_sha_v1) instructions[19] = @import("../isa/sha256_compression_v1.zig").encode(5, 6);
    const elf = @import("../runner/guest_precompile/test_elf.zig").buildReleaseProgram(instructions.len, &instructions, 0, profile);
    // The old uniform counting schedule ends after publication. Its final
    // chunk still fails strict proof receipt capture, as it must.
    {
        var strict = try Session.init(a, &elf, .{
            .strict_completion = true,
            .stop_on_halt_flag = true,
            .trace_retention = .segment_owned,
            .clock_frame = .leaf_local,
        });
        defer strict.deinit();
        var part = try strict.startSegment(5);
        var part_live = true;
        defer if (part_live) part.deinit();
        for (0..2) |_| {
            const next = part.base.continuation.?;
            part.deinit();
            part_live = false;
            part = try strict.resumeSegment(next, 5);
            part_live = true;
        }
        const next = part.base.continuation.?;
        part.deinit();
        part_live = false;
        try std.testing.expectError(error.OutputAddressNotAccessed, strict.resumeSegment(next, 5));
    }
    const planned = try runEthereumForProfile(profile, a, &elf, &.{}, &.{1}, 5);
    try std.testing.expectEqual(@as(u64, 18), planned.last.cycle);
    try std.testing.expectEqual(@as(u64, 5), planned.required_terminal_cycles);
    try std.testing.expectEqual(@as(u32, 4), planned.schedule.segments);
    var session = try Session.init(a, &elf, .{
        .strict_completion = true,
        .stop_on_halt_flag = true,
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
    });
    defer session.deinit();
    var current = try session.startSegment(try planned.schedule.budget(0));
    var live = true;
    defer if (live) current.deinit();
    for (1..planned.schedule.segments) |i| {
        const next = current.base.continuation.?;
        current.deinit();
        live = false;
        current = try session.resumeSegment(next, try planned.schedule.budget(@intCast(i)));
        live = true;
    }
    try std.testing.expect(current.base.isComplete());
    for (current.base.output_words) |word| try std.testing.expect(word.clock > 0);
    var data = try @import("blake3_segment_public.zig").Owned.init(a, &current.base);
    defer data.deinit();
    var program = try @import("../air/program/blake3_commitment.zig").buildDeclared(a, @import("../air/program/commitment.zig").DeclaredDecodeAuthority{ .profile = profile }, .{}, current.base.rw_memory.program_words, null);
    defer program.deinit();
    var initial = try snapshot.fromSnapshot(a, &current.base.rw_memory, .entry, .ordinary_boundary);
    defer initial.deinit();
    var final = try snapshot.fromSnapshot(a, &current.base.rw_memory, .exit, .ordinary_boundary);
    defer final.deinit();
    data.data.program_root = program.root;
    data.data.initial_rw_root = initial.root;
    data.data.final_rw_root = final.root;
    try std.testing.expectEqualDeep(planned.last.io, try io_hash.output(&data.data));
    try std.testing.expectEqualDeep(planned.last, try endpointClaim(profile, a, &current.base, .exit));
    try std.testing.expectError(error.TerminalPublicationExceedsSegmentBudget, runEthereumForProfile(profile, a, &elf, &.{}, &.{1}, 4));
    try std.testing.expectError(error.BlockOutputMismatch, runEthereumForProfile(profile, a, &elf, &.{}, &.{2}, 5));
}
