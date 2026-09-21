const std = @import("std");
const Cpu = @import("../cpu.zig").Cpu;
const DecodedInst = @import("../decode.zig").DecodedInst;
const generated = @import("../generated_retirement.zig");
const Memory = @import("../memory.zig").Memory;
const StateChainTracker = @import("../state_chain.zig").StateChainTracker;
const trace_mod = @import("../trace.zig");
const minimal = @import("mod.zig");

const entry_pc: u32 = 0x1000;
const data_address: u32 = 0x0200;

const instructions = [_]u32{
    encodeI(0x200, 0, 0b000, 1, 0b0010011), // ADDI x1, x0, 0x200
    encodeI(0x055, 0, 0b000, 2, 0b0010011), // ADDI x2, x0, 0x55
    encodeS(0, 2, 1, 0b010, 0b0100011), // SW x2, 0(x1)
    encodeI(0, 1, 0b010, 3, 0b0000011), // LW x3, 0(x1)
    encodeR(0, 3, 2, 0b000, 4, 0b0110011), // ADD x4, x2, x3
    encodeI(0x00f, 4, 0b100, 5, 0b0010011), // XORI x5, x4, 15
    encodeI(2, 5, 0b001, 6, 0b0010011), // SLLI x6, x5, 2
    encodeI(512, 6, 0b011, 7, 0b0010011), // SLTIU x7, x6, 512
    encodeR(1, 3, 2, 0b000, 8, 0b0110011), // MUL x8, x2, x3
    encodeR(1, 2, 8, 0b101, 9, 0b0110011), // DIVU x9, x8, x2
    encodeB(8, 3, 9, 0b000, 0b1100011), // BEQ x9, x3, +8
    encodeI(1, 0, 0b000, 10, 0b0010011), // skipped
    encodeU(0, 11, 0b0010111), // AUIPC x11, 0
    0x0000_000f, // FENCE
    encodeJ(8, 12, 0b1101111), // JAL x12, +8
    encodeI(1, 0, 0b000, 10, 0b0010011), // skipped
    encodeR(0, 5, 4, 0b110, 13, 0b0110011), // OR x13, x4, x5
    encodeI(0x0ff, 13, 0b111, 14, 0b0010011), // ANDI x14, x13, 255
    encodeU(0x1_0000, 15, 0b0110111), // LUI x15, 0x10000
    encodeR(0, 7, 2, 0b001, 16, 0b0110011), // SLL x16, x2, x7
    encodeR(0, 3, 2, 0b010, 17, 0b0110011), // SLT x17, x2, x3
    encodeB(4, 3, 2, 0b110, 0b1100011), // BLTU x2, x3, +4 (not taken)
    encodeR(1, 3, 2, 0b011, 18, 0b0110011), // MULHU x18, x2, x3
    encodeU(0, 19, 0b0010111), // AUIPC x19, 0
    encodeI(16, 19, 0b000, 19, 0b0010011), // target index 27
    encodeI(0, 19, 0b000, 20, 0b1100111), // JALR x20, x19, 0
    encodeI(1, 0, 0b000, 10, 0b0010011), // skipped
    encodeR(0, 14, 13, 0b111, 21, 0b0110011), // AND x21, x13, x14
};

const program_words = makeProgramWords();
const boundary_words = [_]minimal.BoundaryWord{
    .{ .address = data_address, .entry = 0, .exit = 0x55 },
};

const Baseline = struct {
    entry_cpu: Cpu,
    cpu: Cpu,
    trace: trace_mod.Trace,
    tracker: StateChainTracker,
    memory: Memory,

    fn deinit(self: *Baseline) void {
        self.memory.deinit();
        self.tracker.deinit();
        self.trace.deinit();
        self.* = undefined;
    }
};

test "minimal trace: typed memoryless replay is exact for a mixed leaf" {
    var baseline = try executeBaseline(std.testing.allocator);
    defer baseline.deinit();
    const program = try minimal.SliceProgram.init(&program_words);
    const boundary = try minimal.SliceBoundary.init(&boundary_words);
    var leaf = try captureLeaf(
        std.testing.allocator,
        &baseline,
        program.identity,
        boundary.entry_identity,
        boundary.exit_identity,
    );
    defer leaf.deinit();

    try std.testing.expectEqual(@as(u32, 25), leaf.cycle_count);
    try std.testing.expectEqualSlices(u32, &.{ 0, 0x55 }, leaf.memory_read_words);
    try leaf.validate();
    const families = try baseline.trace.groupByOpcodeFamily(std.testing.allocator);
    for (families.counts) |count| try std.testing.expect(count != 0);

    var replayed = try minimal.replayLeaf(
        std.testing.allocator,
        &leaf,
        program.source(),
        boundary.source(),
    );
    defer replayed.deinit();
    try expectCpuEqual(baseline.cpu, replayed.cpu);
    try std.testing.expectEqualDeep(
        baseline.trace.rows.items,
        replayed.execution_trace.rows.items,
    );
    try expectTrackerEqual(&baseline.tracker, &replayed.state_chain_tracker);
    try std.testing.expectEqual(
        @as(u32, 0x55),
        replayed.touched_memory.readU32(data_address),
    );
}

test "minimal trace: fast capture and typed replay match the retirement oracle" {
    var baseline = try executeBaseline(std.testing.allocator);
    defer baseline.deinit();
    const program = try minimal.SliceProgram.init(&program_words);
    var fast_memory = try Memory.initFallible(std.testing.allocator);
    defer fast_memory.deinit();
    fast_memory.writeU32(data_address, 0);
    var fast_cpu = Cpu.init(entry_pc, 0x8000);
    var captured = try minimal.captureLeafFast(
        std.testing.allocator,
        &fast_cpu,
        &fast_memory,
        program.source(),
        .{
            .segment_index = 0,
            .global_first_cycle = 1,
            .cycle_count = 25,
            .input_identity = minimal.types.digestBytes("mixed-leaf-input"),
            .session_identity = minimal.types.digestBytes("mixed-leaf-session"),
        },
    );
    defer captured.deinit();

    try expectCpuEqual(baseline.cpu, fast_cpu);
    try std.testing.expectEqualSlices(
        u32,
        &.{ 0, 0x55 },
        captured.leaf.memory_read_words,
    );
    try std.testing.expectEqualDeep(&boundary_words, captured.boundary_words);
    const captured_boundary = try captured.boundary();
    var replayed = try minimal.replayLeaf(
        std.testing.allocator,
        &captured.leaf,
        program.source(),
        captured_boundary.source(),
    );
    defer replayed.deinit();
    try expectCpuEqual(baseline.cpu, replayed.cpu);
    try std.testing.expectEqualDeep(
        baseline.trace.rows.items,
        replayed.execution_trace.rows.items,
    );
    try expectTrackerEqual(&baseline.tracker, &replayed.state_chain_tracker);
}

test "minimal trace: fast capture reports bounded representative throughput" {
    const benchmark_instructions = [_]u32{
        encodeI(1, 1, 0b000, 1, 0b0010011), // ADDI x1, x1, 1
        encodeI(0x55, 3, 0b100, 3, 0b0010011), // XORI x3, x3, 0x55
        encodeS(0, 1, 2, 0b010, 0b0100011), // SW x1, 0(x2)
        encodeI(0, 2, 0b010, 4, 0b0000011), // LW x4, 0(x2)
        encodeR(1, 1, 4, 0b000, 5, 0b0110011), // MUL x5, x4, x1
        encodeB(-20, 1, 0, 0b001, 0b1100011), // BNE x0, x1, loop
    };
    // Match the current combined guest's multi-megabyte ROM geometry. Fetch
    // remains O(1); the complete image is authenticated before timing begins.
    const rom_word_count: usize = 837_500;
    const rom = try std.testing.allocator.alloc(u32, rom_word_count);
    defer std.testing.allocator.free(rom);
    @memset(rom, encodeI(0, 0, 0b000, 0, 0b0010011)); // ADDI x0, x0, 0
    @memcpy(rom[0..benchmark_instructions.len], &benchmark_instructions);
    const program = try minimal.DenseProgram.init(entry_pc, rom);
    var dispatcher = try minimal.CaptureDispatcherV1.init(std.testing.allocator);
    defer dispatcher.deinit();
    var memory = try Memory.initFallible(std.testing.allocator);
    defer memory.deinit();
    var cpu = Cpu.init(entry_pc, data_address);
    const cycle_count: u32 = 65_532;
    var timer = try std.time.Timer.start();
    var captured = try dispatcher.captureDenseLeaf(
        std.testing.allocator,
        &cpu,
        &memory,
        &program,
        .{
            .segment_index = 0,
            .global_first_cycle = 1,
            .cycle_count = cycle_count,
            .input_identity = minimal.types.digestBytes("benchmark-input"),
            .session_identity = minimal.types.digestBytes("benchmark-session"),
        },
    );
    const capture_elapsed_ns = @max(timer.read(), 1);
    defer captured.deinit();
    const capture_cycles_per_second = @as(f64, @floatFromInt(cycle_count)) *
        @as(f64, std.time.ns_per_s) /
        @as(f64, @floatFromInt(capture_elapsed_ns));
    const boundary = try captured.boundary();
    timer.reset();
    var replayed = try minimal.replayLeaf(
        std.testing.allocator,
        &captured.leaf,
        program.source(),
        boundary.source(),
    );
    const replay_elapsed_ns = @max(timer.read(), 1);
    defer replayed.deinit();
    const replay_cycles_per_second = @as(f64, @floatFromInt(cycle_count)) *
        @as(f64, std.time.ns_per_s) /
        @as(f64, @floatFromInt(replay_elapsed_ns));
    std.debug.print(
        "minimal-capture-benchmark cycles={} rom_bytes={} capture_ns={} capture_cycles_per_second={d:.0} replay_ns={} replay_cycles_per_second={d:.0}\n",
        .{
            cycle_count,
            rom.len * @sizeOf(u32),
            capture_elapsed_ns,
            capture_cycles_per_second,
            replay_elapsed_ns,
            replay_cycles_per_second,
        },
    );
    try captured.leaf.validate();
    try std.testing.expectEqual(
        @as(usize, cycle_count / 3),
        captured.leaf.memory_read_words.len,
    );
    try std.testing.expectEqual(@as(usize, 1), captured.boundary_words.len);
    try expectCpuEqual(cpu, replayed.cpu);
    try std.testing.expect(capture_cycles_per_second > 0);
    try std.testing.expect(replay_cycles_per_second > 0);
}

test "minimal trace: tape and authority mutations fail closed" {
    var baseline = try executeBaseline(std.testing.allocator);
    defer baseline.deinit();
    const program = try minimal.SliceProgram.init(&program_words);
    const boundary = try minimal.SliceBoundary.init(&boundary_words);
    var leaf = try captureLeaf(
        std.testing.allocator,
        &baseline,
        program.identity,
        boundary.entry_identity,
        boundary.exit_identity,
    );
    defer leaf.deinit();

    leaf.memory_read_words[0] = 1;
    try std.testing.expectError(error.TapeSealMismatch, leaf.validate());
    leaf.reseal();
    try std.testing.expectError(
        error.MemoryBoundaryEntryMismatch,
        minimal.replayLeaf(
            std.testing.allocator,
            &leaf,
            program.source(),
            boundary.source(),
        ),
    );

    leaf.memory_read_words[0] = 0;
    leaf.memory_read_words[1] = 0;
    leaf.reseal();
    try std.testing.expectError(
        error.ReplayMemoryMismatch,
        minimal.replayLeaf(
            std.testing.allocator,
            &leaf,
            program.source(),
            boundary.source(),
        ),
    );

    leaf.memory_read_words[1] = 0x55;
    leaf.exit_cpu.regs[14] ^= 1;
    leaf.reseal();
    try std.testing.expectError(
        error.ExitCpuMismatch,
        minimal.replayLeaf(
            std.testing.allocator,
            &leaf,
            program.source(),
            boundary.source(),
        ),
    );

    leaf.exit_cpu.regs[14] ^= 1;
    leaf.source.program = minimal.types.digestBytes("different-program");
    leaf.reseal();
    try std.testing.expectError(
        error.ProgramIdentityMismatch,
        minimal.replayLeaf(
            std.testing.allocator,
            &leaf,
            program.source(),
            boundary.source(),
        ),
    );
}

test "minimal trace: cursor rejects both truncated and appended tapes" {
    var short = minimal.MemoryReadCursor{ .words = &.{0} };
    _ = try short.next();
    try std.testing.expectError(error.MemoryReadTapeExhausted, short.next());

    var long = minimal.MemoryReadCursor{ .words = &.{ 0, 1 } };
    _ = try long.next();
    try std.testing.expectError(error.MemoryReadTapeNotExhausted, long.finish());
}

test "minimal trace: completion self-loop never becomes a captured or replayed row" {
    const self_loop_words = [_]minimal.ProgramWord{
        .{ .address = entry_pc, .word = encodeJ(0, 0, 0b1101111) },
    };
    const program = try minimal.SliceProgram.init(&self_loop_words);
    const empty_boundary = try minimal.SliceBoundary.init(&.{});
    var memory = try Memory.initFallible(std.testing.allocator);
    defer memory.deinit();
    var cpu = Cpu.init(entry_pc, 0x8000);
    const before = cpu;
    try std.testing.expectError(
        error.UnretiredSelfLoop,
        minimal.captureLeafFast(
            std.testing.allocator,
            &cpu,
            &memory,
            program.source(),
            .{
                .segment_index = 0,
                .global_first_cycle = 1,
                .cycle_count = 1,
                .input_identity = minimal.types.digestBytes("self-loop-input"),
                .session_identity = minimal.types.digestBytes("self-loop-session"),
            },
        ),
    );
    try expectCpuEqual(before, cpu);

    const no_words = try std.testing.allocator.alloc(u32, 0);
    var leaf = try minimal.LeafV1.initOwned(
        std.testing.allocator,
        .{
            .program = program.identity,
            .input = minimal.types.digestBytes("self-loop-input"),
            .session = minimal.types.digestBytes("self-loop-session"),
            .entry_memory = empty_boundary.entry_identity,
            .exit_memory = empty_boundary.exit_identity,
        },
        0,
        1,
        1,
        before,
        before,
        null,
        no_words,
    );
    defer leaf.deinit();
    try std.testing.expectError(
        error.UnretiredSelfLoop,
        minimal.replayLeaf(
            std.testing.allocator,
            &leaf,
            program.source(),
            empty_boundary.source(),
        ),
    );
}

test "minimal trace: program and boundary views require canonical order" {
    const bad_program = [_]minimal.ProgramWord{
        .{ .address = 4, .word = 1 },
        .{ .address = 0, .word = 2 },
    };
    try std.testing.expectError(
        error.NonCanonicalProgramOrder,
        minimal.SliceProgram.init(&bad_program),
    );
    const bad_boundary = [_]minimal.BoundaryWord{
        .{ .address = 2, .entry = 0, .exit = 0 },
    };
    try std.testing.expectError(
        error.UnalignedBoundaryWord,
        minimal.SliceBoundary.init(&bad_boundary),
    );

    const slice = try minimal.SliceProgram.init(&program_words);
    const dense = try minimal.DenseProgram.init(entry_pc, &instructions);
    try std.testing.expectEqualSlices(u8, &slice.identity, &dense.identity);
}

test "minimal trace: bounded parallel replay preserves canonical leaf order" {
    const parallel_entry_pc: u32 = 0x4000;
    const parallel_data_address: u32 = 0x6000;
    const parallel_words = [_]minimal.ProgramWord{
        .{ .address = parallel_entry_pc, .word = encodeI(1, 1, 0b000, 1, 0b0010011) },
        .{ .address = parallel_entry_pc + 4, .word = encodeS(0, 1, 2, 0b010, 0b0100011) },
        .{ .address = parallel_entry_pc + 8, .word = encodeI(0, 2, 0b010, 3, 0b0000011) },
        .{ .address = parallel_entry_pc + 12, .word = encodeJ(-12, 0, 0b1101111) },
    };
    const program = try minimal.SliceProgram.init(&parallel_words);
    var dispatcher = try minimal.CaptureDispatcherV1.init(std.testing.allocator);
    defer dispatcher.deinit();
    var memory = try Memory.initFallible(std.testing.allocator);
    defer memory.deinit();
    var cpu = Cpu.init(parallel_entry_pc, parallel_data_address);
    const leaf_count = 4;
    const cycles_per_leaf: u32 = 2048;
    var captures: [leaf_count]minimal.CaptureResultV1 = undefined;
    var initialized: usize = 0;
    defer for (captures[0..initialized]) |*capture| capture.deinit();
    var boundaries: [leaf_count]minimal.SliceBoundary = undefined;
    var requests: [leaf_count]minimal.ParallelReplayRequestV1 = undefined;
    for (0..leaf_count) |index| {
        captures[index] = try dispatcher.captureLeaf(
            std.testing.allocator,
            &cpu,
            &memory,
            program.source(),
            .{
                .segment_index = @intCast(index),
                .global_first_cycle = 1 + @as(u64, index) * cycles_per_leaf,
                .cycle_count = cycles_per_leaf,
                .input_identity = minimal.types.digestBytes("parallel-input"),
                .session_identity = minimal.types.digestBytes("parallel-session"),
            },
        );
        initialized += 1;
        boundaries[index] = try captures[index].boundary();
        requests[index] = .{
            .leaf = &captures[index].leaf,
            .program = program.source(),
            .boundary = boundaries[index].source(),
        };
    }

    const Collector = struct {
        exits: *[leaf_count]Cpu,
        calls: std.atomic.Value(usize) = .init(0),

        fn consume(
            context_ptr: *anyopaque,
            index: usize,
            result: *minimal.ReplayResult,
        ) !void {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            self.exits[index] = result.cpu;
            _ = self.calls.fetchAdd(1, .monotonic);
        }
    };
    var serial_exits: [leaf_count]Cpu = undefined;
    var serial = Collector{ .exits = &serial_exits };
    const serial_receipt = try minimal.replayLeavesParallel(
        std.testing.allocator,
        &requests,
        .{
            .worker_count = 1,
            .max_total_cycles = leaf_count * cycles_per_leaf,
        },
        .{ .context = &serial, .consume_fn = Collector.consume },
    );
    var parallel_exits: [leaf_count]Cpu = undefined;
    var parallel = Collector{ .exits = &parallel_exits };
    const parallel_receipt = try minimal.replayLeavesParallel(
        std.testing.allocator,
        &requests,
        .{
            .worker_count = leaf_count,
            .max_total_cycles = leaf_count * cycles_per_leaf,
        },
        .{ .context = &parallel, .consume_fn = Collector.consume },
    );
    try std.testing.expectEqual(@as(u32, leaf_count), serial_receipt.leaf_count);
    try std.testing.expectEqual(@as(u16, 1), serial_receipt.admitted_workers);
    try std.testing.expectEqual(@as(u16, leaf_count), parallel_receipt.admitted_workers);
    try std.testing.expectEqual(serial_receipt.total_cycles, parallel_receipt.total_cycles);
    try std.testing.expectEqual(@as(usize, leaf_count), serial.calls.load(.monotonic));
    try std.testing.expectEqual(@as(usize, leaf_count), parallel.calls.load(.monotonic));
    for (0..leaf_count) |index| {
        try expectCpuEqual(captures[index].leaf.exit_cpu, serial_exits[index]);
        try expectCpuEqual(serial_exits[index], parallel_exits[index]);
    }

    captures[1].leaf.segment_index = 0;
    captures[1].leaf.reseal();
    try std.testing.expectError(
        error.NonCanonicalSegmentOrder,
        minimal.replayLeavesParallel(
            std.testing.allocator,
            &requests,
            .{
                .worker_count = leaf_count,
                .max_total_cycles = leaf_count * cycles_per_leaf,
            },
            .{ .context = &parallel, .consume_fn = Collector.consume },
        ),
    );
    captures[1].leaf.segment_index = 1;
    captures[1].leaf.reseal();

    captures[2].leaf.memory_read_words[0] ^= 1;
    captures[2].leaf.reseal();
    try std.testing.expectError(
        error.MemoryBoundaryEntryMismatch,
        minimal.replayLeavesParallel(
            std.testing.allocator,
            &requests,
            .{
                .worker_count = leaf_count,
                .max_total_cycles = leaf_count * cycles_per_leaf,
            },
            .{ .context = &parallel, .consume_fn = Collector.consume },
        ),
    );
}

test "minimal trace: parallel replay reports bounded scaling" {
    const scaling_words = [_]u32{
        encodeI(1, 1, 0b000, 1, 0b0010011),
        encodeI(0x55, 3, 0b100, 3, 0b0010011),
        encodeS(0, 1, 2, 0b010, 0b0100011),
        encodeI(0, 2, 0b010, 4, 0b0000011),
        encodeR(1, 1, 4, 0b000, 5, 0b0110011),
        encodeB(-20, 1, 0, 0b001, 0b1100011),
    };
    const rom_word_count: usize = 837_500;
    const rom = try std.testing.allocator.alloc(u32, rom_word_count);
    defer std.testing.allocator.free(rom);
    @memset(rom, encodeI(0, 0, 0b000, 0, 0b0010011));
    @memcpy(rom[0..scaling_words.len], &scaling_words);
    const program = try minimal.DenseProgram.init(entry_pc, rom);

    const leaf_count = 256;
    const cycles_per_leaf: u32 = 65_532;
    const total_cycles: u64 = @as(u64, leaf_count) * cycles_per_leaf;
    var dispatcher = try minimal.CaptureDispatcherV1.init(std.testing.allocator);
    defer dispatcher.deinit();
    var memory = try Memory.initFallible(std.testing.allocator);
    defer memory.deinit();
    var cpu = Cpu.init(entry_pc, data_address);
    var captures: [leaf_count]minimal.CaptureResultV1 = undefined;
    var initialized: usize = 0;
    defer for (captures[0..initialized]) |*capture| capture.deinit();
    var boundaries: [leaf_count]minimal.SliceBoundary = undefined;
    var requests: [leaf_count]minimal.ParallelReplayRequestV1 = undefined;
    for (0..leaf_count) |index| {
        captures[index] = try dispatcher.captureDenseLeaf(
            std.testing.allocator,
            &cpu,
            &memory,
            &program,
            .{
                .segment_index = @intCast(index),
                .global_first_cycle = 1 + @as(u64, index) * cycles_per_leaf,
                .cycle_count = cycles_per_leaf,
                .input_identity = minimal.types.digestBytes("scaling-input"),
                .session_identity = minimal.types.digestBytes("scaling-session"),
            },
        );
        initialized += 1;
        boundaries[index] = try captures[index].boundary();
        requests[index] = .{
            .leaf = &captures[index].leaf,
            .program = program.source(),
            .boundary = boundaries[index].source(),
        };
    }

    const Counter = struct {
        calls: std.atomic.Value(usize) = .init(0),
        cycles: std.atomic.Value(u64) = .init(0),

        fn consume(
            context_ptr: *anyopaque,
            _: usize,
            result: *minimal.ReplayResult,
        ) !void {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            _ = self.calls.fetchAdd(1, .monotonic);
            _ = self.cycles.fetchAdd(
                @intCast(result.execution_trace.step_count),
                .monotonic,
            );
        }
    };

    var warm = Counter{};
    _ = try minimal.replayLeavesParallel(
        std.testing.allocator,
        requests[0..1],
        .{ .worker_count = 1, .max_total_cycles = cycles_per_leaf },
        .{ .context = &warm, .consume_fn = Counter.consume },
    );

    const worker_counts = [_]usize{ 1, 2, 4, 8, 12, 16 };
    var serial_wall_ns: u64 = 0;
    for (worker_counts) |worker_count| {
        var counter = Counter{};
        var timer = try std.time.Timer.start();
        const receipt = try minimal.replayLeavesParallel(
            std.testing.allocator,
            &requests,
            .{ .worker_count = worker_count, .max_total_cycles = total_cycles },
            .{ .context = &counter, .consume_fn = Counter.consume },
        );
        const wall_ns = @max(timer.read(), 1);
        if (worker_count == 1) serial_wall_ns = wall_ns;
        try std.testing.expectEqual(@as(usize, leaf_count), counter.calls.load(.monotonic));
        try std.testing.expectEqual(total_cycles, counter.cycles.load(.monotonic));
        try std.testing.expectEqual(total_cycles, receipt.total_cycles);
        const cycles_per_second = @as(f64, @floatFromInt(total_cycles)) *
            @as(f64, std.time.ns_per_s) /
            @as(f64, @floatFromInt(wall_ns));
        const efficiency = @as(f64, @floatFromInt(serial_wall_ns)) /
            (@as(f64, @floatFromInt(wall_ns)) *
                @as(f64, @floatFromInt(worker_count)));
        std.debug.print(
            "minimal-parallel-replay-benchmark leaves={} cycles={} workers={} wall_ns={} cycles_per_second={d:.0} efficiency={d:.6}\n",
            .{
                leaf_count,
                total_cycles,
                worker_count,
                wall_ns,
                cycles_per_second,
                efficiency,
            },
        );
    }
}

fn executeBaseline(allocator: std.mem.Allocator) !Baseline {
    var memory = try Memory.initFallible(allocator);
    errdefer memory.deinit();
    for (program_words) |word| memory.writeU32(word.address, word.word);
    memory.writeU32(data_address, 0);
    var trace = trace_mod.Trace.init(allocator);
    errdefer trace.deinit();
    trace.initial_pc = entry_pc;
    var tracker = StateChainTracker.init(allocator);
    errdefer tracker.deinit();
    var cpu = Cpu.init(entry_pc, 0x8000);
    const entry_cpu = cpu;
    var clock: u32 = 1;
    while (cpu.pc != entry_pc + instructions.len * 4) : (clock += 1) {
        const inst_word = memory.readU32(cpu.pc);
        const instruction = try DecodedInst.decode(inst_word);
        if (!try generated.retireAtomic(
            &cpu,
            &memory,
            &trace,
            &tracker,
            instruction,
            inst_word,
            clock,
        )) return error.UnsupportedBaselineInstruction;
    }
    trace.final_pc = cpu.pc;
    try trace.validateClockRange(0, clock - 1, 0);
    return .{
        .entry_cpu = entry_cpu,
        .cpu = cpu,
        .trace = trace,
        .tracker = tracker,
        .memory = memory,
    };
}

fn captureLeaf(
    allocator: std.mem.Allocator,
    baseline: *const Baseline,
    program: minimal.Digest,
    entry_memory: minimal.Digest,
    exit_memory: minimal.Digest,
) !minimal.LeafV1 {
    return minimal.LeafV1.capture(allocator, .{
        .source = .{
            .program = program,
            .input = minimal.types.digestBytes("mixed-leaf-input"),
            .session = minimal.types.digestBytes("mixed-leaf-session"),
            .entry_memory = entry_memory,
            .exit_memory = exit_memory,
        },
        .segment_index = 0,
        .global_first_cycle = 1,
        .entry_cpu = baseline.entry_cpu,
        .exit_cpu = baseline.cpu,
        .execution_trace = &baseline.trace,
    });
}

fn expectCpuEqual(expected: Cpu, actual: Cpu) !void {
    try std.testing.expectEqual(expected.pc, actual.pc);
    try std.testing.expectEqualSlices(u32, &expected.regs, &actual.regs);
}

fn expectTrackerEqual(
    expected: *const StateChainTracker,
    actual: *const StateChainTracker,
) !void {
    try std.testing.expectEqualSlices(
        u32,
        &expected.reg_last_clk,
        &actual.reg_last_clk,
    );
    try std.testing.expectEqualDeep(expected.accesses.items, actual.accesses.items);
    try std.testing.expectEqualDeep(
        expected.clock_updates_mem.items,
        actual.clock_updates_mem.items,
    );
    try std.testing.expectEqualDeep(
        expected.clock_updates_reg.items,
        actual.clock_updates_reg.items,
    );
    try std.testing.expectEqual(expected.mem_initial.count(), actual.mem_initial.count());
    var initial = expected.mem_initial.iterator();
    while (initial.next()) |entry| {
        try std.testing.expectEqual(
            entry.value_ptr.*,
            actual.mem_initial.get(entry.key_ptr.*) orelse
                return error.MissingInitialMemoryWord,
        );
    }
    try std.testing.expectEqual(expected.mem_last_clk.count(), actual.mem_last_clk.count());
    var last = expected.mem_last_clk.iterator();
    while (last.next()) |entry| {
        try std.testing.expectEqual(
            entry.value_ptr.*,
            actual.mem_last_clk.get(entry.key_ptr.*) orelse
                return error.MissingFinalMemoryClock,
        );
    }
}

fn makeProgramWords() [instructions.len]minimal.ProgramWord {
    var result: [instructions.len]minimal.ProgramWord = undefined;
    for (instructions, 0..) |instruction, index| {
        result[index] = .{
            .address = entry_pc + @as(u32, @intCast(index)) * 4,
            .word = instruction,
        };
    }
    return result;
}

fn encodeR(
    funct7: u7,
    rs2: u5,
    rs1: u5,
    funct3: u3,
    rd: u5,
    opcode: u7,
) u32 {
    return @as(u32, funct7) << 25 |
        @as(u32, rs2) << 20 |
        @as(u32, rs1) << 15 |
        @as(u32, funct3) << 12 |
        @as(u32, rd) << 7 |
        opcode;
}

fn encodeI(imm: i32, rs1: u5, funct3: u3, rd: u5, opcode: u7) u32 {
    return (@as(u32, @bitCast(imm)) & 0xfff) << 20 |
        @as(u32, rs1) << 15 |
        @as(u32, funct3) << 12 |
        @as(u32, rd) << 7 |
        opcode;
}

fn encodeS(imm: i32, rs2: u5, rs1: u5, funct3: u3, opcode: u7) u32 {
    const bits = @as(u32, @bitCast(imm)) & 0xfff;
    return (bits >> 5) << 25 |
        @as(u32, rs2) << 20 |
        @as(u32, rs1) << 15 |
        @as(u32, funct3) << 12 |
        (bits & 0x1f) << 7 |
        opcode;
}

fn encodeB(imm: i32, rs2: u5, rs1: u5, funct3: u3, opcode: u7) u32 {
    const bits = @as(u32, @bitCast(imm)) & 0x1fff;
    return ((bits >> 12) & 1) << 31 |
        ((bits >> 5) & 0x3f) << 25 |
        @as(u32, rs2) << 20 |
        @as(u32, rs1) << 15 |
        @as(u32, funct3) << 12 |
        ((bits >> 1) & 0x0f) << 8 |
        ((bits >> 11) & 1) << 7 |
        opcode;
}

fn encodeU(imm: i32, rd: u5, opcode: u7) u32 {
    return (@as(u32, @bitCast(imm)) & 0xffff_f000) |
        @as(u32, rd) << 7 |
        opcode;
}

fn encodeJ(imm: i32, rd: u5, opcode: u7) u32 {
    const bits = @as(u32, @bitCast(imm)) & 0x1f_ffff;
    return ((bits >> 20) & 1) << 31 |
        ((bits >> 1) & 0x03ff) << 21 |
        ((bits >> 11) & 1) << 20 |
        ((bits >> 12) & 0x00ff) << 12 |
        @as(u32, rd) << 7 |
        opcode;
}
