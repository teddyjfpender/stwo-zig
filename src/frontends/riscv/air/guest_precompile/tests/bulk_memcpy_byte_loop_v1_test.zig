const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const C = @import("../bulk_memcpy_byte_loop_certificate_v1.zig");
const K = @import("../bulk_memcpy_byte_loop_kernel_v1.zig");
fn zero(row: [K.COLUMN_COUNT]M) bool {
    for (K.constraints(M, row)) |v| if (!v.isZero()) return false;
    return true;
}
test "same ROM byte loop exact five instructions reject every encoding bit change" {
    const certificate = try C.Certificate.fromWords(0x331a0, C.words, @splat(1));
    for (0..5) |i| for (0..32) |bit| {
        var changed = C.words;
        changed[i] ^= @as(u32, 1) << @intCast(bit);
        try std.testing.expectError(error.UnrecognizedByteLoop, C.Certificate.fromWords(0x331a0, changed, @splat(1)));
    };
    try std.testing.expectEqualDeep([5]u32{ 0x331a0, 22, 11, 14, 0 }, certificate.tuples[0]);
    try std.testing.expectEqualDeep([5]u32{ 0x331a4, 24, 13, 14, 0 }, certificate.tuples[1]);
    try std.testing.expectEqualDeep([5]u32{ 0x331b0, 28, 13, 12, core.fields.m31.Modulus - 16 }, certificate.tuples[4]);
    for (try certificate.fetches(17)) |fetch| try std.testing.expectEqual(@as(u32, 17), fetch.count);
    try std.testing.expect(!C.production_active and !C.whole_source_qualified);
}
test "same ROM byte loop arbitrary alignment packing and query weights match byte oracle" {
    var rng = std.Random.DefaultPrng.init(0xb815a11);
    const random = rng.random();
    for (0..32) |_| for (0..4) |shift| for (0..4) |start| for (start + 1..5) |end| {
        const source_low = random.int(u32);
        const source_high = random.int(u32);
        const before = random.int(u32);
        const row = try K.witness(source_low, source_high, before, @intCast(start), @intCast(end), @intCast(shift));
        try std.testing.expect(zero(row));
        const source: u64 = @as(u64, source_low) | (@as(u64, source_high) << 32);
        for (0..4) |byte| {
            const expected = if (byte >= start and byte < end) @as(u32, @intCast((source >> @as(u6, @intCast(8 * (byte + shift)))) & 255)) else (before >> @as(u5, @intCast(8 * byte))) & 255;
            try std.testing.expectEqual(expected, row[K.Layout.destination_after + byte].v);
            var changed = row;
            changed[K.Layout.destination_after + byte] = changed[K.Layout.destination_after + byte].add(M.one());
            try std.testing.expect(!zero(changed));
        }
        const weights = K.sourceQueryWeights(M, row);
        try std.testing.expectEqual(@as(u32, @intFromBool(start + shift < 4)), weights[0].v);
        try std.testing.expectEqual(@as(u32, @intFromBool(end + shift > 4)), weights[1].v);
        try std.testing.expectEqual(@as(u32, @intCast((source >> @as(u6, @intCast(8 * (end - 1 + shift)))) & 255)), K.lastCopiedByte(M, row).v);
    };
    try std.testing.expect(zero(@splat(M.zero())));
    var no_bytes = try K.witness(1, 2, 3, 0, 1, 0);
    no_bytes[K.Layout.start] = M.zero();
    no_bytes[K.Layout.start + 3] = M.one();
    try std.testing.expect(!zero(no_bytes));
}
const Degree = struct {
    n: usize,
    pub fn zero() @This() {
        return .{ .n = 0 };
    }
    pub fn one() @This() {
        return .{ .n = 0 };
    }
    pub fn add(a: @This(), b: @This()) @This() {
        return .{ .n = @max(a.n, b.n) };
    }
    pub fn sub(a: @This(), b: @This()) @This() {
        return a.add(b);
    }
    pub fn mul(a: @This(), b: @This()) @This() {
        return .{ .n = a.n + b.n };
    }
};
test "same ROM byte loop byte kernel stays within degree three" {
    const row: [K.COLUMN_COUNT]Degree = @splat(Degree{ .n = 1 });
    for (K.constraints(Degree, row)) |check| try std.testing.expect(check.n <= K.MAX_DEGREE);
    for (K.sourceQueryWeights(Degree, row)) |check| try std.testing.expect(check.n <= 2);
    try std.testing.expect(K.lastCopiedByte(Degree, row).n <= 3);
}
test "same ROM byte loop complete and partial boundaries match actual RV32 execution and last clocks" {
    const Runner = @import("../../../runner/mod.zig");
    const a = std.testing.allocator;
    const code = C.words ++ [_]u32{0x0000006f};
    const elf = @import("../../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(code.len, &code, 1024, .rv32im_zkvm_v1);
    for (0..4) |source_offset| for (0..4) |destination_offset| for ([_]u32{ 1, 3, 8, 9 }) |count| for ([_]bool{ false, true }) |partial| {
        var session = try Runner.BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
        defer session.deinit();
        const source: u32 = 0x100100 + @as(u32, @intCast(source_offset));
        const destination: u32 = 0x100200 + @as(u32, @intCast(destination_offset));
        const end = destination + count + @as(u32, @intFromBool(partial));
        session.cpu.writeReg(11, source);
        session.cpu.writeReg(13, destination);
        session.cpu.writeReg(12, end);
        session.cpu.writeReg(14, 0x12345678);
        for (0..count) |i| session.memory.writeByte(source + @as(u32, @intCast(i)), @intCast(0x40 + i));
        for (0..count + 2) |i| session.memory.writeByte(destination - 1 + @as(u32, @intCast(i)), 0xa5);
        const certificate = try C.Certificate.fromWords(session.cpu.pc, C.words, @splat(1));
        const call = C.Call{ .entry_cycle = 1, .source = source, .destination = destination, .destination_end = end, .length = count, .max_instruction_cycle = 5 * count };
        var segment = try session.startSegment(5 * count);
        defer segment.deinit();
        try std.testing.expectEqual(5 * count, segment.execution_trace.step_count);
        try std.testing.expectEqual(try call.nextPc(certificate), segment.exit_cpu.pc);
        const values = try call.finalRegisterValues(@intCast(0x40 + count - 1));
        const clocks = try call.finalRegisterClocks();
        for (C.registers, values, clocks) |reg, value, clock| {
            try std.testing.expectEqual(value, segment.exit_cpu.regs[reg]);
            try std.testing.expectEqual(clock, segment.state_chain_tracker.reg_last_clk[reg]);
        }
        if (source_offset == 1 and destination_offset == 2 and count == 9) {
            const Q = core.fields.qm31.QM31;
            const Relations = @import("../../../recursion/air/universal_challenges.zig").UniversalRelations;
            const Entries = @import("../../lookups/opcode_entries.zig");
            const Trace = @import("../../../runner/trace.zig");
            const relations = Relations.dummy();
            var native_sums: [3]Q = @splat(Q.zero());
            for (segment.execution_trace.rows.items) |trace_row| {
                const list = try Entries.fromTraceRow(trace_row, (try Trace.ProofOpcode.classify(trace_row.opcode)).family());
                for (list.entries[0..list.len]) |entry| {
                    const selected: ?usize = switch (entry.domain) {
                        .program_access => 0,
                        .registers_state => 1,
                        .memory_access => if (entry.values[0].isZero()) 2 else null,
                        else => null,
                    };
                    if (selected) |index| {
                        const relation = switch (index) {
                            0 => relations.get(.program_access),
                            1 => relations.get(.registers_state),
                            else => relations.get(.memory_access),
                        };
                        native_sums[index] = native_sums[index].add(entry.numerator.mul(try (try relation.combineSecure(entry.values[0..entry.arity])).inv()));
                    }
                }
            }
            try std.testing.expect(native_sums[0].eql(try C.programContribution(certificate, call, &relations)));
            try std.testing.expect(native_sums[1].eql(try C.stateContribution(certificate, call, &relations)));
            try std.testing.expect(native_sums[2].eql(try C.registerContribution(call, @splat(0), 0x12345678, @intCast(0x40 + count - 1), &relations)));
            var bad_predecessors: [4]u32 = @splat(0);
            bad_predecessors[0] = 1;
            try std.testing.expectError(error.InvalidByteLoopRegisterPredecessor, C.registerContribution(call, bad_predecessors, 0x12345678, @intCast(0x40 + count - 1), &relations));
        }
        for (0..count) |i| try std.testing.expectEqual(@as(u8, @intCast(0x40 + i)), session.memory.readByte(destination + @as(u32, @intCast(i))));
        try std.testing.expectEqual(@as(u8, 0xa5), session.memory.readByte(destination - 1));
        try std.testing.expectEqual(@as(u8, 0xa5), session.memory.readByte(destination + count));
        var word = source & ~@as(u32, 3);
        while (word < source + count) : (word += 4) try std.testing.expectEqual(try call.finalWordClock(true, word), segment.state_chain_tracker.mem_last_clk.get(word).?);
        word = destination & ~@as(u32, 3);
        while (word < destination + count) : (word += 4) try std.testing.expectEqual(try call.finalWordClock(false, word), segment.state_chain_tracker.mem_last_clk.get(word).?);
    };
}
test "same ROM byte loop interval and word alias conditions fail closed" {
    var call = C.Call{ .entry_cycle = 1, .source = 0x100101, .destination = 0x100202, .destination_end = 0x100222, .length = 16, .max_instruction_cycle = 1000 };
    try call.validate();
    call.length = 33;
    try std.testing.expectError(error.InvalidByteLoopCall, call.validate());
    call.length = 0;
    try std.testing.expectError(error.InvalidByteLoopCall, call.validate());
    call.length = 16;
    call.destination = 0x100110;
    try std.testing.expectError(error.OverlappingByteLoopWords, call.validate());
    call.destination = 0x100202;
    call.entry_cycle = 999;
    try std.testing.expectError(error.InvalidByteLoopCall, call.validate());
}

test "same ROM byte loop certificate checks actual decoded ROM leaves and root" {
    const Image = @import("../../../prover/block_v7_program_image_v1.zig");
    const Tree = @import("../../memory_commitment/blake3_state_tree.zig");
    const a = std.testing.allocator;
    const expected = try C.Certificate.fromWords(0x331a0, C.words, @splat(1));
    const leaves = try a.alloc(Tree.Leaf, 20);
    for (expected.tuples, 0..) |tuple, i| for (0..4) |field| {
        leaves[4 * i + field] = .{ .index = tuple[0] + @as(u32, @intCast(field)), .value = tuple[field + 1] };
    };
    var image = Image.Owned{ .a = a, .leaves = leaves, .root = try Tree.TreeHasher.init(.program).root(leaves) };
    defer image.deinit();
    const actual = try C.Certificate.fromProgramImage(&image, expected.pc);
    try actual.validate();
    try actual.require(actual);
    image.leaves[0].value += 1;
    if (C.Certificate.fromProgramImage(&image, expected.pc)) |_| return error.AcceptedMutatedByteLoopImage else |err| if (err == error.OutOfMemory) return err;
    image.root = try Tree.TreeHasher.init(.program).root(image.leaves);
    try std.testing.expectError(error.UnrecognizedByteLoop, C.Certificate.fromProgramImage(&image, expected.pc));
    var mutated = actual;
    mutated.tuples[0][1] += 1;
    try std.testing.expectError(error.InvalidByteLoopCertificate, mutated.validate());
    try std.testing.expectError(error.UntrustedByteLoopCertificate, mutated.require(actual));
}

test "same ROM byte loop destination word plans handle unequal alignment and address zero" {
    for (0..4) |source_offset| for (0..4) |destination_offset| for ([_]u32{ 1, 2, 4, 5, 9, 17 }) |count| {
        var memory: [256]u8 = undefined;
        for (&memory, 0..) |*byte, i| byte.* = @truncate(31 * i + 7);
        const source: u32 = @intCast(source_offset);
        const destination: u32 = 64 + @as(u32, @intCast(destination_offset));
        const call = C.Call{ .entry_cycle = 1, .source = source, .destination = destination, .destination_end = destination + count, .length = count, .max_instruction_cycle = 5 * count };
        var expected = memory;
        for (0..count) |i| expected[destination + i] = memory[source + i];
        const words = try call.destinationWordCount();
        for (0..words) |i| {
            const plan = try call.destinationWordPlan(@intCast(i));
            const low = if (plan.source_low_word) |address| std.mem.readInt(u32, memory[address..][0..4], .little) else 0;
            const high = if (plan.source_high_word) |address| std.mem.readInt(u32, memory[address..][0..4], .little) else 0;
            const before = std.mem.readInt(u32, memory[plan.destination_word..][0..4], .little);
            const row = try K.witness(low, high, before, plan.start, plan.end, plan.shift);
            const weights = K.sourceQueryWeights(M, row);
            try std.testing.expectEqual(@as(u32, @intFromBool(plan.source_low_word != null)), weights[0].v);
            try std.testing.expectEqual(@as(u32, @intFromBool(plan.source_high_word != null)), weights[1].v);
            for (0..4) |byte| try std.testing.expectEqual(@as(u32, expected[plan.destination_word + byte]), row[K.Layout.destination_after + byte].v);
            try std.testing.expect(plan.first_store_clock <= plan.final_store_clock);
        }
    };
}
