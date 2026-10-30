//! Diagnostic real-guest window capture. An incoming-state capsule is an
//! explicit benchmark input, NOT a proof of the skipped prefix or a terminal
//! Ethereum statement. No production verifier imports this module.
const std = @import("std");
const Runner = @import("../runner/mod.zig");
const Cpu = @import("../runner/cpu.zig").Cpu;
const Segment = @import("../runner/result.zig").EthereumShaSegmentResult;
const Memory = @import("../runner/memory.zig").Memory;
const Token = @import("../runner/result.zig").ContinuationToken;
pub const Digest = [32]u8;
pub const Pins = struct { elf: Digest, input: Digest };
pub const Window = struct { skip_cycles: u64, cycles: u32 };
pub const Limits = struct {
    max_elf_bytes: usize = 32 << 20,
    max_input_bytes: usize = 4 << 20,
    max_skip_cycles: u64 = 150_000_000,
    max_window_cycles: u32 = 1 << 18,
    replay_chunk_cycles: u32 = 1 << 16,
    max_snapshot_words: usize = 8_000_000,
};
pub const Word = struct { address: u32, value: u32 };
pub const Snapshot = struct {
    cpu: Cpu,
    words: []Word,
    pub fn deinit(self: *Snapshot, a: std.mem.Allocator) void {
        a.free(self.words);
        self.* = undefined;
    }
    pub fn identity(self: Snapshot) Digest {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("stwo-v7-real-window-state-v1");
        mix(&h, self.cpu.pc);
        for (self.cpu.regs) |v| mix(&h, v);
        mix(&h, self.words.len);
        for (self.words) |word| {
            mix(&h, word.address);
            mix(&h, word.value);
        }
        return h.finalResult();
    }
    pub fn encode(self: Snapshot, a: std.mem.Allocator) ![]u8 {
        const header = 8 + 33 * 4 + 8;
        const bytes = try a.alloc(u8, try std.math.add(usize, header, try std.math.mul(usize, self.words.len, 8)));
        @memcpy(bytes[0..8], "B7WIN001");
        std.mem.writeInt(u32, bytes[8..12], self.cpu.pc, .little);
        for (self.cpu.regs, 0..) |value, i| std.mem.writeInt(u32, bytes[12 + 4 * i ..][0..4], value, .little);
        std.mem.writeInt(u64, bytes[140..148], self.words.len, .little);
        for (self.words, 0..) |word, i| {
            std.mem.writeInt(u32, bytes[header + 8 * i ..][0..4], word.address, .little);
            std.mem.writeInt(u32, bytes[header + 8 * i + 4 ..][0..4], word.value, .little);
        }
        return bytes;
    }
    pub fn decode(a: std.mem.Allocator, bytes: []const u8, expected: Digest, limits: Limits) !Snapshot {
        if (bytes.len < 148 or !std.mem.eql(u8, bytes[0..8], "B7WIN001")) return error.InvalidRealWindowSnapshot;
        const count64 = std.mem.readInt(u64, bytes[140..148], .little);
        const count = std.math.cast(usize, count64) orelse return error.RealWindowResourceLimit;
        if (count > limits.max_snapshot_words) return error.RealWindowResourceLimit;
        if (bytes.len != try std.math.add(usize, 148, try std.math.mul(usize, count, 8))) return error.InvalidRealWindowSnapshot;
        var cpu: Cpu = undefined;
        cpu.pc = std.mem.readInt(u32, bytes[8..12], .little);
        for (&cpu.regs, 0..) |*reg, i| reg.* = std.mem.readInt(u32, bytes[12 + 4 * i ..][0..4], .little);
        if (cpu.regs[0] != 0) return error.InvalidRealWindowSnapshot;
        const words = try a.alloc(Word, count);
        errdefer a.free(words);
        for (words, 0..) |*word, i| {
            word.* = .{ .address = std.mem.readInt(u32, bytes[148 + 8 * i ..][0..4], .little), .value = std.mem.readInt(u32, bytes[152 + 8 * i ..][0..4], .little) };
            if (word.address & 3 != 0 or (i != 0 and words[i - 1].address >= word.address)) return error.InvalidRealWindowSnapshot;
        }
        const result: Snapshot = .{ .cpu = cpu, .words = words };
        if (!std.meta.eql(result.identity(), expected)) return error.UntrustedRealWindowIncomingState;
        return result;
    }
};
pub const Stats = struct {
    skipped_cycles: u64,
    cycles: u32,
    core_rows: usize,
    keccak_calls: usize,
    recovery_calls: usize,
    sha_calls: usize,
    incoming_words: usize,
    outgoing_words: usize,
    prefix_ns: u64,
    window_ns: u64,
};
pub const Captured = struct {
    a: std.mem.Allocator,
    pins: Pins,
    window: Window,
    incoming: Snapshot,
    outgoing: Snapshot,
    segment: Segment,
    has_execution: bool = true,
    behavior: Digest,
    stats: Stats,
    pub fn deinit(self: *Captured) void {
        self.releaseExecution();
        self.incoming.deinit(self.a);
        self.outgoing.deinit(self.a);
        self.* = undefined;
    }
    pub fn releaseExecution(self: *Captured) void {
        if (self.has_execution) self.segment.deinit();
        self.has_execution = false;
    }
};
pub fn sha(bytes: []const u8) Digest {
    var result: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}
fn mix(h: *std.crypto.hash.sha2.Sha256, value: anytype) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, @intCast(value), .little);
    h.update(&bytes);
}
fn admit(elf: []const u8, input: []const u8, pins: Pins, window: Window, limits: Limits) !void {
    if (elf.len > limits.max_elf_bytes or input.len > limits.max_input_bytes or
        window.skip_cycles > limits.max_skip_cycles or window.cycles == 0 or
        window.cycles > limits.max_window_cycles or limits.replay_chunk_cycles == 0)
        return error.RealWindowResourceLimit;
    _ = try std.math.add(u64, window.skip_cycles, window.cycles);
    if (!std.meta.eql(sha(elf), pins.elf) or !std.meta.eql(sha(input), pins.input))
        return error.UntrustedRealWindowSource;
}
pub fn snapshot(a: std.mem.Allocator, cpu: Cpu, memory: *Memory, limits: Limits) !Snapshot {
    if (memory.initialized_word_count > limits.max_snapshot_words) return error.RealWindowResourceLimit;
    const addresses = try memory.canonicalAlignedWordAddresses();
    const words = try a.alloc(Word, addresses.len);
    for (addresses, words) |address, *word| word.* = .{ .address = address, .value = memory.readU32(address) };
    return .{ .cpu = cpu, .words = words };
}
fn behaviorDigest(a: std.mem.Allocator, segment: *const Segment) !Digest {
    // No pointers or struct padding enter this canonical field-order encoding.
    // Leaf-local clocks remain exact; frame indices/global placement are kept
    // separately in the capsule, not confused with instruction semantics.
    const bytes = try std.json.Stringify.valueAlloc(a, .{
        .entry = segment.base.entry_cpu,
        .exit = segment.base.exit_cpu,
        .rows = segment.base.execution_trace.rows.items,
        .keccak = segment.extension.keccakf_calls.records(),
        .recovery = segment.extension.signer_recovery_calls.records(),
        .sha = segment.extension.sha_calls.records(),
        .completion = segment.base.completion_reason,
    }, .{});
    defer a.free(bytes);
    return sha(bytes);
}
pub fn capture(a: std.mem.Allocator, elf: []const u8, input: []const u8, pins: Pins, window: Window, limits: Limits) !Captured {
    try admit(elf, input, pins, window, limits);
    var session = try Runner.EthereumShaExecutionSession.init(a, elf, .{
        .input = input,
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
        .stop_on_halt_flag = true,
        .require_current_output_accesses = false,
    });
    defer session.deinit();
    var timer = try std.time.Timer.start();
    var left = window.skip_cycles;
    var continuation: ?Token = null;
    while (left != 0) {
        const count: usize = @intCast(@min(left, limits.replay_chunk_cycles));
        var skipped = if (continuation) |token| try session.resumeSegment(token, count) else try session.startSegment(count);
        defer skipped.deinit();
        if (skipped.base.cycle_count != count or skipped.base.completion_reason != null) return error.RealWindowPastCompletion;
        continuation = skipped.base.continuation orelse return error.RealWindowPastCompletion;
        left -= count;
    }
    const prefix_ns = timer.read();
    var incoming = try snapshot(a, session.cpu, &session.memory, limits);
    errdefer incoming.deinit(a);
    timer.reset();
    var segment = if (continuation) |token| try session.resumeSegment(token, window.cycles) else try session.startSegment(window.cycles);
    errdefer segment.deinit();
    const window_ns = timer.read();
    if (segment.base.cycle_count != window.cycles) return error.RealWindowPastCompletion;
    var outgoing = try snapshot(a, session.cpu, &session.memory, limits);
    errdefer outgoing.deinit(a);
    return .{ .a = a, .pins = pins, .window = window, .incoming = incoming, .outgoing = outgoing, .behavior = try behaviorDigest(a, &segment), .stats = .{
        .skipped_cycles = window.skip_cycles,
        .cycles = window.cycles,
        .core_rows = segment.base.execution_trace.rows.items.len,
        .keccak_calls = segment.extension.keccakf_calls.records().len,
        .recovery_calls = segment.extension.signer_recovery_calls.records().len,
        .sha_calls = segment.extension.sha_calls.records().len,
        .incoming_words = incoming.words.len,
        .outgoing_words = outgoing.words.len,
        .prefix_ns = prefix_ns,
        .window_ns = window_ns,
    }, .segment = segment };
}
/// Re-execute a selected window from an independently pinned incoming state.
/// This establishes diagnostic reproducibility only. The state digest is an
/// explicit external benchmark input; it does not authenticate the prefix.
pub fn replay(a: std.mem.Allocator, elf: []const u8, input: []const u8, captured: *const Captured, expected_incoming: Digest, limits: Limits) !void {
    try admit(elf, input, captured.pins, captured.window, limits);
    if (!std.meta.eql(captured.incoming.identity(), expected_incoming) or
        captured.incoming.cpu.regs[0] != 0 or captured.incoming.words.len > limits.max_snapshot_words)
        return error.UntrustedRealWindowIncomingState;
    var session = try Runner.EthereumShaExecutionSession.init(a, elf, .{
        .input = input,
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
        .stop_on_halt_flag = true,
        .require_current_output_accesses = false,
    });
    defer session.deinit();
    const addresses = try a.alloc(u32, captured.incoming.words.len);
    defer a.free(addresses);
    for (captured.incoming.words, addresses, 0..) |word, *address, index| {
        if (word.address & 3 != 0 or (index != 0 and captured.incoming.words[index - 1].address >= word.address))
            return error.UntrustedRealWindowIncomingState;
        if (session.elf_info.memory_layout.isProgramAddr(word.address) and session.memory.readU32(word.address) != word.value)
            return error.UntrustedRealWindowProgram;
        address.* = word.address;
    }
    try session.memory.prepareAlignedWordWrites(addresses);
    for (captured.incoming.words) |word| session.memory.writeU32AssumePrepared(word.address, word.value);
    session.cpu = captured.incoming.cpu;
    var segment = try session.startSegment(captured.window.cycles);
    defer segment.deinit();
    if (segment.base.cycle_count != captured.window.cycles or
        !std.meta.eql(try behaviorDigest(a, &segment), captured.behavior)) return error.RealWindowReplayMismatch;
    var outgoing = try snapshot(a, session.cpu, &session.memory, limits);
    defer outgoing.deinit(a);
    if (!std.meta.eql(outgoing.identity(), captured.outgoing.identity())) return error.RealWindowReplayMismatch;
}
