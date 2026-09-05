//! Versioned custody for one base-RV32 minimal execution leaf.
//!
//! The leaf deliberately does not carry instruction words, addresses, decoded
//! opcodes, or full witness rows. Those values must be reconstructed from the
//! admitted program and entry CPU. Its only per-memory-operation payload is
//! the aligned word observed immediately before an ordinary load or store.
//! A SHA-256 seal catches accidental corruption; proof soundness still comes
//! from the separately authenticated program and memory-boundary identities.

const std = @import("std");
const execution_profile = @import("../../isa/execution_profile.zig");
const Cpu = @import("../cpu.zig").Cpu;
const decode = @import("../decode.zig");
const trace_mod = @import("../trace.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
/// Match the proof-bearing SegmentV2 clock range. Product controllers remain
/// responsible for choosing a smaller memory-safe leaf budget (the Ethereum
/// product currently uses 2^22); the tape format must not reject an otherwise
/// admissible leaf merely because the first microbenchmark used 2^16 rows.
pub const MAX_LEAF_CYCLES: u32 = 1 << 24;
pub const PROFILE: execution_profile.ExecutionProfile = .rv32im_zkvm_v1;

const LEAF_DOMAIN = "stwo.riscv.minimal-leaf.v1\x00";

pub const Digest = [32]u8;

/// Identities supplied by authorities outside the minimal tape. The tape seal
/// binds them, while replay independently requires matching program and
/// boundary sources before it can publish any witness state.
pub const SourceIdentityV1 = struct {
    profile: execution_profile.ExecutionProfile = PROFILE,
    program: Digest,
    input: Digest,
    session: Digest,
    entry_memory: Digest,
    exit_memory: Digest,

    pub fn validate(self: SourceIdentityV1) error{
        UnsupportedExecutionProfile,
        MissingSourceIdentity,
    }!void {
        if (self.profile != PROFILE) return error.UnsupportedExecutionProfile;
        inline for (.{
            self.program,
            self.input,
            self.session,
            self.entry_memory,
            self.exit_memory,
        }) |digest| {
            if (isZeroDigest(digest)) return error.MissingSourceIdentity;
        }
    }
};

/// Optional terminal metadata. Numeric kind values belong to this wire
/// version; callers must not serialize a host enum ordinal into `kind`.
pub const CompletionV1 = struct {
    kind: u8,
    address: u32,
    value: u32,
    clock: u32,
    exit_code: ?u32 = null,
};

pub const CaptureV1 = struct {
    source: SourceIdentityV1,
    segment_index: u32,
    global_first_cycle: u64,
    entry_cpu: Cpu,
    exit_cpu: Cpu,
    completion: ?CompletionV1 = null,
    execution_trace: *const trace_mod.Trace,
};

/// Owned canonical tape for exactly one independently replayable leaf.
pub const LeafV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    source: SourceIdentityV1,
    segment_index: u32,
    global_first_cycle: u64,
    cycle_count: u32,
    entry_cpu: Cpu,
    exit_cpu: Cpu,
    completion: ?CompletionV1,
    memory_read_words: []u32,
    seal: Digest,
    allocator: std.mem.Allocator,

    /// Seal an already captured minimal tape without reconstructing a full
    /// execution trace. Ownership of `memory_read_words` transfers only when
    /// this function succeeds.
    pub fn initOwned(
        allocator: std.mem.Allocator,
        source: SourceIdentityV1,
        segment_index: u32,
        global_first_cycle: u64,
        cycle_count: u32,
        entry_cpu: Cpu,
        exit_cpu: Cpu,
        completion: ?CompletionV1,
        memory_read_words: []u32,
    ) !LeafV1 {
        var result = LeafV1{
            .source = source,
            .segment_index = segment_index,
            .global_first_cycle = global_first_cycle,
            .cycle_count = cycle_count,
            .entry_cpu = entry_cpu,
            .exit_cpu = exit_cpu,
            .completion = completion,
            .memory_read_words = memory_read_words,
            .seal = undefined,
            .allocator = allocator,
        };
        result.seal = result.calculateSeal();
        try result.validate();
        return result;
    }

    pub fn capture(
        allocator: std.mem.Allocator,
        source_capture: CaptureV1,
    ) !LeafV1 {
        try source_capture.source.validate();
        if (source_capture.entry_cpu.regs[0] != 0 or
            source_capture.exit_cpu.regs[0] != 0)
            return error.ZeroRegisterInvariant;
        if (source_capture.global_first_cycle == 0)
            return error.InvalidGlobalCycleRange;
        if (source_capture.execution_trace.initial_pc != source_capture.entry_cpu.pc or
            source_capture.execution_trace.final_pc != source_capture.exit_cpu.pc)
        {
            return error.CpuTraceBoundaryMismatch;
        }
        const count = std.math.cast(
            u32,
            source_capture.execution_trace.rows.items.len,
        ) orelse return error.LeafCycleLimitExceeded;
        if (count == 0 or count > MAX_LEAF_CYCLES)
            return error.LeafCycleLimitExceeded;
        _ = std.math.add(
            u64,
            source_capture.global_first_cycle - 1,
            count,
        ) catch return error.InvalidGlobalCycleRange;
        source_capture.execution_trace.validateClockRange(0, count, 0) catch
            return error.InvalidTraceClockRange;

        var memory_word_count: usize = 0;
        for (source_capture.execution_trace.rows.items) |row| {
            const family = trace_mod.proofOpcodeFamily(row.opcode) catch
                return error.UnsupportedTraceOpcode;
            trace_mod.validateFamilyRow(row, family) catch
                return error.InvalidTraceRow;
            const is_memory = row.is_load or row.is_store;
            if (is_memory != (decode.isLoad(row.opcode) or decode.isStore(row.opcode)))
                return error.InvalidTraceRow;
            memory_word_count += @intFromBool(is_memory);
        }

        const words = try allocator.alloc(u32, memory_word_count);
        errdefer allocator.free(words);
        var at: usize = 0;
        for (source_capture.execution_trace.rows.items) |row| {
            if (!row.is_load and !row.is_store) continue;
            words[at] = row.mem_prev_word;
            at += 1;
        }
        std.debug.assert(at == words.len);

        var result = LeafV1{
            .source = source_capture.source,
            .segment_index = source_capture.segment_index,
            .global_first_cycle = source_capture.global_first_cycle,
            .cycle_count = count,
            .entry_cpu = source_capture.entry_cpu,
            .exit_cpu = source_capture.exit_cpu,
            .completion = source_capture.completion,
            .memory_read_words = words,
            .seal = undefined,
            .allocator = allocator,
        };
        result.seal = result.calculateSeal();
        return result;
    }

    pub fn deinit(self: *LeafV1) void {
        self.allocator.free(self.memory_read_words);
        self.* = undefined;
    }

    pub fn validate(self: *const LeafV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION)
        {
            return error.UnsupportedTapeVersion;
        }
        try self.source.validate();
        if (self.cycle_count == 0 or self.cycle_count > MAX_LEAF_CYCLES)
            return error.LeafCycleLimitExceeded;
        if (self.global_first_cycle == 0)
            return error.InvalidGlobalCycleRange;
        _ = std.math.add(
            u64,
            self.global_first_cycle - 1,
            self.cycle_count,
        ) catch return error.InvalidGlobalCycleRange;
        if (self.memory_read_words.len > self.cycle_count)
            return error.InvalidMemoryReadCount;
        if (self.entry_cpu.regs[0] != 0 or self.exit_cpu.regs[0] != 0)
            return error.ZeroRegisterInvariant;
        if (!std.mem.eql(u8, &self.seal, &self.calculateSeal()))
            return error.TapeSealMismatch;
    }

    /// Recompute the corruption seal after a deliberate mutation. This is
    /// exposed for mutation testing and format tooling; it is not a signature.
    pub fn reseal(self: *LeafV1) void {
        self.seal = self.calculateSeal();
    }

    pub fn calculateSeal(self: *const LeafV1) Digest {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(LEAF_DOMAIN);
        putInt(&hasher, u16, self.format_version);
        putInt(&hasher, u16, self.schema_version);
        putInt(&hasher, u16, @intFromEnum(self.source.profile));
        hasher.update(&self.source.program);
        hasher.update(&self.source.input);
        hasher.update(&self.source.session);
        hasher.update(&self.source.entry_memory);
        hasher.update(&self.source.exit_memory);
        putInt(&hasher, u32, self.segment_index);
        putInt(&hasher, u64, self.global_first_cycle);
        putInt(&hasher, u32, self.cycle_count);
        putCpu(&hasher, self.entry_cpu);
        putCpu(&hasher, self.exit_cpu);
        if (self.completion) |completion| {
            hasher.update(&.{1});
            hasher.update(&.{completion.kind});
            putInt(&hasher, u32, completion.address);
            putInt(&hasher, u32, completion.value);
            putInt(&hasher, u32, completion.clock);
            if (completion.exit_code) |exit_code| {
                hasher.update(&.{1});
                putInt(&hasher, u32, exit_code);
            } else {
                hasher.update(&.{0});
            }
        } else {
            hasher.update(&.{0});
        }
        putInt(&hasher, u32, @intCast(self.memory_read_words.len));
        for (self.memory_read_words) |word| putInt(&hasher, u32, word);
        var digest: Digest = undefined;
        hasher.final(&digest);
        return digest;
    }
};

pub fn digestBytes(bytes: []const u8) Digest {
    var result: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}

/// The zkVM completion sentinel is observed by the host and never retires as
/// an architectural row. Keep capture and replay on the same policy seam.
pub inline fn isUnretiredSelfLoop(instruction: decode.DecodedInst, cpu: Cpu) bool {
    return switch (instruction.opcode) {
        .JAL => instruction.rd == 0 and instruction.imm == 0,
        .JALR => instruction.rd == 0 and
            ((cpu.readReg(instruction.rs1) +%
                @as(u32, @bitCast(instruction.imm))) & ~@as(u32, 1)) == cpu.pc,
        else => false,
    };
}

fn isZeroDigest(digest: Digest) bool {
    var aggregate: u8 = 0;
    for (digest) |byte| aggregate |= byte;
    return aggregate == 0;
}

fn putCpu(hasher: anytype, cpu: Cpu) void {
    putInt(hasher, u32, cpu.pc);
    for (cpu.regs) |value| putInt(hasher, u32, value);
}

fn putInt(hasher: anytype, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hasher.update(&encoded);
}
