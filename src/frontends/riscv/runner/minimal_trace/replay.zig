//! Memory-image-free replay of one base-RV32 minimal leaf.
//!
//! Instruction words come from a separately authenticated immutable program.
//! Initial/final memory words come from a separately authenticated boundary.
//! The local `Memory` below is only a touched-word overlay required by the
//! existing failure-atomic typed retirement transactions; it never loads the
//! ELF, input image, or untouched global memory.

const std = @import("std");
const isa_profile = @import("../../isa/profile.zig");
const Cpu = @import("../cpu.zig").Cpu;
const DecodedInst = @import("../decode.zig").DecodedInst;
const decode = @import("../decode.zig");
const generated = @import("../generated_retirement.zig");
const Memory = @import("../memory.zig").Memory;
const segment_capacity = @import("../segment_capacity.zig");
const StateChainTracker = @import("../state_chain.zig").StateChainTracker;
const trace_mod = @import("../trace.zig");
const types = @import("types.zig");

const PROGRAM_DOMAIN = "stwo.riscv.minimal-program.v1\x00";
const BOUNDARY_ENTRY_DOMAIN = "stwo.riscv.minimal-boundary.entry.v1\x00";
const BOUNDARY_EXIT_DOMAIN = "stwo.riscv.minimal-boundary.exit.v1\x00";

comptime {
    if (generated.MIGRATED.len != 46)
        @compileError("minimal replay must be reviewed when ordinary retirement coverage changes");
}

pub const ProgramWord = struct {
    address: u32,
    word: u32,
};

/// General fetch seam used by both the slice-backed first implementation and
/// a later content-addressed native/basic-block executor.
pub const ProgramSource = struct {
    context: *const anyopaque,
    fetch_fn: *const fn (*const anyopaque, u32) error{ProgramWordUnavailable}!u32,
    identity: types.Digest,

    pub inline fn fetch(
        self: ProgramSource,
        address: u32,
    ) error{ProgramWordUnavailable}!u32 {
        return self.fetch_fn(self.context, address);
    }
};

/// Borrowed canonical program words. Construction pins sorted, aligned,
/// duplicate-free addresses and hashes the complete contents.
pub const SliceProgram = struct {
    words: []const ProgramWord,
    identity: types.Digest,

    pub fn init(words: []const ProgramWord) !SliceProgram {
        var previous: ?u32 = null;
        for (words) |word| {
            if (word.address & 3 != 0) return error.UnalignedProgramWord;
            if (previous) |address| {
                if (word.address <= address)
                    return error.NonCanonicalProgramOrder;
            }
            previous = word.address;
        }
        return .{ .words = words, .identity = programIdentity(words) };
    }

    pub fn source(self: *const SliceProgram) ProgramSource {
        return .{
            .context = self,
            .fetch_fn = fetchOpaque,
            .identity = self.identity,
        };
    }

    fn fetchOpaque(
        context: *const anyopaque,
        address: u32,
    ) error{ProgramWordUnavailable}!u32 {
        const self: *const SliceProgram = @ptrCast(@alignCast(context));
        var low: usize = 0;
        var high: usize = self.words.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            const candidate = self.words[mid];
            if (candidate.address < address) {
                low = mid + 1;
            } else if (candidate.address > address) {
                high = mid;
            } else {
                return candidate.word;
            }
        }
        return error.ProgramWordUnavailable;
    }
};

/// Borrowed contiguous immutable program image. Fetch is one bounds check and
/// one indexed load regardless of ELF size; its identity is byte-for-byte the
/// same canonical `(address, word)` commitment used by `SliceProgram`.
pub const DenseProgram = struct {
    base_address: u32,
    words: []const u32,
    identity: types.Digest,

    pub fn init(base_address: u32, words: []const u32) !DenseProgram {
        if (words.len == 0) return error.EmptyProgram;
        if (base_address & 3 != 0) return error.UnalignedProgramWord;
        const last_offset = std.math.mul(
            usize,
            words.len - 1,
            4,
        ) catch return error.ProgramImageOutOfRange;
        const last_offset_u32 = std.math.cast(u32, last_offset) orelse
            return error.ProgramImageOutOfRange;
        _ = std.math.add(u32, base_address, last_offset_u32) catch
            return error.ProgramImageOutOfRange;
        return .{
            .base_address = base_address,
            .words = words,
            .identity = denseProgramIdentity(base_address, words),
        };
    }

    pub fn source(self: *const DenseProgram) ProgramSource {
        return .{
            .context = self,
            .fetch_fn = fetchOpaque,
            .identity = self.identity,
        };
    }

    pub inline fn fetch(
        self: *const DenseProgram,
        address: u32,
    ) error{ProgramWordUnavailable}!u32 {
        if (address < self.base_address) return error.ProgramWordUnavailable;
        const offset = address - self.base_address;
        if (offset & 3 != 0) return error.ProgramWordUnavailable;
        const index: usize = offset >> 2;
        if (index >= self.words.len) return error.ProgramWordUnavailable;
        return self.words[index];
    }

    fn fetchOpaque(
        context: *const anyopaque,
        address: u32,
    ) error{ProgramWordUnavailable}!u32 {
        const self: *const DenseProgram = @ptrCast(@alignCast(context));
        return self.fetch(address);
    }
};

pub const BoundaryWord = struct {
    address: u32,
    entry: u32,
    exit: u32,
};

pub const BoundarySource = struct {
    context: *const anyopaque,
    entry_fn: *const fn (*const anyopaque, u32) u32,
    exit_fn: *const fn (*const anyopaque, u32) u32,
    entry_identity: types.Digest,
    exit_identity: types.Digest,

    pub inline fn entryWord(self: BoundarySource, address: u32) u32 {
        return self.entry_fn(self.context, address);
    }

    pub inline fn exitWord(self: BoundarySource, address: u32) u32 {
        return self.exit_fn(self.context, address);
    }
};

/// Borrowed sparse boundary adapter. Missing addresses are canonical zero
/// leaves; callers with a different memory tree policy must provide another
/// `BoundarySource` rather than weakening this adapter.
pub const SliceBoundary = struct {
    words: []const BoundaryWord,
    entry_identity: types.Digest,
    exit_identity: types.Digest,

    pub fn init(words: []const BoundaryWord) !SliceBoundary {
        var previous: ?u32 = null;
        for (words) |word| {
            if (word.address & 3 != 0) return error.UnalignedBoundaryWord;
            if (previous) |address| {
                if (word.address <= address)
                    return error.NonCanonicalBoundaryOrder;
            }
            previous = word.address;
        }
        return .{
            .words = words,
            .entry_identity = boundaryIdentity(words, .entry),
            .exit_identity = boundaryIdentity(words, .exit),
        };
    }

    pub fn source(self: *const SliceBoundary) BoundarySource {
        return .{
            .context = self,
            .entry_fn = entryOpaque,
            .exit_fn = exitOpaque,
            .entry_identity = self.entry_identity,
            .exit_identity = self.exit_identity,
        };
    }

    fn entryOpaque(context: *const anyopaque, address: u32) u32 {
        const self: *const SliceBoundary = @ptrCast(@alignCast(context));
        return self.find(address, .entry);
    }

    fn exitOpaque(context: *const anyopaque, address: u32) u32 {
        const self: *const SliceBoundary = @ptrCast(@alignCast(context));
        return self.find(address, .exit);
    }

    fn find(
        self: *const SliceBoundary,
        address: u32,
        comptime side: enum { entry, exit },
    ) u32 {
        var low: usize = 0;
        var high: usize = self.words.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            const candidate = self.words[mid];
            if (candidate.address < address) {
                low = mid + 1;
            } else if (candidate.address > address) {
                high = mid;
            } else {
                return @field(candidate, @tagName(side));
            }
        }
        return 0;
    }
};

pub const MemoryReadCursor = struct {
    words: []const u32,
    next_index: usize = 0,

    pub fn next(self: *MemoryReadCursor) error{MemoryReadTapeExhausted}!u32 {
        if (self.next_index == self.words.len)
            return error.MemoryReadTapeExhausted;
        const result = self.words[self.next_index];
        self.next_index += 1;
        return result;
    }

    pub fn finish(self: MemoryReadCursor) error{MemoryReadTapeNotExhausted}!void {
        if (self.next_index != self.words.len)
            return error.MemoryReadTapeNotExhausted;
    }
};

pub const Result = struct {
    cpu: Cpu,
    execution_trace: trace_mod.Trace,
    state_chain_tracker: StateChainTracker,
    /// Contains only words touched by this leaf, never the full memory image.
    touched_memory: Memory,

    pub fn deinit(self: *Result) void {
        self.touched_memory.deinit();
        self.state_chain_tracker.deinit();
        self.execution_trace.deinit();
        self.* = undefined;
    }
};

pub fn replay(
    allocator: std.mem.Allocator,
    leaf: *const types.LeafV1,
    program: ProgramSource,
    boundary: BoundarySource,
) !Result {
    try leaf.validate();
    if (leaf.completion != null) return error.UnsupportedCompletion;
    if (!std.mem.eql(u8, &leaf.source.program, &program.identity))
        return error.ProgramIdentityMismatch;
    if (!std.mem.eql(u8, &leaf.source.entry_memory, &boundary.entry_identity) or
        !std.mem.eql(u8, &leaf.source.exit_memory, &boundary.exit_identity))
    {
        return error.MemoryBoundaryIdentityMismatch;
    }

    var memory = try Memory.initFallible(allocator);
    errdefer memory.deinit();
    var trace = trace_mod.Trace.init(allocator);
    errdefer trace.deinit();
    trace.initial_pc = leaf.entry_cpu.pc;
    var tracker = StateChainTracker.init(allocator);
    errdefer tracker.deinit();
    try segment_capacity.reserveLeafLogs(&trace, &tracker, leaf.cycle_count);
    var touched = std.AutoHashMap(u32, u32).init(allocator);
    defer touched.deinit();
    var cursor = MemoryReadCursor{ .words = leaf.memory_read_words };
    var cpu = leaf.entry_cpu;

    for (0..leaf.cycle_count) |zero_based_clock| {
        isa_profile.requireInstructionAligned(cpu.pc) catch
            return error.InstructionAddressMisaligned;
        const inst_word = try program.fetch(cpu.pc);
        const instruction = DecodedInst.decode(inst_word) catch
            return error.InvalidProgramInstruction;
        if (types.isUnretiredSelfLoop(instruction, cpu))
            return error.UnretiredSelfLoop;
        if (decode.isLoad(instruction.opcode) or decode.isStore(instruction.opcode)) {
            const address = cpu.readReg(instruction.rs1) +%
                @as(u32, @bitCast(instruction.imm));
            const aligned = address & ~@as(u32, 3);
            const previous_word = try cursor.next();
            const observed = try touched.getOrPut(aligned);
            if (observed.found_existing) {
                if (memory.readU32(aligned) != previous_word)
                    return error.ReplayMemoryMismatch;
            } else {
                const expected = boundary.entryWord(aligned);
                if (previous_word != expected)
                    return error.MemoryBoundaryEntryMismatch;
                observed.value_ptr.* = previous_word;
                try memory.prepareAlignedWordWrites(&.{aligned});
                memory.writeU32AssumePrepared(aligned, previous_word);
            }
        }

        const instruction_clock: u32 = @intCast(zero_based_clock + 1);
        const retired = try generated.retireAtomic(
            &cpu,
            &memory,
            &trace,
            &tracker,
            instruction,
            inst_word,
            instruction_clock,
        );
        if (!retired) return error.UnsupportedReplayInstruction;
        const row = trace.rows.items[trace.rows.items.len - 1];
        const family = trace_mod.proofOpcodeFamily(row.opcode) catch
            return error.UnsupportedReplayInstruction;
        trace_mod.validateFamilyRow(row, family) catch
            return error.InvalidReplayedTraceRow;
    }
    try cursor.finish();
    trace.final_pc = cpu.pc;
    trace.validateClockRange(0, leaf.cycle_count, 0) catch
        return error.InvalidReplayedClockRange;
    if (!cpuEqual(cpu, leaf.exit_cpu)) return error.ExitCpuMismatch;

    var touched_iterator = touched.keyIterator();
    while (touched_iterator.next()) |address| {
        if (memory.readU32(address.*) != boundary.exitWord(address.*))
            return error.MemoryBoundaryExitMismatch;
    }

    return .{
        .cpu = cpu,
        .execution_trace = trace,
        .state_chain_tracker = tracker,
        .touched_memory = memory,
    };
}

fn cpuEqual(left: Cpu, right: Cpu) bool {
    return left.pc == right.pc and std.mem.eql(u32, &left.regs, &right.regs);
}

fn programIdentity(words: []const ProgramWord) types.Digest {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(PROGRAM_DOMAIN);
    putInt(&hasher, u32, @intCast(words.len));
    for (words) |word| {
        putInt(&hasher, u32, word.address);
        putInt(&hasher, u32, word.word);
    }
    var result: types.Digest = undefined;
    hasher.final(&result);
    return result;
}

fn denseProgramIdentity(base_address: u32, words: []const u32) types.Digest {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(PROGRAM_DOMAIN);
    putInt(&hasher, u32, @intCast(words.len));
    for (words, 0..) |word, index| {
        putInt(
            &hasher,
            u32,
            base_address + @as(u32, @intCast(index)) * 4,
        );
        putInt(&hasher, u32, word);
    }
    var result: types.Digest = undefined;
    hasher.final(&result);
    return result;
}

fn boundaryIdentity(
    words: []const BoundaryWord,
    comptime side: enum { entry, exit },
) types.Digest {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(if (side == .entry) BOUNDARY_ENTRY_DOMAIN else BOUNDARY_EXIT_DOMAIN);
    putInt(&hasher, u32, @intCast(words.len));
    for (words) |word| {
        putInt(&hasher, u32, word.address);
        putInt(&hasher, u32, @field(word, @tagName(side)));
    }
    var result: types.Digest = undefined;
    hasher.final(&result);
    return result;
}

fn putInt(hasher: anytype, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hasher.update(&encoded);
}
