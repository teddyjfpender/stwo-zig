//! Sequential phase-one capture for one base-RV32 leaf.
//!
//! This dispatcher deliberately constructs neither `Trace` nor
//! `StateChainTracker`. The generated 46-op registry selects the same pinned,
//! pure typed retirement authority used by the proof-bearing runner. Capture
//! retains only CPU checkpoints, ordered pre-operation memory words, and the
//! sparse entry/exit delta for touched aligned words.

const std = @import("std");
const isa_profile = @import("../../isa/profile.zig");
const auipc = @import("../auipc_retirement.zig");
const base_alu_imm = @import("../base_alu_imm_retirement.zig");
const base_alu_reg = @import("../base_alu_reg_retirement.zig");
const branch_eq = @import("../branch_eq_retirement.zig");
const branch_lt = @import("../branch_lt_retirement.zig");
const Cpu = @import("../cpu.zig").Cpu;
const decode = @import("../decode.zig");
const decode_cache = @import("../decode_cache.zig");
const div = @import("../div_retirement.zig");
const fence = @import("../fence_retirement.zig");
const generated = @import("../generated_retirement.zig");
const jal = @import("../jal_retirement.zig");
const jalr = @import("../jalr_retirement.zig");
const load_store = @import("../load_store_retirement.zig");
const lt_imm = @import("../lt_imm_retirement.zig");
const lt_reg = @import("../lt_reg_retirement.zig");
const lui = @import("../lui_retirement.zig");
const Memory = @import("../memory.zig").Memory;
const mul = @import("../mul_retirement.zig");
const mulh = @import("../mulh_retirement.zig");
const shifts_imm = @import("../shifts_imm_retirement.zig");
const shifts_reg = @import("../shifts_reg_retirement.zig");
const replay = @import("replay.zig");
const types = @import("types.zig");

comptime {
    if (generated.MIGRATED.len != 46)
        @compileError("minimal capture must be reviewed when ordinary retirement coverage changes");
}

pub const RequestV1 = struct {
    segment_index: u32,
    global_first_cycle: u64,
    cycle_count: u32,
    input_identity: types.Digest,
    session_identity: types.Digest,
};

pub const ResultV1 = struct {
    leaf: types.LeafV1,
    boundary_words: []replay.BoundaryWord,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ResultV1) void {
        self.leaf.deinit();
        self.allocator.free(self.boundary_words);
        self.* = undefined;
    }

    pub fn boundary(self: *const ResultV1) !replay.SliceBoundary {
        return replay.SliceBoundary.init(self.boundary_words);
    }
};

/// Reusable sequential dispatcher. A word-keyed decode cache is retained
/// across leaves so repeated basic blocks do not repay decoder cost.
pub const DispatcherV1 = struct {
    instruction_cache: decode_cache.Cache,

    pub fn init(allocator: std.mem.Allocator) !DispatcherV1 {
        return .{ .instruction_cache = try decode_cache.Cache.init(allocator) };
    }

    pub fn deinit(self: *DispatcherV1) void {
        self.instruction_cache.deinit();
        self.* = undefined;
    }

    pub fn captureLeaf(
        self: *DispatcherV1,
        allocator: std.mem.Allocator,
        cpu: *Cpu,
        memory: *Memory,
        program: replay.ProgramSource,
        request: RequestV1,
    ) !ResultV1 {
        return captureImpl(
            &self.instruction_cache,
            allocator,
            cpu,
            memory,
            program,
            request,
        );
    }

    /// Concrete dense-image entry point. Both fetch and typed retirement can
    /// inline; there is no erased fetch call in the instruction loop.
    pub fn captureDenseLeaf(
        self: *DispatcherV1,
        allocator: std.mem.Allocator,
        cpu: *Cpu,
        memory: *Memory,
        program: *const replay.DenseProgram,
        request: RequestV1,
    ) !ResultV1 {
        return captureImpl(
            &self.instruction_cache,
            allocator,
            cpu,
            memory,
            program,
            request,
        );
    }
};

/// Execute exactly `request.cycle_count` successful ordinary retirements.
/// Allocation is completed before the first instruction. A semantic or fetch
/// error leaves prior successful instructions visible, so callers must discard
/// the in-progress leaf/session just as the production runner does.
pub fn captureLeaf(
    allocator: std.mem.Allocator,
    cpu: *Cpu,
    memory: *Memory,
    program: replay.ProgramSource,
    request: RequestV1,
) !ResultV1 {
    var dispatcher = try DispatcherV1.init(allocator);
    defer dispatcher.deinit();
    return dispatcher.captureLeaf(allocator, cpu, memory, program, request);
}

fn captureImpl(
    instruction_cache: *decode_cache.Cache,
    allocator: std.mem.Allocator,
    cpu: *Cpu,
    memory: *Memory,
    program: anytype,
    request: RequestV1,
) !ResultV1 {
    if (request.cycle_count == 0 or
        request.cycle_count > types.MAX_LEAF_CYCLES)
    {
        return error.LeafCycleLimitExceeded;
    }
    if (request.global_first_cycle == 0)
        return error.InvalidGlobalCycleRange;
    _ = std.math.add(
        u64,
        request.global_first_cycle - 1,
        request.cycle_count,
    ) catch return error.InvalidGlobalCycleRange;
    if (cpu.regs[0] != 0) return error.ZeroRegisterInvariant;

    const entry_cpu = cpu.*;
    var memory_words: std.ArrayList(u32) = .empty;
    defer memory_words.deinit(allocator);
    try memory_words.ensureTotalCapacity(allocator, request.cycle_count);
    var boundary_words: std.ArrayList(replay.BoundaryWord) = .empty;
    defer boundary_words.deinit(allocator);
    try boundary_words.ensureTotalCapacity(allocator, request.cycle_count);
    var touched = std.AutoHashMap(u32, usize).init(allocator);
    defer touched.deinit();
    try touched.ensureTotalCapacity(request.cycle_count);

    for (0..request.cycle_count) |_| {
        isa_profile.requireProgramWordAddress(cpu.pc) catch
            return error.InvalidProgramCounter;
        const inst_word = try program.fetch(cpu.pc);
        const instruction = instruction_cache.decode(inst_word) catch
            return error.InvalidProgramInstruction;
        if (types.isUnretiredSelfLoop(instruction, cpu.*))
            return error.UnretiredSelfLoop;
        const descriptor = generated.descriptorFor(instruction.opcode) orelse
            return error.UnsupportedCaptureInstruction;
        try retireOne(
            descriptor.kind,
            cpu,
            memory,
            instruction,
            &memory_words,
            &boundary_words,
            &touched,
        );
    }
    std.debug.assert(cpu.regs[0] == 0);

    std.mem.sort(
        replay.BoundaryWord,
        boundary_words.items,
        {},
        boundaryLessThan,
    );
    const owned_boundary = try boundary_words.toOwnedSlice(allocator);
    errdefer allocator.free(owned_boundary);
    const boundary = try replay.SliceBoundary.init(owned_boundary);
    const owned_memory_words = try memory_words.toOwnedSlice(allocator);
    errdefer allocator.free(owned_memory_words);
    const leaf = try types.LeafV1.initOwned(
        allocator,
        .{
            .program = program.identity,
            .input = request.input_identity,
            .session = request.session_identity,
            .entry_memory = boundary.entry_identity,
            .exit_memory = boundary.exit_identity,
        },
        request.segment_index,
        request.global_first_cycle,
        request.cycle_count,
        entry_cpu,
        cpu.*,
        null,
        owned_memory_words,
    );
    return .{
        .leaf = leaf,
        .boundary_words = owned_boundary,
        .allocator = allocator,
    };
}

inline fn retireOne(
    kind: generated.AuthorityKind,
    cpu: *Cpu,
    memory: *Memory,
    instruction: decode.DecodedInst,
    memory_words: *std.ArrayList(u32),
    boundary_words: *std.ArrayList(replay.BoundaryWord),
    touched: *std.AutoHashMap(u32, usize),
) !void {
    const pc = cpu.pc;
    const source_1 = cpu.readReg(instruction.rs1);
    const source_2 = cpu.readReg(instruction.rs2);
    switch (kind) {
        .lui => {
            const retired = try lui.PINNED_AUTHORITY.retire(instruction);
            cpu.writeReg(retired.rd, retired.visible_value);
            cpu.pc +%= 4;
        },
        .fence => {
            const retired = try fence.PINNED_AUTHORITY.retire(instruction, pc);
            cpu.pc = retired.next_pc;
        },
        .addi, .xori, .ori, .andi => {
            const retired = try base_alu_imm.PINNED_AUTHORITY.retire(
                instruction,
                source_1,
            );
            cpu.writeReg(retired.rd, retired.visible_value);
            cpu.pc +%= 4;
        },
        .auipc => {
            const retired = try auipc.PINNED_AUTHORITY.retire(instruction, pc);
            cpu.writeReg(retired.rd, retired.visible_value);
            cpu.pc = retired.next_pc;
        },
        .add, .sub, .xor, .or_reg, .and_reg => {
            const retired = try base_alu_reg.PINNED_AUTHORITY.retire(
                instruction,
                source_1,
                source_2,
            );
            cpu.writeReg(retired.rd, retired.visible_value);
            cpu.pc +%= 4;
        },
        .jal => {
            const retired = try jal.PINNED_AUTHORITY.retire(instruction, pc);
            cpu.writeReg(retired.rd, retired.visible_value);
            cpu.pc = retired.next_pc;
        },
        .jalr => {
            const retired = try jalr.PINNED_AUTHORITY.retire(
                instruction,
                pc,
                source_1,
            );
            cpu.writeReg(retired.rd, retired.visible_value);
            cpu.pc = retired.next_pc;
        },
        .beq, .bne => {
            const retired = try branch_eq.PINNED_AUTHORITY.retire(
                instruction,
                pc,
                source_1,
                source_2,
            );
            cpu.pc = retired.next_pc;
        },
        .blt, .bltu, .bge, .bgeu => {
            const retired = try branch_lt.PINNED_AUTHORITY.retire(
                instruction,
                pc,
                source_1,
                source_2,
            );
            cpu.pc = retired.next_pc;
        },
        .slti, .sltiu => {
            const retired = try lt_imm.PINNED_AUTHORITY.retire(
                instruction,
                source_1,
            );
            cpu.writeReg(retired.rd, retired.visible_value);
            cpu.pc +%= 4;
        },
        .slt, .sltu => {
            const retired = try lt_reg.PINNED_AUTHORITY.retire(
                instruction,
                source_1,
                source_2,
            );
            cpu.writeReg(retired.rd, retired.visible_value);
            cpu.pc +%= 4;
        },
        .slli, .srli, .srai => {
            const retired = try shifts_imm.PINNED_AUTHORITY.retire(
                instruction,
                source_1,
            );
            cpu.writeReg(retired.rd, retired.visible_value);
            cpu.pc +%= 4;
        },
        .sll, .srl, .sra => {
            const retired = try shifts_reg.PINNED_AUTHORITY.retire(
                instruction,
                source_1,
                source_2,
            );
            cpu.writeReg(retired.rd, retired.visible_value);
            cpu.pc +%= 4;
        },
        .mul => {
            const retired = try mul.PINNED_AUTHORITY.retire(
                instruction,
                source_1,
                source_2,
            );
            cpu.writeReg(retired.rd, retired.visible_value);
            cpu.pc +%= 4;
        },
        .mulh, .mulhsu, .mulhu => {
            const retired = try mulh.PINNED_AUTHORITY.retire(
                instruction,
                source_1,
                source_2,
            );
            cpu.writeReg(retired.rd, retired.visible_value);
            cpu.pc +%= 4;
        },
        .div, .divu, .rem, .remu => {
            const retired = try div.PINNED_AUTHORITY.retire(
                instruction,
                source_1,
                source_2,
            );
            cpu.writeReg(retired.rd, retired.visible_value);
            cpu.pc +%= 4;
        },
        .lb, .lh, .lbu, .lhu, .lw, .sb, .sh, .sw => try retireMemory(
            cpu,
            memory,
            instruction,
            source_1,
            source_2,
            memory_words,
            boundary_words,
            touched,
        ),
    }
}

inline fn retireMemory(
    cpu: *Cpu,
    memory: *Memory,
    instruction: decode.DecodedInst,
    base_value: u32,
    source_value: u32,
    memory_words: *std.ArrayList(u32),
    boundary_words: *std.ArrayList(replay.BoundaryWord),
    touched: *std.AutoHashMap(u32, usize),
) !void {
    const address = base_value +% @as(u32, @bitCast(instruction.imm));
    const aligned = address & ~@as(u32, 3);
    const previous_word = memory.readU32(aligned);
    const retired = try load_store.PINNED_AUTHORITY.retire(
        instruction,
        base_value,
        source_value,
        previous_word,
    );
    std.debug.assert(retired.aligned_address == aligned);
    if (retired.write_memory and !memory.alignedWordWriteIsPrepared(aligned))
        try memory.prepareAlignedWordWrites(&.{aligned});

    memory_words.appendAssumeCapacity(previous_word);
    const slot = touched.getOrPutAssumeCapacity(aligned);
    if (!slot.found_existing) {
        slot.value_ptr.* = boundary_words.items.len;
        boundary_words.appendAssumeCapacity(.{
            .address = aligned,
            .entry = previous_word,
            .exit = previous_word,
        });
    }
    if (retired.write_register)
        cpu.writeReg(instruction.rd, retired.register_value);
    if (retired.write_memory)
        memory.writeU32AssumePrepared(aligned, retired.memory_next_word);
    boundary_words.items[slot.value_ptr.*].exit = memory.readU32(aligned);
    cpu.pc +%= 4;
}

fn boundaryLessThan(
    _: void,
    left: replay.BoundaryWord,
    right: replay.BoundaryWord,
) bool {
    return left.address < right.address;
}
