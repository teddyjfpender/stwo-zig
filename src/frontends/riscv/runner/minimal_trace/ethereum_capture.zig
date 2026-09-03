//! Compact an already executed leaf-local Ethereum segment.
//!
//! This first integration boundary deliberately consumes the existing full
//! execution result. It proves that compact custody and independent replay are
//! exact before the sequential runner is replaced by a semantic-only capture
//! loop. No full trace or state-chain allocation survives this conversion.

const std = @import("std");
const custom0 = @import("../../isa/custom0.zig");
const execution_profile = @import("../../isa/execution_profile.zig");
const recovery_abi = @import("../../isa/ethereum_signer_recovery.zig");
const decode = @import("../decode.zig");
const memory_state = @import("../memory_state.zig");
const result_mod = @import("../result.zig");
const trace_mod = @import("../trace.zig");
const keccakf_v1 = @import("../guest_precompile/keccakf_v1.zig");
const recovery_v1 = @import("../guest_precompile/secp256k1_recover_v1.zig");
const replay = @import("replay.zig");
const types = @import("ethereum_types.zig");

pub const RequestV1 = struct {
    segment: *const result_mod.EthereumSegmentResult,
    program: replay.ProgramSource,
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

pub fn captureFromSegment(
    allocator: std.mem.Allocator,
    request: RequestV1,
) !ResultV1 {
    const segment = request.segment;
    const base = &segment.base;
    if (base.clock_frame != .leaf_local)
        return error.LeafLocalClockFrameRequired;
    if (base.execution_trace.step_count != base.execution_trace.rows.items.len)
        return error.InvalidTraceShape;

    try validateExternalTape(
        request.program,
        segment.keccakf_calls.records(),
        segment.keccakf_execution_rows.rows(),
        .keccakf_1600_permute_in_place_v1,
    );
    try validateExternalTape(
        request.program,
        segment.signer_recovery_calls.records(),
        segment.signer_recovery_execution_rows.rows(),
        .secp256k1_recover_signer_v1,
    );
    const external_count = std.math.add(
        usize,
        segment.keccakf_calls.len(),
        segment.signer_recovery_calls.len(),
    ) catch return error.InvalidExternalCount;
    const cycle_count = std.math.cast(u32, base.cycle_count) orelse
        return error.LeafCycleLimitExceeded;
    const core_cycle_count = std.math.cast(
        u32,
        base.execution_trace.rows.items.len,
    ) orelse return error.LeafCycleLimitExceeded;
    const reconstructed_cycles = std.math.add(
        usize,
        @as(usize, core_cycle_count),
        external_count,
    ) catch return error.InvalidExternalCount;
    if (reconstructed_cycles != cycle_count)
        return error.InvalidExternalCount;
    base.execution_trace.validateClockRange(
        0,
        cycle_count,
        external_count,
    ) catch return error.InvalidTraceClockRange;

    var memory_word_count: usize = 0;
    for (base.execution_trace.rows.items) |row| {
        const family = trace_mod.proofOpcodeFamily(row.opcode) catch
            return error.UnsupportedTraceOpcode;
        trace_mod.validateFamilyRow(row, family) catch
            return error.InvalidTraceRow;
        const is_memory = row.is_load or row.is_store;
        if (is_memory != (decode.isLoad(row.opcode) or decode.isStore(row.opcode)))
            return error.InvalidTraceRow;
        memory_word_count += @intFromBool(is_memory);
    }
    const ordinary_words = try allocator.alloc(u32, memory_word_count);
    errdefer allocator.free(ordinary_words);
    var memory_at: usize = 0;
    for (base.execution_trace.rows.items) |row| {
        if (!row.is_load and !row.is_store) continue;
        ordinary_words[memory_at] = row.mem_prev_word;
        memory_at += 1;
    }
    std.debug.assert(memory_at == ordinary_words.len);

    const keccak_records = try allocator.dupe(
        types.KeccakRecord,
        segment.keccakf_calls.records(),
    );
    errdefer allocator.free(keccak_records);
    const recovery_records = try allocator.dupe(
        types.RecoveryRecord,
        segment.signer_recovery_calls.records(),
    );
    errdefer allocator.free(recovery_records);
    const boundary_words = try buildBoundary(allocator, segment);
    errdefer allocator.free(boundary_words);
    const boundary = try replay.SliceBoundary.init(boundary_words);

    const completion = if (base.completion_reason) |reason|
        completionFromSegment(base, reason)
    else
        null;
    const leaf = try types.LeafV1.initOwned(
        allocator,
        .{
            .program = request.program.identity,
            .input = request.input_identity,
            .session = request.session_identity,
            .entry_memory = snapshotIdentity(base.rw_memory, .entry),
            .exit_memory = snapshotIdentity(base.rw_memory, .exit),
        },
        boundary.entry_identity,
        boundary.exit_identity,
        base.segment_index,
        base.global_first_cycle,
        cycle_count,
        core_cycle_count,
        base.entry_cpu,
        base.exit_cpu,
        completion,
        ordinary_words,
        keccak_records,
        recovery_records,
    );
    return .{
        .leaf = leaf,
        .boundary_words = boundary_words,
        .allocator = allocator,
    };
}

pub const SnapshotSide = enum { entry, exit };

/// Match the canonical segment-journal memory authority while keeping the
/// compact touched-word replay boundary as a separate identity. Zero-valued
/// words are omitted, so adjacent snapshots with different sparse unions
/// still produce the same identity when their complete memory state agrees.
pub fn snapshotIdentity(
    snapshot: memory_state.Snapshot,
    side: SnapshotSide,
) types.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv/segment-boundary-memory/v1\x00");
    inline for (@typeInfo(memory_state.MemoryLayout).@"struct".fields) |field| {
        updateInt(&hash, u32, @field(snapshot.layout, field.name));
    }
    var nonzero_words: u64 = 0;
    for (snapshot.words) |word| {
        const value = switch (side) {
            .entry => word.initial_word,
            .exit => word.final_word,
        };
        nonzero_words += @intFromBool(value != 0);
    }
    updateInt(&hash, u64, nonzero_words);
    for (snapshot.words) |word| {
        const value = switch (side) {
            .entry => word.initial_word,
            .exit => word.final_word,
        };
        if (value == 0) continue;
        updateInt(&hash, u32, word.addr);
        updateInt(&hash, u32, value);
    }
    return hash.finalResult();
}

fn validateExternalTape(
    program: replay.ProgramSource,
    records: anytype,
    rows: anytype,
    expected_opcode: custom0.Opcode,
) !void {
    if (records.len != rows.len) return error.ExternalTapeLengthMismatch;
    for (records, rows, 0..) |record, row, index| {
        if (record.execution_clock != row.execution_clock or
            record.pc != row.pc or
            row.call_index != @as(u32, @intCast(index)))
        {
            return error.ExternalTapeMismatch;
        }
        const word = program.fetch(row.pc) catch
            return error.ProgramWordUnavailable;
        if (word != row.inst_word) return error.ExternalInstructionMismatch;
        const decoded = custom0.decode(
            execution_profile.ExecutionProfile.rv32im_zkvm_ethereum_v1,
            word,
        ) catch return error.ExternalInstructionMismatch;
        if (decoded.opcode != expected_opcode)
            return error.ExternalInstructionMismatch;
    }
}

fn buildBoundary(
    allocator: std.mem.Allocator,
    segment: *const result_mod.EthereumSegmentResult,
) ![]replay.BoundaryWord {
    const base = &segment.base;
    var touched = std.AutoHashMap(u32, void).init(allocator);
    defer touched.deinit();
    for (base.execution_trace.rows.items) |row| {
        if (!row.is_load and !row.is_store) continue;
        try touched.put(row.mem_addr & ~@as(u32, 3), {});
    }
    for (segment.keccakf_calls.records()) |record| {
        for (0..record.input.len) |index|
            try touched.put(record.state_ptr + @as(u32, @intCast(index * 4)), {});
    }
    for (segment.signer_recovery_calls.records()) |record| {
        for (0..recovery_abi.input_word_count) |index|
            try touched.put(recovery_abi.inputWordAddress(record.io_ptr, index), {});
        for (0..recovery_abi.output_word_count) |index|
            try touched.put(recovery_abi.outputWordAddress(record.io_ptr, index), {});
    }

    const words = try allocator.alloc(replay.BoundaryWord, touched.count());
    errdefer allocator.free(words);
    var iterator = touched.keyIterator();
    var at: usize = 0;
    while (iterator.next()) |address| {
        const snapshot = findSnapshotWord(base.rw_memory.words, address.*) orelse
            return error.MissingBoundaryWord;
        words[at] = .{
            .address = address.*,
            .entry = snapshot.initial_word,
            .exit = snapshot.final_word,
        };
        at += 1;
    }
    std.debug.assert(at == words.len);
    std.mem.sort(
        replay.BoundaryWord,
        words,
        {},
        boundaryLessThan,
    );
    _ = try replay.SliceBoundary.init(words);
    return words;
}

fn findSnapshotWord(
    words: []const @import("../memory_state.zig").WordState,
    address: u32,
) ?@import("../memory_state.zig").WordState {
    var low: usize = 0;
    var high = words.len;
    while (low < high) {
        const mid = low + (high - low) / 2;
        const candidate = words[mid];
        if (candidate.addr < address) {
            low = mid + 1;
        } else if (candidate.addr > address) {
            high = mid;
        } else {
            return candidate;
        }
    }
    return null;
}

fn completionFromSegment(
    base: *const result_mod.SegmentResult,
    reason: result_mod.CompletionReason,
) types.CompletionV1 {
    return .{
        .kind = switch (reason) {
            .halt_flag => 1,
            .self_loop => 2,
            .stalled_pc => 3,
            .ecall => 4,
            .ebreak => 5,
            .host_halt => 6,
            .invalid_instruction => 7,
            .max_steps => 8,
        },
        .address = base.completion_address,
        .value = base.completion_value,
        .clock = base.completion_clock,
        .exit_code = base.exit_code,
    };
}

fn boundaryLessThan(
    _: void,
    left: replay.BoundaryWord,
    right: replay.BoundaryWord,
) bool {
    return left.address < right.address;
}

fn updateInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: T,
) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

comptime {
    _ = keccakf_v1.ExecutionRow;
    _ = recovery_v1.ExecutionRow;
}
