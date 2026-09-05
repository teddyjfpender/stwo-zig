//! Incremental compact Ethereum capture from the typed retirement stream.
//!
//! This observer records only the semantic data needed by STWEMT01 while an
//! existing leaf-local session retires instructions. It removes the three
//! post-execution full-trace scans formerly needed to validate/count rows,
//! copy ordinary old words, and discover touched addresses. Full trace and
//! state-chain removal is a later typed-retirement storage specialization;
//! this additive seam first establishes byte-for-byte compact parity.

const std = @import("std");
const custom0 = @import("../../isa/custom0.zig");
const execution_profile = @import("../../isa/execution_profile.zig");
const recovery_abi = @import("../../isa/ethereum_signer_recovery.zig");
const decode = @import("../decode.zig");
const result_mod = @import("../result.zig");
const trace_mod = @import("../trace.zig");
const replay = @import("replay.zig");
const types = @import("ethereum_types.zig");
const compatibility = @import("ethereum_capture.zig");

pub const SegmentObservationV1 = struct {
    allocator: std.mem.Allocator,
    segment_index: ?u32 = null,
    core_row_count: u32 = 0,
    ordinary_memory_read_words: std.ArrayList(u32) = .empty,
    touched_addresses: std.AutoHashMap(u32, void),

    pub fn init(allocator: std.mem.Allocator) SegmentObservationV1 {
        return .{
            .allocator = allocator,
            .touched_addresses = std.AutoHashMap(u32, void).init(allocator),
        };
    }

    pub fn deinit(self: *SegmentObservationV1) void {
        self.touched_addresses.deinit();
        self.ordinary_memory_read_words.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn begin(self: *SegmentObservationV1, segment_index: u32) !void {
        if (self.segment_index != null) return error.SemanticCaptureNotConsumed;
        self.segment_index = segment_index;
        self.core_row_count = 0;
        self.ordinary_memory_read_words.clearRetainingCapacity();
        self.touched_addresses.clearRetainingCapacity();
    }

    /// Called only after one typed core retirement has committed its row and
    /// state-chain transitions. A failure poisons the diagnostic session and
    /// cannot publish a partial leaf.
    pub fn observeCoreRow(
        self: *SegmentObservationV1,
        row: trace_mod.TraceRow,
    ) !void {
        if (self.segment_index == null) return error.SemanticCaptureNotStarted;
        const family = trace_mod.proofOpcodeFamily(row.opcode) catch
            return error.UnsupportedTraceOpcode;
        trace_mod.validateFamilyRow(row, family) catch
            return error.InvalidTraceRow;
        const is_memory = row.is_load or row.is_store;
        if (is_memory != (decode.isLoad(row.opcode) or decode.isStore(row.opcode)))
            return error.InvalidTraceRow;
        self.core_row_count = std.math.add(
            u32,
            self.core_row_count,
            1,
        ) catch return error.LeafCycleLimitExceeded;
        if (!is_memory) return;
        try self.ordinary_memory_read_words.append(
            self.allocator,
            row.mem_prev_word,
        );
        try self.touched_addresses.put(row.mem_addr & ~@as(u32, 3), {});
    }

    pub fn capture(
        self: *SegmentObservationV1,
        allocator: std.mem.Allocator,
        request: compatibility.RequestV1,
    ) !compatibility.ResultV1 {
        const segment_index = self.segment_index orelse
            return error.SemanticCaptureNotStarted;
        const segment = request.segment;
        const base = &segment.base;
        if (base.segment_index != segment_index or
            base.execution_trace.rows.items.len != self.core_row_count or
            base.clock_frame != .leaf_local)
        {
            return error.SemanticCaptureSegmentMismatch;
        }
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
        const reconstructed_cycles = std.math.add(
            usize,
            @as(usize, self.core_row_count),
            external_count,
        ) catch return error.InvalidExternalCount;
        if (reconstructed_cycles != cycle_count) {
            return error.InvalidExternalCount;
        }

        const ordinary_words = try allocator.dupe(
            u32,
            self.ordinary_memory_read_words.items,
        );
        errdefer allocator.free(ordinary_words);
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
        const boundary_words = try self.buildBoundary(allocator, segment);
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
                .entry_memory = compatibility.snapshotIdentity(
                    base.rw_memory,
                    .entry,
                ),
                .exit_memory = compatibility.snapshotIdentity(
                    base.rw_memory,
                    .exit,
                ),
            },
            boundary.entry_identity,
            boundary.exit_identity,
            base.segment_index,
            base.global_first_cycle,
            cycle_count,
            self.core_row_count,
            base.entry_cpu,
            base.exit_cpu,
            completion,
            ordinary_words,
            keccak_records,
            recovery_records,
        );
        self.segment_index = null;
        return .{
            .leaf = leaf,
            .boundary_words = boundary_words,
            .allocator = allocator,
        };
    }

    fn buildBoundary(
        self: *SegmentObservationV1,
        allocator: std.mem.Allocator,
        segment: *const result_mod.EthereumSegmentResult,
    ) ![]replay.BoundaryWord {
        for (segment.keccakf_calls.records()) |record| {
            for (0..record.input.len) |index| try self.touched_addresses.put(
                record.state_ptr + @as(u32, @intCast(index * 4)),
                {},
            );
        }
        for (segment.signer_recovery_calls.records()) |record| {
            for (0..recovery_abi.input_word_count) |index|
                try self.touched_addresses.put(
                    recovery_abi.inputWordAddress(record.io_ptr, index),
                    {},
                );
            for (0..recovery_abi.output_word_count) |index|
                try self.touched_addresses.put(
                    recovery_abi.outputWordAddress(record.io_ptr, index),
                    {},
                );
        }
        const words = try allocator.alloc(
            replay.BoundaryWord,
            self.touched_addresses.count(),
        );
        errdefer allocator.free(words);
        var iterator = self.touched_addresses.keyIterator();
        var at: usize = 0;
        while (iterator.next()) |address| : (at += 1) {
            const snapshot = findSnapshotWord(
                segment.base.rw_memory.words,
                address.*,
            ) orelse return error.MissingBoundaryWord;
            words[at] = .{
                .address = address.*,
                .entry = snapshot.initial_word,
                .exit = snapshot.final_word,
            };
        }
        if (at != words.len) return error.InvalidBoundaryInventory;
        std.mem.sort(replay.BoundaryWord, words, {}, boundaryLessThan);
        _ = try replay.SliceBoundary.init(words);
        return words;
    }
};

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
        } else return candidate;
    }
    return null;
}

fn boundaryLessThan(
    _: void,
    left: replay.BoundaryWord,
    right: replay.BoundaryWord,
) bool {
    return left.address < right.address;
}
