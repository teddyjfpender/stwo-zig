//! Chronological RV32 retirement observation and exact guest-byte recovery.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const semantics = frontend.diagnostics.revm_legacy;
const witness_codes = @import("witness_codes.zig");

const runner = frontend.runner;
const Snapshot = runner.memory_state.Snapshot;
const TraceRow = runner.trace.TraceRow;

const authority_owner = @import("authority.zig");
const digest = authority_owner.digest;
const expected_call_count = authority_owner.expected_call_count;
const expected_length_sum = authority_owner.expected_length_sum;
const expected_symbol_rows = authority_owner.expected_symbol_rows;
const function_authority = authority_owner.function_authority;
const symbol_end_exclusive = authority_owner.symbol_end_exclusive;

pub const PendingCall = struct {
    bytes_struct_pointer: ?u32 = null,
    entry_clock: u32,
    entry_segment_index: u32,
    length: ?u32 = null,
    length_clock: ?u32 = null,
};

pub const RawCall = struct {
    bytes_struct_pointer: u32,
    entry_clock: u32,
    entry_segment_index: u32,
    length: u32,
    length_clock: u32,
    observation_segment_index: u32,
    pointer_clock: u32,
    source_pointer: u32,
    witness_code_index: u32,
};

pub const Call = struct {
    analysis: semantics.Analysis,
    authority: RawCall,
    source_bytes_sha256: [32]u8,
    source_bytes_sha256_hex: [64]u8,
};

pub const Capture = struct {
    allocator: std.mem.Allocator,
    calls: std.ArrayList(Call) = .empty,
    completed_segment_rows: u64 = 0,
    current_segment_rows: usize = 0,
    inventory: witness_codes.Inventory,
    observed_codes: []bool,
    pending: ?PendingCall = null,
    raw_calls: std.ArrayList(RawCall) = .empty,
    segment_count: u32 = 0,
    symbol_rows: u64 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        inventory: witness_codes.Inventory,
    ) !Capture {
        const observed_codes = try allocator.alloc(bool, inventory.codes.len);
        @memset(observed_codes, false);
        return .{
            .allocator = allocator,
            .inventory = inventory,
            .observed_codes = observed_codes,
        };
    }

    pub fn deinit(self: *Capture) void {
        for (self.calls.items) |*call| call.analysis.deinit(self.allocator);
        self.calls.deinit(self.allocator);
        self.allocator.free(self.observed_codes);
        self.raw_calls.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn observer(self: *Capture) runner.RetirementObserverV1 {
        return .{
            .context = self,
            .begin_segment_fn = beginSegmentOpaque,
            .core_row_fn = observeRowOpaque,
        };
    }

    pub fn beginSegmentOpaque(context: *anyopaque, segment_index: u32) !void {
        const self: *Capture = @ptrCast(@alignCast(context));
        if (segment_index != self.segment_count or self.raw_calls.items.len != 0)
            return error.ObserverSegmentOrderMismatch;
        self.completed_segment_rows = std.math.add(
            u64,
            self.completed_segment_rows,
            self.current_segment_rows,
        ) catch return error.ObserverCountOverflow;
        self.current_segment_rows = 0;
        self.segment_count += 1;
    }

    pub fn observeRowOpaque(context: *anyopaque, row: TraceRow) !void {
        const self: *Capture = @ptrCast(@alignCast(context));
        const segment_index = self.segment_count - 1;
        if (row.pc >= function_authority.entry_pc and row.pc < symbol_end_exclusive) {
            self.symbol_rows = std.math.add(u64, self.symbol_rows, 1) catch
                return error.ObserverCountOverflow;
        }
        if (row.pc == function_authority.entry_pc) {
            if (row.inst_word != function_authority.entry_instruction_word)
                return error.EntryInstructionMismatch;
            if (self.pending != null) return error.NestedObservedFunctionEntry;
            self.pending = .{
                .entry_clock = row.clk,
                .entry_segment_index = segment_index,
            };
        }
        if (row.pc == function_authority.length_pc) {
            if (row.inst_word != function_authority.length_instruction_word or
                !row.is_load or row.is_store or
                row.rd != function_authority.length_rd or
                row.rs1 != function_authority.length_rs1 or
                row.imm != function_authority.length_imm or
                row.mem_addr != row.rs1_val +% @as(u32, @intCast(function_authority.length_imm)) or
                row.mem_val != row.rd_val)
            {
                return error.LengthInstructionMismatch;
            }
            const pending = &(self.pending orelse return error.LengthWithoutEntry);
            if (pending.length != null) return error.DuplicateLengthObservation;
            pending.bytes_struct_pointer = row.rs1_val;
            pending.length = row.rd_val;
            pending.length_clock = row.clk;
        }
        if (row.pc == function_authority.source_pointer_pc) {
            if (row.inst_word != function_authority.source_pointer_instruction_word or
                !row.is_load or row.is_store or
                row.rd != function_authority.source_pointer_rd or
                row.rs1 != function_authority.source_pointer_rs1 or
                row.imm != function_authority.source_pointer_imm or
                row.mem_addr != row.rs1_val +% @as(u32, @intCast(function_authority.source_pointer_imm)) or
                row.mem_val != row.rd_val)
            {
                return error.SourcePointerInstructionMismatch;
            }
            const pending = self.pending orelse return error.PointerWithoutEntry;
            if (pending.length == null or pending.length_clock == null or
                pending.bytes_struct_pointer == null or
                pending.bytes_struct_pointer.? != row.rs1_val)
            {
                return error.BytesAuthorityMismatch;
            }
            try validateGuestRange(row.rd_val, pending.length.?);
            try self.raw_calls.append(self.allocator, .{
                .bytes_struct_pointer = row.rs1_val,
                .entry_clock = pending.entry_clock,
                .entry_segment_index = pending.entry_segment_index,
                .length = pending.length.?,
                .length_clock = pending.length_clock.?,
                .observation_segment_index = segment_index,
                .pointer_clock = row.clk,
                .source_pointer = row.rd_val,
                .witness_code_index = undefined,
            });
            self.pending = null;
        }
        if (row.is_store) try self.rejectSourceMutation(row);
        self.current_segment_rows = std.math.add(
            usize,
            self.current_segment_rows,
            1,
        ) catch return error.ObserverCountOverflow;
    }

    pub fn rejectSourceMutation(self: *const Capture, row: TraceRow) !void {
        const width = runner.decode.memoryWidthBytes(row.opcode) orelse
            return error.InvalidStoreWidth;
        const store_start: u64 = row.mem_addr;
        const store_end = store_start + @as(u64, width);
        for (self.raw_calls.items) |call| {
            const source_start: u64 = call.source_pointer;
            const source_end = source_start + call.length;
            if (store_start < source_end and source_start < store_end)
                return error.SourceMutatedAfterAuthentication;
        }
    }

    pub fn finishSegment(
        self: *Capture,
        snapshot: Snapshot,
        segment_index: u32,
    ) !void {
        for (self.raw_calls.items) |raw| {
            if (raw.observation_segment_index != segment_index)
                return error.ObserverSegmentOrderMismatch;
            const bytecode = try readGuestBytes(
                self.allocator,
                snapshot,
                raw.source_pointer,
                raw.length,
            );
            defer self.allocator.free(bytecode);
            const code_index = try self.inventory.findLegacyExact(bytecode);
            const observed_index: usize = @intCast(code_index);
            if (self.observed_codes[observed_index])
                return error.DuplicateWitnessCodeObservation;
            self.observed_codes[observed_index] = true;
            var analysis = try semantics.analyze(self.allocator, bytecode);
            errdefer analysis.deinit(self.allocator);
            const source_digest = digest(bytecode);
            try self.calls.append(self.allocator, .{
                .analysis = analysis,
                .authority = authority: {
                    var authority = raw;
                    authority.witness_code_index = code_index;
                    break :authority authority;
                },
                .source_bytes_sha256 = source_digest,
                .source_bytes_sha256_hex = std.fmt.bytesToHex(source_digest, .lower),
            });
        }
        self.raw_calls.clearRetainingCapacity();
    }

    pub fn totalRows(self: *const Capture) !u64 {
        return std.math.add(
            u64,
            self.completed_segment_rows,
            self.current_segment_rows,
        );
    }

    pub fn validate(self: *const Capture, expected_rows: u64, segments: usize) !void {
        if (self.segment_count != segments or try self.totalRows() != expected_rows or
            self.pending != null or self.raw_calls.items.len != 0 or
            self.calls.items.len != expected_call_count or
            self.symbol_rows != expected_symbol_rows)
        {
            return error.ObserverExecutionMismatch;
        }
        var length_sum: u64 = 0;
        for (self.calls.items) |call| {
            length_sum = std.math.add(u64, length_sum, call.authority.length) catch
                return error.ObserverCountOverflow;
        }
        for (self.inventory.codes, self.observed_codes) |code, observed| {
            if (observed != (code.classification == .legacy))
                return error.WitnessCodeObservationMismatch;
        }
        if (length_sum != expected_length_sum)
            return error.ObserverExecutionMismatch;
    }
};

pub fn readGuestBytes(
    allocator: std.mem.Allocator,
    snapshot: Snapshot,
    pointer: u32,
    length: u32,
) ![]u8 {
    try validateGuestRange(pointer, length);
    const result = try allocator.alloc(u8, length);
    errdefer allocator.free(result);
    if (length == 0) return result;
    const last_address: u32 = @intCast(@as(u64, pointer) + length - 1);
    if (!snapshot.layout.isRwAddr(pointer) or !snapshot.layout.isRwAddr(last_address))
        return error.SourceOutsideRwMemory;
    var aligned = pointer & ~@as(u32, 3);
    const final_aligned = last_address & ~@as(u32, 3);
    var word_index = findWordIndex(snapshot.words, aligned) orelse
        return error.MissingSourceWord;
    var output_index: usize = 0;
    while (true) {
        if (word_index >= snapshot.words.len or snapshot.words[word_index].addr != aligned)
            return error.MissingSourceWord;
        const word = snapshot.words[word_index].final_word;
        const low: u32 = if (aligned < pointer) pointer - aligned else 0;
        const high: u32 = if (aligned == final_aligned)
            last_address - aligned + 1
        else
            4;
        var byte_index = low;
        while (byte_index < high) : (byte_index += 1) {
            result[output_index] = @truncate(word >> @intCast(byte_index * 8));
            output_index += 1;
        }
        if (aligned == final_aligned) break;
        aligned += 4;
        word_index += 1;
    }
    if (output_index != result.len) return error.SourceLengthMismatch;
    return result;
}

pub fn findWordIndex(words: []const runner.memory_state.WordState, address: u32) ?usize {
    var low: usize = 0;
    var high = words.len;
    while (low < high) {
        const mid = low + (high - low) / 2;
        const candidate = words[mid].addr;
        if (candidate < address) low = mid + 1 else if (candidate > address) high = mid else return mid;
    }
    return null;
}

pub fn validateGuestRange(pointer: u32, length: u32) !void {
    const end = @as(u64, pointer) + length;
    if (end > (@as(u64, std.math.maxInt(u32)) + 1))
        return error.SourceRangeOverflow;
}
