//! Exact diagnostic observer for Revm 42 `analyze_legacy` guest semantics.
//!
//! The tool reexecutes a sealed V3 Ethereum-profile journal prefix, captures
//! the exact RV32 loads that authenticate the input `Bytes` pointer and length,
//! reopens those bytes from the segment memory snapshot, and independently
//! simulates the pinned Revm scan. It emits no proof or production claim.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const semantics = @import("semantics.zig");
const witness_codes = @import("witness_codes.zig");

const runner = frontend.runner;
const Snapshot = runner.memory_state.Snapshot;
const TraceRow = runner.trace.TraceRow;

const schema = "stwo.riscv.analyze-legacy-semantic-observation.v1";
const status = "captured-diagnostic-only";
const claim_boundary = "exact-revm42-execution-observation-not-air-or-proof";
const profile_name = "rv32im-zkvm-ethereum-v1";
const clock_frame = "leaf_local";
const revm_bytecode_version = "42.0.0";
const revm_git_revision = "45f05bd88fd09e32ea43cf5e94190759ea6ace7c";
const revm_source_sha256 = "cf26e05a027549b772a04ff4f2ad7bcd03eaaa5dbd42d53f03830050504671d4";
const cargo_lock_sha256 = "17b841e66b7017edd621877bcbbd76ad50242d648e6dd49667d6e05dc3c46ce9";
const expected_call_count: u32 = 115;
const expected_length_sum: u64 = 1_328_485;
const expected_symbol_rows: u64 = 6_846_967;
const symbol_end_exclusive: u32 = 0x000bd9e8;
const maximum_input_bytes: usize = 64 << 20;
const maximum_elf_bytes: usize = 64 << 20;
const maximum_executable_bytes: usize = 64 << 20;
const maximum_journal_bytes: usize = 64 << 20;
const maximum_source_bytes: usize = 4 << 20;
const maximum_evidence_bytes: usize = 16 << 20;
const maximum_sample_segments: u32 = 64;

const function_authority = FunctionAuthority{
    .entry_instruction_word = 0xfc010113,
    .entry_pc = 0x000bd490,
    .length_imm = 8,
    .length_instruction_word = 0x0085a903,
    .length_pc = 0x000bd4c4,
    .length_rd = 18,
    .length_rs1 = 11,
    .revm_bytecode_version = revm_bytecode_version,
    .revm_git_revision = revm_git_revision,
    .source_pointer_imm = 4,
    .source_pointer_instruction_word = 0x0044aa83,
    .source_pointer_pc = 0x000bd5c4,
    .source_pointer_rd = 21,
    .source_pointer_rs1 = 9,
    .symbol = "revm_bytecode::legacy::analysis::analyze_legacy",
    .symbol_end_exclusive = symbol_end_exclusive,
    .symbol_rows = expected_symbol_rows,
};

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    const options = try Options.parse(args[1..]);

    var executable = try InputFile.open(
        allocator,
        args[0],
        maximum_executable_bytes,
    );
    defer executable.deinit(allocator);
    var elf = try InputFile.open(allocator, options.elf, maximum_elf_bytes);
    defer elf.deinit(allocator);
    var input = try InputFile.open(allocator, options.input, maximum_input_bytes);
    defer input.deinit(allocator);
    var journal = try InputFile.open(
        allocator,
        options.execution_journal,
        maximum_journal_bytes,
    );
    defer journal.deinit(allocator);
    var observer_source = try InputFile.open(
        allocator,
        options.observer_source,
        maximum_source_bytes,
    );
    defer observer_source.deinit(allocator);
    var observer_semantics_source = try InputFile.open(
        allocator,
        options.observer_semantics_source,
        maximum_source_bytes,
    );
    defer observer_semantics_source.deinit(allocator);
    var observer_witness_source = try InputFile.open(
        allocator,
        options.observer_witness_source,
        maximum_source_bytes,
    );
    defer observer_witness_source.deinit(allocator);
    var revm_source = try InputFile.open(
        allocator,
        options.revm_source,
        maximum_source_bytes,
    );
    defer revm_source.deinit(allocator);
    var cargo_lock = try InputFile.open(
        allocator,
        options.cargo_lock,
        maximum_source_bytes,
    );
    defer cargo_lock.deinit(allocator);
    var function_value_evidence = try InputFile.open(
        allocator,
        options.function_value_evidence,
        maximum_evidence_bytes,
    );
    defer function_value_evidence.deinit(allocator);
    var nm_map = try InputFile.open(
        allocator,
        options.nm_map,
        maximum_evidence_bytes,
    );
    defer nm_map.deinit(allocator);
    var pc_observation = try InputFile.open(
        allocator,
        options.pc_observation,
        maximum_evidence_bytes,
    );
    defer pc_observation.deinit(allocator);
    if (!std.mem.eql(u8, &revm_source.sha256_hex, revm_source_sha256) or
        !std.mem.eql(u8, &cargo_lock.sha256_hex, cargo_lock_sha256))
    {
        return error.RevmAuthorityMismatch;
    }
    try validateNmAuthority(nm_map.bytes);

    var inventory = try witness_codes.parse(allocator, input.bytes);
    defer inventory.deinit(allocator);
    if (inventory.codes.len != 120 or inventory.total_bytes != 1_328_577 or
        inventory.legacy_count != expected_call_count or
        inventory.legacy_bytes != expected_length_sum or
        inventory.eip7702_delegation_count != 4 or inventory.empty_count != 1)
    {
        return error.WitnessCodeInventoryMismatch;
    }
    inline for ([_]usize{ 4, 30, 70, 110 }) |index| {
        if (inventory.codes[index].classification != .eip7702_delegation or
            inventory.codes[index].bytes.len != 23)
        {
            return error.WitnessCodeInventoryMismatch;
        }
    }
    if (inventory.codes[119].classification != .empty)
        return error.WitnessCodeInventoryMismatch;

    var expected = try JournalAuthority.parse(
        allocator,
        journal.bytes,
        elf.sha256,
        input.sha256,
        options.segment_count,
    );
    defer expected.deinit(allocator);

    var capture = try Capture.init(allocator, inventory);
    defer capture.deinit();
    var session = try runner.EthereumExecutionSession.init(allocator, elf.bytes, .{
        .input = input.bytes,
        .stop_on_halt_flag = true,
        .strict_completion = true,
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
        .retirement_observer = capture.observer(),
    });
    defer session.deinit();

    var continuation: ?runner.result_mod.ContinuationToken = null;
    for (expected.segments, 0..) |wanted, index| {
        var segment = if (index == 0)
            try session.startSegment(expected.segment_step_budget)
        else
            try session.resumeSegment(
                continuation orelse return error.MissingContinuation,
                expected.segment_step_budget,
            );
        defer segment.deinit();
        if (segment.base.segment_index != wanted.segment_index or
            segment.base.global_first_cycle != wanted.global_first_cycle or
            segment.base.cycle_count != wanted.cycle_count or
            segment.base.execution_trace.rows.items.len != wanted.core_trace_rows or
            capture.current_segment_rows != wanted.core_trace_rows)
        {
            return error.JournalExecutionMismatch;
        }
        try capture.finishSegment(segment.base.rw_memory, wanted.segment_index);
        continuation = segment.base.continuation;
        if (index + 1 < expected.segments.len and continuation == null)
            return error.ExecutionCompletedBeforeSample;
    }

    try capture.validate(expected.retired_instructions, expected.segments.len);
    const encoded = try encodeObservation(
        allocator,
        &capture,
        expected,
        executable,
        elf,
        input,
        journal,
        observer_source,
        observer_semantics_source,
        observer_witness_source,
        revm_source,
        cargo_lock,
        function_value_evidence,
        nm_map,
        pc_observation,
        inventory,
    );
    defer allocator.free(encoded);
    try std.fs.File.stdout().writeAll(encoded);
}

const Options = struct {
    cargo_lock: []const u8,
    elf: []const u8,
    execution_journal: []const u8,
    function_value_evidence: []const u8,
    input: []const u8,
    nm_map: []const u8,
    observer_semantics_source: []const u8,
    observer_source: []const u8,
    observer_witness_source: []const u8,
    pc_observation: []const u8,
    revm_source: []const u8,
    segment_count: u32,

    fn parse(arguments: []const []const u8) !Options {
        if (arguments.len != 24) return error.InvalidArguments;
        var cargo_lock: ?[]const u8 = null;
        var elf: ?[]const u8 = null;
        var journal: ?[]const u8 = null;
        var function_value_evidence: ?[]const u8 = null;
        var input: ?[]const u8 = null;
        var nm_map: ?[]const u8 = null;
        var observer_semantics_source: ?[]const u8 = null;
        var observer_source: ?[]const u8 = null;
        var observer_witness_source: ?[]const u8 = null;
        var pc_observation: ?[]const u8 = null;
        var revm_source: ?[]const u8 = null;
        var segment_count: ?u32 = null;
        var cursor: usize = 0;
        while (cursor < arguments.len) : (cursor += 2) {
            const name = arguments[cursor];
            const value = arguments[cursor + 1];
            if (std.mem.eql(u8, name, "--cargo-lock")) {
                if (cargo_lock != null) return error.DuplicateArgument;
                cargo_lock = value;
            } else if (std.mem.eql(u8, name, "--elf")) {
                if (elf != null) return error.DuplicateArgument;
                elf = value;
            } else if (std.mem.eql(u8, name, "--execution-journal")) {
                if (journal != null) return error.DuplicateArgument;
                journal = value;
            } else if (std.mem.eql(u8, name, "--function-value-evidence")) {
                if (function_value_evidence != null) return error.DuplicateArgument;
                function_value_evidence = value;
            } else if (std.mem.eql(u8, name, "--input")) {
                if (input != null) return error.DuplicateArgument;
                input = value;
            } else if (std.mem.eql(u8, name, "--nm-map")) {
                if (nm_map != null) return error.DuplicateArgument;
                nm_map = value;
            } else if (std.mem.eql(u8, name, "--observer-semantics-source")) {
                if (observer_semantics_source != null) return error.DuplicateArgument;
                observer_semantics_source = value;
            } else if (std.mem.eql(u8, name, "--observer-source")) {
                if (observer_source != null) return error.DuplicateArgument;
                observer_source = value;
            } else if (std.mem.eql(u8, name, "--observer-witness-source")) {
                if (observer_witness_source != null) return error.DuplicateArgument;
                observer_witness_source = value;
            } else if (std.mem.eql(u8, name, "--pc-observation")) {
                if (pc_observation != null) return error.DuplicateArgument;
                pc_observation = value;
            } else if (std.mem.eql(u8, name, "--revm-source")) {
                if (revm_source != null) return error.DuplicateArgument;
                revm_source = value;
            } else if (std.mem.eql(u8, name, "--segment-count")) {
                if (segment_count != null) return error.DuplicateArgument;
                segment_count = try std.fmt.parseInt(u32, value, 10);
            } else return error.InvalidArguments;
        }
        const count = segment_count orelse return error.InvalidArguments;
        if (count == 0 or count > maximum_sample_segments)
            return error.InvalidSegmentCount;
        return .{
            .cargo_lock = cargo_lock orelse return error.InvalidArguments,
            .elf = elf orelse return error.InvalidArguments,
            .execution_journal = journal orelse return error.InvalidArguments,
            .function_value_evidence = function_value_evidence orelse
                return error.InvalidArguments,
            .input = input orelse return error.InvalidArguments,
            .nm_map = nm_map orelse return error.InvalidArguments,
            .observer_semantics_source = observer_semantics_source orelse
                return error.InvalidArguments,
            .observer_source = observer_source orelse return error.InvalidArguments,
            .observer_witness_source = observer_witness_source orelse
                return error.InvalidArguments,
            .pc_observation = pc_observation orelse return error.InvalidArguments,
            .revm_source = revm_source orelse return error.InvalidArguments,
            .segment_count = count,
        };
    }
};

const InputFile = struct {
    bytes: []u8,
    path: []u8,
    sha256: [32]u8,
    sha256_hex: [64]u8,

    fn open(
        allocator: std.mem.Allocator,
        path: []const u8,
        maximum: usize,
    ) !InputFile {
        const canonical = try std.fs.realpathAlloc(allocator, path);
        errdefer allocator.free(canonical);
        const file = try std.fs.openFileAbsolute(canonical, .{});
        defer file.close();
        const metadata = try file.stat();
        if (metadata.kind != .file or metadata.size > maximum)
            return error.InvalidInputFile;
        const bytes = try file.readToEndAlloc(allocator, maximum);
        errdefer allocator.free(bytes);
        const sha256 = digest(bytes);
        return .{
            .bytes = bytes,
            .path = canonical,
            .sha256 = sha256,
            .sha256_hex = std.fmt.bytesToHex(sha256, .lower),
        };
    }

    fn deinit(self: *InputFile, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        allocator.free(self.path);
        self.* = undefined;
    }

    fn identity(self: *const InputFile) Identity {
        return .{
            .bytes = self.bytes.len,
            .path = self.path,
            .sha256 = &self.sha256_hex,
        };
    }
};

const ExpectedSegment = struct {
    core_trace_rows: usize,
    cycle_count: u32,
    global_first_cycle: u64,
    segment_index: u32,
};

const JournalAuthority = struct {
    first_global_cycle: u64,
    retired_instructions: u64,
    sampled_cycles: u64,
    segment_step_budget: usize,
    segments: []ExpectedSegment,

    fn parse(
        allocator: std.mem.Allocator,
        bytes: []const u8,
        elf_sha256: [32]u8,
        input_sha256: [32]u8,
        segment_count: u32,
    ) !JournalAuthority {
        var lines = std.mem.splitScalar(u8, bytes, '\n');
        const header_line = lines.next() orelse return error.InvalidJournal;
        var header = try std.json.parseFromSlice(std.json.Value, allocator, header_line, .{});
        defer header.deinit();
        const payload = try objectField(header.value, "payload");
        if (!std.mem.eql(u8, try stringField(payload, "schema"), "stwo.riscv.segmented-execution-header.v3") or
            !std.mem.eql(u8, try stringField(payload, "profile"), profile_name) or
            !std.mem.eql(u8, try stringField(payload, "clock_frame"), clock_frame) or
            !(try boolField(payload, "strict_completion")) or
            !std.mem.eql(u8, try stringField(payload, "trace_retention"), "segment-owned"))
        {
            return error.InvalidJournal;
        }
        const elf_hex = std.fmt.bytesToHex(elf_sha256, .lower);
        const input_hex = std.fmt.bytesToHex(input_sha256, .lower);
        if (!std.mem.eql(u8, try stringField(payload, "elf_sha256"), &elf_hex) or
            !std.mem.eql(u8, try stringField(payload, "input_sha256"), &input_hex))
        {
            return error.JournalInputMismatch;
        }
        const budget = try unsignedField(payload, "segment_step_budget");
        if (budget == 0 or budget > std.math.maxInt(u32))
            return error.InvalidJournal;
        const segments = try allocator.alloc(ExpectedSegment, segment_count);
        errdefer allocator.free(segments);
        var sampled_cycles: u64 = 0;
        var retired: u64 = 0;
        for (segments, 0..) |*out, index| {
            const line = lines.next() orelse return error.InvalidJournal;
            var parsed = try std.json.parseFromSlice(std.json.Value, allocator, line, .{});
            defer parsed.deinit();
            const segment = try objectField(parsed.value, "payload");
            if (!std.mem.eql(u8, try stringField(segment, "schema"), "stwo.riscv.segmented-execution-segment.v3"))
                return error.InvalidJournal;
            const segment_index = try unsignedField(segment, "segment_index");
            const first_cycle = try unsignedField(segment, "global_first_cycle");
            const cycles = try unsignedField(segment, "cycle_count");
            const core_rows = try unsignedField(segment, "core_trace_rows");
            if (segment_index != index or cycles == 0 or core_rows == 0 or
                segment_index > std.math.maxInt(u32) or cycles > std.math.maxInt(u32) or
                core_rows > std.math.maxInt(usize))
            {
                return error.InvalidJournal;
            }
            out.* = .{
                .core_trace_rows = @intCast(core_rows),
                .cycle_count = @intCast(cycles),
                .global_first_cycle = first_cycle,
                .segment_index = @intCast(segment_index),
            };
            sampled_cycles = std.math.add(u64, sampled_cycles, cycles) catch
                return error.InvalidJournal;
            retired = std.math.add(u64, retired, core_rows) catch
                return error.InvalidJournal;
        }
        const summary_line = lines.next() orelse return error.InvalidJournal;
        var summary_parsed = try std.json.parseFromSlice(
            std.json.Value,
            allocator,
            summary_line,
            .{},
        );
        defer summary_parsed.deinit();
        const summary = try objectField(summary_parsed.value, "payload");
        if (!std.mem.eql(u8, try stringField(summary, "schema"), "stwo.riscv.segmented-execution-summary.v3") or
            !std.mem.eql(u8, try stringField(summary, "clock_frame"), clock_frame) or
            !(try boolField(summary, "completed")) or
            try unsignedField(summary, "segment_count") != segment_count or
            try unsignedField(summary, "total_cycles") != sampled_cycles or
            try unsignedField(summary, "total_core_trace_rows") != retired)
        {
            return error.InvalidJournal;
        }
        while (lines.next()) |trailing| {
            if (trailing.len != 0) return error.InvalidJournal;
        }
        return .{
            .first_global_cycle = segments[0].global_first_cycle,
            .retired_instructions = retired,
            .sampled_cycles = sampled_cycles,
            .segment_step_budget = @intCast(budget),
            .segments = segments,
        };
    }

    fn deinit(self: *JournalAuthority, allocator: std.mem.Allocator) void {
        allocator.free(self.segments);
        self.* = undefined;
    }
};

const PendingCall = struct {
    bytes_struct_pointer: ?u32 = null,
    entry_clock: u32,
    entry_segment_index: u32,
    length: ?u32 = null,
    length_clock: ?u32 = null,
};

const RawCall = struct {
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

const Call = struct {
    analysis: semantics.Analysis,
    authority: RawCall,
    source_bytes_sha256: [32]u8,
    source_bytes_sha256_hex: [64]u8,
};

const Capture = struct {
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

    fn init(
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

    fn deinit(self: *Capture) void {
        for (self.calls.items) |*call| call.analysis.deinit(self.allocator);
        self.calls.deinit(self.allocator);
        self.allocator.free(self.observed_codes);
        self.raw_calls.deinit(self.allocator);
        self.* = undefined;
    }

    fn observer(self: *Capture) runner.RetirementObserverV1 {
        return .{
            .context = self,
            .begin_segment_fn = beginSegmentOpaque,
            .core_row_fn = observeRowOpaque,
        };
    }

    fn beginSegmentOpaque(context: *anyopaque, segment_index: u32) !void {
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

    fn observeRowOpaque(context: *anyopaque, row: TraceRow) !void {
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

    fn rejectSourceMutation(self: *const Capture, row: TraceRow) !void {
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

    fn finishSegment(
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

    fn totalRows(self: *const Capture) !u64 {
        return std.math.add(
            u64,
            self.completed_segment_rows,
            self.current_segment_rows,
        );
    }

    fn validate(self: *const Capture, expected_rows: u64, segments: usize) !void {
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

const FunctionAuthority = struct {
    entry_instruction_word: u32,
    entry_pc: u32,
    length_imm: i32,
    length_instruction_word: u32,
    length_pc: u32,
    length_rd: u5,
    length_rs1: u5,
    revm_bytecode_version: []const u8,
    revm_git_revision: []const u8,
    source_pointer_imm: i32,
    source_pointer_instruction_word: u32,
    source_pointer_pc: u32,
    source_pointer_rd: u5,
    source_pointer_rs1: u5,
    symbol: []const u8,
    symbol_end_exclusive: u32,
    symbol_rows: u64,
};

const Identity = struct {
    bytes: usize,
    path: []const u8,
    sha256: []const u8,
};

const CallWire = struct {
    bitmap_bytes: u32,
    bytes_struct_pointer: u32,
    call_index: u32,
    entry_clock: u32,
    entry_segment_index: u32,
    eof_immediate_padding: u32,
    jumpdest_count: u32,
    length: u32,
    length_clock: u32,
    observation_segment_index: u32,
    opcode_positions: []const u32,
    pointer_clock: u32,
    push_count: u32,
    push_overflow: u32,
    scan_iterations: u32,
    source_bytes_sha256: []const u8,
    source_pointer: u32,
    total_padding: u32,
    witness_code_index: u32,
};

const Aggregate = struct {
    bitmap_bytes_sum: u64,
    call_count: u32,
    eof_immediate_padding_sum: u64,
    jumpdest_count_sum: u64,
    length_sum: u64,
    opcode_positions_sum: u64,
    push_count_sum: u64,
    push_overflow_sum: u64,
    scan_iterations_sum: u64,
    source_bytes_chain_sha256: []const u8,
    total_padding_sum: u64,
};

const WitnessCodeWire = struct {
    analyze_legacy_observed: bool,
    classification: []const u8,
    index: u32,
    length: usize,
    sha256: []const u8,
};

const WitnessInventoryWire = struct {
    accessed_legacy_code_count: u32,
    code_count: usize,
    eip7702_delegation_code_count: u32,
    empty_code_count: u32,
    legacy_bytes: u64,
    legacy_code_count: u32,
    routing_policy: []const u8,
    total_bytes: u64,
    unobserved_fallback_code_count: u32,
};

const Promotion = struct {
    air_claim: ?bool = null,
    end_to_end_wall_ns: ?u64 = null,
    fresh_verification: ?bool = null,
    performance_claim_eligible: bool = false,
    production_promotion_eligible: bool = false,
    proof_correctness: ?bool = null,
    savings_claim: ?bool = null,
    scope: []const u8 = "exact-analyze-legacy-call-semantics-only",
};

const UnsignedWire = struct {
    aggregate: Aggregate,
    calls: []const CallWire,
    claim_boundary: []const u8,
    clock_frame: []const u8,
    elf: Identity,
    execution_journal: Identity,
    execution_profile: []const u8,
    first_global_cycle: u64,
    first_segment_index: u32,
    function_authority: FunctionAuthority,
    function_value_evidence: Identity,
    input: Identity,
    nm_map: Identity,
    observer_executable: Identity,
    observer_semantics_source: Identity,
    observer_source: Identity,
    observer_witness_source: Identity,
    pc_observation: Identity,
    production: bool,
    promotion: Promotion,
    retired_instructions: u64,
    revm_cargo_lock: Identity,
    revm_source: Identity,
    sampled_cycles: u64,
    schema: []const u8,
    segment_count: u32,
    status: []const u8,
    witness_code_inventory: WitnessInventoryWire,
    witness_codes: []const WitnessCodeWire,
};

const Wire = struct {
    aggregate: Aggregate,
    calls: []const CallWire,
    claim_boundary: []const u8,
    clock_frame: []const u8,
    content_sha256: []const u8,
    elf: Identity,
    execution_journal: Identity,
    execution_profile: []const u8,
    first_global_cycle: u64,
    first_segment_index: u32,
    function_authority: FunctionAuthority,
    function_value_evidence: Identity,
    input: Identity,
    nm_map: Identity,
    observer_executable: Identity,
    observer_semantics_source: Identity,
    observer_source: Identity,
    observer_witness_source: Identity,
    pc_observation: Identity,
    production: bool,
    promotion: Promotion,
    retired_instructions: u64,
    revm_cargo_lock: Identity,
    revm_source: Identity,
    sampled_cycles: u64,
    schema: []const u8,
    segment_count: u32,
    status: []const u8,
    witness_code_inventory: WitnessInventoryWire,
    witness_codes: []const WitnessCodeWire,
};

fn encodeObservation(
    allocator: std.mem.Allocator,
    capture: *const Capture,
    expected: JournalAuthority,
    executable: InputFile,
    elf: InputFile,
    input: InputFile,
    journal: InputFile,
    observer_source: InputFile,
    observer_semantics_source: InputFile,
    observer_witness_source: InputFile,
    revm_source: InputFile,
    cargo_lock: InputFile,
    function_value_evidence: InputFile,
    nm_map: InputFile,
    pc_observation: InputFile,
    inventory: witness_codes.Inventory,
) ![]u8 {
    const calls = try allocator.alloc(CallWire, capture.calls.items.len);
    defer allocator.free(calls);
    var aggregate = Aggregate{
        .bitmap_bytes_sum = 0,
        .call_count = @intCast(calls.len),
        .eof_immediate_padding_sum = 0,
        .jumpdest_count_sum = 0,
        .length_sum = 0,
        .opcode_positions_sum = 0,
        .push_count_sum = 0,
        .push_overflow_sum = 0,
        .scan_iterations_sum = 0,
        .source_bytes_chain_sha256 = undefined,
        .total_padding_sum = 0,
    };
    var chain = std.crypto.hash.sha2.Sha256.init(.{});
    chain.update("stwo.riscv.analyze-legacy-source-bytes-chain.v1\x00");
    for (calls, 0..) |*wire, index| {
        const call = &capture.calls.items[index];
        const scan_iterations = call.analysis.scanIterations();
        wire.* = callWire(call, index, scan_iterations);
        try addAggregate(&aggregate, call, scan_iterations);
        chain.update(&call.source_bytes_sha256);
    }
    var chain_digest: [32]u8 = undefined;
    chain.final(&chain_digest);
    const chain_hex = std.fmt.bytesToHex(chain_digest, .lower);
    aggregate.source_bytes_chain_sha256 = &chain_hex;
    const code_hexes = try allocator.alloc([64]u8, inventory.codes.len);
    defer allocator.free(code_hexes);
    const code_wires = try allocator.alloc(WitnessCodeWire, inventory.codes.len);
    defer allocator.free(code_wires);
    for (code_hexes, code_wires, 0..) |*hex, *wire, index| {
        const code = &inventory.codes[index];
        hex.* = std.fmt.bytesToHex(code.sha256, .lower);
        wire.* = witnessCodeWire(
            code,
            capture.observed_codes[index],
            index,
            hex,
        );
    }
    const inventory_wire = WitnessInventoryWire{
        .accessed_legacy_code_count = @intCast(capture.calls.items.len),
        .code_count = inventory.codes.len,
        .eip7702_delegation_code_count = inventory.eip7702_delegation_count,
        .empty_code_count = inventory.empty_count,
        .legacy_bytes = inventory.legacy_bytes,
        .legacy_code_count = inventory.legacy_count,
        .routing_policy = "legacy=>analyze_legacy;empty-or-0xef01=>Bytecode::new_raw",
        .total_bytes = inventory.total_bytes,
        .unobserved_fallback_code_count = inventory.empty_count +
            inventory.eip7702_delegation_count,
    };

    const unsigned = UnsignedWire{
        .aggregate = aggregate,
        .calls = calls,
        .claim_boundary = claim_boundary,
        .clock_frame = clock_frame,
        .elf = elf.identity(),
        .execution_journal = journal.identity(),
        .execution_profile = profile_name,
        .first_global_cycle = expected.first_global_cycle,
        .first_segment_index = 0,
        .function_authority = function_authority,
        .function_value_evidence = function_value_evidence.identity(),
        .input = input.identity(),
        .nm_map = nm_map.identity(),
        .observer_executable = executable.identity(),
        .observer_semantics_source = observer_semantics_source.identity(),
        .observer_source = observer_source.identity(),
        .observer_witness_source = observer_witness_source.identity(),
        .pc_observation = pc_observation.identity(),
        .production = false,
        .promotion = .{},
        .retired_instructions = expected.retired_instructions,
        .revm_cargo_lock = cargo_lock.identity(),
        .revm_source = revm_source.identity(),
        .sampled_cycles = expected.sampled_cycles,
        .schema = schema,
        .segment_count = @intCast(expected.segments.len),
        .status = status,
        .witness_code_inventory = inventory_wire,
        .witness_codes = code_wires,
    };
    const unsigned_json = try std.json.Stringify.valueAlloc(allocator, unsigned, .{});
    defer allocator.free(unsigned_json);
    const content_digest = digestWithNewline(unsigned_json);
    const content_hex = std.fmt.bytesToHex(content_digest, .lower);
    const sealed = Wire{
        .aggregate = unsigned.aggregate,
        .calls = unsigned.calls,
        .claim_boundary = unsigned.claim_boundary,
        .clock_frame = unsigned.clock_frame,
        .content_sha256 = &content_hex,
        .elf = unsigned.elf,
        .execution_journal = unsigned.execution_journal,
        .execution_profile = unsigned.execution_profile,
        .first_global_cycle = unsigned.first_global_cycle,
        .first_segment_index = unsigned.first_segment_index,
        .function_authority = unsigned.function_authority,
        .function_value_evidence = unsigned.function_value_evidence,
        .input = unsigned.input,
        .nm_map = unsigned.nm_map,
        .observer_executable = unsigned.observer_executable,
        .observer_semantics_source = unsigned.observer_semantics_source,
        .observer_source = unsigned.observer_source,
        .observer_witness_source = unsigned.observer_witness_source,
        .pc_observation = unsigned.pc_observation,
        .production = unsigned.production,
        .promotion = unsigned.promotion,
        .retired_instructions = unsigned.retired_instructions,
        .revm_cargo_lock = unsigned.revm_cargo_lock,
        .revm_source = unsigned.revm_source,
        .sampled_cycles = unsigned.sampled_cycles,
        .schema = unsigned.schema,
        .segment_count = unsigned.segment_count,
        .status = unsigned.status,
        .witness_code_inventory = unsigned.witness_code_inventory,
        .witness_codes = unsigned.witness_codes,
    };
    const body = try std.json.Stringify.valueAlloc(allocator, sealed, .{});
    defer allocator.free(body);
    const encoded = try allocator.alloc(u8, body.len + 1);
    @memcpy(encoded[0..body.len], body);
    encoded[body.len] = '\n';
    return encoded;
}

fn callWire(call: *const Call, index: usize, scan_iterations: u32) CallWire {
    return .{
        .bitmap_bytes = call.analysis.bitmap_bytes,
        .bytes_struct_pointer = call.authority.bytes_struct_pointer,
        .call_index = @intCast(index),
        .entry_clock = call.authority.entry_clock,
        .entry_segment_index = call.authority.entry_segment_index,
        .eof_immediate_padding = call.analysis.eof_immediate_padding,
        .jumpdest_count = call.analysis.jumpdest_count,
        .length = call.authority.length,
        .length_clock = call.authority.length_clock,
        .observation_segment_index = call.authority.observation_segment_index,
        .opcode_positions = call.analysis.opcode_positions,
        .pointer_clock = call.authority.pointer_clock,
        .push_count = call.analysis.push_count,
        .push_overflow = call.analysis.push_overflow,
        .scan_iterations = scan_iterations,
        .source_bytes_sha256 = &call.source_bytes_sha256_hex,
        .source_pointer = call.authority.source_pointer,
        .total_padding = call.analysis.total_padding,
        .witness_code_index = call.authority.witness_code_index,
    };
}

fn witnessCodeWire(
    code: *const witness_codes.Code,
    observed: bool,
    index: usize,
    sha256_hex: *const [64]u8,
) WitnessCodeWire {
    return .{
        .analyze_legacy_observed = observed,
        .classification = code.classification.wireName(),
        .index = @intCast(index),
        .length = code.bytes.len,
        .sha256 = sha256_hex,
    };
}

fn addAggregate(aggregate: *Aggregate, call: *const Call, scan_iterations: u32) !void {
    aggregate.bitmap_bytes_sum = try add64(aggregate.bitmap_bytes_sum, call.analysis.bitmap_bytes);
    aggregate.eof_immediate_padding_sum = try add64(
        aggregate.eof_immediate_padding_sum,
        call.analysis.eof_immediate_padding,
    );
    aggregate.jumpdest_count_sum = try add64(
        aggregate.jumpdest_count_sum,
        call.analysis.jumpdest_count,
    );
    aggregate.length_sum = try add64(aggregate.length_sum, call.authority.length);
    for (call.analysis.opcode_positions) |position|
        aggregate.opcode_positions_sum = try add64(aggregate.opcode_positions_sum, position);
    aggregate.push_count_sum = try add64(aggregate.push_count_sum, call.analysis.push_count);
    aggregate.push_overflow_sum = try add64(
        aggregate.push_overflow_sum,
        call.analysis.push_overflow,
    );
    aggregate.scan_iterations_sum = try add64(aggregate.scan_iterations_sum, scan_iterations);
    aggregate.total_padding_sum = try add64(
        aggregate.total_padding_sum,
        call.analysis.total_padding,
    );
}

fn add64(left: u64, right: anytype) !u64 {
    return std.math.add(u64, left, @intCast(right)) catch
        return error.ObserverCountOverflow;
}

fn readGuestBytes(
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

fn findWordIndex(words: []const runner.memory_state.WordState, address: u32) ?usize {
    var low: usize = 0;
    var high = words.len;
    while (low < high) {
        const mid = low + (high - low) / 2;
        const candidate = words[mid].addr;
        if (candidate < address) low = mid + 1 else if (candidate > address) high = mid else return mid;
    }
    return null;
}

fn validateGuestRange(pointer: u32, length: u32) !void {
    const end = @as(u64, pointer) + length;
    if (end > (@as(u64, std.math.maxInt(u32)) + 1))
        return error.SourceRangeOverflow;
}

fn objectField(value: std.json.Value, name: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidJournal;
    return value.object.get(name) orelse error.InvalidJournal;
}

fn stringField(value: std.json.Value, name: []const u8) ![]const u8 {
    const field = try objectField(value, name);
    if (field != .string) return error.InvalidJournal;
    return field.string;
}

fn unsignedField(value: std.json.Value, name: []const u8) !u64 {
    const field = try objectField(value, name);
    return switch (field) {
        .integer => |number| std.math.cast(u64, number) orelse error.InvalidJournal,
        else => error.InvalidJournal,
    };
}

fn boolField(value: std.json.Value, name: []const u8) !bool {
    const field = try objectField(value, name);
    if (field != .bool) return error.InvalidJournal;
    return field.bool;
}

fn validateNmAuthority(bytes: []const u8) !void {
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    var found = false;
    while (lines.next()) |line| {
        if (line.len < 12) continue;
        var fields = std.mem.splitScalar(u8, line, ' ');
        const address_text = fields.next() orelse continue;
        const kind = fields.next() orelse continue;
        const name = fields.rest();
        if (address_text.len != 8 or kind.len != 1 or
            (kind[0] != 't' and kind[0] != 'T'))
        {
            continue;
        }
        const address = std.fmt.parseInt(u32, address_text, 16) catch continue;
        if (!found) {
            if (address == function_authority.entry_pc and
                std.mem.eql(u8, name, function_authority.symbol))
            {
                found = true;
            }
            continue;
        }
        if (address == function_authority.entry_pc) continue;
        if (address != function_authority.symbol_end_exclusive)
            return error.NmSymbolIntervalMismatch;
        return;
    }
    return error.NmSymbolIntervalMismatch;
}

fn digest(bytes: []const u8) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(bytes);
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

fn digestWithNewline(bytes: []const u8) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(bytes);
    hasher.update("\n");
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

test "options require every exact custody input" {
    const args = [_][]const u8{
        "--cargo-lock",                "a", "--elf",             "b", "--execution-journal",       "c",
        "--function-value-evidence",   "d", "--input",           "e", "--nm-map",                  "f",
        "--observer-semantics-source", "g", "--observer-source", "h", "--observer-witness-source", "i",
        "--pc-observation",            "j", "--revm-source",     "j", "--segment-count",           "31",
    };
    const options = try Options.parse(&args);
    try std.testing.expectEqual(@as(u32, 31), options.segment_count);
}

test "input identity borrows digest storage from its owner" {
    var bytes = [_]u8{0x42};
    var path = [_]u8{ '/', 'x' };
    var input = InputFile{
        .bytes = &bytes,
        .path = &path,
        .sha256 = [_]u8{0x11} ** 32,
        .sha256_hex = [_]u8{'1'} ** 64,
    };
    const identity = input.identity();
    try std.testing.expectEqual(
        @intFromPtr(input.sha256_hex[0..].ptr),
        @intFromPtr(identity.sha256.ptr),
    );
    try std.testing.expectEqualStrings(&input.sha256_hex, identity.sha256);
}

test "call wire borrows digest and opcode storage from retained call" {
    var opcode_positions = [_]u32{ 0, 2 };
    var call = Call{
        .analysis = .{
            .bitmap_bytes = 1,
            .eof_immediate_padding = 1,
            .jumpdest_count = 0,
            .opcode_positions = &opcode_positions,
            .push_count = 1,
            .push_overflow = 0,
            .total_padding = 1,
        },
        .authority = .{
            .bytes_struct_pointer = 1,
            .entry_clock = 2,
            .entry_segment_index = 3,
            .length = 4,
            .length_clock = 5,
            .observation_segment_index = 6,
            .pointer_clock = 7,
            .source_pointer = 8,
            .witness_code_index = 9,
        },
        .source_bytes_sha256 = [_]u8{0x11} ** 32,
        .source_bytes_sha256_hex = [_]u8{'1'} ** 64,
    };
    const wire = callWire(&call, 0, 2);
    try std.testing.expectEqual(
        @intFromPtr(call.source_bytes_sha256_hex[0..].ptr),
        @intFromPtr(wire.source_bytes_sha256.ptr),
    );
    try std.testing.expectEqual(
        @intFromPtr(call.analysis.opcode_positions.ptr),
        @intFromPtr(wire.opcode_positions.ptr),
    );
}

test "witness code wire borrows its retained hex allocation" {
    const bytes = [_]u8{0x00};
    var code = witness_codes.Code{
        .bytes = &bytes,
        .classification = .legacy,
        .sha256 = [_]u8{0x22} ** 32,
    };
    var sha256_hex = [_]u8{'2'} ** 64;
    const wire = witnessCodeWire(&code, true, 7, &sha256_hex);
    try std.testing.expectEqual(
        @intFromPtr(sha256_hex[0..].ptr),
        @intFromPtr(wire.sha256.ptr),
    );
    try std.testing.expectEqualStrings(&sha256_hex, wire.sha256);
}

test "canonical sealed identity wire reopens to its unsigned bytes" {
    const Unsigned = struct {
        elf: Identity,
        input: Identity,
    };
    const Sealed = struct {
        content_sha256: []const u8,
        elf: Identity,
        input: Identity,
    };
    var bytes = [_]u8{0x42};
    var path = [_]u8{ '/', 'x' };
    var input_file = InputFile{
        .bytes = &bytes,
        .path = &path,
        .sha256 = [_]u8{0x11} ** 32,
        .sha256_hex = [_]u8{'1'} ** 64,
    };
    const unsigned = Unsigned{
        .elf = input_file.identity(),
        .input = input_file.identity(),
    };
    const unsigned_json = try std.json.Stringify.valueAlloc(
        std.testing.allocator,
        unsigned,
        .{},
    );
    defer std.testing.allocator.free(unsigned_json);
    const content_digest = digestWithNewline(unsigned_json);
    const content_hex = std.fmt.bytesToHex(content_digest, .lower);
    const sealed_json = try std.json.Stringify.valueAlloc(
        std.testing.allocator,
        Sealed{
            .content_sha256 = &content_hex,
            .elf = unsigned.elf,
            .input = unsigned.input,
        },
        .{},
    );
    defer std.testing.allocator.free(sealed_json);
    const field = ",\"elf\":";
    const marker = std.mem.indexOf(u8, sealed_json, field) orelse
        return error.MissingSyntheticElfIdentity;
    const reopened = try std.testing.allocator.alloc(
        u8,
        1 + sealed_json[marker + 1 ..].len,
    );
    defer std.testing.allocator.free(reopened);
    reopened[0] = '{';
    @memcpy(reopened[1..], sealed_json[marker + 1 ..]);
    try std.testing.expectEqualStrings(unsigned_json, reopened);
    try std.testing.expectEqualSlices(
        u8,
        &content_digest,
        &digestWithNewline(reopened),
    );
}

test "snapshot reader handles unaligned exact bytes" {
    var words = [_]runner.memory_state.WordState{
        .{ .addr = 0x2000, .initial_word = 0, .final_word = 0x44332211, .final_clock = 1 },
        .{ .addr = 0x2004, .initial_word = 0, .final_word = 0x88776655, .final_clock = 1 },
    };
    const snapshot = Snapshot{
        .layout = .{
            .program_base = 0,
            .program_end = 0,
            .data_base = 0x2000,
            .data_end = 0x3000,
            .stack_bottom = 0,
            .stack_top = 0,
            .io_base = 0,
            .io_end = 0,
            .input_base = 0,
            .input_end = 0,
            .output_len_addr = 0,
            .output_data_addr = 0,
            .output_base = 0,
            .output_end = 0,
        },
        .segment_role = .single(),
        .words = &words,
    };
    const bytes = try readGuestBytes(std.testing.allocator, snapshot, 0x2002, 4);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualSlices(u8, &.{ 0x33, 0x44, 0x55, 0x66 }, bytes);
}
