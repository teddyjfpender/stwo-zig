//! Exact, bounded function-load observation for RISC-V autoresearch.
//!
//! The observer reexecutes a prefix of a sealed V3 execution journal and
//! records the value written by one exact load instruction after one exact
//! function-entry instruction.  This is diagnostic evidence only.  It does
//! not alter execution, generate a proof, or authorize a precompile.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const runner = frontend.runner;
const TraceRow = runner.trace.TraceRow;

const schema = "stwo.riscv.function-load-value-observation.v1";
const status = "captured-diagnostic-only";
const claim_boundary = "execution-observation-only-not-air-or-proof";
const profile_name = "rv32im-zkvm-ethereum-v1";
const clock_frame = "leaf_local";
const value_source = "retired-row-rd-val";
const maximum_input_bytes: usize = 64 << 20;
const maximum_elf_bytes: usize = 64 << 20;
const maximum_journal_bytes: usize = 64 << 20;
const maximum_sample_segments: u32 = 64;

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    const options = try Options.parse(args[1..]);

    const elf = try readPathAlloc(allocator, options.elf, maximum_elf_bytes);
    defer allocator.free(elf);
    const input = try readPathAlloc(allocator, options.input, maximum_input_bytes);
    defer allocator.free(input);
    const journal = try readPathAlloc(
        allocator,
        options.execution_journal,
        maximum_journal_bytes,
    );
    defer allocator.free(journal);

    const elf_sha256 = digest(elf);
    const input_sha256 = digest(input);
    const source_sha256 = digest(journal);
    var expected = try JournalAuthority.parse(
        allocator,
        journal,
        elf_sha256,
        input_sha256,
        options.segment_count,
    );
    defer expected.deinit(allocator);

    var capture = Capture.init(allocator, options);
    defer capture.deinit();
    var session = try runner.EthereumExecutionSession.init(allocator, elf, .{
        .input = input,
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
            segment.base.execution_trace.rows.items.len != wanted.core_trace_rows)
        {
            return error.JournalExecutionMismatch;
        }
        if (capture.current_segment_rows != wanted.core_trace_rows)
            return error.ObserverExecutionMismatch;
        continuation = segment.base.continuation;
        if (index + 1 < expected.segments.len and continuation == null)
            return error.ExecutionCompletedBeforeSample;
    }

    try capture.validate(expected.retired_instructions, expected.segments.len);
    const encoded = try encodeObservation(
        allocator,
        &capture,
        expected,
        elf_sha256,
        input_sha256,
        source_sha256,
    );
    defer allocator.free(encoded);
    try std.fs.File.stdout().writeAll(encoded);
}

const Options = struct {
    elf: []const u8,
    input: []const u8,
    execution_journal: []const u8,
    segment_count: u32,
    entry_pc: u32,
    entry_instruction_word: u32,
    value_pc: u32,
    value_instruction_word: u32,

    fn parse(arguments: []const []const u8) !Options {
        if (arguments.len != 16) return error.InvalidArguments;
        var elf: ?[]const u8 = null;
        var input: ?[]const u8 = null;
        var journal: ?[]const u8 = null;
        var count: ?u32 = null;
        var entry_pc: ?u32 = null;
        var entry_instruction: ?u32 = null;
        var value_pc: ?u32 = null;
        var value_instruction: ?u32 = null;
        var cursor: usize = 0;
        while (cursor < arguments.len) : (cursor += 2) {
            const name = arguments[cursor];
            const value = arguments[cursor + 1];
            if (std.mem.eql(u8, name, "--elf")) {
                if (elf != null) return error.DuplicateArgument;
                elf = value;
            } else if (std.mem.eql(u8, name, "--input")) {
                if (input != null) return error.DuplicateArgument;
                input = value;
            } else if (std.mem.eql(u8, name, "--execution-journal")) {
                if (journal != null) return error.DuplicateArgument;
                journal = value;
            } else if (std.mem.eql(u8, name, "--segment-count")) {
                if (count != null) return error.DuplicateArgument;
                count = try parseU32(value);
            } else if (std.mem.eql(u8, name, "--entry-pc")) {
                if (entry_pc != null) return error.DuplicateArgument;
                entry_pc = try parseU32(value);
            } else if (std.mem.eql(u8, name, "--entry-instruction-word")) {
                if (entry_instruction != null) return error.DuplicateArgument;
                entry_instruction = try parseU32(value);
            } else if (std.mem.eql(u8, name, "--value-pc")) {
                if (value_pc != null) return error.DuplicateArgument;
                value_pc = try parseU32(value);
            } else if (std.mem.eql(u8, name, "--value-instruction-word")) {
                if (value_instruction != null) return error.DuplicateArgument;
                value_instruction = try parseU32(value);
            } else return error.InvalidArguments;
        }
        const segment_count = count orelse return error.InvalidArguments;
        if (segment_count == 0 or segment_count > maximum_sample_segments)
            return error.InvalidSegmentCount;
        const resolved_entry_pc = entry_pc orelse return error.InvalidArguments;
        const resolved_value_pc = value_pc orelse return error.InvalidArguments;
        if (resolved_entry_pc == resolved_value_pc)
            return error.InvalidArguments;
        return .{
            .elf = elf orelse return error.InvalidArguments,
            .input = input orelse return error.InvalidArguments,
            .execution_journal = journal orelse return error.InvalidArguments,
            .segment_count = segment_count,
            .entry_pc = resolved_entry_pc,
            .entry_instruction_word = entry_instruction orelse
                return error.InvalidArguments,
            .value_pc = resolved_value_pc,
            .value_instruction_word = value_instruction orelse
                return error.InvalidArguments,
        };
    }
};

const ExpectedSegment = struct {
    segment_index: u32,
    global_first_cycle: u64,
    cycle_count: u32,
    core_trace_rows: usize,
};

const JournalAuthority = struct {
    segment_step_budget: usize,
    first_global_cycle: u64,
    sampled_cycles: u64,
    retired_instructions: u64,
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
        if (header_line.len == 0) return error.InvalidJournal;
        var header = try std.json.parseFromSlice(
            std.json.Value,
            allocator,
            header_line,
            .{},
        );
        defer header.deinit();
        const payload = try objectField(header.value, "payload");
        if (!std.mem.eql(u8, try stringField(payload, "schema"), "stwo.riscv.segmented-execution-header.v3") or
            !std.mem.eql(u8, try stringField(payload, "profile"), profile_name) or
            !std.mem.eql(u8, try stringField(payload, "clock_frame"), clock_frame))
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
            if (line.len == 0) return error.InvalidJournal;
            var parsed = try std.json.parseFromSlice(
                std.json.Value,
                allocator,
                line,
                .{},
            );
            defer parsed.deinit();
            const segment = try objectField(parsed.value, "payload");
            if (!std.mem.eql(u8, try stringField(segment, "schema"), "stwo.riscv.segmented-execution-segment.v3"))
                return error.InvalidJournal;
            const segment_index = try unsignedField(segment, "segment_index");
            const first_cycle = try unsignedField(segment, "global_first_cycle");
            const cycles = try unsignedField(segment, "cycle_count");
            const core_rows = try unsignedField(segment, "core_trace_rows");
            if (segment_index != index or cycles == 0 or core_rows == 0 or
                segment_index > std.math.maxInt(u32) or
                cycles > std.math.maxInt(u32) or
                core_rows > std.math.maxInt(usize))
            {
                return error.InvalidJournal;
            }
            out.* = .{
                .segment_index = @intCast(segment_index),
                .global_first_cycle = first_cycle,
                .cycle_count = @intCast(cycles),
                .core_trace_rows = @intCast(core_rows),
            };
            sampled_cycles = std.math.add(u64, sampled_cycles, cycles) catch
                return error.InvalidJournal;
            retired = std.math.add(u64, retired, core_rows) catch
                return error.InvalidJournal;
        }
        return .{
            .segment_step_budget = @intCast(budget),
            .first_global_cycle = segments[0].global_first_cycle,
            .sampled_cycles = sampled_cycles,
            .retired_instructions = retired,
            .segments = segments,
        };
    }

    fn deinit(self: *JournalAuthority, allocator: std.mem.Allocator) void {
        allocator.free(self.segments);
        self.* = undefined;
    }
};

const Capture = struct {
    allocator: std.mem.Allocator,
    options: Options,
    histogram: std.AutoHashMap(u32, u64),
    current_segment_rows: usize = 0,
    completed_segment_rows: u64 = 0,
    segment_count: u32 = 0,
    entry_count: u64 = 0,
    value_count: u64 = 0,
    value_sum: u64 = 0,
    minimum_value: ?u32 = null,
    maximum_value: ?u32 = null,
    awaiting_value: bool = false,
    value_rd: ?u5 = null,
    value_rs1: ?u5 = null,
    value_imm: ?i32 = null,

    fn init(allocator: std.mem.Allocator, options: Options) Capture {
        return .{
            .allocator = allocator,
            .options = options,
            .histogram = std.AutoHashMap(u32, u64).init(allocator),
        };
    }

    fn deinit(self: *Capture) void {
        self.histogram.deinit();
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
        if (segment_index != self.segment_count)
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
        if (row.pc == self.options.entry_pc) {
            if (row.inst_word != self.options.entry_instruction_word)
                return error.EntryInstructionMismatch;
            if (self.awaiting_value) return error.NestedObservedFunctionEntry;
            self.awaiting_value = true;
            self.entry_count = std.math.add(u64, self.entry_count, 1) catch
                return error.ObserverCountOverflow;
        }
        if (row.pc == self.options.value_pc) {
            if (row.inst_word != self.options.value_instruction_word or
                !row.is_load or row.is_store)
            {
                return error.ValueInstructionMismatch;
            }
            if (!self.awaiting_value) return error.ValueWithoutFunctionEntry;
            if (self.value_rd) |rd| {
                if (rd != row.rd or self.value_rs1.? != row.rs1 or
                    self.value_imm.? != row.imm)
                {
                    return error.ValueInstructionShapeMismatch;
                }
            } else {
                self.value_rd = row.rd;
                self.value_rs1 = row.rs1;
                self.value_imm = row.imm;
            }
            self.awaiting_value = false;
            self.value_count = std.math.add(u64, self.value_count, 1) catch
                return error.ObserverCountOverflow;
            self.value_sum = std.math.add(u64, self.value_sum, row.rd_val) catch
                return error.ObserverCountOverflow;
            self.minimum_value = if (self.minimum_value) |current|
                @min(current, row.rd_val)
            else
                row.rd_val;
            self.maximum_value = if (self.maximum_value) |current|
                @max(current, row.rd_val)
            else
                row.rd_val;
            const count = try self.histogram.getOrPut(row.rd_val);
            if (!count.found_existing) count.value_ptr.* = 0;
            count.value_ptr.* = std.math.add(u64, count.value_ptr.*, 1) catch
                return error.ObserverCountOverflow;
        }
        self.current_segment_rows = std.math.add(
            usize,
            self.current_segment_rows,
            1,
        ) catch return error.ObserverCountOverflow;
    }

    fn totalRows(self: *const Capture) !u64 {
        return std.math.add(
            u64,
            self.completed_segment_rows,
            self.current_segment_rows,
        );
    }

    fn validate(self: *const Capture, expected_rows: u64, segments: usize) !void {
        if (self.segment_count != segments or try self.totalRows() != expected_rows)
            return error.ObserverExecutionMismatch;
        const pending: u64 = @intFromBool(self.awaiting_value);
        if (self.entry_count != self.value_count + pending or
            self.value_count == 0 or self.histogram.count() == 0 or
            self.value_rd == null or self.value_rs1 == null or self.value_imm == null)
        {
            return error.ObserverExecutionMismatch;
        }
        var histogram_count: u64 = 0;
        var histogram_sum: u64 = 0;
        var iterator = self.histogram.iterator();
        while (iterator.next()) |entry| {
            histogram_count = std.math.add(u64, histogram_count, entry.value_ptr.*) catch
                return error.ObserverCountOverflow;
            histogram_sum = std.math.add(
                u64,
                histogram_sum,
                std.math.mul(u64, entry.key_ptr.*, entry.value_ptr.*) catch
                    return error.ObserverCountOverflow,
            ) catch return error.ObserverCountOverflow;
        }
        if (histogram_count != self.value_count or histogram_sum != self.value_sum)
            return error.ObserverExecutionMismatch;
    }
};

const ValueCount = struct {
    count: u64,
    value: u32,
};

const UnsignedWire = struct {
    claim_boundary: []const u8,
    clock_frame: []const u8,
    distinct_value_count: usize,
    elf_sha256: []const u8,
    entry_count: u64,
    entry_instruction_word: u32,
    entry_pc: u32,
    execution_profile: []const u8,
    first_global_cycle: u64,
    first_segment_index: u32,
    histogram: []const ValueCount,
    input_sha256: []const u8,
    maximum_value: u32,
    minimum_value: u32,
    pending_entry_count: u64,
    production: bool,
    retired_instructions: u64,
    sampled_cycles: u64,
    schema: []const u8,
    segment_count: u32,
    source_sha256: []const u8,
    status: []const u8,
    value_count: u64,
    value_imm: i32,
    value_instruction_word: u32,
    value_pc: u32,
    value_rd: u5,
    value_rs1: u5,
    value_source: []const u8,
    value_sum: u64,
};

const Wire = struct {
    claim_boundary: []const u8,
    clock_frame: []const u8,
    content_sha256: []const u8,
    distinct_value_count: usize,
    elf_sha256: []const u8,
    entry_count: u64,
    entry_instruction_word: u32,
    entry_pc: u32,
    execution_profile: []const u8,
    first_global_cycle: u64,
    first_segment_index: u32,
    histogram: []const ValueCount,
    input_sha256: []const u8,
    maximum_value: u32,
    minimum_value: u32,
    pending_entry_count: u64,
    production: bool,
    retired_instructions: u64,
    sampled_cycles: u64,
    schema: []const u8,
    segment_count: u32,
    source_sha256: []const u8,
    status: []const u8,
    value_count: u64,
    value_imm: i32,
    value_instruction_word: u32,
    value_pc: u32,
    value_rd: u5,
    value_rs1: u5,
    value_source: []const u8,
    value_sum: u64,
};

fn encodeObservation(
    allocator: std.mem.Allocator,
    capture: *const Capture,
    expected: JournalAuthority,
    elf_sha256: [32]u8,
    input_sha256: [32]u8,
    source_sha256: [32]u8,
) ![]u8 {
    const histogram = try collectHistogram(allocator, capture);
    defer allocator.free(histogram);
    const elf_hex = std.fmt.bytesToHex(elf_sha256, .lower);
    const input_hex = std.fmt.bytesToHex(input_sha256, .lower);
    const source_hex = std.fmt.bytesToHex(source_sha256, .lower);
    const unsigned = UnsignedWire{
        .claim_boundary = claim_boundary,
        .clock_frame = clock_frame,
        .distinct_value_count = histogram.len,
        .elf_sha256 = &elf_hex,
        .entry_count = capture.entry_count,
        .entry_instruction_word = capture.options.entry_instruction_word,
        .entry_pc = capture.options.entry_pc,
        .execution_profile = profile_name,
        .first_global_cycle = expected.first_global_cycle,
        .first_segment_index = 0,
        .histogram = histogram,
        .input_sha256 = &input_hex,
        .maximum_value = capture.maximum_value.?,
        .minimum_value = capture.minimum_value.?,
        .pending_entry_count = @intFromBool(capture.awaiting_value),
        .production = false,
        .retired_instructions = expected.retired_instructions,
        .sampled_cycles = expected.sampled_cycles,
        .schema = schema,
        .segment_count = @intCast(expected.segments.len),
        .source_sha256 = &source_hex,
        .status = status,
        .value_count = capture.value_count,
        .value_imm = capture.value_imm.?,
        .value_instruction_word = capture.options.value_instruction_word,
        .value_pc = capture.options.value_pc,
        .value_rd = capture.value_rd.?,
        .value_rs1 = capture.value_rs1.?,
        .value_source = value_source,
        .value_sum = capture.value_sum,
    };
    const unsigned_json = try std.json.Stringify.valueAlloc(allocator, unsigned, .{});
    defer allocator.free(unsigned_json);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(unsigned_json);
    hasher.update("\n");
    var content_digest: [32]u8 = undefined;
    hasher.final(&content_digest);
    const content_hex = std.fmt.bytesToHex(content_digest, .lower);
    const sealed = Wire{
        .claim_boundary = unsigned.claim_boundary,
        .clock_frame = unsigned.clock_frame,
        .content_sha256 = &content_hex,
        .distinct_value_count = unsigned.distinct_value_count,
        .elf_sha256 = unsigned.elf_sha256,
        .entry_count = unsigned.entry_count,
        .entry_instruction_word = unsigned.entry_instruction_word,
        .entry_pc = unsigned.entry_pc,
        .execution_profile = unsigned.execution_profile,
        .first_global_cycle = unsigned.first_global_cycle,
        .first_segment_index = unsigned.first_segment_index,
        .histogram = unsigned.histogram,
        .input_sha256 = unsigned.input_sha256,
        .maximum_value = unsigned.maximum_value,
        .minimum_value = unsigned.minimum_value,
        .pending_entry_count = unsigned.pending_entry_count,
        .production = unsigned.production,
        .retired_instructions = unsigned.retired_instructions,
        .sampled_cycles = unsigned.sampled_cycles,
        .schema = unsigned.schema,
        .segment_count = unsigned.segment_count,
        .source_sha256 = unsigned.source_sha256,
        .status = unsigned.status,
        .value_count = unsigned.value_count,
        .value_imm = unsigned.value_imm,
        .value_instruction_word = unsigned.value_instruction_word,
        .value_pc = unsigned.value_pc,
        .value_rd = unsigned.value_rd,
        .value_rs1 = unsigned.value_rs1,
        .value_source = unsigned.value_source,
        .value_sum = unsigned.value_sum,
    };
    const body = try std.json.Stringify.valueAlloc(allocator, sealed, .{});
    defer allocator.free(body);
    const encoded = try allocator.alloc(u8, body.len + 1);
    @memcpy(encoded[0..body.len], body);
    encoded[body.len] = '\n';
    return encoded;
}

fn collectHistogram(allocator: std.mem.Allocator, capture: *const Capture) ![]ValueCount {
    const result = try allocator.alloc(ValueCount, capture.histogram.count());
    var index: usize = 0;
    var iterator = capture.histogram.iterator();
    while (iterator.next()) |entry| : (index += 1) {
        result[index] = .{
            .count = entry.value_ptr.*,
            .value = entry.key_ptr.*,
        };
    }
    std.mem.sort(ValueCount, result, {}, lessValue);
    return result;
}

fn lessValue(_: void, left: ValueCount, right: ValueCount) bool {
    return left.value < right.value;
}

fn parseU32(value: []const u8) !u32 {
    if (std.mem.startsWith(u8, value, "0x"))
        return std.fmt.parseInt(u32, value[2..], 16);
    return std.fmt.parseInt(u32, value, 10);
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
        .integer => |number| std.math.cast(u64, number) orelse
            error.InvalidJournal,
        else => error.InvalidJournal,
    };
}

fn readPathAlloc(
    allocator: std.mem.Allocator,
    path: []const u8,
    maximum: usize,
) ![]u8 {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const metadata = try file.stat();
    if (metadata.kind != .file or metadata.size > maximum)
        return error.InvalidInputFile;
    return file.readToEndAlloc(allocator, maximum);
}

fn digest(bytes: []const u8) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(bytes);
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

test "options accept exact hex PCs and instruction words" {
    const args = [_][]const u8{
        "--elf",           "a",       "--input",                  "b",          "--execution-journal",      "c",
        "--segment-count", "31",      "--entry-pc",               "0xbd490",    "--entry-instruction-word", "0xfc010113",
        "--value-pc",      "0xbd4c4", "--value-instruction-word", "0x0085a903",
    };
    const options = try Options.parse(&args);
    try std.testing.expectEqual(@as(u32, 0xbd490), options.entry_pc);
    try std.testing.expectEqual(@as(u32, 0xbd4c4), options.value_pc);
    try std.testing.expectEqual(@as(u32, 0x0085a903), options.value_instruction_word);
}
