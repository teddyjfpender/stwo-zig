//! Exact, bounded memcpy-call observation for Ethereum prover autoresearch.
//!
//! The observer replays a sealed V3 execution-journal prefix, reconstructs the
//! architectural integer registers from typed retirement rows, and records
//! the complete `(length, src mod 16, dst mod 16)` distribution at one pinned
//! memcpy entry PC.  It is diagnostic execution evidence only: no proof or
//! verification claim is made here.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const runner = frontend.runner;
const TraceRow = runner.trace.TraceRow;

const schema = "stwo.riscv.memcpy-call-hotspot-observation.v1";
const status = "captured-diagnostic-only";
const profile_name = "rv32im-zkvm-ethereum-v1";
const clock_frame = "leaf_local";
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

    var admission_memory = try runner.Memory.initFallible(allocator);
    defer admission_memory.deinit();
    const elf_info = try runner.elf_loader.loadElfForProfile(
        elf,
        &admission_memory,
        .rv32im_zkvm_ethereum_v1,
    );

    var capture = Capture.init(
        allocator,
        options.memcpy_entry_pc,
        elf_info.stack_pointer,
        elf_info.global_pointer,
    );
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
    memcpy_entry_pc: u32,

    fn parse(arguments: []const []const u8) !Options {
        if (arguments.len != 12) return error.InvalidArguments;
        var elf: ?[]const u8 = null;
        var input: ?[]const u8 = null;
        var journal: ?[]const u8 = null;
        var first: ?u32 = null;
        var count: ?u32 = null;
        var entry: ?u32 = null;
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
            } else if (std.mem.eql(u8, name, "--first-segment-index")) {
                if (first != null) return error.DuplicateArgument;
                first = try std.fmt.parseInt(u32, value, 0);
            } else if (std.mem.eql(u8, name, "--segment-count")) {
                if (count != null) return error.DuplicateArgument;
                count = try std.fmt.parseInt(u32, value, 0);
            } else if (std.mem.eql(u8, name, "--memcpy-entry-pc")) {
                if (entry != null) return error.DuplicateArgument;
                entry = try std.fmt.parseInt(u32, value, 0);
            } else return error.InvalidArguments;
        }
        if ((first orelse return error.InvalidArguments) != 0)
            return error.NonPrefixSampleUnavailable;
        const segment_count = count orelse return error.InvalidArguments;
        if (segment_count == 0 or segment_count > maximum_sample_segments)
            return error.InvalidSegmentCount;
        return .{
            .elf = elf orelse return error.InvalidArguments,
            .input = input orelse return error.InvalidArguments,
            .execution_journal = journal orelse return error.InvalidArguments,
            .segment_count = segment_count,
            .memcpy_entry_pc = entry orelse return error.InvalidArguments,
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

const CountAndBytes = struct {
    count: u64 = 0,
    bytes: u64 = 0,
};

const Capture = struct {
    allocator: std.mem.Allocator,
    memcpy_entry_pc: u32,
    registers: [32]u32,
    lengths: std.AutoHashMap(u32, u64),
    alignments: std.AutoHashMap(u8, CountAndBytes),
    current_segment_rows: usize = 0,
    completed_segment_rows: u64 = 0,
    segment_count: u32 = 0,
    call_count: u64 = 0,
    total_requested_bytes: u64 = 0,
    maximum_requested_bytes: u32 = 0,
    zero_length_calls: u64 = 0,
    validated_register_reads: u64 = 0,

    fn init(
        allocator: std.mem.Allocator,
        memcpy_entry_pc: u32,
        stack_pointer: u32,
        global_pointer: u32,
    ) Capture {
        var registers = [_]u32{0} ** 32;
        registers[2] = stack_pointer;
        registers[3] = global_pointer;
        return .{
            .allocator = allocator,
            .memcpy_entry_pc = memcpy_entry_pc,
            .registers = registers,
            .lengths = std.AutoHashMap(u32, u64).init(allocator),
            .alignments = std.AutoHashMap(u8, CountAndBytes).init(allocator),
        };
    }

    fn deinit(self: *Capture) void {
        self.lengths.deinit();
        self.alignments.deinit();
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
        const usage = frontend.isa.decode.operandUsage(row.opcode);
        if (usage.reads_rs1) {
            if (self.registers[row.rs1] != row.rs1_val)
                return error.RegisterReconstructionMismatch;
            self.validated_register_reads += 1;
        }
        if (usage.reads_rs2) {
            if (self.registers[row.rs2] != row.rs2_val)
                return error.RegisterReconstructionMismatch;
            self.validated_register_reads += 1;
        }
        if (row.pc == self.memcpy_entry_pc)
            try self.recordCall(self.registers[10], self.registers[11], self.registers[12]);
        if (usage.writes_rd and row.rd != 0)
            self.registers[row.rd] = row.rd_val;
        self.registers[0] = 0;
        self.current_segment_rows = std.math.add(
            usize,
            self.current_segment_rows,
            1,
        ) catch return error.ObserverCountOverflow;
    }

    fn recordCall(self: *Capture, destination: u32, source: u32, length: u32) !void {
        const length_entry = try self.lengths.getOrPut(length);
        if (!length_entry.found_existing) length_entry.value_ptr.* = 0;
        length_entry.value_ptr.* = std.math.add(u64, length_entry.value_ptr.*, 1) catch
            return error.ObserverCountOverflow;
        const key: u8 = @intCast(((destination & 15) << 4) | (source & 15));
        const alignment = try self.alignments.getOrPut(key);
        if (!alignment.found_existing) alignment.value_ptr.* = .{};
        alignment.value_ptr.count = std.math.add(u64, alignment.value_ptr.count, 1) catch
            return error.ObserverCountOverflow;
        alignment.value_ptr.bytes = std.math.add(u64, alignment.value_ptr.bytes, length) catch
            return error.ObserverCountOverflow;
        self.call_count = std.math.add(u64, self.call_count, 1) catch
            return error.ObserverCountOverflow;
        self.total_requested_bytes = std.math.add(
            u64,
            self.total_requested_bytes,
            length,
        ) catch return error.ObserverCountOverflow;
        self.maximum_requested_bytes = @max(self.maximum_requested_bytes, length);
        self.zero_length_calls += @intFromBool(length == 0);
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
        var calls: u64 = 0;
        var bytes: u64 = 0;
        var iterator = self.lengths.iterator();
        while (iterator.next()) |entry| {
            calls = std.math.add(u64, calls, entry.value_ptr.*) catch
                return error.ObserverCountOverflow;
            const contribution = std.math.mul(u64, entry.key_ptr.*, entry.value_ptr.*) catch
                return error.ObserverCountOverflow;
            bytes = std.math.add(u64, bytes, contribution) catch
                return error.ObserverCountOverflow;
        }
        if (calls != self.call_count or bytes != self.total_requested_bytes)
            return error.ObserverExecutionMismatch;
        var alignment_calls: u64 = 0;
        var alignment_bytes: u64 = 0;
        var alignment_iterator = self.alignments.iterator();
        while (alignment_iterator.next()) |entry| {
            alignment_calls = std.math.add(u64, alignment_calls, entry.value_ptr.count) catch
                return error.ObserverCountOverflow;
            alignment_bytes = std.math.add(u64, alignment_bytes, entry.value_ptr.bytes) catch
                return error.ObserverCountOverflow;
        }
        if (alignment_calls != calls or alignment_bytes != bytes)
            return error.ObserverExecutionMismatch;
    }
};

const LengthBucket = struct {
    call_count: u64,
    length: u32,
    total_bytes: u64,
};

const AlignmentBucket = struct {
    call_count: u64,
    destination_mod_16: u8,
    source_mod_16: u8,
    total_bytes: u64,
};

fn encodeObservation(
    allocator: std.mem.Allocator,
    capture: *const Capture,
    expected: JournalAuthority,
    elf_sha256: [32]u8,
    input_sha256: [32]u8,
    source_sha256: [32]u8,
) ![]u8 {
    const lengths = try collectLengths(allocator, capture);
    defer allocator.free(lengths);
    const alignments = try collectAlignments(allocator, capture);
    defer allocator.free(alignments);
    const elf_hex = std.fmt.bytesToHex(elf_sha256, .lower);
    const input_hex = std.fmt.bytesToHex(input_sha256, .lower);
    const source_hex = std.fmt.bytesToHex(source_sha256, .lower);
    const unsigned = UnsignedWire{
        .alignment_histogram = alignments,
        .call_count = capture.call_count,
        .clock_frame = clock_frame,
        .distinct_alignment_count = alignments.len,
        .distinct_length_count = lengths.len,
        .elf_sha256 = &elf_hex,
        .execution_profile = profile_name,
        .first_global_cycle = expected.first_global_cycle,
        .first_segment_index = 0,
        .input_sha256 = &input_hex,
        .length_histogram = lengths,
        .maximum_requested_bytes = capture.maximum_requested_bytes,
        .memcpy_entry_pc = capture.memcpy_entry_pc,
        .production = false,
        .retired_instructions = expected.retired_instructions,
        .sampled_cycles = expected.sampled_cycles,
        .schema = schema,
        .segment_count = @intCast(expected.segments.len),
        .source_sha256 = &source_hex,
        .status = status,
        .total_requested_bytes = capture.total_requested_bytes,
        .validated_register_reads = capture.validated_register_reads,
        .zero_length_calls = capture.zero_length_calls,
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
        .alignment_histogram = unsigned.alignment_histogram,
        .call_count = unsigned.call_count,
        .clock_frame = unsigned.clock_frame,
        .content_sha256 = &content_hex,
        .distinct_alignment_count = unsigned.distinct_alignment_count,
        .distinct_length_count = unsigned.distinct_length_count,
        .elf_sha256 = unsigned.elf_sha256,
        .execution_profile = unsigned.execution_profile,
        .first_global_cycle = unsigned.first_global_cycle,
        .first_segment_index = unsigned.first_segment_index,
        .input_sha256 = unsigned.input_sha256,
        .length_histogram = unsigned.length_histogram,
        .maximum_requested_bytes = unsigned.maximum_requested_bytes,
        .memcpy_entry_pc = unsigned.memcpy_entry_pc,
        .production = unsigned.production,
        .retired_instructions = unsigned.retired_instructions,
        .sampled_cycles = unsigned.sampled_cycles,
        .schema = unsigned.schema,
        .segment_count = unsigned.segment_count,
        .source_sha256 = unsigned.source_sha256,
        .status = unsigned.status,
        .total_requested_bytes = unsigned.total_requested_bytes,
        .validated_register_reads = unsigned.validated_register_reads,
        .zero_length_calls = unsigned.zero_length_calls,
    };
    const body = try std.json.Stringify.valueAlloc(allocator, sealed, .{});
    defer allocator.free(body);
    const encoded = try allocator.alloc(u8, body.len + 1);
    @memcpy(encoded[0..body.len], body);
    encoded[body.len] = '\n';
    return encoded;
}

const UnsignedWire = struct {
    alignment_histogram: []const AlignmentBucket,
    call_count: u64,
    clock_frame: []const u8,
    distinct_alignment_count: usize,
    distinct_length_count: usize,
    elf_sha256: []const u8,
    execution_profile: []const u8,
    first_global_cycle: u64,
    first_segment_index: u32,
    input_sha256: []const u8,
    length_histogram: []const LengthBucket,
    maximum_requested_bytes: u32,
    memcpy_entry_pc: u32,
    production: bool,
    retired_instructions: u64,
    sampled_cycles: u64,
    schema: []const u8,
    segment_count: u32,
    source_sha256: []const u8,
    status: []const u8,
    total_requested_bytes: u64,
    validated_register_reads: u64,
    zero_length_calls: u64,
};

const Wire = struct {
    alignment_histogram: []const AlignmentBucket,
    call_count: u64,
    clock_frame: []const u8,
    content_sha256: []const u8,
    distinct_alignment_count: usize,
    distinct_length_count: usize,
    elf_sha256: []const u8,
    execution_profile: []const u8,
    first_global_cycle: u64,
    first_segment_index: u32,
    input_sha256: []const u8,
    length_histogram: []const LengthBucket,
    maximum_requested_bytes: u32,
    memcpy_entry_pc: u32,
    production: bool,
    retired_instructions: u64,
    sampled_cycles: u64,
    schema: []const u8,
    segment_count: u32,
    source_sha256: []const u8,
    status: []const u8,
    total_requested_bytes: u64,
    validated_register_reads: u64,
    zero_length_calls: u64,
};

fn collectLengths(allocator: std.mem.Allocator, capture: *const Capture) ![]LengthBucket {
    const result = try allocator.alloc(LengthBucket, capture.lengths.count());
    var index: usize = 0;
    var iterator = capture.lengths.iterator();
    while (iterator.next()) |entry| : (index += 1) {
        result[index] = .{
            .call_count = entry.value_ptr.*,
            .length = entry.key_ptr.*,
            .total_bytes = try std.math.mul(u64, entry.key_ptr.*, entry.value_ptr.*),
        };
    }
    std.mem.sort(LengthBucket, result, {}, lessLength);
    return result;
}

fn collectAlignments(
    allocator: std.mem.Allocator,
    capture: *const Capture,
) ![]AlignmentBucket {
    const result = try allocator.alloc(AlignmentBucket, capture.alignments.count());
    var index: usize = 0;
    var iterator = capture.alignments.iterator();
    while (iterator.next()) |entry| : (index += 1) {
        result[index] = .{
            .call_count = entry.value_ptr.count,
            .destination_mod_16 = entry.key_ptr.* >> 4,
            .source_mod_16 = entry.key_ptr.* & 15,
            .total_bytes = entry.value_ptr.bytes,
        };
    }
    std.mem.sort(AlignmentBucket, result, {}, lessAlignment);
    return result;
}

fn lessLength(_: void, left: LengthBucket, right: LengthBucket) bool {
    return left.length < right.length;
}

fn lessAlignment(_: void, left: AlignmentBucket, right: AlignmentBucket) bool {
    return left.destination_mod_16 < right.destination_mod_16 or
        (left.destination_mod_16 == right.destination_mod_16 and
            left.source_mod_16 < right.source_mod_16);
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

fn readPathAlloc(
    allocator: std.mem.Allocator,
    path: []const u8,
    maximum_bytes: usize,
) ![]u8 {
    var file = if (std.fs.path.isAbsolute(path))
        try std.fs.openFileAbsolute(path, .{})
    else
        try std.fs.cwd().openFile(path, .{});
    defer file.close();
    return file.readToEndAlloc(allocator, maximum_bytes);
}

fn digest(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}
