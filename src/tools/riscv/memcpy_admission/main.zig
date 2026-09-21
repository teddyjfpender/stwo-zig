//! Exact retained-prefix admission and dynamic-row observation for the
//! nonproduction word-granular bulk memcpy candidate.
//!
//! The observer replays an authenticated V3 execution prefix, reconstructs
//! architectural registers, and measures each complete software `memcpy`
//! invocation from entry through its return.  It applies the exact candidate
//! predicate, including the stricter aligned-word-disjoint rule, and emits a
//! sealed diagnostic receipt.  It neither executes the custom instruction nor
//! makes a proof, verification, production, or whole-block timing claim.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const runner = frontend.runner;
const TraceRow = runner.trace.TraceRow;

const schema = "stwo.riscv.bulk-memcpy-admission-observation.v1";
const status = "captured-diagnostic-only";
const profile_name = "rv32im-zkvm-ethereum-v1";
const clock_frame = "leaf_local";
const predicate = "length>=32 && source_mod4==destination_mod4 && endpoints<=2^30 && byte_spans_disjoint && aligned_word_spans_disjoint";
const maximum_input_bytes: usize = 64 << 20;
const maximum_elf_bytes: usize = 64 << 20;
const maximum_journal_bytes: usize = 64 << 20;
const maximum_sample_segments: u32 = 64;
const data_address_limit: u32 = @as(u32, 1) << 30;

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
    const journal_sha256 = digest(journal);
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
        options.memcpy_entry_pc,
        elf_info.stack_pointer,
        elf_info.global_pointer,
    );
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
        capture,
        expected,
        elf_sha256,
        input_sha256,
        journal_sha256,
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

const Classification = enum {
    admitted,
    too_short,
    alignment_mismatch,
    endpoint_invalid,
    byte_overlap,
    aligned_word_overlap,
};

const CallObservation = struct {
    classification: Classification,
    length: u32,
    word_rows: u32,
    return_pc: u32,
    start_row: u64,
};

const Bucket = struct {
    calls: u64 = 0,
    requested_bytes: u64 = 0,
    software_rows: u64 = 0,
    word_rows: u64 = 0,

    fn add(self: *Bucket, call: CallObservation, software_rows: u64) !void {
        self.calls = try std.math.add(u64, self.calls, 1);
        self.requested_bytes = try std.math.add(
            u64,
            self.requested_bytes,
            call.length,
        );
        self.software_rows = try std.math.add(
            u64,
            self.software_rows,
            software_rows,
        );
        self.word_rows = try std.math.add(u64, self.word_rows, call.word_rows);
    }
};

const Capture = struct {
    memcpy_entry_pc: u32,
    registers: [32]u32,
    current: ?CallObservation = null,
    admitted: Bucket = .{},
    too_short: Bucket = .{},
    alignment_mismatch: Bucket = .{},
    endpoint_invalid: Bucket = .{},
    byte_overlap: Bucket = .{},
    aligned_word_overlap: Bucket = .{},
    current_segment_rows: usize = 0,
    completed_segment_rows: u64 = 0,
    rows_seen: u64 = 0,
    segment_count: u32 = 0,
    validated_register_reads: u64 = 0,

    fn init(memcpy_entry_pc: u32, stack_pointer: u32, global_pointer: u32) Capture {
        var registers = [_]u32{0} ** 32;
        registers[2] = stack_pointer;
        registers[3] = global_pointer;
        return .{
            .memcpy_entry_pc = memcpy_entry_pc,
            .registers = registers,
        };
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
        self.completed_segment_rows = try std.math.add(
            u64,
            self.completed_segment_rows,
            self.current_segment_rows,
        );
        self.current_segment_rows = 0;
        self.segment_count += 1;
    }

    fn observeRowOpaque(context: *anyopaque, row: TraceRow) !void {
        const self: *Capture = @ptrCast(@alignCast(context));
        if (self.current) |call| {
            if (row.pc == call.return_pc) {
                const software_rows = self.rows_seen - call.start_row;
                if (software_rows == 0) return error.InvalidMemcpyCallDuration;
                try self.finish(call, software_rows);
                self.current = null;
            }
        }
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
        if (row.pc == self.memcpy_entry_pc) {
            if (self.current != null) return error.RecursiveMemcpyUnavailable;
            self.current = classify(
                self.registers[10],
                self.registers[11],
                self.registers[12],
                self.registers[1],
                self.rows_seen,
            );
        }
        if (usage.writes_rd and row.rd != 0)
            self.registers[row.rd] = row.rd_val;
        self.registers[0] = 0;
        self.current_segment_rows = try std.math.add(
            usize,
            self.current_segment_rows,
            1,
        );
        self.rows_seen = try std.math.add(u64, self.rows_seen, 1);
    }

    fn finish(self: *Capture, call: CallObservation, software_rows: u64) !void {
        switch (call.classification) {
            .admitted => try self.admitted.add(call, software_rows),
            .too_short => try self.too_short.add(call, software_rows),
            .alignment_mismatch => try self.alignment_mismatch.add(call, software_rows),
            .endpoint_invalid => try self.endpoint_invalid.add(call, software_rows),
            .byte_overlap => try self.byte_overlap.add(call, software_rows),
            .aligned_word_overlap => try self.aligned_word_overlap.add(call, software_rows),
        }
    }

    fn totalRows(self: Capture) !u64 {
        return std.math.add(
            u64,
            self.completed_segment_rows,
            self.current_segment_rows,
        );
    }

    fn totalCalls(self: Capture) !u64 {
        var result: u64 = 0;
        inline for (.{
            self.admitted.calls,
            self.too_short.calls,
            self.alignment_mismatch.calls,
            self.endpoint_invalid.calls,
            self.byte_overlap.calls,
            self.aligned_word_overlap.calls,
        }) |value| result = try std.math.add(u64, result, value);
        return result;
    }

    fn totalSoftwareRows(self: Capture) !u64 {
        var result: u64 = 0;
        inline for (.{
            self.admitted.software_rows,
            self.too_short.software_rows,
            self.alignment_mismatch.software_rows,
            self.endpoint_invalid.software_rows,
            self.byte_overlap.software_rows,
            self.aligned_word_overlap.software_rows,
        }) |value| result = try std.math.add(u64, result, value);
        return result;
    }

    fn validate(self: Capture, expected_rows: u64, segments: usize) !void {
        if (self.current != null) return error.IncompleteMemcpyCall;
        if (self.segment_count != segments or
            try self.totalRows() != expected_rows or
            self.rows_seen != expected_rows or
            try self.totalCalls() == 0 or
            self.admitted.calls == 0 or
            self.admitted.software_rows < self.admitted.calls)
        {
            return error.ObserverExecutionMismatch;
        }
    }
};

fn classify(
    destination: u32,
    source: u32,
    length: u32,
    return_pc: u32,
    start_row: u64,
) CallObservation {
    var result = CallObservation{
        .classification = .admitted,
        .length = length,
        .word_rows = 0,
        .return_pc = return_pc,
        .start_row = start_row,
    };
    if (length < 32) {
        result.classification = .too_short;
        return result;
    }
    if ((destination ^ source) & 3 != 0) {
        result.classification = .alignment_mismatch;
        return result;
    }
    const destination_end = std.math.add(u32, destination, length) catch {
        result.classification = .endpoint_invalid;
        return result;
    };
    const source_end = std.math.add(u32, source, length) catch {
        result.classification = .endpoint_invalid;
        return result;
    };
    if (destination_end > data_address_limit or source_end > data_address_limit) {
        result.classification = .endpoint_invalid;
        return result;
    }
    if (!(source_end <= destination or destination_end <= source)) {
        result.classification = .byte_overlap;
        return result;
    }
    const start_offset = destination & 3;
    result.word_rows = (length + start_offset + 3) / 4;
    const source_first_word = source / 4;
    const destination_first_word = destination / 4;
    const source_word_end = std.math.add(
        u32,
        source_first_word,
        result.word_rows,
    ) catch {
        result.classification = .endpoint_invalid;
        return result;
    };
    const destination_word_end = std.math.add(
        u32,
        destination_first_word,
        result.word_rows,
    ) catch {
        result.classification = .endpoint_invalid;
        return result;
    };
    if (!(source_word_end <= destination_first_word or
        destination_word_end <= source_first_word))
    {
        result.classification = .aligned_word_overlap;
    }
    return result;
}

const BucketWire = struct {
    calls: u64,
    requested_bytes: u64,
    software_rows: u64,
    word_rows: u64,
};

fn bucketWire(bucket: Bucket) BucketWire {
    return .{
        .calls = bucket.calls,
        .requested_bytes = bucket.requested_bytes,
        .software_rows = bucket.software_rows,
        .word_rows = bucket.word_rows,
    };
}

const UnsignedWire = struct {
    admission_predicate: []const u8,
    admitted: BucketWire,
    aligned_word_overlap: BucketWire,
    alignment_mismatch: BucketWire,
    byte_overlap: BucketWire,
    clock_frame: []const u8,
    completed_call_count: u64,
    elf_sha256: []const u8,
    endpoint_invalid: BucketWire,
    execution_profile: []const u8,
    first_global_cycle: u64,
    first_segment_index: u32,
    input_sha256: []const u8,
    journal_sha256: []const u8,
    memcpy_entry_pc: u32,
    production: bool,
    removable_core_rows: u64,
    retired_instructions: u64,
    sampled_cycles: u64,
    schema: []const u8,
    segment_count: u32,
    status: []const u8,
    too_short: BucketWire,
    total_software_rows_in_memcpy: u64,
    validated_register_reads: u64,
};

const Wire = struct {
    admission_predicate: []const u8,
    admitted: BucketWire,
    aligned_word_overlap: BucketWire,
    alignment_mismatch: BucketWire,
    byte_overlap: BucketWire,
    clock_frame: []const u8,
    completed_call_count: u64,
    content_sha256: []const u8,
    elf_sha256: []const u8,
    endpoint_invalid: BucketWire,
    execution_profile: []const u8,
    first_global_cycle: u64,
    first_segment_index: u32,
    input_sha256: []const u8,
    journal_sha256: []const u8,
    memcpy_entry_pc: u32,
    production: bool,
    removable_core_rows: u64,
    retired_instructions: u64,
    sampled_cycles: u64,
    schema: []const u8,
    segment_count: u32,
    status: []const u8,
    too_short: BucketWire,
    total_software_rows_in_memcpy: u64,
    validated_register_reads: u64,
};

fn encodeObservation(
    allocator: std.mem.Allocator,
    capture: Capture,
    expected: JournalAuthority,
    elf_sha256: [32]u8,
    input_sha256: [32]u8,
    journal_sha256: [32]u8,
) ![]u8 {
    const elf_hex = std.fmt.bytesToHex(elf_sha256, .lower);
    const input_hex = std.fmt.bytesToHex(input_sha256, .lower);
    const journal_hex = std.fmt.bytesToHex(journal_sha256, .lower);
    const completed_calls = try capture.totalCalls();
    const total_software_rows = try capture.totalSoftwareRows();
    const removable = try std.math.sub(
        u64,
        capture.admitted.software_rows,
        capture.admitted.calls,
    );
    const unsigned = UnsignedWire{
        .admission_predicate = predicate,
        .admitted = bucketWire(capture.admitted),
        .aligned_word_overlap = bucketWire(capture.aligned_word_overlap),
        .alignment_mismatch = bucketWire(capture.alignment_mismatch),
        .byte_overlap = bucketWire(capture.byte_overlap),
        .clock_frame = clock_frame,
        .completed_call_count = completed_calls,
        .elf_sha256 = &elf_hex,
        .endpoint_invalid = bucketWire(capture.endpoint_invalid),
        .execution_profile = profile_name,
        .first_global_cycle = expected.first_global_cycle,
        .first_segment_index = 0,
        .input_sha256 = &input_hex,
        .journal_sha256 = &journal_hex,
        .memcpy_entry_pc = capture.memcpy_entry_pc,
        .production = false,
        .removable_core_rows = removable,
        .retired_instructions = expected.retired_instructions,
        .sampled_cycles = expected.sampled_cycles,
        .schema = schema,
        .segment_count = @intCast(expected.segments.len),
        .status = status,
        .too_short = bucketWire(capture.too_short),
        .total_software_rows_in_memcpy = total_software_rows,
        .validated_register_reads = capture.validated_register_reads,
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
        .admission_predicate = unsigned.admission_predicate,
        .admitted = unsigned.admitted,
        .aligned_word_overlap = unsigned.aligned_word_overlap,
        .alignment_mismatch = unsigned.alignment_mismatch,
        .byte_overlap = unsigned.byte_overlap,
        .clock_frame = unsigned.clock_frame,
        .completed_call_count = unsigned.completed_call_count,
        .content_sha256 = &content_hex,
        .elf_sha256 = unsigned.elf_sha256,
        .endpoint_invalid = unsigned.endpoint_invalid,
        .execution_profile = unsigned.execution_profile,
        .first_global_cycle = unsigned.first_global_cycle,
        .first_segment_index = unsigned.first_segment_index,
        .input_sha256 = unsigned.input_sha256,
        .journal_sha256 = unsigned.journal_sha256,
        .memcpy_entry_pc = unsigned.memcpy_entry_pc,
        .production = unsigned.production,
        .removable_core_rows = unsigned.removable_core_rows,
        .retired_instructions = unsigned.retired_instructions,
        .sampled_cycles = unsigned.sampled_cycles,
        .schema = unsigned.schema,
        .segment_count = unsigned.segment_count,
        .status = unsigned.status,
        .too_short = unsigned.too_short,
        .total_software_rows_in_memcpy = unsigned.total_software_rows_in_memcpy,
        .validated_register_reads = unsigned.validated_register_reads,
    };
    const body = try std.json.Stringify.valueAlloc(allocator, sealed, .{});
    defer allocator.free(body);
    const encoded = try allocator.alloc(u8, body.len + 1);
    @memcpy(encoded[0..body.len], body);
    encoded[body.len] = '\n';
    return encoded;
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

test "classifier matches aligned-word candidate boundary" {
    const admitted = classify(0x2000, 0x1000, 32, 4, 0);
    try std.testing.expectEqual(Classification.admitted, admitted.classification);
    try std.testing.expectEqual(@as(u32, 8), admitted.word_rows);

    const boundary_collision = classify(0x1021, 0x1001, 32, 4, 0);
    try std.testing.expectEqual(
        Classification.aligned_word_overlap,
        boundary_collision.classification,
    );
    const mismatch = classify(0x2000, 0x1001, 32, 4, 0);
    try std.testing.expectEqual(
        Classification.alignment_mismatch,
        mismatch.classification,
    );
}
