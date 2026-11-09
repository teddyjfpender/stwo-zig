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
const journal_support = @import("observation_journal");
const JournalAuthority = journal_support.JournalAuthority;
const readPathAlloc = journal_support.readPathAlloc;
const digest = journal_support.digest;
const Options = @import("options.zig").Options;
const classifier = @import("classifier.zig");
const Classification = classifier.Classification;
const CallObservation = classifier.CallObservation;
const classify = classifier.classify;
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

pub fn run(allocator: std.mem.Allocator, arguments: []const []const u8) !void {
    const options = try Options.parse(arguments);

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
