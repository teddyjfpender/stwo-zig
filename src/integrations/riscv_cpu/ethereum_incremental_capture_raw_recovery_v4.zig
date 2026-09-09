//! Typed recovery authority for a complete raw-only V4 capture checkpoint.
//!
//! A failed live observer may leave every create-only STWEMT01/STWIPW04 pair
//! while never publishing its diagnostic guest-PC profile or compact JSON
//! manifest. Each compact tape is sufficient for an independent typed replay.
//! Recovery therefore cold-opens and replays every raw pair, rebuilds the
//! ordinary guest-PC profile from actual retired rows, and seals this distinct
//! ordered manifest. No timing, host, or fabricated attribution is admitted.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const authority_mod =
    @import("ethereum_incremental_capture_postprocess_authority_v4.zig");
const guest_profile = @import("ethereum_guest_pc_profile.zig");
const publication = @import("ethereum_incremental_capture_publication_v4.zig");

const minimal = frontend.runner.minimal_trace;
const public_data = frontend.air.public_data;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 4;
pub const MANIFEST_MAGIC = [8]u8{ 'S', 'T', 'W', 'I', 'R', 'M', '0', '4' };
pub const manifest_basename = "incremental-raw-recovery-manifest.stwirm04";
pub const PRODUCTION_ACTIVE = false;
pub const PC_ATTRIBUTION_REPLAYED_FROM_COLD_RAW = true;
pub const VM_REEXECUTION_REQUIRED = false;

const manifest_domain =
    "stwo.ethereum.incremental-raw-recovery-manifest.v4\x00";
const identity_bytes: usize = 8 + 32;
const execution_bytes: usize = identity_bytes * 3 + 32 + 4 + 8 + 4 + 4;
const record_bytes: usize = 552;
const manifest_prefix_bytes: usize = 8 + 2 + 2 + execution_bytes +
    identity_bytes * 4 + 32 + 32 + 4;
pub const manifest_max_byte_count: usize = manifest_prefix_bytes +
    record_bytes * publication.MAX_SEGMENT_COUNT + 32;

/// One cold-reconstructed raw segment. `role_completion` is deliberately
/// distinct from the SegmentV2 completion: nonfinal records bind the exact
/// declared-program fetch derived from the admitted ELF.
pub const SegmentRecordV4 = struct {
    segment_index: u32,
    segment_count: u32,
    global_first_cycle: u64,
    cycle_count: u32,
    core_cycle_count: u32,
    keccak_call_count: u32,
    recovery_call_count: u32,
    role_completion: public_data.Completion,
    compact_tape: publication.ArtifactIdentityV4,
    public_wire: publication.ArtifactIdentityV4,
    source: publication.ArtifactIdentityV4,
    journal_record_sha256: [32]u8,
    program_identity_sha256: [32]u8,
    input_identity_sha256: [32]u8,
    session_identity_sha256: [32]u8,
    entry_memory_sha256: [32]u8,
    exit_memory_sha256: [32]u8,
    entry_boundary_sha256: [32]u8,
    exit_boundary_sha256: [32]u8,
    entry_cpu_sha256: [32]u8,
    exit_cpu_sha256: [32]u8,
    leaf_seal_sha256: [32]u8,
    public_wire_id: [8]u32,

    pub fn init(
        input: *const authority_mod.OwnedMintInputV4,
        execution: publication.ExecutionAuthorityV4,
    ) !SegmentRecordV4 {
        try input.validate(execution);
        const leaf = &input.compact.leaf;
        const role_completion = input.publicAuthority().public_data
            .completion orelse return error.MissingCompletion;
        const result = SegmentRecordV4{
            .segment_index = input.segment_index,
            .segment_count = input.segment_count,
            .global_first_cycle = leaf.global_first_cycle,
            .cycle_count = leaf.cycle_count,
            .core_cycle_count = leaf.core_cycle_count,
            .keccak_call_count = @intCast(leaf.keccak_records.len),
            .recovery_call_count = @intCast(leaf.recovery_records.len),
            .role_completion = role_completion,
            .compact_tape = input.compact_identity,
            .public_wire = input.wire_identity,
            .source = input.source_identity,
            .journal_record_sha256 = input.journal_record_sha256,
            .program_identity_sha256 = leaf.source.program,
            .input_identity_sha256 = leaf.source.input,
            .session_identity_sha256 = leaf.source.session,
            .entry_memory_sha256 = leaf.source.entry_memory,
            .exit_memory_sha256 = leaf.source.exit_memory,
            .entry_boundary_sha256 = leaf.entry_boundary,
            .exit_boundary_sha256 = leaf.exit_boundary,
            .entry_cpu_sha256 = minimal.ethereumCpuIdentity(leaf.entry_cpu),
            .exit_cpu_sha256 = minimal.ethereumCpuIdentity(leaf.exit_cpu),
            .leaf_seal_sha256 = leaf.seal,
            .public_wire_id = input.wire.data.wireId(),
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: SegmentRecordV4) !void {
        try self.compact_tape.validate(false);
        try self.public_wire.validate(false);
        try self.source.validate(false);
        const calls = std.math.add(
            u32,
            self.keccak_call_count,
            self.recovery_call_count,
        ) catch return error.InvalidIncrementalRawRecoveryRecordV4;
        const expected_cycles = std.math.add(
            u32,
            self.core_cycle_count,
            calls,
        ) catch return error.InvalidIncrementalRawRecoveryRecordV4;
        if (self.segment_count < 2 or self.segment_index >= self.segment_count or
            self.global_first_cycle == 0 or self.cycle_count == 0 or
            expected_cycles != self.cycle_count or
            allZero(&self.journal_record_sha256) or
            allZero(&self.program_identity_sha256) or
            allZero(&self.input_identity_sha256) or
            allZero(&self.session_identity_sha256) or
            allZero(&self.entry_memory_sha256) or
            allZero(&self.exit_memory_sha256) or
            allZero(&self.entry_boundary_sha256) or
            allZero(&self.exit_boundary_sha256) or
            allZero(&self.entry_cpu_sha256) or
            allZero(&self.exit_cpu_sha256) or
            allZero(&self.leaf_seal_sha256) or
            allZero(std.mem.asBytes(&self.public_wire_id)))
        {
            return error.InvalidIncrementalRawRecoveryRecordV4;
        }
        const is_final = self.segment_index + 1 == self.segment_count;
        switch (self.role_completion.kind) {
            .unretired_program_fetch => if (is_final or
                self.role_completion.clock != 0)
            {
                return error.InvalidIncrementalRawRecoveryRoleV4;
            },
            .halt_flag, .unretired_self_loop => if (!is_final) {
                return error.InvalidIncrementalRawRecoveryRoleV4;
            },
        }
        if (self.role_completion.kind == .unretired_self_loop and
            (self.role_completion.value != public_data.CANONICAL_SELF_LOOP_WORD or
                self.role_completion.clock != 0))
        {
            return error.InvalidIncrementalRawRecoveryRoleV4;
        }
    }
};

/// Result of a genuine compact replay. The local profiler can be merged only
/// into another profiler constructed from the same admitted ELF.
pub const OwnedSegmentRecoveryV4 = struct {
    profiler: guest_profile.Profiler,
    record: SegmentRecordV4,

    pub fn deinit(self: *OwnedSegmentRecoveryV4) void {
        self.profiler.deinit();
        self.* = undefined;
    }

    pub fn mergeInto(
        self: *const OwnedSegmentRecoveryV4,
        destination: *guest_profile.Profiler,
    ) !void {
        if (destination.text_start != self.profiler.text_start or
            destination.text_end != self.profiler.text_end or
            destination.core_counts.len != self.profiler.core_counts.len or
            destination.external_counts.len !=
                self.profiler.external_counts.len or
            !std.mem.eql(
                u32,
                destination.slot_symbols,
                self.profiler.slot_symbols,
            )) return error.IncrementalRawRecoveryProfileLayoutMismatchV4;
        for (
            destination.core_counts,
            self.profiler.core_counts,
        ) |*target, value| target.* = try add(target.*, value);
        for (
            destination.external_counts,
            self.profiler.external_counts,
        ) |*target, value| target.* = try add(target.*, value);
        for (
            &destination.family_calls,
            self.profiler.family_calls,
        ) |*target, value| target.* = try add(target.*, value);
        for (
            &destination.family_execution_rows,
            self.profiler.family_execution_rows,
        ) |*target, value| target.* = try add(target.*, value);
        destination.out_of_text_core_rows = try add(
            destination.out_of_text_core_rows,
            self.profiler.out_of_text_core_rows,
        );
        destination.out_of_text_external_calls = try add(
            destination.out_of_text_external_calls,
            self.profiler.out_of_text_external_calls,
        );
    }
};

/// Runs the same typed compact replay used by the native-leaf producer. The
/// request fields are admitted by `OwnedMintInputV4.validate` before any value
/// from the resealable compact tape is reused as an expected replay value.
pub fn replayAndAttribute(
    allocator: std.mem.Allocator,
    input: *const authority_mod.OwnedMintInputV4,
    execution: publication.ExecutionAuthorityV4,
    elf_bytes: []const u8,
) !OwnedSegmentRecoveryV4 {
    try input.validate(execution);
    const program = try minimal.SliceProgram.init(input.program_source.words);
    if (!std.mem.eql(
        u8,
        &program.identity,
        &input.program_source.identity,
    )) return error.IncrementalRawRecoveryProgramMismatchV4;
    var boundary = try minimal.SliceBoundary.init(input.compact.boundary_words);
    var replay = try minimal.replayEthereumLeaf(allocator, .{
        .leaf = &input.compact.leaf,
        .program = program.source(),
        .boundary = boundary.source(),
        .expected_memory_layout = input.layout,
        .expected_source = input.replay_authority.source,
        .expected_entry_cpu_sha256 = input.replay_authority.entry_cpu_sha256,
        .expected_exit_cpu_sha256 = input.replay_authority.exit_cpu_sha256,
        .expected_completion = input.replay_authority.completion,
    });
    defer replay.deinit();
    var profiler = try guest_profile.Profiler.init(allocator, elf_bytes);
    errdefer profiler.deinit();
    try profiler.observeCoreRows(replay.execution_trace.rows.items);
    try profiler.observeExternalRecords(
        .keccakf,
        replay.keccakf_calls.records(),
        replay.keccakf_execution_rows.rows().len,
    );
    try profiler.observeExternalRecords(
        .secp256k1_recover,
        replay.signer_recovery_calls.records(),
        replay.signer_recovery_execution_rows.rows().len,
    );
    return .{
        .profiler = profiler,
        .record = try SegmentRecordV4.init(input, execution),
    };
}

/// Canonical aggregate for a replay-recovered normal guest-PC receipt and the
/// exact ordered cold-opened raw inventory which produced it.
pub const ManifestV4 = struct {
    execution: publication.ExecutionAuthorityV4,
    materialization_result: publication.ArtifactIdentityV4,
    source_request: publication.ArtifactIdentityV4,
    journal: publication.ArtifactIdentityV4,
    execution_profile_receipt: publication.ArtifactIdentityV4,
    program_identity_sha256: [32]u8,
    session_identity_sha256: [32]u8,
    segment_count: u32,
    records: []const SegmentRecordV4,
    content_sha256: [32]u8,

    pub fn seal(value: ManifestV4) !ManifestV4 {
        var result = value;
        result.content_sha256 = manifestIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const ManifestV4) !void {
        try self.execution.validate();
        try self.materialization_result.validate(false);
        try self.source_request.validate(false);
        try self.journal.validate(false);
        try self.execution_profile_receipt.validate(false);
        const session = try self.execution.sessionIdentity();
        if (self.segment_count != self.execution.segment_count or
            self.records.len != self.segment_count or
            allZero(&self.program_identity_sha256) or
            !std.mem.eql(u8, &session, &self.session_identity_sha256) or
            !std.mem.eql(u8, &manifestIdentity(self), &self.content_sha256))
        {
            return error.InvalidIncrementalRawRecoveryManifestV4;
        }
        var next_cycle: u64 = 1;
        var prior: ?SegmentRecordV4 = null;
        for (self.records, 0..) |record, ordinal| {
            try record.validate();
            if (record.segment_index != ordinal or
                record.segment_count != self.segment_count or
                record.global_first_cycle != next_cycle or
                !std.mem.eql(
                    u8,
                    &record.program_identity_sha256,
                    &self.program_identity_sha256,
                ) or !std.mem.eql(
                u8,
                &record.input_identity_sha256,
                &self.execution.input.sha256,
            ) or !std.mem.eql(
                u8,
                &record.session_identity_sha256,
                &self.session_identity_sha256,
            )) return error.InvalidIncrementalRawRecoveryChainV4;
            if (prior) |previous| {
                if (!std.mem.eql(
                    u8,
                    &previous.exit_memory_sha256,
                    &record.entry_memory_sha256,
                ) or !std.mem.eql(
                    u8,
                    &previous.exit_cpu_sha256,
                    &record.entry_cpu_sha256,
                )) return error.InvalidIncrementalRawRecoveryChainV4;
            }
            next_cycle = std.math.add(
                u64,
                next_cycle,
                record.cycle_count,
            ) catch return error.InvalidIncrementalRawRecoveryChainV4;
            prior = record;
        }
    }
};

pub const OwnedManifestV4 = struct {
    allocator: std.mem.Allocator,
    value: ManifestV4,

    pub fn deinit(self: *OwnedManifestV4) void {
        self.allocator.free(self.value.records);
        self.* = undefined;
    }
};

pub fn encodeManifestAlloc(
    allocator: std.mem.Allocator,
    value: *const ManifestV4,
) ![]u8 {
    try value.validate();
    const byte_count = std.math.add(
        usize,
        manifest_prefix_bytes + 32,
        std.math.mul(usize, value.records.len, record_bytes) catch
            return error.InvalidIncrementalRawRecoveryEncodingV4,
    ) catch return error.InvalidIncrementalRawRecoveryEncodingV4;
    if (byte_count > manifest_max_byte_count)
        return error.InvalidIncrementalRawRecoveryEncodingV4;
    const bytes = try allocator.alloc(u8, byte_count);
    errdefer allocator.free(bytes);
    var writer = Writer.init(bytes);
    writer.raw(&MANIFEST_MAGIC);
    writer.int(u16, FORMAT_VERSION);
    writer.int(u16, SCHEMA_VERSION);
    writeExecution(&writer, value.execution);
    writeIdentity(&writer, value.materialization_result);
    writeIdentity(&writer, value.source_request);
    writeIdentity(&writer, value.journal);
    writeIdentity(&writer, value.execution_profile_receipt);
    writer.raw(&value.program_identity_sha256);
    writer.raw(&value.session_identity_sha256);
    writer.int(u32, value.segment_count);
    for (value.records) |record| writeRecord(&writer, record);
    writer.raw(&value.content_sha256);
    std.debug.assert(writer.at == bytes.len);
    return bytes;
}

pub fn decodeManifestAlloc(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !OwnedManifestV4 {
    if (bytes.len < manifest_prefix_bytes + record_bytes * 2 + 32 or
        bytes.len > manifest_max_byte_count)
    {
        return error.InvalidIncrementalRawRecoveryEncodingV4;
    }
    var reader = Reader.init(bytes);
    try reader.magic(MANIFEST_MAGIC);
    if (try reader.int(u16) != FORMAT_VERSION or
        try reader.int(u16) != SCHEMA_VERSION)
    {
        return error.InvalidIncrementalRawRecoveryEncodingV4;
    }
    const execution = try readExecution(&reader);
    const materialization_result = try readIdentity(&reader);
    const source_request = try readIdentity(&reader);
    const journal = try readIdentity(&reader);
    const execution_profile_receipt = try readIdentity(&reader);
    const program_identity_sha256 = try reader.array(32);
    const session_identity_sha256 = try reader.array(32);
    const segment_count = try reader.int(u32);
    if (segment_count < 2 or segment_count > publication.MAX_SEGMENT_COUNT)
        return error.InvalidIncrementalRawRecoveryEncodingV4;
    const expected_bytes = manifest_prefix_bytes +
        @as(usize, segment_count) * record_bytes + 32;
    if (bytes.len != expected_bytes)
        return error.InvalidIncrementalRawRecoveryEncodingV4;
    const records = try allocator.alloc(SegmentRecordV4, segment_count);
    errdefer allocator.free(records);
    for (records) |*record| record.* = try readRecord(&reader);
    const content_sha256 = try reader.array(32);
    try reader.finish();
    const result = OwnedManifestV4{
        .allocator = allocator,
        .value = .{
            .execution = execution,
            .materialization_result = materialization_result,
            .source_request = source_request,
            .journal = journal,
            .execution_profile_receipt = execution_profile_receipt,
            .program_identity_sha256 = program_identity_sha256,
            .session_identity_sha256 = session_identity_sha256,
            .segment_count = segment_count,
            .records = records,
            .content_sha256 = content_sha256,
        },
    };
    // `records` remains the sole cleanup owner until successful return. Do
    // not also arm `result.deinit()` here: validation failure would otherwise
    // free the same allocation through both active errdefers.
    try result.value.validate();
    return result;
}

fn manifestIdentity(value: *const ManifestV4) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(manifest_domain);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashExecution(&hash, value.execution);
    hashIdentity(&hash, value.materialization_result);
    hashIdentity(&hash, value.source_request);
    hashIdentity(&hash, value.journal);
    hashIdentity(&hash, value.execution_profile_receipt);
    hash.update(&value.program_identity_sha256);
    hash.update(&value.session_identity_sha256);
    hashInt(&hash, u32, value.segment_count);
    for (value.records) |record| hashRecord(&hash, record);
    return hash.finalResult();
}

fn writeRecord(writer: *Writer, value: SegmentRecordV4) void {
    writer.int(u32, value.segment_index);
    writer.int(u32, value.segment_count);
    writer.int(u64, value.global_first_cycle);
    writer.int(u32, value.cycle_count);
    writer.int(u32, value.core_cycle_count);
    writer.int(u32, value.keccak_call_count);
    writer.int(u32, value.recovery_call_count);
    writeCompletion(writer, value.role_completion);
    writeIdentity(writer, value.compact_tape);
    writeIdentity(writer, value.public_wire);
    writeIdentity(writer, value.source);
    writer.raw(&value.journal_record_sha256);
    writer.raw(&value.program_identity_sha256);
    writer.raw(&value.input_identity_sha256);
    writer.raw(&value.session_identity_sha256);
    writer.raw(&value.entry_memory_sha256);
    writer.raw(&value.exit_memory_sha256);
    writer.raw(&value.entry_boundary_sha256);
    writer.raw(&value.exit_boundary_sha256);
    writer.raw(&value.entry_cpu_sha256);
    writer.raw(&value.exit_cpu_sha256);
    writer.raw(&value.leaf_seal_sha256);
    for (value.public_wire_id) |word| writer.int(u32, word);
}

fn readRecord(reader: *Reader) !SegmentRecordV4 {
    return .{
        .segment_index = try reader.int(u32),
        .segment_count = try reader.int(u32),
        .global_first_cycle = try reader.int(u64),
        .cycle_count = try reader.int(u32),
        .core_cycle_count = try reader.int(u32),
        .keccak_call_count = try reader.int(u32),
        .recovery_call_count = try reader.int(u32),
        .role_completion = try readCompletion(reader),
        .compact_tape = try readIdentity(reader),
        .public_wire = try readIdentity(reader),
        .source = try readIdentity(reader),
        .journal_record_sha256 = try reader.array(32),
        .program_identity_sha256 = try reader.array(32),
        .input_identity_sha256 = try reader.array(32),
        .session_identity_sha256 = try reader.array(32),
        .entry_memory_sha256 = try reader.array(32),
        .exit_memory_sha256 = try reader.array(32),
        .entry_boundary_sha256 = try reader.array(32),
        .exit_boundary_sha256 = try reader.array(32),
        .entry_cpu_sha256 = try reader.array(32),
        .exit_cpu_sha256 = try reader.array(32),
        .leaf_seal_sha256 = try reader.array(32),
        .public_wire_id = try readDigest(reader),
    };
}

fn hashRecord(hash: *Sha256, value: SegmentRecordV4) void {
    hashInt(hash, u32, value.segment_index);
    hashInt(hash, u32, value.segment_count);
    hashInt(hash, u64, value.global_first_cycle);
    hashInt(hash, u32, value.cycle_count);
    hashInt(hash, u32, value.core_cycle_count);
    hashInt(hash, u32, value.keccak_call_count);
    hashInt(hash, u32, value.recovery_call_count);
    hashCompletion(hash, value.role_completion);
    hashIdentity(hash, value.compact_tape);
    hashIdentity(hash, value.public_wire);
    hashIdentity(hash, value.source);
    hash.update(&value.journal_record_sha256);
    hash.update(&value.program_identity_sha256);
    hash.update(&value.input_identity_sha256);
    hash.update(&value.session_identity_sha256);
    hash.update(&value.entry_memory_sha256);
    hash.update(&value.exit_memory_sha256);
    hash.update(&value.entry_boundary_sha256);
    hash.update(&value.exit_boundary_sha256);
    hash.update(&value.entry_cpu_sha256);
    hash.update(&value.exit_cpu_sha256);
    hash.update(&value.leaf_seal_sha256);
    for (value.public_wire_id) |word| hashInt(hash, u32, word);
}

fn writeExecution(writer: *Writer, value: publication.ExecutionAuthorityV4) void {
    writeIdentity(writer, value.elf);
    writeIdentity(writer, value.input);
    writeIdentity(writer, value.expected_output);
    writer.raw(&value.execution_profile_semantic_sha256);
    writer.int(u32, value.segment_count);
    writer.int(u64, value.segment_step_budget);
    writer.int(u32, value.clock_frame);
    writer.int(u32, value.strict_completion);
}

fn readExecution(reader: *Reader) !publication.ExecutionAuthorityV4 {
    return .{
        .elf = try readIdentity(reader),
        .input = try readIdentity(reader),
        .expected_output = try readIdentity(reader),
        .execution_profile_semantic_sha256 = try reader.array(32),
        .segment_count = try reader.int(u32),
        .segment_step_budget = try reader.int(u64),
        .clock_frame = try reader.int(u32),
        .strict_completion = try reader.int(u32),
    };
}

fn hashExecution(hash: *Sha256, value: publication.ExecutionAuthorityV4) void {
    hashIdentity(hash, value.elf);
    hashIdentity(hash, value.input);
    hashIdentity(hash, value.expected_output);
    hash.update(&value.execution_profile_semantic_sha256);
    hashInt(hash, u32, value.segment_count);
    hashInt(hash, u64, value.segment_step_budget);
    hashInt(hash, u32, value.clock_frame);
    hashInt(hash, u32, value.strict_completion);
}

fn writeIdentity(writer: *Writer, value: publication.ArtifactIdentityV4) void {
    writer.int(u64, value.byte_count);
    writer.raw(&value.sha256);
}

fn readIdentity(reader: *Reader) !publication.ArtifactIdentityV4 {
    return .{
        .byte_count = try reader.int(u64),
        .sha256 = try reader.array(32),
    };
}

fn hashIdentity(hash: *Sha256, value: publication.ArtifactIdentityV4) void {
    hashInt(hash, u64, value.byte_count);
    hash.update(&value.sha256);
}

fn writeCompletion(writer: *Writer, value: public_data.Completion) void {
    writer.int(u32, @intFromEnum(value.kind));
    writer.int(u32, value.address);
    writer.int(u32, value.value);
    writer.int(u32, value.clock);
}

fn readCompletion(reader: *Reader) !public_data.Completion {
    return .{
        .kind = std.meta.intToEnum(
            public_data.CompletionKind,
            try reader.int(u32),
        ) catch return error.InvalidIncrementalRawRecoveryEncodingV4,
        .address = try reader.int(u32),
        .value = try reader.int(u32),
        .clock = try reader.int(u32),
    };
}

fn hashCompletion(hash: *Sha256, value: public_data.Completion) void {
    hashInt(hash, u32, @intFromEnum(value.kind));
    hashInt(hash, u32, value.address);
    hashInt(hash, u32, value.value);
    hashInt(hash, u32, value.clock);
}

fn readDigest(reader: *Reader) ![8]u32 {
    var result: [8]u32 = undefined;
    for (&result) |*word| word.* = try reader.int(u32);
    return result;
}

const Writer = struct {
    bytes: []u8,
    at: usize = 0,

    fn init(bytes: []u8) Writer {
        return .{ .bytes = bytes };
    }

    fn raw(self: *Writer, value: []const u8) void {
        @memcpy(self.bytes[self.at..][0..value.len], value);
        self.at += value.len;
    }

    fn int(self: *Writer, comptime T: type, value: anytype) void {
        var encoded: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &encoded, @intCast(value), .little);
        self.raw(&encoded);
    }
};

const Reader = struct {
    bytes: []const u8,
    at: usize = 0,

    fn init(bytes: []const u8) Reader {
        return .{ .bytes = bytes };
    }

    fn take(self: *Reader, count: usize) ![]const u8 {
        if (self.at > self.bytes.len or count > self.bytes.len - self.at)
            return error.InvalidIncrementalRawRecoveryEncodingV4;
        const result = self.bytes[self.at..][0..count];
        self.at += count;
        return result;
    }

    fn magic(self: *Reader, expected: [8]u8) !void {
        if (!std.mem.eql(u8, try self.take(8), &expected))
            return error.InvalidIncrementalRawRecoveryEncodingV4;
    }

    fn int(self: *Reader, comptime T: type) !T {
        const bytes = try self.take(@sizeOf(T));
        const pointer: *const [@sizeOf(T)]u8 = @ptrCast(bytes.ptr);
        return std.mem.readInt(T, pointer, .little);
    }

    fn array(self: *Reader, comptime count: usize) ![count]u8 {
        var result: [count]u8 = undefined;
        @memcpy(&result, try self.take(count));
        return result;
    }

    fn finish(self: *Reader) !void {
        if (self.at != self.bytes.len)
            return error.InvalidIncrementalRawRecoveryEncodingV4;
    }
};

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

fn add(left: u64, right: u64) !u64 {
    return std.math.add(u64, left, right) catch
        error.IncrementalRawRecoveryProfileOverflowV4;
}

fn allZero(bytes: []const u8) bool {
    return std.mem.allEqual(u8, bytes, 0);
}

comptime {
    if (manifest_prefix_bytes != 412 or record_bytes != 552 or
        FORMAT_VERSION != 1 or SCHEMA_VERSION != 4 or PRODUCTION_ACTIVE or
        !PC_ATTRIBUTION_REPLAYED_FROM_COLD_RAW or VM_REEXECUTION_REQUIRED)
    {
        @compileError("incremental raw recovery V4 contract drifted");
    }
}
