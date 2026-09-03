//! Canonical custody and timing receipt for compact Ethereum replay leaves.
//!
//! This is diagnostic execution evidence, never a proof or recursive
//! publication. Every artifact is create-only and byte-addressed; the ordered
//! manifest additionally binds the exact execution/source authorities and the
//! independently emitted guest-PC profile receipt.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");

const Cpu = frontend.runner.Cpu;
pub const CompletionV1 = frontend.runner.minimal_trace.CompletionV1;

pub const schema =
    "stwo.ethereum.block-compact-replay-materialization.v1";
pub const status = "captured-diagnostic-only";
pub const artifact_magic = "STWEMT01";
pub const max_manifest_bytes: usize = 64 * 1024 * 1024;
const session_domain =
    "stwo-zig/riscv/ethereum-minimal-materialization-session/v1\x00";
const artifact_chain_domain =
    "stwo-zig/riscv/ethereum-minimal-artifact-chain/v1\x00";

pub const StageTimings = struct {
    capture_wall_ns: u64,
    encode_wall_ns: u64,
    observer_wall_ns: u64,
    pc_attribution_wall_ns: u64,
    post_execution_authority_wall_ns: u64,
    publish_wall_ns: u64,
    stream_observed_wall_ns: u64,
    pre_manifest_materialization_wall_ns: u64,

    pub fn validate(self: StageTimings) !void {
        const classified_observer = try add(
            try add(self.capture_wall_ns, self.encode_wall_ns),
            try add(self.publish_wall_ns, self.pc_attribution_wall_ns),
        );
        if (self.stream_observed_wall_ns == 0 or
            self.pre_manifest_materialization_wall_ns == 0 or
            self.observer_wall_ns < classified_observer or
            self.stream_observed_wall_ns < self.observer_wall_ns or
            self.pre_manifest_materialization_wall_ns < try add(
                self.stream_observed_wall_ns,
                self.post_execution_authority_wall_ns,
            ))
        {
            return error.InvalidCompactStageTimings;
        }
    }
};

pub const Artifact = struct {
    artifact: contract.Identity,
    capture_wall_ns: u64,
    completion: ?CompletionV1,
    core_cycle_count: u32,
    cycle_count: u32,
    encode_wall_ns: u64,
    entry_boundary_sha256: []const u8,
    entry_cpu_sha256: []const u8,
    entry_memory_sha256: []const u8,
    exit_boundary_sha256: []const u8,
    exit_cpu_sha256: []const u8,
    exit_memory_sha256: []const u8,
    global_first_cycle: u64,
    keccak_calls: u32,
    leaf_seal_sha256: []const u8,
    publish_wall_ns: u64,
    recovery_calls: u32,
    segment_index: u32,

    pub fn validate(self: Artifact, index: usize, count: usize) !void {
        try self.artifact.validate(false);
        inline for (.{
            self.entry_boundary_sha256,
            self.entry_cpu_sha256,
            self.entry_memory_sha256,
            self.exit_boundary_sha256,
            self.exit_cpu_sha256,
            self.exit_memory_sha256,
            self.leaf_seal_sha256,
        }) |digest| _ = try contract.parseSha256(digest);
        if (self.segment_index != index or self.global_first_cycle == 0 or
            self.cycle_count == 0 or
            self.core_cycle_count > self.cycle_count or
            (self.completion != null) != (index + 1 == count) or
            try add(self.keccak_calls, self.recovery_calls) !=
                self.cycle_count - self.core_cycle_count)
        {
            return error.InvalidCompactArtifactRecord;
        }
        if (self.completion) |completion| try validateCompletion(completion);
    }
};

pub const Receipt = struct {
    content_sha256: []const u8,
    artifact_chain_sha256: []const u8,
    artifact_format_version: u16,
    artifact_magic: []const u8,
    artifacts: []const Artifact,
    clock_frame: []const u8,
    elf: contract.Identity,
    execution_journal: contract.Identity,
    execution_profile: []const u8,
    execution_profile_abi_version: u16,
    execution_profile_receipt: contract.Identity,
    execution_profile_semantic_sha256: []const u8,
    expected_output: contract.Identity,
    input: contract.Identity,
    materialization_result: contract.Identity,
    materializer_executable_sha256: []const u8,
    program_sha256: []const u8,
    segment_count: u32,
    segment_step_budget: u64,
    session_sha256: []const u8,
    source_request: contract.Identity,
    stage_timings: StageTimings,
    status: []const u8,
    total_artifact_bytes: u64,
    total_core_cycles: u64,
    total_cycles: u64,
    total_keccak_calls: u64,
    total_recovery_calls: u64,
    schema: []const u8,

    pub fn validate(self: Receipt) !void {
        if (!std.mem.eql(u8, self.schema, schema) or
            !std.mem.eql(u8, self.status, status) or
            !std.mem.eql(u8, self.artifact_magic, artifact_magic) or
            !std.mem.eql(u8, self.clock_frame, contract.clock_frame) or
            !std.mem.eql(u8, self.execution_profile, contract.profile_name) or
            self.execution_profile_abi_version !=
                inputExecutionProfileAbiVersion() or
            self.artifact_format_version != 1 or self.segment_count < 2 or
            self.segment_step_budget == 0 or
            self.artifacts.len != self.segment_count)
        {
            return error.InvalidCompactManifest;
        }
        try self.elf.validate(false);
        try self.execution_journal.validate(false);
        try self.execution_profile_receipt.validate(false);
        try self.expected_output.validate(false);
        try self.input.validate(true);
        try self.materialization_result.validate(false);
        try self.source_request.validate(false);
        inline for (.{
            self.content_sha256,
            self.artifact_chain_sha256,
            self.execution_profile_semantic_sha256,
            self.materializer_executable_sha256,
            self.program_sha256,
            self.session_sha256,
        }) |digest| _ = try contract.parseSha256(digest);
        try self.stage_timings.validate();

        var artifact_bytes: u64 = 0;
        var core_cycles: u64 = 0;
        var cycles: u64 = 0;
        var keccak_calls: u64 = 0;
        var recovery_calls: u64 = 0;
        var capture_wall_ns: u64 = 0;
        var encode_wall_ns: u64 = 0;
        var publish_wall_ns: u64 = 0;
        var expected_global_first_cycle: u64 = 1;
        for (self.artifacts, 0..) |artifact, index| {
            try artifact.validate(index, self.artifacts.len);
            if (artifact.global_first_cycle != expected_global_first_cycle)
                return error.InvalidCompactArtifactRecord;
            expected_global_first_cycle = try add(
                expected_global_first_cycle,
                artifact.cycle_count,
            );
            artifact_bytes = try add(artifact_bytes, artifact.artifact.bytes);
            core_cycles = try add(core_cycles, artifact.core_cycle_count);
            cycles = try add(cycles, artifact.cycle_count);
            keccak_calls = try add(keccak_calls, artifact.keccak_calls);
            recovery_calls = try add(recovery_calls, artifact.recovery_calls);
            capture_wall_ns = try add(
                capture_wall_ns,
                artifact.capture_wall_ns,
            );
            encode_wall_ns = try add(encode_wall_ns, artifact.encode_wall_ns);
            publish_wall_ns = try add(
                publish_wall_ns,
                artifact.publish_wall_ns,
            );
            if (index != 0 and !std.mem.eql(
                u8,
                self.artifacts[index - 1].exit_memory_sha256,
                artifact.entry_memory_sha256,
            )) return error.InvalidCompactMemoryContinuation;
            if (index != 0 and !std.mem.eql(
                u8,
                self.artifacts[index - 1].exit_cpu_sha256,
                artifact.entry_cpu_sha256,
            )) return error.InvalidCompactCpuContinuation;
        }
        if (artifact_bytes != self.total_artifact_bytes or
            core_cycles != self.total_core_cycles or
            cycles != self.total_cycles or
            keccak_calls != self.total_keccak_calls or
            recovery_calls != self.total_recovery_calls or
            capture_wall_ns != self.stage_timings.capture_wall_ns or
            encode_wall_ns != self.stage_timings.encode_wall_ns or
            publish_wall_ns != self.stage_timings.publish_wall_ns)
        {
            return error.InvalidCompactManifestTotals;
        }
        const expected_chain = try artifactChainReceipt(self.artifacts);
        if (!std.mem.eql(u8, &hex(expected_chain), self.artifact_chain_sha256))
            return error.InvalidCompactArtifactChain;
    }
};

pub const ArtifactInput = struct {
    artifact: evidence.FileIdentity,
    capture_wall_ns: u64,
    completion: ?CompletionV1,
    core_cycle_count: u32,
    cycle_count: u32,
    encode_wall_ns: u64,
    entry_boundary: [32]u8,
    entry_cpu: [32]u8,
    entry_memory: [32]u8,
    exit_boundary: [32]u8,
    exit_cpu: [32]u8,
    exit_memory: [32]u8,
    global_first_cycle: u64,
    keccak_calls: u32,
    leaf_seal: [32]u8,
    publish_wall_ns: u64,
    recovery_calls: u32,
    segment_index: u32,
};

pub const Input = struct {
    artifacts: []const ArtifactInput,
    elf: evidence.FileIdentity,
    execution_journal: evidence.FileIdentity,
    execution_profile_abi_version: u16,
    execution_profile_receipt: evidence.FileIdentity,
    execution_profile_semantic_sha256: [32]u8,
    expected_output: evidence.FileIdentity,
    input: evidence.FileIdentity,
    materialization_result: evidence.FileIdentity,
    materializer_executable_sha256: [32]u8,
    program_sha256: [32]u8,
    segment_step_budget: u64,
    session_sha256: [32]u8,
    source_request: evidence.FileIdentity,
    stage_timings: StageTimings,
};

const ArtifactStorage = struct {
    artifact_sha: [64]u8,
    entry_boundary: [64]u8,
    entry_cpu: [64]u8,
    entry_memory: [64]u8,
    exit_boundary: [64]u8,
    exit_cpu: [64]u8,
    exit_memory: [64]u8,
    leaf_seal: [64]u8,
};

pub fn encode(allocator: std.mem.Allocator, input: Input) ![]u8 {
    if (input.artifacts.len == 0 or
        input.artifacts.len > std.math.maxInt(u32))
    {
        return error.InvalidCompactManifest;
    }
    const storage = try allocator.alloc(ArtifactStorage, input.artifacts.len);
    defer allocator.free(storage);
    const artifacts = try allocator.alloc(Artifact, input.artifacts.len);
    defer allocator.free(artifacts);
    for (input.artifacts, storage, artifacts) |source, *hexes, *destination| {
        hexes.* = .{
            .artifact_sha = hex(source.artifact.sha256),
            .entry_boundary = hex(source.entry_boundary),
            .entry_cpu = hex(source.entry_cpu),
            .entry_memory = hex(source.entry_memory),
            .exit_boundary = hex(source.exit_boundary),
            .exit_cpu = hex(source.exit_cpu),
            .exit_memory = hex(source.exit_memory),
            .leaf_seal = hex(source.leaf_seal),
        };
        destination.* = .{
            .artifact = identity(source.artifact, &hexes.artifact_sha),
            .capture_wall_ns = source.capture_wall_ns,
            .completion = source.completion,
            .core_cycle_count = source.core_cycle_count,
            .cycle_count = source.cycle_count,
            .encode_wall_ns = source.encode_wall_ns,
            .entry_boundary_sha256 = &hexes.entry_boundary,
            .entry_cpu_sha256 = &hexes.entry_cpu,
            .entry_memory_sha256 = &hexes.entry_memory,
            .exit_boundary_sha256 = &hexes.exit_boundary,
            .exit_cpu_sha256 = &hexes.exit_cpu,
            .exit_memory_sha256 = &hexes.exit_memory,
            .global_first_cycle = source.global_first_cycle,
            .keccak_calls = source.keccak_calls,
            .leaf_seal_sha256 = &hexes.leaf_seal,
            .publish_wall_ns = source.publish_wall_ns,
            .recovery_calls = source.recovery_calls,
            .segment_index = source.segment_index,
        };
    }
    const chain = artifactChain(input.artifacts);
    const chain_hex = hex(chain);
    const elf_hex = hex(input.elf.sha256);
    const journal_hex = hex(input.execution_journal.sha256);
    const profile_receipt_hex = hex(input.execution_profile_receipt.sha256);
    const output_hex = hex(input.expected_output.sha256);
    const input_hex = hex(input.input.sha256);
    const result_hex = hex(input.materialization_result.sha256);
    const executable_hex = hex(input.materializer_executable_sha256);
    const program_hex = hex(input.program_sha256);
    const semantic_hex = hex(input.execution_profile_semantic_sha256);
    const session_hex = hex(input.session_sha256);
    const source_hex = hex(input.source_request.sha256);
    var total_artifact_bytes: u64 = 0;
    var total_core_cycles: u64 = 0;
    var total_cycles: u64 = 0;
    var total_keccak_calls: u64 = 0;
    var total_recovery_calls: u64 = 0;
    for (input.artifacts) |artifact| {
        total_artifact_bytes = try add(
            total_artifact_bytes,
            artifact.artifact.bytes,
        );
        total_core_cycles = try add(
            total_core_cycles,
            artifact.core_cycle_count,
        );
        total_cycles = try add(total_cycles, artifact.cycle_count);
        total_keccak_calls = try add(total_keccak_calls, artifact.keccak_calls);
        total_recovery_calls = try add(
            total_recovery_calls,
            artifact.recovery_calls,
        );
    }
    const receipt = Receipt{
        .content_sha256 = "0" ** 64,
        .artifact_chain_sha256 = &chain_hex,
        .artifact_format_version = 1,
        .artifact_magic = artifact_magic,
        .artifacts = artifacts,
        .clock_frame = contract.clock_frame,
        .elf = identity(input.elf, &elf_hex),
        .execution_journal = identity(input.execution_journal, &journal_hex),
        .execution_profile = contract.profile_name,
        .execution_profile_abi_version = input.execution_profile_abi_version,
        .execution_profile_receipt = identity(
            input.execution_profile_receipt,
            &profile_receipt_hex,
        ),
        .execution_profile_semantic_sha256 = &semantic_hex,
        .expected_output = identity(input.expected_output, &output_hex),
        .input = identity(input.input, &input_hex),
        .materialization_result = identity(
            input.materialization_result,
            &result_hex,
        ),
        .materializer_executable_sha256 = &executable_hex,
        .program_sha256 = &program_hex,
        .segment_count = @intCast(input.artifacts.len),
        .segment_step_budget = input.segment_step_budget,
        .session_sha256 = &session_hex,
        .source_request = identity(input.source_request, &source_hex),
        .stage_timings = input.stage_timings,
        .status = status,
        .total_artifact_bytes = total_artifact_bytes,
        .total_core_cycles = total_core_cycles,
        .total_cycles = total_cycles,
        .total_keccak_calls = total_keccak_calls,
        .total_recovery_calls = total_recovery_calls,
        .schema = schema,
    };
    const json_with_placeholder = try std.json.Stringify.valueAlloc(
        allocator,
        receipt,
        .{},
    );
    defer allocator.free(json_with_placeholder);
    const placeholder = "{\"content_sha256\":\"" ++ "0" ** 64 ++ "\",";
    if (!std.mem.startsWith(u8, json_with_placeholder, placeholder))
        return error.InvalidCanonicalJson;
    const unsigned = try std.fmt.allocPrint(
        allocator,
        "{{{s}",
        .{json_with_placeholder[placeholder.len..]},
    );
    defer allocator.free(unsigned);
    const sealed = try evidence.seal(allocator, unsigned);
    errdefer allocator.free(sealed);
    var parsed = try parse(allocator, sealed);
    parsed.deinit();
    return sealed;
}

pub fn parse(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(Receipt) {
    if (bytes.len == 0 or bytes.len > max_manifest_bytes or
        bytes[bytes.len - 1] != '\n' or
        (bytes.len > 1 and bytes[bytes.len - 2] == '\n'))
    {
        return error.InvalidCanonicalJson;
    }
    var parsed = try std.json.parseFromSlice(Receipt, allocator, bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    errdefer parsed.deinit();
    const canonical = try std.json.Stringify.valueAlloc(
        allocator,
        parsed.value,
        .{},
    );
    defer allocator.free(canonical);
    if (canonical.len + 1 != bytes.len or
        !std.mem.eql(u8, canonical, bytes[0..canonical.len]))
    {
        return error.InvalidCanonicalJson;
    }
    try parsed.value.validate();
    try validateContentSha256(allocator, bytes, parsed.value.content_sha256);
    return parsed;
}

pub fn sessionIdentity(
    elf_sha256: [32]u8,
    input_sha256: [32]u8,
    expected_output_sha256: [32]u8,
    execution_profile_semantic_sha256: [32]u8,
    segment_count: u32,
    segment_step_budget: u64,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(session_domain);
    hash.update(&elf_sha256);
    hash.update(&input_sha256);
    hash.update(&expected_output_sha256);
    hash.update(&execution_profile_semantic_sha256);
    putInt(&hash, u16, 1);
    putInt(&hash, u16, inputExecutionProfileAbiVersion());
    putInt(&hash, u32, segment_count);
    putInt(&hash, u64, segment_step_budget);
    hash.update(contract.clock_frame);
    hash.update(artifact_magic);
    return hash.finalResult();
}

/// Exact boundary-CPU authority used by the canonical V3 execution journal.
/// Keeping this helper public lets capture and replay custody share the same
/// domain and byte order without trusting CPU fields decoded from STWEMT01.
pub fn cpuIdentity(cpu: Cpu) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv/segment-boundary-cpu/v1\x00");
    putInt(&hash, u32, cpu.pc);
    for (cpu.regs) |value| putInt(&hash, u32, value);
    return hash.finalResult();
}

fn artifactChain(artifacts: []const ArtifactInput) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(artifact_chain_domain);
    putInt(&hash, u32, @as(u32, @intCast(artifacts.len)));
    for (artifacts) |artifact| {
        putInt(&hash, u32, artifact.segment_index);
        putInt(&hash, u64, artifact.artifact.bytes);
        hash.update(&artifact.artifact.sha256);
        hash.update(&artifact.leaf_seal);
    }
    return hash.finalResult();
}

fn artifactChainReceipt(artifacts: []const Artifact) ![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(artifact_chain_domain);
    putInt(&hash, u32, @as(u32, @intCast(artifacts.len)));
    for (artifacts) |artifact| {
        putInt(&hash, u32, artifact.segment_index);
        putInt(&hash, u64, artifact.artifact.bytes);
        const artifact_sha256 = try contract.parseSha256(
            artifact.artifact.sha256,
        );
        const leaf_seal = try contract.parseSha256(
            artifact.leaf_seal_sha256,
        );
        hash.update(&artifact_sha256);
        hash.update(&leaf_seal);
    }
    return hash.finalResult();
}

fn validateCompletion(value: CompletionV1) !void {
    if (value.kind == 0 or value.kind > 8)
        return error.InvalidCompactCompletion;
    if (value.kind == 2 and
        (value.clock != 0 or value.address & 3 != 0))
    {
        return error.InvalidCompactCompletion;
    }
}

fn identity(value: evidence.FileIdentity, sha256: []const u8) contract.Identity {
    return .{ .bytes = value.bytes, .path = value.path, .sha256 = sha256 };
}

fn inputExecutionProfileAbiVersion() u16 {
    return @import("stwo_riscv_frontend").isa.execution_profile.ethereum_abi_version;
}

fn validateContentSha256(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected: []const u8,
) !void {
    _ = try contract.parseSha256(expected);
    const prefix = "{\"content_sha256\":\"";
    if (!std.mem.startsWith(u8, bytes, prefix))
        return error.InvalidContentSha256;
    const start = prefix.len;
    const end = start + 64;
    if (end + 1 >= bytes.len or bytes[end] != '"' or bytes[end + 1] != ',' or
        !std.mem.eql(u8, bytes[start..end], expected))
    {
        return error.InvalidContentSha256;
    }
    const unsigned = try std.fmt.allocPrint(
        allocator,
        "{{{s}",
        .{bytes[end + 2 ..]},
    );
    defer allocator.free(unsigned);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(unsigned, &digest, .{});
    if (!std.mem.eql(u8, &hex(digest), expected))
        return error.InvalidContentSha256;
}

fn putInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn hex(value: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(value, .lower);
}

fn add(left: u64, right: anytype) !u64 {
    return std.math.add(u64, left, @intCast(right)) catch
        error.CompactManifestOverflow;
}

comptime {
    if (!std.mem.eql(u8, artifact_magic, "STWEMT01"))
        @compileError("compact Ethereum artifact magic drifted");
}
