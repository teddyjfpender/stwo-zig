//! Canonical receipt for one independently replayed compact Ethereum block.
//!
//! This publication is diagnostic execution evidence, not a proof. It binds
//! the exact materialization manifest, executable, source authorities, replay
//! resource choice, regenerated per-leaf witness authorities, and SELF
//! process timing. Publication is create-only and happens only after every
//! replay worker and ordered sink authority have completed.

const std = @import("std");

const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");

pub const schema = "stwo.ethereum.block-compact-parallel-replay-receipt.v1";
pub const status = "replayed-diagnostic-only";
pub const timing_scope = "parallel-replay-call-self-rusage";
pub const process_scope = "single-cli-process";
pub const max_receipt_bytes: usize = 16 * 1024 * 1024;
const witness_domain = "stwo-zig/riscv/ethereum-compact-replay-witness/v1\x00";
const chain_domain = "stwo-zig/riscv/ethereum-compact-replay-chain/v1\x00";

pub const ReplayReceipt = struct {
    admitted_workers: u16,
    core_cycles: u64,
    keccak_calls: u64,
    leaf_count: u32,
    recovery_calls: u64,
    total_cycles: u64,
};

pub const LeafAuthority = struct {
    core_trace_rows: u32,
    core_trace_sha256: []const u8,
    entry_cpu_sha256: []const u8,
    exit_cpu_sha256: []const u8,
    keccak_call_count: u32,
    keccak_calls_sha256: []const u8,
    keccak_execution_rows: u32,
    keccak_rows_sha256: []const u8,
    recovery_call_count: u32,
    recovery_calls_sha256: []const u8,
    recovery_execution_rows: u32,
    recovery_rows_sha256: []const u8,
    segment_index: u32,
    state_chain_access_count: u32,
    state_chain_memory_clock_updates: u32,
    state_chain_register_clock_updates: u32,
    state_chain_sha256: []const u8,
    touched_memory_sha256: []const u8,
    touched_memory_words: u32,
    witness_sha256: []const u8,

    pub fn validate(self: LeafAuthority, index: usize) !void {
        if (self.segment_index != index or
            self.keccak_execution_rows != self.keccak_call_count or
            self.recovery_execution_rows != self.recovery_call_count)
        {
            return error.InvalidReplayLeafAuthority;
        }
        inline for (.{
            self.core_trace_sha256,
            self.entry_cpu_sha256,
            self.exit_cpu_sha256,
            self.keccak_calls_sha256,
            self.keccak_rows_sha256,
            self.recovery_calls_sha256,
            self.recovery_rows_sha256,
            self.state_chain_sha256,
            self.touched_memory_sha256,
            self.witness_sha256,
        }) |digest| _ = try contract.parseSha256(digest);
        const expected = try witnessIdentityFromReceipt(self);
        if (!std.mem.eql(u8, &hex(expected), self.witness_sha256))
            return error.InvalidReplayWitnessIdentity;
    }
};

pub const Receipt = struct {
    content_sha256: []const u8,
    artifact_chain_sha256: []const u8,
    artifacts_manifest: contract.Identity,
    clock_frame: []const u8,
    elf: contract.Identity,
    execution_journal: contract.Identity,
    execution_profile: []const u8,
    execution_profile_abi_version: u16,
    execution_profile_receipt: contract.Identity,
    execution_profile_semantic_sha256: []const u8,
    expected_output: contract.Identity,
    input: contract.Identity,
    leaf_authorities: []const LeafAuthority,
    manifest_content_sha256: []const u8,
    materialization_result: contract.Identity,
    process_scope: []const u8,
    program_sha256: []const u8,
    replay_chain_sha256: []const u8,
    replay_executable: contract.Identity,
    replay_receipt: ReplayReceipt,
    replay_timing: evidence.Timing,
    requested_workers: u16,
    schema: []const u8,
    segment_count: u32,
    segment_step_budget: u64,
    session_sha256: []const u8,
    source_request: contract.Identity,
    status: []const u8,
    timing_scope: []const u8,

    pub fn validate(self: Receipt) !void {
        if (!std.mem.eql(u8, self.schema, schema) or
            !std.mem.eql(u8, self.status, status) or
            !std.mem.eql(u8, self.timing_scope, timing_scope) or
            !std.mem.eql(u8, self.process_scope, process_scope) or
            !std.mem.eql(u8, self.clock_frame, contract.clock_frame) or
            !std.mem.eql(u8, self.execution_profile, contract.profile_name) or
            self.requested_workers == 0 or self.requested_workers > 32 or
            self.replay_receipt.admitted_workers == 0 or
            self.replay_receipt.admitted_workers > self.requested_workers or
            self.segment_count < 2 or self.segment_step_budget == 0 or
            self.leaf_authorities.len != self.segment_count or
            self.replay_receipt.leaf_count != self.segment_count or
            self.replay_timing.wall_ns == 0)
        {
            return error.InvalidCompactReplayReceipt;
        }
        try self.artifacts_manifest.validate(false);
        try self.elf.validate(false);
        try self.execution_journal.validate(false);
        try self.execution_profile_receipt.validate(false);
        try self.expected_output.validate(false);
        try self.input.validate(true);
        try self.materialization_result.validate(false);
        try self.replay_executable.validate(false);
        try self.source_request.validate(false);
        inline for (.{
            self.content_sha256,
            self.artifact_chain_sha256,
            self.execution_profile_semantic_sha256,
            self.manifest_content_sha256,
            self.program_sha256,
            self.replay_chain_sha256,
            self.session_sha256,
        }) |digest| _ = try contract.parseSha256(digest);

        var core_cycles: u64 = 0;
        var keccak_calls: u64 = 0;
        var recovery_calls: u64 = 0;
        for (self.leaf_authorities, 0..) |leaf, index| {
            try leaf.validate(index);
            core_cycles = try add(core_cycles, leaf.core_trace_rows);
            keccak_calls = try add(keccak_calls, leaf.keccak_call_count);
            recovery_calls = try add(
                recovery_calls,
                leaf.recovery_call_count,
            );
        }
        if (core_cycles != self.replay_receipt.core_cycles or
            keccak_calls != self.replay_receipt.keccak_calls or
            recovery_calls != self.replay_receipt.recovery_calls or
            try add(core_cycles, try add(keccak_calls, recovery_calls)) !=
                self.replay_receipt.total_cycles)
        {
            return error.InvalidCompactReplayTotals;
        }
        const expected_chain = try replayChainFromReceipt(
            self.leaf_authorities,
        );
        if (!std.mem.eql(u8, &hex(expected_chain), self.replay_chain_sha256))
            return error.InvalidCompactReplayChain;
    }
};

pub const LeafAuthorityInput = struct {
    core_trace_rows: u32,
    core_trace_sha256: [32]u8,
    entry_cpu_sha256: [32]u8,
    exit_cpu_sha256: [32]u8,
    keccak_call_count: u32,
    keccak_calls_sha256: [32]u8,
    keccak_execution_rows: u32,
    keccak_rows_sha256: [32]u8,
    recovery_call_count: u32,
    recovery_calls_sha256: [32]u8,
    recovery_execution_rows: u32,
    recovery_rows_sha256: [32]u8,
    segment_index: u32,
    state_chain_access_count: u32,
    state_chain_memory_clock_updates: u32,
    state_chain_register_clock_updates: u32,
    state_chain_sha256: [32]u8,
    touched_memory_sha256: [32]u8,
    touched_memory_words: u32,
    witness_sha256: [32]u8,
};

pub const Input = struct {
    artifact_chain_sha256: [32]u8,
    artifacts_manifest: evidence.FileIdentity,
    elf: evidence.FileIdentity,
    execution_journal: evidence.FileIdentity,
    execution_profile_abi_version: u16,
    execution_profile_receipt: evidence.FileIdentity,
    execution_profile_semantic_sha256: [32]u8,
    expected_output: evidence.FileIdentity,
    input: evidence.FileIdentity,
    leaf_authorities: []const LeafAuthorityInput,
    manifest_content_sha256: [32]u8,
    materialization_result: evidence.FileIdentity,
    program_sha256: [32]u8,
    replay_executable: evidence.FileIdentity,
    replay_receipt: ReplayReceipt,
    replay_timing: evidence.Timing,
    requested_workers: u16,
    segment_step_budget: u64,
    session_sha256: [32]u8,
    source_request: evidence.FileIdentity,
};

const LeafStorage = struct {
    core_trace: [64]u8,
    entry_cpu: [64]u8,
    exit_cpu: [64]u8,
    keccak_calls: [64]u8,
    keccak_rows: [64]u8,
    recovery_calls: [64]u8,
    recovery_rows: [64]u8,
    state_chain: [64]u8,
    touched_memory: [64]u8,
    witness: [64]u8,
};

pub fn encode(allocator: std.mem.Allocator, input: Input) ![]u8 {
    if (input.leaf_authorities.len == 0 or
        input.leaf_authorities.len > std.math.maxInt(u32))
    {
        return error.InvalidCompactReplayReceipt;
    }
    const storage = try allocator.alloc(LeafStorage, input.leaf_authorities.len);
    defer allocator.free(storage);
    const leaves = try allocator.alloc(LeafAuthority, input.leaf_authorities.len);
    defer allocator.free(leaves);
    for (input.leaf_authorities, storage, leaves) |source, *hexes, *leaf| {
        hexes.* = .{
            .core_trace = hex(source.core_trace_sha256),
            .entry_cpu = hex(source.entry_cpu_sha256),
            .exit_cpu = hex(source.exit_cpu_sha256),
            .keccak_calls = hex(source.keccak_calls_sha256),
            .keccak_rows = hex(source.keccak_rows_sha256),
            .recovery_calls = hex(source.recovery_calls_sha256),
            .recovery_rows = hex(source.recovery_rows_sha256),
            .state_chain = hex(source.state_chain_sha256),
            .touched_memory = hex(source.touched_memory_sha256),
            .witness = hex(source.witness_sha256),
        };
        leaf.* = .{
            .core_trace_rows = source.core_trace_rows,
            .core_trace_sha256 = &hexes.core_trace,
            .entry_cpu_sha256 = &hexes.entry_cpu,
            .exit_cpu_sha256 = &hexes.exit_cpu,
            .keccak_call_count = source.keccak_call_count,
            .keccak_calls_sha256 = &hexes.keccak_calls,
            .keccak_execution_rows = source.keccak_execution_rows,
            .keccak_rows_sha256 = &hexes.keccak_rows,
            .recovery_call_count = source.recovery_call_count,
            .recovery_calls_sha256 = &hexes.recovery_calls,
            .recovery_execution_rows = source.recovery_execution_rows,
            .recovery_rows_sha256 = &hexes.recovery_rows,
            .segment_index = source.segment_index,
            .state_chain_access_count = source.state_chain_access_count,
            .state_chain_memory_clock_updates = source.state_chain_memory_clock_updates,
            .state_chain_register_clock_updates = source.state_chain_register_clock_updates,
            .state_chain_sha256 = &hexes.state_chain,
            .touched_memory_sha256 = &hexes.touched_memory,
            .touched_memory_words = source.touched_memory_words,
            .witness_sha256 = &hexes.witness,
        };
    }

    const artifact_chain = hex(input.artifact_chain_sha256);
    const manifest_content = hex(input.manifest_content_sha256);
    const semantic = hex(input.execution_profile_semantic_sha256);
    const program = hex(input.program_sha256);
    const replay_chain = hex(replayChain(input.leaf_authorities));
    const session = hex(input.session_sha256);
    const manifest_sha = hex(input.artifacts_manifest.sha256);
    const elf_sha = hex(input.elf.sha256);
    const journal_sha = hex(input.execution_journal.sha256);
    const profile_sha = hex(input.execution_profile_receipt.sha256);
    const output_sha = hex(input.expected_output.sha256);
    const input_sha = hex(input.input.sha256);
    const result_sha = hex(input.materialization_result.sha256);
    const executable_sha = hex(input.replay_executable.sha256);
    const source_sha = hex(input.source_request.sha256);
    const receipt = Receipt{
        .content_sha256 = "0" ** 64,
        .artifact_chain_sha256 = &artifact_chain,
        .artifacts_manifest = identity(input.artifacts_manifest, &manifest_sha),
        .clock_frame = contract.clock_frame,
        .elf = identity(input.elf, &elf_sha),
        .execution_journal = identity(input.execution_journal, &journal_sha),
        .execution_profile = contract.profile_name,
        .execution_profile_abi_version = input.execution_profile_abi_version,
        .execution_profile_receipt = identity(
            input.execution_profile_receipt,
            &profile_sha,
        ),
        .execution_profile_semantic_sha256 = &semantic,
        .expected_output = identity(input.expected_output, &output_sha),
        .input = identity(input.input, &input_sha),
        .leaf_authorities = leaves,
        .manifest_content_sha256 = &manifest_content,
        .materialization_result = identity(
            input.materialization_result,
            &result_sha,
        ),
        .process_scope = process_scope,
        .program_sha256 = &program,
        .replay_chain_sha256 = &replay_chain,
        .replay_executable = identity(
            input.replay_executable,
            &executable_sha,
        ),
        .replay_receipt = input.replay_receipt,
        .replay_timing = input.replay_timing,
        .requested_workers = input.requested_workers,
        .schema = schema,
        .segment_count = @intCast(input.leaf_authorities.len),
        .segment_step_budget = input.segment_step_budget,
        .session_sha256 = &session,
        .source_request = identity(input.source_request, &source_sha),
        .status = status,
        .timing_scope = timing_scope,
    };
    const placeholder_json = try std.json.Stringify.valueAlloc(
        allocator,
        receipt,
        .{},
    );
    defer allocator.free(placeholder_json);
    const placeholder = "{\"content_sha256\":\"" ++ "0" ** 64 ++ "\",";
    if (!std.mem.startsWith(u8, placeholder_json, placeholder))
        return error.InvalidCanonicalJson;
    const unsigned = try std.fmt.allocPrint(
        allocator,
        "{{{s}",
        .{placeholder_json[placeholder.len..]},
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
    if (bytes.len == 0 or bytes.len > max_receipt_bytes or
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

pub fn witnessIdentity(input: LeafAuthorityInput) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(witness_domain);
    hashLeaf(&hash, input);
    return hash.finalResult();
}

pub fn replayChain(leaves: []const LeafAuthorityInput) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(chain_domain);
    putInt(&hash, u32, @as(u32, @intCast(leaves.len)));
    for (leaves) |leaf| {
        putInt(&hash, u32, leaf.segment_index);
        hash.update(&leaf.witness_sha256);
    }
    return hash.finalResult();
}

fn witnessIdentityFromReceipt(input: LeafAuthority) ![32]u8 {
    return witnessIdentity(.{
        .core_trace_rows = input.core_trace_rows,
        .core_trace_sha256 = try contract.parseSha256(input.core_trace_sha256),
        .entry_cpu_sha256 = try contract.parseSha256(input.entry_cpu_sha256),
        .exit_cpu_sha256 = try contract.parseSha256(input.exit_cpu_sha256),
        .keccak_call_count = input.keccak_call_count,
        .keccak_calls_sha256 = try contract.parseSha256(input.keccak_calls_sha256),
        .keccak_execution_rows = input.keccak_execution_rows,
        .keccak_rows_sha256 = try contract.parseSha256(input.keccak_rows_sha256),
        .recovery_call_count = input.recovery_call_count,
        .recovery_calls_sha256 = try contract.parseSha256(input.recovery_calls_sha256),
        .recovery_execution_rows = input.recovery_execution_rows,
        .recovery_rows_sha256 = try contract.parseSha256(input.recovery_rows_sha256),
        .segment_index = input.segment_index,
        .state_chain_access_count = input.state_chain_access_count,
        .state_chain_memory_clock_updates = input.state_chain_memory_clock_updates,
        .state_chain_register_clock_updates = input.state_chain_register_clock_updates,
        .state_chain_sha256 = try contract.parseSha256(input.state_chain_sha256),
        .touched_memory_sha256 = try contract.parseSha256(input.touched_memory_sha256),
        .touched_memory_words = input.touched_memory_words,
        .witness_sha256 = .{0} ** 32,
    });
}

fn replayChainFromReceipt(leaves: []const LeafAuthority) ![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(chain_domain);
    putInt(&hash, u32, @as(u32, @intCast(leaves.len)));
    for (leaves) |leaf| {
        putInt(&hash, u32, leaf.segment_index);
        const witness = try contract.parseSha256(leaf.witness_sha256);
        hash.update(&witness);
    }
    return hash.finalResult();
}

fn hashLeaf(hash: anytype, input: LeafAuthorityInput) void {
    putInt(hash, u32, input.segment_index);
    putInt(hash, u32, input.core_trace_rows);
    hash.update(&input.core_trace_sha256);
    hash.update(&input.entry_cpu_sha256);
    hash.update(&input.exit_cpu_sha256);
    putInt(hash, u32, input.keccak_call_count);
    hash.update(&input.keccak_calls_sha256);
    putInt(hash, u32, input.keccak_execution_rows);
    hash.update(&input.keccak_rows_sha256);
    putInt(hash, u32, input.recovery_call_count);
    hash.update(&input.recovery_calls_sha256);
    putInt(hash, u32, input.recovery_execution_rows);
    hash.update(&input.recovery_rows_sha256);
    putInt(hash, u32, input.state_chain_access_count);
    putInt(hash, u32, input.state_chain_memory_clock_updates);
    putInt(hash, u32, input.state_chain_register_clock_updates);
    hash.update(&input.state_chain_sha256);
    putInt(hash, u32, input.touched_memory_words);
    hash.update(&input.touched_memory_sha256);
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

fn identity(value: evidence.FileIdentity, sha256: []const u8) contract.Identity {
    return .{ .bytes = value.bytes, .path = value.path, .sha256 = sha256 };
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
        error.CompactReplayReceiptOverflow;
}
