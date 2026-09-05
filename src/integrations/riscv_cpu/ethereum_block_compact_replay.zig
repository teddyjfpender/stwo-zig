//! Fresh-process parallel replay of a retained compact Ethereum block.
//!
//! The command reopens the canonical materialization manifest and every file
//! it names with exact byte/SHA custody, cold-rebuilds the immutable program
//! and memory layout from the admitted ELF, independently replays the ordered
//! compact leaves, and publishes one sealed create-only diagnostic receipt.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const compact_manifest = @import("ethereum_block_leaf_compact_manifest.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const receipt_wire = @import("ethereum_block_compact_replay_receipt.zig");
const support = @import("ethereum_block_leaf_support.zig");

const minimal = frontend.runner.minimal_trace;
const Memory = frontend.runner.Memory;
const max_external_file_bytes: usize = 512 * 1024 * 1024;
const max_executable_bytes: usize = 512 * 1024 * 1024;
const max_total_artifact_bytes: u64 = 16 * 1024 * 1024 * 1024;

const Options = struct {
    manifest: []const u8,
    result: []const u8,
    workers: usize,

    fn parse(arguments: []const []const u8) !Options {
        var manifest: ?[]const u8 = null;
        var result: ?[]const u8 = null;
        var workers: ?usize = null;
        var index: usize = 0;
        while (index < arguments.len) : (index += 2) {
            if (index + 1 == arguments.len) return error.InvalidArguments;
            const key = arguments[index];
            const value = arguments[index + 1];
            if (std.mem.eql(u8, key, "--manifest")) {
                if (manifest != null) return error.DuplicateArgument;
                manifest = value;
            } else if (std.mem.eql(u8, key, "--result")) {
                if (result != null) return error.DuplicateArgument;
                result = value;
            } else if (std.mem.eql(u8, key, "--workers")) {
                if (workers != null) return error.DuplicateArgument;
                workers = std.fmt.parseInt(usize, value, 10) catch
                    return error.InvalidArguments;
            } else return error.InvalidArguments;
        }
        return .{
            .manifest = manifest orelse return error.MissingArgument,
            .result = result orelse return error.MissingArgument,
            .workers = workers orelse return error.MissingArgument,
        };
    }
};

const ResolvedOptions = struct {
    manifest: []u8,
    result: []u8,
    workers: usize,

    fn deinit(self: *ResolvedOptions, allocator: std.mem.Allocator) void {
        allocator.free(self.manifest);
        allocator.free(self.result);
        self.* = undefined;
    }
};

pub fn run(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !void {
    const parsed_options = try Options.parse(arguments);
    if (parsed_options.workers == 0 or
        parsed_options.workers > minimal.ethereum_parallel_replay.MAX_WORKERS)
    {
        return error.InvalidReplayWorkerCount;
    }
    var options = ResolvedOptions{
        .manifest = try artifact_io.resolveAbsolute(
            allocator,
            parsed_options.manifest,
        ),
        .result = try artifact_io.resolveAbsolute(
            allocator,
            parsed_options.result,
        ),
        .workers = parsed_options.workers,
    };
    defer options.deinit(allocator);

    const manifest_bytes = try artifact_io.readFileBounded(
        allocator,
        options.manifest,
        compact_manifest.max_manifest_bytes,
    );
    defer allocator.free(manifest_bytes);
    const manifest_identity = evidence.identity(
        options.manifest,
        manifest_bytes,
    );
    var parsed_manifest = try compact_manifest.parse(
        allocator,
        manifest_bytes,
    );
    defer parsed_manifest.deinit();
    const manifest = parsed_manifest.value;
    if (manifest.total_artifact_bytes > max_total_artifact_bytes)
        return error.CompactReplayResourceLimitExceeded;

    const elf_bytes = try support.readIdentity(
        allocator,
        manifest.elf,
        max_external_file_bytes,
    );
    defer allocator.free(elf_bytes);
    try reopenExternalAuthorities(allocator, manifest);

    var program_memory = try Memory.initFallible(allocator);
    defer program_memory.deinit();
    const elf_info = try frontend.runner.elf_loader.loadElfForProfile(
        elf_bytes,
        &program_memory,
        .rv32im_zkvm_ethereum_v1,
    );
    const initialized = try program_memory.canonicalAlignedWordAddresses();
    var program_word_count: usize = 0;
    for (initialized) |address| {
        if (elf_info.memory_layout.isProgramAddr(address))
            program_word_count += 1;
    }
    if (program_word_count == 0) return error.EmptyProgram;
    const program_words = try allocator.alloc(
        minimal.ProgramWord,
        program_word_count,
    );
    defer allocator.free(program_words);
    var program_index: usize = 0;
    for (initialized) |address| {
        if (!elf_info.memory_layout.isProgramAddr(address)) continue;
        program_words[program_index] = .{
            .address = address,
            .word = program_memory.readU32(address),
        };
        program_index += 1;
    }
    const program = try minimal.SliceProgram.init(program_words);
    const expected_program_identity = try contract.parseSha256(
        manifest.program_sha256,
    );
    if (!std.mem.eql(
        u8,
        &program.identity,
        &expected_program_identity,
    )) return error.ProgramIdentityMismatch;

    const artifacts = try allocator.alloc(
        minimal.EthereumMinimalArtifactV1,
        manifest.artifacts.len,
    );
    var artifact_count: usize = 0;
    defer {
        for (artifacts[0..artifact_count]) |*artifact| artifact.deinit();
        allocator.free(artifacts);
    }
    const requests = try allocator.alloc(
        minimal.EthereumParallelReplayRequestV1,
        manifest.artifacts.len,
    );
    defer allocator.free(requests);
    for (manifest.artifacts, 0..) |record, index| {
        const encoded = try support.readIdentity(
            allocator,
            record.artifact,
            minimal.ethereum_wire.MAX_ENCODED_BYTES,
        );
        defer allocator.free(encoded);
        artifacts[index] = try minimal.decodeEthereumMinimalArtifactAlloc(
            allocator,
            encoded,
        );
        artifact_count += 1;
        try validateArtifact(manifest, record, &artifacts[index], index);
        requests[index] = .{
            .leaf = &artifacts[index].leaf,
            .program = program.source(),
            .boundary_words = artifacts[index].boundary_words,
            .expected_memory_layout = elf_info.memory_layout,
            .expected_source = .{
                .program = try contract.parseSha256(manifest.program_sha256),
                .input = try contract.parseSha256(manifest.input.sha256),
                .session = try contract.parseSha256(manifest.session_sha256),
                .entry_memory = try contract.parseSha256(
                    record.entry_memory_sha256,
                ),
                .exit_memory = try contract.parseSha256(
                    record.exit_memory_sha256,
                ),
            },
            .expected_entry_cpu_sha256 = try contract.parseSha256(
                record.entry_cpu_sha256,
            ),
            .expected_exit_cpu_sha256 = try contract.parseSha256(
                record.exit_cpu_sha256,
            ),
            .expected_completion = record.completion,
        };
    }
    const admitted = try minimal.ethereum_parallel_replay.validateCollection(
        requests,
        manifest.total_cycles,
    );
    if (admitted.total_cycles != manifest.total_cycles or
        admitted.core_cycles != manifest.total_core_cycles or
        admitted.keccak_calls != manifest.total_keccak_calls or
        admitted.recovery_calls != manifest.total_recovery_calls)
    {
        return error.CompactReplayManifestMismatch;
    }

    const leaf_authorities = try allocator.alloc(
        receipt_wire.LeafAuthorityInput,
        manifest.artifacts.len,
    );
    defer allocator.free(leaf_authorities);
    const published = try allocator.alloc(bool, manifest.artifacts.len);
    defer allocator.free(published);
    @memset(published, false);
    var sink_context = SinkContext{
        .authorities = leaf_authorities,
        .published = published,
        .requests = requests,
    };
    var replay_clock = try evidence.Clock.start();
    const replayed = try minimal.replayEthereumLeavesParallel(
        allocator,
        requests,
        .{
            .worker_count = options.workers,
            .max_total_cycles = manifest.total_cycles,
        },
        .{
            .context = &sink_context,
            .consume_fn = SinkContext.consume,
        },
    );
    const replay_timing = try replay_clock.finish();
    for (published) |value| if (!value) return error.IncompleteReplaySink;
    if (replayed.leaf_count != admitted.leaf_count or
        replayed.total_cycles != admitted.total_cycles or
        replayed.core_cycles != admitted.core_cycles or
        replayed.keccak_calls != admitted.keccak_calls or
        replayed.recovery_calls != admitted.recovery_calls)
    {
        return error.CompactReplayReceiptMismatch;
    }

    const self_path = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(self_path);
    const absolute_self_path = try artifact_io.resolveAbsolute(
        allocator,
        self_path,
    );
    defer allocator.free(absolute_self_path);
    const executable_bytes = try artifact_io.readFileBounded(
        allocator,
        absolute_self_path,
        max_executable_bytes,
    );
    defer allocator.free(executable_bytes);
    const executable_identity = evidence.identity(
        absolute_self_path,
        executable_bytes,
    );

    const encoded_receipt = try receipt_wire.encode(allocator, .{
        .artifact_chain_sha256 = try contract.parseSha256(
            manifest.artifact_chain_sha256,
        ),
        .artifacts_manifest = manifest_identity,
        .elf = fileIdentity(manifest.elf),
        .execution_journal = fileIdentity(manifest.execution_journal),
        .execution_profile_abi_version = manifest.execution_profile_abi_version,
        .execution_profile_receipt = fileIdentity(
            manifest.execution_profile_receipt,
        ),
        .execution_profile_semantic_sha256 = try contract.parseSha256(
            manifest.execution_profile_semantic_sha256,
        ),
        .expected_output = fileIdentity(manifest.expected_output),
        .input = fileIdentity(manifest.input),
        .leaf_authorities = leaf_authorities,
        .manifest_content_sha256 = try contract.parseSha256(
            manifest.content_sha256,
        ),
        .materialization_result = fileIdentity(
            manifest.materialization_result,
        ),
        .program_sha256 = try contract.parseSha256(manifest.program_sha256),
        .replay_executable = executable_identity,
        .replay_receipt = .{
            .admitted_workers = replayed.admitted_workers,
            .core_cycles = replayed.core_cycles,
            .keccak_calls = replayed.keccak_calls,
            .leaf_count = replayed.leaf_count,
            .recovery_calls = replayed.recovery_calls,
            .total_cycles = replayed.total_cycles,
        },
        .replay_timing = replay_timing,
        .requested_workers = @intCast(options.workers),
        .segment_step_budget = manifest.segment_step_budget,
        .session_sha256 = try contract.parseSha256(manifest.session_sha256),
        .source_request = fileIdentity(manifest.source_request),
    });
    defer allocator.free(encoded_receipt);
    try artifact_io.publishCreateOnlyDurable(options.result, encoded_receipt);
}

const SinkContext = struct {
    authorities: []receipt_wire.LeafAuthorityInput,
    published: []bool,
    requests: []const minimal.EthereumParallelReplayRequestV1,

    fn consume(
        opaque_context: *anyopaque,
        index: usize,
        result: *minimal.EthereumReplayResultV1,
    ) anyerror!void {
        const self: *SinkContext = @ptrCast(@alignCast(opaque_context));
        if (index >= self.authorities.len or self.published[index])
            return error.InvalidReplaySinkIndex;
        var authority = try authorityForResult(
            self.requests[index].leaf.segment_index,
            self.requests[index].expected_entry_cpu_sha256,
            self.requests[index].expected_exit_cpu_sha256,
            result,
        );
        authority.witness_sha256 = receipt_wire.witnessIdentity(authority);
        self.authorities[index] = authority;
        self.published[index] = true;
    }
};

fn authorityForResult(
    segment_index: u32,
    entry_cpu_sha256: [32]u8,
    expected_exit_cpu_sha256: [32]u8,
    result: *minimal.EthereumReplayResultV1,
) !receipt_wire.LeafAuthorityInput {
    const trace_rows = std.math.cast(
        u32,
        result.execution_trace.rows.items.len,
    ) orelse return error.ReplayAuthorityOverflow;
    const keccak_calls = std.math.cast(
        u32,
        result.keccakf_calls.records().len,
    ) orelse return error.ReplayAuthorityOverflow;
    const keccak_rows = std.math.cast(
        u32,
        result.keccakf_execution_rows.rows().len,
    ) orelse return error.ReplayAuthorityOverflow;
    const recovery_calls = std.math.cast(
        u32,
        result.signer_recovery_calls.records().len,
    ) orelse return error.ReplayAuthorityOverflow;
    const recovery_rows = std.math.cast(
        u32,
        result.signer_recovery_execution_rows.rows().len,
    ) orelse return error.ReplayAuthorityOverflow;
    const accesses = std.math.cast(
        u32,
        result.state_chain_tracker.accesses.items.len,
    ) orelse return error.ReplayAuthorityOverflow;
    const memory_updates = std.math.cast(
        u32,
        result.state_chain_tracker.clock_updates_mem.items.len,
    ) orelse return error.ReplayAuthorityOverflow;
    const register_updates = std.math.cast(
        u32,
        result.state_chain_tracker.clock_updates_reg.items.len,
    ) orelse return error.ReplayAuthorityOverflow;
    const touched_addresses = try result.touched_memory
        .canonicalAlignedWordAddresses();
    const touched_count = std.math.cast(u32, touched_addresses.len) orelse
        return error.ReplayAuthorityOverflow;
    const cpu_sha = minimal.ethereumCpuIdentity(result.cpu);
    if (!std.mem.eql(u8, &cpu_sha, &expected_exit_cpu_sha256))
        return error.ExitCpuAuthorityMismatch;
    return .{
        .core_trace_rows = trace_rows,
        .core_trace_sha256 = traceIdentity(&result.execution_trace),
        .entry_cpu_sha256 = entry_cpu_sha256,
        .exit_cpu_sha256 = cpu_sha,
        .keccak_call_count = keccak_calls,
        .keccak_calls_sha256 = keccakCallsIdentity(
            result.keccakf_calls.records(),
        ),
        .keccak_execution_rows = keccak_rows,
        .keccak_rows_sha256 = executionRowsIdentity(
            "stwo-zig/riscv/ethereum-replay-keccak-rows/v1\x00",
            result.keccakf_execution_rows.rows(),
        ),
        .recovery_call_count = recovery_calls,
        .recovery_calls_sha256 = recoveryCallsIdentity(
            result.signer_recovery_calls.records(),
        ),
        .recovery_execution_rows = recovery_rows,
        .recovery_rows_sha256 = executionRowsIdentity(
            "stwo-zig/riscv/ethereum-replay-recovery-rows/v1\x00",
            result.signer_recovery_execution_rows.rows(),
        ),
        .segment_index = segment_index,
        .state_chain_access_count = accesses,
        .state_chain_memory_clock_updates = memory_updates,
        .state_chain_register_clock_updates = register_updates,
        .state_chain_sha256 = try stateChainIdentity(
            &result.state_chain_tracker,
        ),
        .touched_memory_sha256 = touchedMemoryIdentity(
            &result.touched_memory,
            touched_addresses,
        ),
        .touched_memory_words = touched_count,
        .witness_sha256 = .{0} ** 32,
    };
}

fn validateArtifact(
    manifest: compact_manifest.Receipt,
    record: compact_manifest.Artifact,
    artifact: *const minimal.EthereumMinimalArtifactV1,
    index: usize,
) !void {
    const leaf = artifact.leaf;
    const leaf_seal = try contract.parseSha256(record.leaf_seal_sha256);
    const entry_boundary = try contract.parseSha256(
        record.entry_boundary_sha256,
    );
    const exit_boundary = try contract.parseSha256(
        record.exit_boundary_sha256,
    );
    const entry_cpu = try contract.parseSha256(record.entry_cpu_sha256);
    const exit_cpu = try contract.parseSha256(record.exit_cpu_sha256);
    const program = try contract.parseSha256(manifest.program_sha256);
    const input = try contract.parseSha256(manifest.input.sha256);
    const session = try contract.parseSha256(manifest.session_sha256);
    const entry_memory = try contract.parseSha256(record.entry_memory_sha256);
    const exit_memory = try contract.parseSha256(record.exit_memory_sha256);
    const actual_entry_cpu = minimal.ethereumCpuIdentity(leaf.entry_cpu);
    const actual_exit_cpu = minimal.ethereumCpuIdentity(leaf.exit_cpu);
    if (leaf.segment_index != index or
        leaf.global_first_cycle != record.global_first_cycle or
        leaf.cycle_count != record.cycle_count or
        leaf.core_cycle_count != record.core_cycle_count or
        leaf.keccak_records.len != record.keccak_calls or
        leaf.recovery_records.len != record.recovery_calls or
        !std.meta.eql(leaf.completion, record.completion) or
        !std.mem.eql(u8, &leaf.seal, &leaf_seal) or
        !std.mem.eql(u8, &leaf.entry_boundary, &entry_boundary) or
        !std.mem.eql(u8, &leaf.exit_boundary, &exit_boundary) or
        !std.mem.eql(u8, &actual_entry_cpu, &entry_cpu) or
        !std.mem.eql(u8, &actual_exit_cpu, &exit_cpu) or
        !std.mem.eql(u8, &leaf.source.program, &program) or
        !std.mem.eql(u8, &leaf.source.input, &input) or
        !std.mem.eql(u8, &leaf.source.session, &session) or
        !std.mem.eql(u8, &leaf.source.entry_memory, &entry_memory) or
        !std.mem.eql(u8, &leaf.source.exit_memory, &exit_memory))
    {
        return error.CompactReplayArtifactMismatch;
    }
}

fn reopenExternalAuthorities(
    allocator: std.mem.Allocator,
    manifest: compact_manifest.Receipt,
) !void {
    inline for (.{
        manifest.execution_journal,
        manifest.execution_profile_receipt,
        manifest.expected_output,
        manifest.input,
        manifest.materialization_result,
        manifest.source_request,
    }) |identity| {
        const bytes = try support.readIdentity(
            allocator,
            identity,
            max_external_file_bytes,
        );
        allocator.free(bytes);
    }
}

fn traceIdentity(trace: *const frontend.runner.trace.Trace) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv/ethereum-replay-core-trace/v1\x00");
    putInt(&hash, u32, trace.initial_pc);
    putInt(&hash, u32, trace.final_pc);
    putInt(&hash, u64, trace.step_count);
    putInt(&hash, u32, trace.clock_origin);
    putInt(&hash, u32, trace.last_retirement_clock);
    putInt(&hash, u64, trace.recorded_external_steps);
    putInt(&hash, u32, @as(u32, @intCast(trace.rows.items.len)));
    for (trace.rows.items) |row| {
        putInt(&hash, u32, row.clk);
        putInt(&hash, u32, row.pc);
        putInt(&hash, u8, @intFromEnum(row.opcode));
        putInt(&hash, u8, row.rd);
        putInt(&hash, u8, row.rs1);
        putInt(&hash, u8, row.rs2);
        putInt(&hash, u32, @as(u32, @bitCast(row.imm)));
        putInt(&hash, u32, row.rs1_val);
        putInt(&hash, u32, row.rs2_val);
        putInt(&hash, u32, row.rs1_prev_clk);
        putInt(&hash, u32, row.rs2_prev_clk);
        putInt(&hash, u32, row.rd_prev_val);
        putInt(&hash, u32, row.rd_prev_clk);
        putInt(&hash, u32, row.rd_val);
        putInt(&hash, u32, row.mem_addr);
        putInt(&hash, u32, row.mem_val);
        putInt(&hash, u32, row.mem_prev_word);
        putInt(&hash, u32, row.mem_next_word);
        putInt(&hash, u32, row.mem_prev_clk);
        putInt(&hash, u8, @intFromBool(row.is_load));
        putInt(&hash, u8, @intFromBool(row.is_store));
        putInt(&hash, u8, @intFromBool(row.branch_taken));
        putInt(&hash, u32, row.next_pc);
        putInt(&hash, u32, row.inst_word);
    }
    return hash.finalResult();
}

const MapEntry = struct { key: u32, value: u32 };

fn stateChainIdentity(
    tracker: *const frontend.runner.state_chain.StateChainTracker,
) ![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv/ethereum-replay-state-chain/v1\x00");
    for (tracker.reg_last_clk) |clock| putInt(&hash, u32, clock);
    try hashMap(&hash, tracker.mem_last_clk);
    try hashMap(&hash, tracker.mem_initial);
    putInt(&hash, u32, @as(u32, @intCast(tracker.accesses.items.len)));
    for (tracker.accesses.items) |access| {
        putInt(&hash, u8, access.addr_space);
        putInt(&hash, u32, access.addr);
        putInt(&hash, u32, access.clk);
        putInt(&hash, u32, access.value);
        putInt(&hash, u32, access.clk_prev);
    }
    hashClockUpdates(&hash, tracker.clock_updates_mem.items);
    hashClockUpdates(&hash, tracker.clock_updates_reg.items);
    return hash.finalResult();
}

fn hashMap(hash: anytype, map: std.AutoHashMap(u32, u32)) !void {
    const entries = try std.heap.smp_allocator.alloc(MapEntry, map.count());
    defer std.heap.smp_allocator.free(entries);
    var iterator = map.iterator();
    var index: usize = 0;
    while (iterator.next()) |entry| : (index += 1)
        entries[index] = .{ .key = entry.key_ptr.*, .value = entry.value_ptr.* };
    std.mem.sortUnstable(MapEntry, entries, {}, struct {
        fn lessThan(_: void, left: MapEntry, right: MapEntry) bool {
            return left.key < right.key;
        }
    }.lessThan);
    putInt(hash, u32, @as(u32, @intCast(entries.len)));
    for (entries) |entry| {
        putInt(hash, u32, entry.key);
        putInt(hash, u32, entry.value);
    }
}

fn hashClockUpdates(hash: anytype, updates: anytype) void {
    putInt(hash, u32, @as(u32, @intCast(updates.len)));
    for (updates) |update| {
        putInt(hash, u8, update.addr_space);
        putInt(hash, u32, update.addr);
        putInt(hash, u32, update.clk);
        putInt(hash, u32, update.clk_prev);
        putInt(hash, u32, update.value);
    }
}

fn touchedMemoryIdentity(
    memory: *const Memory,
    addresses: []const u32,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv/ethereum-replay-touched-memory/v1\x00");
    putInt(&hash, u32, @as(u32, @intCast(addresses.len)));
    for (addresses) |address| {
        putInt(&hash, u32, address);
        putInt(&hash, u32, memory.readU32(address));
    }
    return hash.finalResult();
}

fn keccakCallsIdentity(records: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv/ethereum-replay-keccak-calls/v1\x00");
    putInt(&hash, u32, @as(u32, @intCast(records.len)));
    for (records) |record| {
        putInt(&hash, u32, record.execution_clock);
        putInt(&hash, u32, record.pc);
        putInt(&hash, u32, record.state_ptr);
        putInt(&hash, u8, record.pointer_register);
        putInt(&hash, u32, record.pointer_previous_clock);
        for (record.input) |value| putInt(&hash, u32, value);
        for (record.output) |value| putInt(&hash, u32, value);
        for (record.memory_previous_clocks) |value| putInt(&hash, u32, value);
    }
    return hash.finalResult();
}

fn recoveryCallsIdentity(records: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv/ethereum-replay-recovery-calls/v1\x00");
    putInt(&hash, u32, @as(u32, @intCast(records.len)));
    for (records) |record| {
        putInt(&hash, u32, record.execution_clock);
        putInt(&hash, u32, record.pc);
        putInt(&hash, u32, record.io_ptr);
        putInt(&hash, u8, record.pointer_register);
        putInt(&hash, u32, record.pointer_previous_clock);
        hash.update(&record.digest_big_endian);
        hash.update(&record.r_big_endian);
        hash.update(&record.s_big_endian);
        putInt(&hash, u32, record.recovery_id);
        hash.update(&record.public_key_xy_big_endian);
        putInt(&hash, u32, record.status);
        for (record.input_previous_clocks) |value| putInt(&hash, u32, value);
        for (record.output_previous_words) |value| putInt(&hash, u32, value);
        for (record.output_previous_clocks) |value| putInt(&hash, u32, value);
    }
    return hash.finalResult();
}

fn executionRowsIdentity(domain: []const u8, rows: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(domain);
    putInt(&hash, u32, @as(u32, @intCast(rows.len)));
    for (rows) |row| {
        putInt(&hash, u32, row.execution_clock);
        putInt(&hash, u32, row.pc);
        putInt(&hash, u32, row.inst_word);
        putInt(&hash, u32, row.call_index);
    }
    return hash.finalResult();
}

fn fileIdentity(value: contract.Identity) evidence.FileIdentity {
    return .{
        .bytes = value.bytes,
        .path = value.path,
        .sha256 = contract.parseSha256(value.sha256) catch unreachable,
    };
}

fn putInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
