//! Two-pass retained-workload bridge for one genuine bulk-memcpy microproof.
//!
//! The historical journal and aggregate observation are cold-validated only as
//! completion/corpus custody. Pass 1 executes one complete current segment0,
//! selects the first execution-ordered call satisfying the frozen candidate
//! and fixed 16-word cap, and durably publishes a sealed current authority.
//! Pass 2 starts from the same current ELF/input, replays to exactly
//! `TraceRow.clk - 1`, exact-matches the cold-reopened pass1 authority, and
//! projects a tape through the const-only candidate runner. No guest state is
//! committed by the projection.

const std = @import("std");
const stwo_core = @import("stwo_core");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const current_authority = @import("bulk_memcpy_current_selected_segment_authority_v1.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const journal_authority = @import("ethereum_block_leaf_journal.zig");
const retained_journal = @import("bulk_memcpy_retained_journal_v1.zig");
const observation_mod = @import("bulk_memcpy_retained_observation_v1.zig");
const receipt_mod = @import("bulk_memcpy_retained_microproof_receipt_v2.zig");
const replay = @import("bulk_memcpy_retained_replay_v1.zig");
const statement_artifact = @import("bulk_memcpy_statement_artifact_v1.zig");
const support = @import("ethereum_block_leaf_support.zig");
const tape_artifact = @import("bulk_memcpy_tape_artifact_v1.zig");

const Engine = frontend.prover_mod.ProverEngineForBackend(CpuBackend);
const harness = frontend.testing.bulk_memcpy_proof_harness_v1;
const tape_mod = frontend.runner.guest_precompile.bulk_memcpy_session_tape_v1;
const Selection = replay.Selection;
const Pass1Result = replay.Pass1Result;
const Pass2Result = replay.Pass2Result;
const PassStats = replay.PassStats;
const ReplayBoundary = replay.ReplayBoundary;

pub const tape_basename = "bulk-memcpy-tape.stwbmt01";
pub const statement_basename = "bulk-memcpy-statement.stwbms01";
pub const proof_basename = "bulk-memcpy-proof.postcard";
pub const current_authority_basename =
    "bulk-memcpy-current-selected-segment-authority.json";
pub const receipt_basename = "bulk-memcpy-receipt-v2.json";
pub const maximum_source_bytes: usize = contract.max_json_bytes;

pub const Options = struct {
    source_request_path: []const u8,
    observation_path: []const u8,
    output_root: []const u8,
    memcpy_entry_pc: u32,
    max_word_rows: u32 = receipt_mod.maximum_word_row_cap,
    hard_cap_ns: u64 = receipt_mod.maximum_hard_cap_ns,

    pub fn validate(self: Options) !void {
        if (!std.fs.path.isAbsolute(self.source_request_path) or
            !std.fs.path.isAbsolute(self.observation_path) or
            !std.fs.path.isAbsolute(self.output_root) or
            self.memcpy_entry_pc == 0 or
            self.max_word_rows != receipt_mod.maximum_word_row_cap or
            self.hard_cap_ns == 0 or
            self.hard_cap_ns > receipt_mod.maximum_hard_cap_ns or
            std.mem.eql(u8, self.source_request_path, self.observation_path) or
            std.mem.eql(u8, self.source_request_path, self.output_root) or
            std.mem.eql(u8, self.observation_path, self.output_root))
        {
            return error.InvalidRetainedMicroproofOptions;
        }
    }
};

pub fn run(allocator: std.mem.Allocator, options: Options) !void {
    try options.validate();
    var total_clock = try evidence.Clock.start();
    var hard_timer = try std.time.Timer.start();

    const source_bytes = try artifact_io.readFileBounded(
        allocator,
        options.source_request_path,
        maximum_source_bytes,
    );
    defer allocator.free(source_bytes);
    var source = try contract.parseRecursiveSource(allocator, source_bytes);
    defer source.deinit();
    const source_file = evidence.identity(options.source_request_path, source_bytes);

    const elf = try support.readIdentity(
        allocator,
        source.value.elf,
        64 * 1024 * 1024,
    );
    defer allocator.free(elf);
    const input = try support.readIdentity(
        allocator,
        source.value.input,
        64 * 1024 * 1024,
    );
    defer allocator.free(input);
    const journal = try support.readIdentity(
        allocator,
        source.value.execution_journal,
        64 * 1024 * 1024,
    );
    defer allocator.free(journal);
    const elf_file = evidence.identity(source.value.elf.path, elf);
    const input_file = evidence.identity(source.value.input.path, input);
    const journal_file = evidence.identity(source.value.execution_journal.path, journal);

    const observation_bytes = try artifact_io.readFileBounded(
        allocator,
        options.observation_path,
        observation_mod.maximum_bytes,
    );
    defer allocator.free(observation_bytes);
    var observation = try observation_mod.parse(allocator, observation_bytes);
    defer observation.deinit();
    const observation_file = evidence.identity(
        options.observation_path,
        observation_bytes,
    );
    try observation.value.validateAgainst(
        elf_file.sha256,
        input_file.sha256,
        journal_file.sha256,
        options.memcpy_entry_pc,
        source.value.segment_count,
    );

    const journal_records = try journal_authority.validate(
        allocator,
        journal,
        source.value,
    );
    defer allocator.free(journal_records);
    var historical_segments = try retained_journal.parse(
        allocator,
        journal,
        journal_records,
    );
    defer historical_segments.deinit(allocator);
    if (historical_segments.items.len != source.value.segment_count)
        return error.InvalidRetainedJournalDescription;
    try ensureWithinCap(&hard_timer, options.hard_cap_ns);

    const producer_executable_path = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(producer_executable_path);
    const producer_executable_bytes = try artifact_io.readFileBounded(
        allocator,
        producer_executable_path,
        512 * 1024 * 1024,
    );
    defer allocator.free(producer_executable_bytes);
    const producer_executable_file = evidence.identity(
        producer_executable_path,
        producer_executable_bytes,
    );
    const producer_executable_sha256 = producer_executable_file.sha256;
    var pass1 = try replay.executePass1(
        allocator,
        elf,
        input,
        &source.value,
        options.memcpy_entry_pc,
        options.max_word_rows,
    );
    defer pass1.deinit();
    try ensureWithinCap(&hard_timer, options.hard_cap_ns);

    try artifact_io.createDirectoryCreateOnly(options.output_root);
    const current_authority_path = try artifact_io.resolveCreateOnlyChild(
        allocator,
        options.output_root,
        current_authority_basename,
    );
    defer allocator.free(current_authority_path);
    const authority_bytes = try current_authority.encode(allocator, .{
        .producer_executable = producer_executable_file,
        .source_request = source_file,
        .elf = elf_file,
        .input = input_file,
        .historical_journal = journal_file,
        .historical_observation = observation_file,
        .historical_observation_content_sha256 = observation.value.content_sha256,
        .max_word_rows = options.max_word_rows,
        .pass1 = pass1,
    });
    defer allocator.free(authority_bytes);
    try artifact_io.publishCreateOnlyDurable(
        current_authority_path,
        authority_bytes,
    );
    const reopened_authority_bytes = try reopenExact(
        allocator,
        current_authority_path,
        authority_bytes,
        current_authority.maximum_bytes,
    );
    defer allocator.free(reopened_authority_bytes);
    var parsed_authority = try current_authority.parse(
        allocator,
        reopened_authority_bytes,
    );
    defer parsed_authority.deinit();
    var admitted_authority = try current_authority.admit(
        allocator,
        parsed_authority.value,
        .{
            .producer_executable = producer_executable_file,
            .source_request = source_file,
            .elf = elf_file,
            .input = input_file,
            .historical_journal = journal_file,
            .historical_observation = observation_file,
            .historical_observation_content_sha256 = observation.value.content_sha256,
            .max_word_rows = options.max_word_rows,
            .pass1 = pass1,
        },
    );
    defer admitted_authority.deinit();
    const authority_file = evidence.identity(
        current_authority_path,
        reopened_authority_bytes,
    );
    try ensureWithinCap(&hard_timer, options.hard_cap_ns);

    var pass2 = try replay.executePass2(
        allocator,
        elf,
        input,
        admitted_authority.segment,
        admitted_authority.selection,
        admitted_authority.projection.value,
    );
    defer pass2.tape.deinit();
    try ensureWithinCap(&hard_timer, options.hard_cap_ns);

    const tape_bytes = try tape_artifact.encodeAlloc(allocator, &pass2.tape);
    defer allocator.free(tape_bytes);
    const tape_identity = tape_artifact.identity(tape_bytes);
    var cold_tape = try tape_artifact.decodeAlloc(allocator, tape_bytes);
    defer cold_tape.deinit();
    if (!std.meta.eql(tape_identity, tape_artifact.identity(tape_bytes)))
        return error.BulkMemcpyTapeIdentityMismatch;

    const pcs_config = stwo_core.pcs.PcsConfig{
        .pow_bits = 0,
        .fri_config = try stwo_core.fri.FriConfig.init(0, 1, 3),
    };
    var output = try harness.prove(Engine, allocator, pcs_config, &cold_tape);
    const statement = output.statement;
    const prove_timings = output.timings;
    const roots_identity = rootsIdentity(output.roots);
    const proof_bytes = try harness.encodeProofAlloc(
        Engine,
        allocator,
        &output.proof,
    );
    defer allocator.free(proof_bytes);
    output.deinit(allocator);
    try ensureWithinCap(&hard_timer, options.hard_cap_ns);

    const statement_bytes = try statement_artifact.encodeAlloc(
        allocator,
        statement,
    );
    defer allocator.free(statement_bytes);
    const statement_identity = statement_artifact.identity(statement_bytes);
    _ = try statement_artifact.decodeCanonical(
        allocator,
        statement_bytes,
    );

    const tape_path = try artifact_io.resolveCreateOnlyChild(
        allocator,
        options.output_root,
        tape_basename,
    );
    defer allocator.free(tape_path);
    const statement_path = try artifact_io.resolveCreateOnlyChild(
        allocator,
        options.output_root,
        statement_basename,
    );
    defer allocator.free(statement_path);
    const proof_path = try artifact_io.resolveCreateOnlyChild(
        allocator,
        options.output_root,
        proof_basename,
    );
    defer allocator.free(proof_path);
    const receipt_path = try artifact_io.resolveCreateOnlyChild(
        allocator,
        options.output_root,
        receipt_basename,
    );
    defer allocator.free(receipt_path);

    try artifact_io.publishCreateOnlyDurable(tape_path, tape_bytes);
    try artifact_io.publishCreateOnlyDurable(statement_path, statement_bytes);
    try artifact_io.publishCreateOnlyDurable(proof_path, proof_bytes);

    const reopened_tape_bytes = try reopenExact(
        allocator,
        tape_path,
        tape_bytes,
        tape_artifact.maximum_artifact_bytes,
    );
    defer allocator.free(reopened_tape_bytes);
    var reopened_tape = try tape_artifact.decodeAlloc(allocator, reopened_tape_bytes);
    defer reopened_tape.deinit();
    if (!std.meta.eql(
        tape_identity,
        tape_artifact.identity(reopened_tape_bytes),
    )) return error.BulkMemcpyTapeIdentityMismatch;

    const reopened_statement_bytes = try reopenExact(
        allocator,
        statement_path,
        statement_bytes,
        statement_artifact.encoded_size,
    );
    defer allocator.free(reopened_statement_bytes);
    const reopened_statement = try statement_artifact.decodeCanonical(
        allocator,
        reopened_statement_bytes,
    );
    if (!std.meta.eql(
        statement_identity,
        statement_artifact.identity(reopened_statement_bytes),
    )) {
        return error.BulkMemcpyStatementIdentityMismatch;
    }

    const reopened_proof_bytes = try reopenExact(
        allocator,
        proof_path,
        proof_bytes,
        harness.maximum_encoded_proof_bytes,
    );
    defer allocator.free(reopened_proof_bytes);
    var verify_clock = try evidence.Clock.start();
    const decoded_proof = try harness.decodeProofAlloc(
        Engine,
        allocator,
        reopened_proof_bytes,
    );
    try harness.verifyFresh(
        Engine,
        allocator,
        pcs_config,
        reopened_statement,
        decoded_proof,
    );
    const verify_timing = try verify_clock.finish();
    try ensureWithinCap(&hard_timer, options.hard_cap_ns);

    const proof_file = evidence.identity(proof_path, reopened_proof_bytes);
    const statement_file = evidence.identity(statement_path, reopened_statement_bytes);
    const tape_file = evidence.identity(tape_path, reopened_tape_bytes);
    const selector_identity = admitted_authority.selector_identity_sha256;
    const boundary_identity = boundaryIdentity(
        admitted_authority.content_sha256,
        pass1.selection,
        pass2.boundary,
    );
    const total_timing = try total_clock.finish();
    if (total_timing.wall_ns > options.hard_cap_ns)
        return error.RetainedMicroproofHardCapExceeded;

    const receipt_bytes = try encodeReceipt(
        allocator,
        options,
        source_file,
        elf_file,
        input_file,
        journal_file,
        observation_file,
        observation.value.content_sha256,
        authority_file,
        admitted_authority.content_sha256,
        pass1,
        pass2,
        tape_file,
        tape_identity,
        statement_file,
        statement_identity,
        proof_file,
        roots_identity,
        producer_executable_sha256,
        prove_timings,
        verify_timing,
        selector_identity,
        boundary_identity,
        total_timing,
        pcs_config,
    );
    defer allocator.free(receipt_bytes);
    try artifact_io.publishCreateOnlyDurable(receipt_path, receipt_bytes);
    const reopened_receipt = try reopenExact(
        allocator,
        receipt_path,
        receipt_bytes,
        receipt_mod.maximum_receipt_bytes,
    );
    defer allocator.free(reopened_receipt);
    var parsed_receipt = try receipt_mod.parse(allocator, reopened_receipt);
    defer parsed_receipt.deinit();
    try receipt_mod.validateAgainstAuthority(
        parsed_receipt.value,
        parsed_authority.value,
        authority_file,
    );
}

fn encodeReceipt(
    allocator: std.mem.Allocator,
    options: Options,
    source_file: evidence.FileIdentity,
    elf_file: evidence.FileIdentity,
    input_file: evidence.FileIdentity,
    journal_file: evidence.FileIdentity,
    observation_file: evidence.FileIdentity,
    observation_content_sha256: []const u8,
    authority_file: evidence.FileIdentity,
    authority_content_sha256: [32]u8,
    pass1: Pass1Result,
    pass2: Pass2Result,
    tape_file: evidence.FileIdentity,
    tape_identity: [32]u8,
    statement_file: evidence.FileIdentity,
    statement_identity: [32]u8,
    proof_file: evidence.FileIdentity,
    roots_identity: [32]u8,
    producer_executable_sha256: [32]u8,
    prove_timings: harness.TimingsV1,
    verify_timing: evidence.Timing,
    selector_identity: [32]u8,
    boundary_identity: [32]u8,
    total_timing: evidence.Timing,
    pcs_config: stwo_core.pcs.PcsConfig,
) ![]u8 {
    const source_hex = hex(source_file.sha256);
    const elf_hex = hex(elf_file.sha256);
    const input_hex = hex(input_file.sha256);
    const journal_hex = hex(journal_file.sha256);
    const observation_hex = hex(observation_file.sha256);
    const authority_hex = hex(authority_file.sha256);
    const authority_content_hex = hex(authority_content_sha256);
    const entry_cpu_hex = hex(pass1.segment.entry.cpu_sha256);
    const exit_cpu_hex = hex(pass1.segment.exit.cpu_sha256);
    const replay_cpu_hex = hex(pass2.boundary.cpu_sha256);
    const replay_memory_hex = hex(pass2.boundary.memory_sha256);
    const replay_clocks_hex = hex(pass2.boundary.access_clocks_sha256);
    const boundary_hex = hex(boundary_identity);
    const selector_hex = hex(selector_identity);
    const executable_hex = hex(producer_executable_sha256);
    const proof_hex = hex(proof_file.sha256);
    const roots_hex = hex(roots_identity);
    const statement_hex = hex(statement_file.sha256);
    const statement_identity_hex = hex(statement_identity);
    const tape_hex = hex(tape_file.sha256);
    const tape_identity_hex = hex(tape_identity);
    const bound_statement_identity = receipt_mod.boundStatementIdentity(
        authority_file.sha256,
        authority_content_sha256,
        statement_file.sha256,
        statement_identity,
    );
    const bound_statement_hex = hex(bound_statement_identity);
    const bound_proof_identity = receipt_mod.boundProofIdentity(
        authority_file.sha256,
        authority_content_sha256,
        bound_statement_identity,
        proof_file.sha256,
        roots_identity,
        tape_identity,
    );
    const bound_proof_hex = hex(bound_proof_identity);
    const joint_custody_identity = receipt_mod.jointCustodyIdentity(
        authority_file.sha256,
        authority_content_sha256,
        bound_statement_identity,
        bound_proof_identity,
    );
    const joint_custody_hex = hex(joint_custody_identity);
    const global_cycle = std.math.add(
        u64,
        pass1.segment.global_first_cycle,
        pass1.selection.trace_clock - 1,
    ) catch return error.InvalidReplayDerivedBoundary;
    return receipt_mod.encode(allocator, .{
        .authorities = .{
            .current_selected_segment_authority = fileWire(
                authority_file,
                &authority_hex,
            ),
            .current_selected_segment_authority_content_sha256 = &authority_content_hex,
            .elf = fileWire(elf_file, &elf_hex),
            .historical_journal = fileWire(journal_file, &journal_hex),
            .historical_observation = fileWire(
                observation_file,
                &observation_hex,
            ),
            .historical_observation_content_sha256 = observation_content_sha256,
            .historical_role = current_authority.historical_role,
            .input = fileWire(input_file, &input_hex),
            .source_request = fileWire(source_file, &source_hex),
        },
        .boundary = .{
            .current_segment_entry_cpu_sha256 = &entry_cpu_hex,
            .current_segment_exit_cpu_sha256 = &exit_cpu_hex,
            .global_execution_cycle = global_cycle,
            .identity_sha256 = &boundary_hex,
            .replay_access_clocks_sha256 = &replay_clocks_hex,
            .replay_cpu_sha256 = &replay_cpu_hex,
            .replay_rw_memory_sha256 = &replay_memory_hex,
            .segment_index = pass1.selection.segment_index,
            .trace_clock = pass1.selection.trace_clock,
        },
        .boundary_authority_caveat = receipt_mod.boundary_caveat,
        .execution_passes = .{
            passWire(pass1.stats),
            passWire(pass2.stats),
        },
        .hard_cap_ns = options.hard_cap_ns,
        .production = false,
        .proof = .{
            .authority_bound_proof_identity_sha256 = &bound_proof_hex,
            .authority_bound_statement_identity_sha256 = &bound_statement_hex,
            .binding_scope = receipt_mod.binding_scope,
            .call_relation_closed = true,
            .cold_fresh_verified = true,
            .external_base_tables_required = true,
            .joint_custody_identity_sha256 = &joint_custody_hex,
            .pcs = .{
                .fold_step = pcs_config.fri_config.fold_step,
                .log_blowup_factor = pcs_config.fri_config.log_blowup_factor,
                .log_last_layer_degree_bound = pcs_config.fri_config.log_last_layer_degree_bound,
                .n_queries = @intCast(pcs_config.fri_config.n_queries),
                .pow_bits = pcs_config.pow_bits,
            },
            .producer_executable_sha256 = &executable_hex,
            .production_eligible = false,
            .proof = fileWire(proof_file, &proof_hex),
            .proof_roots_sha256 = &roots_hex,
            .prove_timings = .{
                .interaction_commit_ns = prove_timings.interaction_commit_ns,
                .interaction_generation_ns = prove_timings.interaction_generation_ns,
                .main_commit_ns = prove_timings.main_commit_ns,
                .preprocessed_commit_ns = prove_timings.preprocessed_commit_ns,
                .prove_ns = prove_timings.prove_ns,
                .witness_ns = prove_timings.witness_ns,
            },
            .statement = fileWire(statement_file, &statement_hex),
            .statement_identity_sha256 = &statement_identity_hex,
            .tape = fileWire(tape_file, &tape_hex),
            .tape_identity_sha256 = &tape_identity_hex,
            .verify_timing = timingWire(verify_timing),
        },
        .schema = receipt_mod.schema,
        .selector = .{
            .descriptor = descriptorWire(pass1.selection),
            .identity_sha256 = &selector_hex,
            .max_word_rows = options.max_word_rows,
            .rule = receipt_mod.selection_rule,
            .selected_execution_ordinal = pass1.selection.execution_ordinal,
            .selected_word_rows = pass1.selection.call.expectedWordCount(),
        },
        .status = receipt_mod.status,
        .total_timing = timingWire(total_timing),
    });
}

fn fileWire(
    value: evidence.FileIdentity,
    digest: []const u8,
) receipt_mod.FileIdentity {
    return .{ .bytes = value.bytes, .path = value.path, .sha256 = digest };
}

fn timingWire(value: evidence.Timing) receipt_mod.Timing {
    return .{
        .system_ns = value.system_ns,
        .user_ns = value.user_ns,
        .wall_ns = value.wall_ns,
    };
}

fn passWire(value: PassStats) receipt_mod.ExecutionPass {
    return .{
        .core_rows = value.core_rows,
        .cycles = value.cycles,
        .segments = value.segments,
        .timing = timingWire(value.timing),
    };
}

fn descriptorWire(value: Selection) receipt_mod.CallDescriptor {
    return .{
        .destination = value.call.destination,
        .execution_clock = value.trace_clock,
        .length = value.call.length,
        .pc = value.call.pc,
        .projected_inst_word = tape_mod.fixed_inst_word,
        .return_pc = value.return_pc,
        .software_inst_word = value.software_inst_word,
        .source = value.call.source,
    };
}

fn boundaryIdentity(
    authority_content_sha256: [32]u8,
    selection: Selection,
    boundary: ReplayBoundary,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv/bulk-memcpy-current-replay-boundary/v2\x00");
    hash.update(&authority_content_sha256);
    hashInt(&hash, u32, selection.segment_index);
    hashInt(&hash, u32, selection.trace_clock);
    hashDescriptor(&hash, selection);
    hashInt(&hash, u32, boundary.pc);
    hash.update(&boundary.cpu_sha256);
    hash.update(&boundary.memory_sha256);
    hashInt(&hash, u64, boundary.retained_words);
    hashInt(&hash, u64, boundary.nonzero_words);
    hashInt(&hash, u64, boundary.zero_words);
    hash.update(&boundary.access_clocks_sha256);
    hashInt(&hash, u64, boundary.memory_clock_entries);
    return hash.finalResult();
}

fn hashDescriptor(hash: anytype, selection: Selection) void {
    hashInt(hash, u32, selection.call.destination);
    hashInt(hash, u32, selection.trace_clock);
    hashInt(hash, u32, selection.call.length);
    hashInt(hash, u32, selection.call.pc);
    hashInt(hash, u32, tape_mod.fixed_inst_word);
    hashInt(hash, u32, selection.return_pc);
    hashInt(hash, u32, selection.software_inst_word);
    hashInt(hash, u32, selection.call.source);
}

fn rootsIdentity(roots: [harness.tree_count]Engine.Hasher.Hash) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv/bulk-memcpy-proof-roots/v1\x00");
    for (roots) |root| hash.update(&root);
    return hash.finalResult();
}

fn reopenExact(
    allocator: std.mem.Allocator,
    path: []const u8,
    expected: []const u8,
    maximum_bytes: usize,
) ![]u8 {
    const bytes = try artifact_io.readFileBounded(allocator, path, maximum_bytes);
    errdefer allocator.free(bytes);
    if (!std.mem.eql(u8, bytes, expected)) return error.PublishedArtifactMismatch;
    return bytes;
}

fn ensureWithinCap(timer: *std.time.Timer, hard_cap_ns: u64) !void {
    if (timer.read() > hard_cap_ns)
        return error.RetainedMicroproofHardCapExceeded;
}

fn hex(value: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(value, .lower);
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}
