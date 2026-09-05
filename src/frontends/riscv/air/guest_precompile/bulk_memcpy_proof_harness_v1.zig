//! Tiny, genuine STARK harness for the nonproduction bulk-memcpy candidate.
//!
//! The caller and word traces share one transcript and the extension-local
//! call relation closes inside the proof.  The remaining twelve base-bus
//! contribution is retained explicitly as an external-table residual; this
//! standalone proof cannot be mistaken for a closed VM proof.

const std = @import("std");
const stwo_core = @import("stwo_core");
const prover_engine = @import("stwo_prover_engine");
const postcard = @import("interop_postcard");

const core_verifier = stwo_core.verifier;
const pcs_core = stwo_core.pcs;
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const prover_pcs = prover_engine.pcs;

const contract = @import("bulk_memcpy_component_v1.zig");
const abi = @import("../../isa/bulk_memcpy_candidate_v1.zig");
const caller = @import("bulk_memcpy_caller_candidate_v1.zig");
const interaction_mod = @import("bulk_memcpy_interaction_v1.zig");
const relations_mod = @import("bulk_memcpy_relations_v1.zig");
const session = @import("../../runner/guest_precompile/bulk_memcpy_session_tape_v1.zig");
const stark_component = @import("bulk_memcpy_stark_component_v1.zig");
const trace_mod = @import("bulk_memcpy_trace_v1.zig");
const words = @import("bulk_memcpy_word_candidate_v1.zig");
const prepared_evaluation = @import("../prepared_evaluation_owner.zig");

pub const format_version: u16 = 1;
pub const production_active = false;
pub const tree_count: usize = 3;
pub const proof_commitment_count: usize = tree_count + 1;
pub const maximum_encoded_proof_bytes: usize = 16 * 1024 * 1024;

/// Candidate-leaf filtered-gate coverage for coefficient-retention parity.
pub fn exerciseRetainedLdeParityForTest(allocator: std.mem.Allocator) !void {
    return prepared_evaluation.exerciseRetainedLdeParityForTest(allocator);
}

const preprocessed_count = 2 * trace_mod.preprocessed_column_count;
const main_count = contract.Caller.main_column_count + contract.Word.main_column_count;
const interaction_count = contract.Caller.interaction_column_count +
    contract.Word.interaction_column_count;

const caller_placement = stark_component.Placement{
    .preprocessed_offset = 0,
    .main_offset = 0,
    .interaction_offset = 0,
};
const word_placement = stark_component.Placement{
    .preprocessed_offset = trace_mod.preprocessed_column_count,
    .main_offset = contract.Caller.main_column_count,
    .interaction_offset = contract.Caller.interaction_column_count,
};

/// Exact verifier-derived split of the component LogUp sum.
///
/// Both schedules dedicate their final batch solely to the call bus.  Its
/// cancellation is therefore proven rather than inferred from a producer
/// tape.  Every earlier batch belongs to the twelve base buses and must be
/// closed by the ordinary VM tables in any future joined proof.
pub const ExternalResidualV1 = struct {
    format: u16 = format_version,
    base_relation_count: u16 = 12,
    call_relation_sum: QM31,
    external_base_sum: QM31,
    combined_component_sum: QM31,
    call_relation_closed: bool,
    external_base_tables_required: bool,
    production_eligible: bool,

    pub fn derive(
        caller_claim: contract.CallerClaim,
        word_claim: contract.WordClaim,
    ) ExternalResidualV1 {
        const call = caller_claim.batch_sums[contract.caller_batch_count - 1]
            .add(word_claim.batch_sums[contract.word_batch_count - 1]);
        var external = QM31.zero();
        for (caller_claim.batch_sums[0 .. contract.caller_batch_count - 1]) |sum|
            external = external.add(sum);
        for (word_claim.batch_sums[0 .. contract.word_batch_count - 1]) |sum|
            external = external.add(sum);
        return .{
            .call_relation_sum = call,
            .external_base_sum = external,
            .combined_component_sum = caller_claim.component_sum.add(
                word_claim.component_sum,
            ),
            .call_relation_closed = call.isZero(),
            .external_base_tables_required = true,
            .production_eligible = false,
        };
    }

    pub fn validateAgainst(
        self: ExternalResidualV1,
        caller_claim: contract.CallerClaim,
        word_claim: contract.WordClaim,
    ) !void {
        const expected = derive(caller_claim, word_claim);
        if (self.format != format_version or self.base_relation_count != 12 or
            !self.call_relation_sum.eql(expected.call_relation_sum) or
            !self.external_base_sum.eql(expected.external_base_sum) or
            !self.combined_component_sum.eql(expected.combined_component_sum) or
            !self.call_relation_closed or !expected.call_relation_closed or
            !self.external_base_tables_required or self.production_eligible or
            !self.external_base_sum.eql(self.combined_component_sum))
        {
            return error.InvalidExternalRelationResidual;
        }
    }
};

pub const StatementV1 = struct {
    format: u16 = format_version,
    caller: contract.CallerClaim,
    words: contract.WordClaim,
    residual: ExternalResidualV1,
    production_eligible: bool = false,

    pub fn canonical(
        caller_claim: contract.CallerClaim,
        word_claim: contract.WordClaim,
    ) !StatementV1 {
        const result = StatementV1{
            .caller = caller_claim,
            .words = word_claim,
            .residual = ExternalResidualV1.derive(caller_claim, word_claim),
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: StatementV1) !void {
        if (self.format != format_version or self.production_eligible)
            return error.InvalidBulkMemcpyStatement;
        try self.caller.validate();
        try self.words.validate();
        try self.residual.validateAgainst(self.caller, self.words);
    }
};

pub const TimingsV1 = struct {
    witness_ns: u64,
    preprocessed_commit_ns: u64,
    main_commit_ns: u64,
    interaction_generation_ns: u64,
    interaction_commit_ns: u64,
    prove_ns: u64,
};

pub const TinyReceiptV1 = struct {
    format: u16 = format_version,
    caller_rows: u32,
    word_rows: u32,
    caller_log_size: u32,
    word_log_size: u32,
    proof_bytes: u32,
    proof_commitments: u32,
    call_relation_closed: bool,
    external_base_tables_required: bool,
    decoded_before_verify: bool,
    cold_fresh_verified: bool,
    production_eligible: bool,
    timings: TimingsV1,
    decode_and_verify_ns: u64,

    pub fn validate(self: TinyReceiptV1) !void {
        if (self.format != format_version or self.caller_rows != 1 or
            self.word_rows != 8 or self.caller_log_size != 1 or
            self.word_log_size != 3 or self.proof_bytes == 0 or
            self.proof_commitments != proof_commitment_count or
            !self.call_relation_closed or !self.external_base_tables_required or
            !self.decoded_before_verify or !self.cold_fresh_verified or
            self.production_eligible)
        {
            return error.InvalidBulkMemcpyTinyReceipt;
        }
    }
};

pub fn ProveOutput(comptime Engine: type) type {
    return struct {
        statement: StatementV1,
        roots: [tree_count]Engine.Hasher.Hash,
        proof: stwo_core.proof.StarkProof(Engine.Hasher),
        timings: TimingsV1,

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            self.proof.deinit(allocator);
            self.* = undefined;
        }

        pub fn deinitAfterProofMoved(self: *@This()) void {
            self.* = undefined;
        }
    };
}

pub fn prove(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    tape: *const session.Frozen,
) !ProveOutput(Engine) {
    var timer = try std.time.Timer.start();
    var traces = try trace_mod.generate(allocator, tape);
    defer traces.deinit();
    try traces.validateAgainst(tape);
    const witness_ns = timer.lap();

    var scheme = try Engine.init(allocator, pcs_config);
    var scheme_moved = false;
    defer if (!scheme_moved) Engine.deinit(&scheme, allocator);
    scheme.setCoefficientRetentionPolicy(.always);
    var channel = Engine.Channel{};
    mixPrefix(&channel, pcs_config);

    const pp_logs = preprocessedLogs(
        traces.caller.log_size,
        traces.words.log_size,
    );
    var pp_tree = try OwnedTree(Engine).init(allocator, &pp_logs);
    defer pp_tree.deinit();
    appendPreprocessed(&traces.caller, &pp_tree, 0);
    appendPreprocessed(
        &traces.words,
        &pp_tree,
        trace_mod.preprocessed_column_count,
    );
    try pp_tree.commit(&scheme, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    const preprocessed_commit_ns = timer.lap();

    const main_logs = mainLogs(traces.caller.log_size, traces.words.log_size);
    var main_tree = try OwnedTree(Engine).init(allocator, &main_logs);
    defer main_tree.deinit();
    appendMain(&traces.caller, &main_tree, 0);
    appendMain(
        &traces.words,
        &main_tree,
        contract.Caller.main_column_count,
    );
    try main_tree.commit(&scheme, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    mixMainStatement(
        &channel,
        traces.caller.log_size,
        traces.caller.logical_rows,
        traces.words.log_size,
        traces.words.logical_rows,
    );
    const main_commit_ns = timer.lap();

    const relations = try relations_mod.Relations.draw(allocator, &channel);
    var pool: prover_engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 2 });
    defer pool.deinit();
    var caller_interaction = try interaction_mod.generate(
        contract.Caller,
        allocator,
        &traces.caller,
        &relations,
        &pool,
    );
    defer caller_interaction.deinit(allocator);
    var word_interaction = try interaction_mod.generate(
        contract.Word,
        allocator,
        &traces.words,
        &relations,
        &pool,
    );
    defer word_interaction.deinit(allocator);
    const caller_claim = try contract.CallerClaim.canonical(
        traces.caller.log_size,
        traces.caller.logical_rows,
        caller_interaction.claims,
    );
    const word_claim = try contract.WordClaim.canonical(
        traces.words.log_size,
        traces.words.logical_rows,
        word_interaction.claims,
    );
    const statement = try StatementV1.canonical(caller_claim, word_claim);
    mixInteractionStatement(&channel, statement);
    const interaction_generation_ns = timer.lap();

    const interaction_logs = interactionLogs(
        traces.caller.log_size,
        traces.words.log_size,
    );
    var interaction_tree = try OwnedTree(Engine).init(
        allocator,
        &interaction_logs,
    );
    defer interaction_tree.deinit();
    appendInteraction(&caller_interaction, &interaction_tree, 0);
    appendInteraction(
        &word_interaction,
        &interaction_tree,
        contract.Caller.interaction_column_count,
    );
    try interaction_tree.commit(&scheme, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    const interaction_commit_ns = timer.lap();

    var roots_value = try scheme.roots(allocator);
    defer roots_value.deinit(allocator);
    if (roots_value.items.len != tree_count)
        return error.InvalidBulkMemcpyTreeCount;
    const roots = [tree_count]Engine.Hasher.Hash{
        roots_value.items[0],
        roots_value.items[1],
        roots_value.items[2],
    };

    var caller_component = try stark_component.Component(contract.Caller).init(
        caller_claim,
        caller_placement,
        &relations,
    );
    var word_component = try stark_component.Component(contract.Word).init(
        word_claim,
        word_placement,
        &relations,
    );
    const components = [_]prover_engine.air.component_prover.ComponentProver{
        caller_component.asProverComponent(),
        word_component.asProverComponent(),
    };
    scheme_moved = true;
    var extended = try Engine.prove(
        allocator,
        &components,
        &channel,
        scheme,
        .{},
    );
    const proof = extended.proof;
    extended.aux.deinit(allocator);
    const prove_ns = timer.lap();
    return .{
        .statement = statement,
        .roots = roots,
        .proof = proof,
        .timings = .{
            .witness_ns = witness_ns,
            .preprocessed_commit_ns = preprocessed_commit_ns,
            .main_commit_ns = main_commit_ns,
            .interaction_generation_ns = interaction_generation_ns,
            .interaction_commit_ns = interaction_commit_ns,
            .prove_ns = prove_ns,
        },
    };
}

/// Consumes the decoded proof on success and failure.  No prover trace, tape,
/// interaction columns, or producer-owned root is accepted by this verifier.
pub fn verifyFresh(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: StatementV1,
    proof_in: stwo_core.proof.StarkProof(Engine.Hasher),
) !void {
    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);
    try statement.validate();
    const commitments = proof.commitment_scheme_proof.commitments.items;
    if (commitments.len != proof_commitment_count)
        return core_verifier.VerificationError.InvalidStructure;
    try verifyCanonicalPreprocessedRoot(
        Engine,
        allocator,
        pcs_config,
        statement,
        commitments[0],
    );

    const VerifierScheme = stwo_core.pcs.verifier.CommitmentSchemeVerifier(
        Engine.Hasher,
        Engine.MerkleChannel,
    );
    var scheme = try VerifierScheme.init(allocator, pcs_config);
    defer scheme.deinit(allocator);
    var channel = Engine.Channel{};
    mixPrefix(&channel, pcs_config);
    const pp_logs = preprocessedLogs(
        statement.caller.log_size,
        statement.words.log_size,
    );
    try scheme.commit(allocator, commitments[0], &pp_logs, &channel);
    const main_logs = mainLogs(
        statement.caller.log_size,
        statement.words.log_size,
    );
    try scheme.commit(allocator, commitments[1], &main_logs, &channel);
    mixMainStatement(
        &channel,
        statement.caller.log_size,
        statement.caller.n_rows,
        statement.words.log_size,
        statement.words.n_rows,
    );
    const relations = try relations_mod.Relations.draw(allocator, &channel);
    mixInteractionStatement(&channel, statement);
    const interaction_logs = interactionLogs(
        statement.caller.log_size,
        statement.words.log_size,
    );
    try scheme.commit(allocator, commitments[2], &interaction_logs, &channel);

    var caller_component = try stark_component.Component(contract.Caller).init(
        statement.caller,
        caller_placement,
        &relations,
    );
    var word_component = try stark_component.Component(contract.Word).init(
        statement.words,
        word_placement,
        &relations,
    );
    const components = [_]stwo_core.air.components.Component{
        caller_component.asVerifierComponent(),
        word_component.asVerifierComponent(),
    };
    proof_moved = true;
    try core_verifier.verify(
        Engine.Hasher,
        Engine.MerkleChannel,
        allocator,
        &components,
        &channel,
        &scheme,
        proof,
    );
}

pub fn encodeProofAlloc(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    proof: *const stwo_core.proof.StarkProof(Engine.Hasher),
) ![]u8 {
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try postcard.serializeProof(Engine.Hasher, bytes.writer(allocator), proof.*);
    if (bytes.items.len == 0 or bytes.items.len > maximum_encoded_proof_bytes)
        return error.InvalidBulkMemcpyProofBytes;
    return bytes.toOwnedSlice(allocator);
}

pub fn decodeProofAlloc(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !stwo_core.proof.StarkProof(Engine.Hasher) {
    if (bytes.len == 0 or bytes.len > maximum_encoded_proof_bytes)
        return error.InvalidBulkMemcpyProofBytes;
    var stream = std.io.fixedBufferStream(bytes);
    var proof = try postcard.deserializeProof(
        Engine.Hasher,
        allocator,
        stream.reader(),
    );
    errdefer proof.deinit(allocator);
    if (stream.pos != bytes.len) return error.TrailingBulkMemcpyProofBytes;
    return proof;
}

/// One backend-instantiated proof exercise.  The producer proof is destroyed
/// before postcard bytes are decoded and handed to `verifyFresh`.
pub fn exerciseTiny(
    comptime Engine: type,
    allocator: std.mem.Allocator,
) !TinyReceiptV1 {
    const pcs_config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try stwo_core.fri.FriConfig.init(0, 1, 3),
    };
    var tape = try tinyTape(allocator);
    defer tape.deinit();
    var output = try prove(Engine, allocator, pcs_config, &tape);
    const statement = output.statement;
    const timings = output.timings;
    const commitment_count = output.proof.commitment_scheme_proof.commitments.items.len;
    const bytes = try encodeProofAlloc(Engine, allocator, &output.proof);
    defer allocator.free(bytes);
    output.deinit(allocator);

    var mutation = statement;
    mutation.residual.call_relation_sum = mutation.residual.call_relation_sum.add(
        QM31.one(),
    );
    if (mutation.validate()) |_| return error.ResidualMutationAccepted else |err| {
        if (err != error.InvalidExternalRelationResidual) return err;
    }

    var timer = try std.time.Timer.start();
    const decoded = try decodeProofAlloc(Engine, allocator, bytes);
    try verifyFresh(Engine, allocator, pcs_config, statement, decoded);
    const receipt = TinyReceiptV1{
        .caller_rows = statement.caller.n_rows,
        .word_rows = statement.words.n_rows,
        .caller_log_size = statement.caller.log_size,
        .word_log_size = statement.words.log_size,
        .proof_bytes = std.math.cast(u32, bytes.len) orelse
            return error.InvalidBulkMemcpyProofBytes,
        .proof_commitments = std.math.cast(u32, commitment_count) orelse
            return error.InvalidBulkMemcpyProofBytes,
        .call_relation_closed = statement.residual.call_relation_closed,
        .external_base_tables_required = statement.residual.external_base_tables_required,
        .decoded_before_verify = true,
        .cold_fresh_verified = true,
        .production_eligible = false,
        .timings = timings,
        .decode_and_verify_ns = timer.read(),
    };
    try receipt.validate();
    return receipt;
}

fn tinyTape(allocator: std.mem.Allocator) !session.Frozen {
    const record = caller.Record{
        .execution_clock = 1,
        .pc = 0x1000,
        .destination_previous_clock = 0,
        .source_previous_clock = 0,
        .length_previous_clock = 0,
        .destination = 0x2100,
        .source = 0x2000,
        .length = 32,
        .call_index = 0,
    };
    const word_count = record.call().expectedWordCount();
    if (word_count != 8) return error.InvalidBulkMemcpyTinyFixture;
    var rows: [8]words.Row = undefined;
    for (&rows, 0..) |*row, index| row.* = try words.materializeRow(
        record.call(),
        @intCast(index),
        .{
            .source_previous_clock = 0,
            .destination_previous_clock = 0,
            .source_bytes = fixtureBytes(@intCast(index), 0x20),
            .destination_before = fixtureBytes(@intCast(index), 0xa0),
        },
    );
    var builder = try session.Builder.init(allocator, 1, rows.len, 0);
    errdefer builder.deinit();
    try builder.reserveOne(rows.len);
    builder.appendAssumeCapacity(abi.fixed_word, record, &rows);
    try builder.validate();
    var result = builder.freeze();
    errdefer result.deinit();
    try result.validate();
    return result;
}

fn fixtureBytes(index: u8, seed: u8) [4]u8 {
    const base = seed +% index *% 4;
    return .{ base, base +% 1, base +% 2, base +% 3 };
}

fn verifyCanonicalPreprocessedRoot(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: StatementV1,
    expected: Engine.Hasher.Hash,
) !void {
    var scheme = try Engine.init(allocator, pcs_config);
    defer Engine.deinit(&scheme, allocator);
    scheme.setCoefficientRetentionPolicy(.never);
    var channel = Engine.Channel{};
    const logs = preprocessedLogs(
        statement.caller.log_size,
        statement.words.log_size,
    );
    var tree = try OwnedTree(Engine).init(allocator, &logs);
    defer tree.deinit();
    fillCanonicalPreprocessed(
        &tree,
        0,
        statement.caller.log_size,
        statement.caller.n_rows,
    );
    fillCanonicalPreprocessed(
        &tree,
        trace_mod.preprocessed_column_count,
        statement.words.log_size,
        statement.words.n_rows,
    );
    try tree.commit(&scheme, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    if (roots.items.len != 1 or !std.meta.eql(roots.items[0], expected))
        return error.InvalidBulkMemcpyPreprocessedRoot;
}

fn preprocessedLogs(caller_log: u32, word_log: u32) [preprocessed_count]u32 {
    return .{caller_log} ** trace_mod.preprocessed_column_count ++
        .{word_log} ** trace_mod.preprocessed_column_count;
}

fn mainLogs(caller_log: u32, word_log: u32) [main_count]u32 {
    return .{caller_log} ** contract.Caller.main_column_count ++
        .{word_log} ** contract.Word.main_column_count;
}

fn interactionLogs(caller_log: u32, word_log: u32) [interaction_count]u32 {
    return .{caller_log} ** contract.Caller.interaction_column_count ++
        .{word_log} ** contract.Word.interaction_column_count;
}

fn appendPreprocessed(trace: anytype, tree: anytype, offset: usize) void {
    for (0..trace_mod.preprocessed_column_count) |column|
        @memcpy(tree.column(offset + column), trace.preprocessedColumn(column));
}

fn appendMain(trace: anytype, tree: anytype, offset: usize) void {
    const Trace = @TypeOf(trace.*);
    const column_count = @divExact(trace.main_storage.len, trace.domainSize());
    _ = Trace;
    for (0..column_count) |column|
        @memcpy(tree.column(offset + column), trace.mainColumn(column));
}

fn appendInteraction(interaction: anytype, tree: anytype, offset: usize) void {
    for (interaction.columns, 0..) |source, column|
        @memcpy(tree.column(offset + column), source);
}

fn fillCanonicalPreprocessed(
    tree: anytype,
    offset: usize,
    log_size: u32,
    n_rows: u32,
) void {
    const size = @as(usize, 1) << @intCast(log_size);
    tree.column(offset + trace_mod.domain_first_column)[
        trace_mod.committedRow(0, log_size)
    ] = M31.one();
    tree.column(offset + trace_mod.domain_last_column)[
        trace_mod.committedRow(size - 1, log_size)
    ] = M31.one();
    for (0..n_rows) |row| tree.column(offset + trace_mod.active_prefix_column)[
        trace_mod.committedRow(row, log_size)
    ] = M31.one();
}

fn mixPrefix(channel: anytype, pcs_config: pcs_core.PcsConfig) void {
    pcs_config.mixInto(channel);
    channel.mixU32s(&prefix_domain_words);
    channel.mixU64(format_version);
    channel.mixU64(@intFromBool(production_active));
}

fn mixMainStatement(
    channel: anytype,
    caller_log: u32,
    caller_rows: u32,
    word_log: u32,
    word_rows: u32,
) void {
    channel.mixU32s(&main_domain_words);
    channel.mixU64(caller_log);
    channel.mixU64(caller_rows);
    channel.mixU64(word_log);
    channel.mixU64(word_rows);
    channel.mixU64(preprocessed_count);
    channel.mixU64(main_count);
    channel.mixU64(interaction_count);
}

fn mixInteractionStatement(channel: anytype, statement: StatementV1) void {
    channel.mixU32s(&interaction_domain_words);
    channel.mixFelts(&statement.caller.batch_sums);
    channel.mixFelts(&.{statement.caller.component_sum});
    channel.mixFelts(&statement.words.batch_sums);
    channel.mixFelts(&.{statement.words.component_sum});
    channel.mixFelts(&.{
        statement.residual.call_relation_sum,
        statement.residual.external_base_sum,
        statement.residual.combined_component_sum,
    });
    channel.mixU64(@intFromBool(statement.residual.call_relation_closed));
    channel.mixU64(@intFromBool(statement.residual.external_base_tables_required));
    channel.mixU64(@intFromBool(statement.production_eligible));
}

fn OwnedTree(comptime Engine: type) type {
    return struct {
        const Self = @This();
        allocator: std.mem.Allocator,
        storage: []M31,
        evaluations: []prover_pcs.ColumnEvaluation,
        columns: [][]M31,
        moved: bool = false,

        fn init(allocator: std.mem.Allocator, logs: []const u32) !Self {
            var cells: usize = 0;
            for (logs) |log_size| cells = try std.math.add(
                usize,
                cells,
                @as(usize, 1) << @intCast(log_size),
            );
            const storage = try allocator.alloc(M31, cells);
            errdefer allocator.free(storage);
            @memset(storage, M31.zero());
            const evaluations = try allocator.alloc(
                prover_pcs.ColumnEvaluation,
                logs.len,
            );
            errdefer allocator.free(evaluations);
            const columns = try allocator.alloc([]M31, logs.len);
            errdefer allocator.free(columns);
            var cursor: usize = 0;
            for (evaluations, columns, logs) |*evaluation, *view, log_size| {
                const size = @as(usize, 1) << @intCast(log_size);
                view.* = storage[cursor..][0..size];
                evaluation.* = .{ .log_size = log_size, .values = view.* };
                cursor += size;
            }
            return .{
                .allocator = allocator,
                .storage = storage,
                .evaluations = evaluations,
                .columns = columns,
            };
        }

        fn deinit(self: *Self) void {
            if (self.columns.len != 0) self.allocator.free(self.columns);
            if (!self.moved) {
                self.allocator.free(self.evaluations);
                self.allocator.free(self.storage);
            }
            self.* = undefined;
        }

        fn column(self: *Self, index: usize) []M31 {
            return self.columns[index];
        }

        fn commit(
            self: *Self,
            scheme: *Engine.Scheme,
            channel: *Engine.Channel,
        ) !void {
            const backing = try self.allocator.alloc([]M31, 1);
            backing[0] = self.storage;
            self.allocator.free(self.columns);
            self.columns = &.{};
            self.moved = true;
            try Engine.commitWithBacking(
                scheme,
                self.allocator,
                self.evaluations,
                backing,
                null,
                channel,
            );
        }
    };
}

const prefix_domain_words = [4]u32{
    0x5354_5742, // STWB
    0x4d43_5059, // MCPY
    0x5052_4631, // PRF1
    1,
};

const main_domain_words = [4]u32{
    0x5354_5742, // STWB
    0x4d43_5059, // MCPY
    0x4d41_494e, // MAIN
    1,
};

const interaction_domain_words = [4]u32{
    0x5354_5742, // STWB
    0x4d43_5059, // MCPY
    0x494e_5431, // INT1
    1,
};

comptime {
    if (production_active or stark_component.production_active or
        contract.production_active or relations_mod.production_active or
        preprocessed_count != 6 or main_count != 136 or
        interaction_count != 76 or
        contract.caller_batch_count != 15 or contract.word_batch_count != 4)
    {
        @compileError("bulk memcpy proof harness contract drifted");
    }
}
