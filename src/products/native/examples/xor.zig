//! Repo-defined Native XOR truth-table lookup protocol.
//!
//! Upstream Stwo's XOR example supplies GKR/MLE preprocessed-column utilities,
//! not a STARK AIR. This module therefore defines the AIR explicitly and keeps
//! a byte-identical implementation in the pinned Rust correctness oracle.

const std = @import("std");
const core_air_components = @import("stwo_core").air.components;
const channel_blake2s = @import("stwo_core").channel.blake2s;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const pcs_core = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const core_proof = @import("stwo_core").proof;
const core_verifier = @import("stwo_core").verifier;
const blake2_merkle = @import("stwo_core").vcs_lifted.blake2_merkle;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_engine = @import("stwo_prover_engine").engine;
const stage_profile = @import("stwo_prover_api").stage_profile;
const prover_transaction = @import("stwo_prover_engine").transaction;
const component_mod = @import("xor/component.zig");
const interaction = @import("xor/interaction.zig");
const trace_input = @import("xor/input.zig");
const preprocessed_commitment = @import("preprocessed_commitment.zig");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointQM31 = @import("stwo_core").circle.CirclePointQM31;
pub const Hasher = blake2_merkle.Blake2sPrefixedMerkleHasher;
pub const MerkleChannel = blake2_merkle.Blake2sPrefixedMerkleChannel;
pub const Channel = channel_blake2s.Blake2sChannel;
pub const Proof = core_proof.StarkProof(Hasher);
pub const ExtendedProof = core_proof.ExtendedStarkProof(Hasher);
pub const CpuProverEngine = prover_engine.ProverEngine(
    CpuBackend,
    Hasher,
    MerkleChannel,
    Channel,
);
pub const protocol_name = "raw-stwo-xor-lookup-v2";
const PROOF_COMMITMENTS: usize = 4;

pub fn ProverEngineForBackend(comptime Backend: type) type {
    return prover_engine.ProverEngine(Backend, Hasher, MerkleChannel, Channel);
}

comptime {
    @import("stwo_prover_api").assertProverEngine(CpuProverEngine);
}

pub const Error = trace_input.Error || error{
    InvalidProofShape,
    InvalidPreprocessedCommitment,
};

/// Generates `IsFirst` preprocessed column values in bit-reversed order.
///
/// Semantics match upstream `examples/xor/gkr_lookups/mod.rs::IsFirst::gen_column_simd`.
pub const genIsFirstColumn = trace_input.genIsFirstColumn;

/// Generates `IsStepWithOffset` preprocessed column values in bit-reversed order.
///
/// Semantics match upstream `examples/xor/gkr_lookups/preprocessed_columns.rs`.
pub const genIsStepWithOffsetColumn = trace_input.genIsStepWithOffsetColumn;

pub const Statement = trace_input.Statement;
pub const PreparedInput = trace_input.PreparedInput;
pub const prepareInput = trace_input.prepare;
pub const validateStatement = trace_input.validate;

pub const ProveOutput = struct {
    statement: Statement,
    proof: Proof,
};

pub const ProveExOutput = prover_transaction.Output(Statement, ExtendedProof);

pub fn prove(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
) anyerror!ProveOutput {
    return proveWithEngine(CpuProverEngine, allocator, pcs_config, statement, null);
}

pub fn proveEx(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
    include_all_preprocessed_columns: bool,
) anyerror!ProveExOutput {
    return proveExWithEngine(
        CpuProverEngine,
        allocator,
        pcs_config,
        statement,
        include_all_preprocessed_columns,
        null,
    );
}

pub fn proveProfiled(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
    recorder: *stage_profile.Recorder,
) anyerror!ProveOutput {
    return proveWithEngine(CpuProverEngine, allocator, pcs_config, statement, recorder);
}

pub fn proveExProfiled(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
    include_all_preprocessed_columns: bool,
    recorder: *stage_profile.Recorder,
) anyerror!ProveExOutput {
    return proveExWithEngine(
        CpuProverEngine,
        allocator,
        pcs_config,
        statement,
        include_all_preprocessed_columns,
        recorder,
    );
}

pub fn proveWithBackend(
    comptime Backend: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
    recorder: ?*stage_profile.Recorder,
) anyerror!ProveOutput {
    return proveWithEngine(
        ProverEngineForBackend(Backend),
        allocator,
        pcs_config,
        statement,
        recorder,
    );
}

pub fn proveExWithBackend(
    comptime Backend: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
    include_all_preprocessed_columns: bool,
    recorder: ?*stage_profile.Recorder,
) anyerror!ProveExOutput {
    return proveExWithEngine(
        ProverEngineForBackend(Backend),
        allocator,
        pcs_config,
        statement,
        include_all_preprocessed_columns,
        recorder,
    );
}

pub fn proveWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
    recorder: ?*stage_profile.Recorder,
) anyerror!ProveOutput {
    var output = try proveExWithEngine(
        Engine,
        allocator,
        pcs_config,
        statement,
        false,
        recorder,
    );
    const proof = output.proof.proof;
    output.proof.aux.deinit(allocator);
    return .{ .statement = output.statement, .proof = proof };
}

pub fn proveExWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
    include_all_preprocessed_columns: bool,
    recorder: ?*stage_profile.Recorder,
) anyerror!ProveExOutput {
    return proveExImpl(
        Engine,
        allocator,
        pcs_config,
        statement,
        include_all_preprocessed_columns,
        recorder,
    );
}

/// Proves a prepared XOR trace and consumes it on success or failure.
pub fn provePreparedWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    prepared: PreparedInput,
    recorder: ?*stage_profile.Recorder,
) anyerror!ProveOutput {
    var output = try provePreparedExImpl(
        Engine,
        false,
        {},
        allocator,
        pcs_config,
        prepared,
        false,
        recorder,
    );
    const proof = output.proof.proof;
    output.proof.aux.deinit(allocator);
    return .{ .statement = output.statement, .proof = proof };
}

pub fn provePreparedExWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    prepared: PreparedInput,
    include_all_preprocessed_columns: bool,
    recorder: ?*stage_profile.Recorder,
) anyerror!ProveExOutput {
    return provePreparedExImpl(
        Engine,
        false,
        {},
        allocator,
        pcs_config,
        prepared,
        include_all_preprocessed_columns,
        recorder,
    );
}

/// Proves with immutable twiddles borrowed from `session`.
pub fn provePreparedWithSessionAndEngine(
    comptime Engine: type,
    session: *const Engine.Session,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    prepared: PreparedInput,
    recorder: ?*stage_profile.Recorder,
) anyerror!ProveOutput {
    var output = try provePreparedExImpl(
        Engine,
        true,
        session,
        allocator,
        pcs_config,
        prepared,
        false,
        recorder,
    );
    const proof = output.proof.proof;
    output.proof.aux.deinit(allocator);
    return .{ .statement = output.statement, .proof = proof };
}

pub fn provePreparedExWithSessionAndEngine(
    comptime Engine: type,
    session: *const Engine.Session,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    prepared: PreparedInput,
    include_all_preprocessed_columns: bool,
    recorder: ?*stage_profile.Recorder,
) anyerror!ProveExOutput {
    return provePreparedExImpl(
        Engine,
        true,
        session,
        allocator,
        pcs_config,
        prepared,
        include_all_preprocessed_columns,
        recorder,
    );
}

fn proveExImpl(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
    include_all_preprocessed_columns: bool,
    recorder: ?*stage_profile.Recorder,
) anyerror!ProveExOutput {
    const prepared = blk: {
        var stage = try stage_profile.StageScope.begin(
            recorder,
            "trace_generation",
            "Trace generation",
        );
        defer stage.end();
        break :blk try prepareInput(allocator, statement);
    };
    return provePreparedExImpl(
        Engine,
        false,
        {},
        allocator,
        pcs_config,
        prepared,
        include_all_preprocessed_columns,
        recorder,
    );
}

fn provePreparedExImpl(
    comptime Engine: type,
    comptime use_session: bool,
    session: if (use_session) *const Engine.Session else void,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    prepared: PreparedInput,
    include_all_preprocessed_columns: bool,
    recorder: ?*stage_profile.Recorder,
) anyerror!ProveExOutput {
    return prover_transaction.provePreparedEx(
        Engine,
        ProvingSpec,
        use_session,
        session,
        allocator,
        pcs_config,
        prepared,
        .{
            .include_all_preprocessed_columns = include_all_preprocessed_columns,
            .recorder = recorder,
        },
    );
}

pub fn requiredTwiddleCircleLog(
    statement: Statement,
    pcs_config: pcs_core.PcsConfig,
) Error!u32 {
    const composition_log = std.math.add(u32, statement.log_size, 1) catch
        return error.InvalidLogSize;
    const commitment_log = std.math.add(
        u32,
        statement.log_size,
        pcs_config.fri_config.log_blowup_factor,
    ) catch return error.InvalidLogSize;
    return @max(
        @max(composition_log, commitment_log),
        pcs_config.lifting_log_size orelse 0,
    );
}

/// Verifies XOR proof wrapper generated by `prove`.
pub fn verify(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
    proof_in: Proof,
) anyerror!void {
    return verifyDiagnosed(allocator, pcs_config, statement, proof_in, null);
}

/// Owned Core verification diagnostics; statement/shape and other origins remain unmapped.
pub fn verifyDiagnosed(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
    proof_in: Proof,
    diagnostic: ?*?@import("stwo_core").error_codes.Entry,
) anyerror!void {
    if (diagnostic) |sink| sink.* = null;
    trace_input.validate(statement) catch |err| {
        var invalid = proof_in;
        invalid.deinit(allocator);
        return err;
    };
    if (proof_in.commitment_scheme_proof.commitments.items.len != PROOF_COMMITMENTS) {
        var proof = proof_in;
        proof.deinit(allocator);
        return Error.InvalidProofShape;
    }

    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);

    const preprocessed_columns = try trace_input.generatePreprocessed(allocator, statement);
    defer preprocessed_commitment.freeColumns(allocator, preprocessed_columns);
    const expected_root = try preprocessed_commitment.root(
        allocator,
        pcs_config,
        preprocessed_columns,
    );
    if (!std.mem.eql(u8, &expected_root, &proof.commitment_scheme_proof.commitments.items[0]))
        return error.InvalidPreprocessedCommitment;

    var channel = Channel{};
    pcs_config.mixInto(&channel);

    var commitment_scheme = try pcs_verifier.CommitmentSchemeVerifier(Hasher, MerkleChannel).init(
        allocator,
        pcs_config,
    );
    defer commitment_scheme.deinit(allocator);

    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[0],
        &([_]u32{statement.log_size} ** trace_input.PREPROCESSED_COLUMNS),
        &channel,
    );
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[1],
        &([_]u32{statement.log_size} ** trace_input.MAIN_COLUMNS),
        &channel,
    );
    const lookup_elements = try interaction.LookupElements.draw(allocator, &channel);
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[2],
        &([_]u32{statement.log_size} ** interaction.N_COLUMNS),
        &channel,
    );

    mixStatement(&channel, statement);

    const component = component_mod.Component{
        .log_size = statement.log_size,
        .lookup_elements = lookup_elements,
        .claimed_sum = statement.claimed_sum,
    };
    const verifier_components = [_]core_air_components.Component{
        component.asVerifierComponent(),
    };

    proof_moved = true;
    if (diagnostic) |sink| return core_verifier.verifyDiagnosed(Hasher, MerkleChannel, allocator, verifier_components[0..], &channel, &commitment_scheme, proof, sink);
    try core_verifier.verify(
        Hasher,
        MerkleChannel,
        allocator,
        verifier_components[0..],
        &channel,
        &commitment_scheme,
        proof,
    );
}

const ProvingSpec = struct {
    pub const Statement = trace_input.Statement;
    pub const PreparedInput = trace_input.PreparedInput;
    pub const PreparedInteraction = interaction.PreparedInteraction;
    pub const max_components: usize = 1;

    pub const ProverContext = struct {
        statement_value: trace_input.Statement,
        component: component_mod.Component,
    };

    pub fn validateRequest(request: trace_input.Statement) Error!void {
        try trace_input.validate(request);
    }

    pub fn validatePrepared(prepared: *const trace_input.PreparedInput) Error!void {
        const preprocessed = prepared.trace.preprocessed.columns orelse
            return error.PreparedInputConsumed;
        const main = prepared.trace.main.columns orelse
            return error.PreparedInputConsumed;
        if (preprocessed.len != trace_input.PREPROCESSED_COLUMNS or
            main.len != trace_input.MAIN_COLUMNS)
        {
            return error.InvalidPreparedGeometry;
        }
        for (preprocessed) |column| {
            if (column.log_size != prepared.request.log_size)
                return error.InvalidPreparedGeometry;
        }
        for (main) |column| {
            if (column.log_size != prepared.request.log_size)
                return error.InvalidPreparedGeometry;
        }
    }

    pub fn compositionLog(request: trace_input.Statement) Error!u32 {
        return std.math.add(u32, request.log_size, 1) catch
            return error.InvalidLogSize;
    }

    pub fn prepareInteraction(
        allocator: std.mem.Allocator,
        channel: *Channel,
        prepared: *const trace_input.PreparedInput,
    ) !PreparedInteraction {
        return interaction.generate(allocator, channel, prepared);
    }

    pub fn deinitPreparedInteraction(
        prepared: *PreparedInteraction,
        allocator: std.mem.Allocator,
    ) void {
        prepared.deinit(allocator);
    }

    pub fn initProverContext(
        out: *ProverContext,
        channel: *Channel,
        request: trace_input.Statement,
        prepared_interaction: *const PreparedInteraction,
    ) !void {
        if (!prepared_interaction.claimed_sum.eql(QM31.zero()))
            return error.InvalidClaimedSum;
        var statement_value = request;
        statement_value.claimed_sum = prepared_interaction.claimed_sum;
        mixStatement(channel, statement_value);
        out.* = .{
            .statement_value = statement_value,
            .component = .{
                .log_size = request.log_size,
                .lookup_elements = prepared_interaction.lookup_elements,
                .claimed_sum = prepared_interaction.claimed_sum,
            },
        };
    }

    pub fn statement(context: *const ProverContext) trace_input.Statement {
        return context.statement_value;
    }

    pub fn proverComponents(
        context: *const ProverContext,
        out: []prover_component.ComponentProver,
    ) ![]const prover_component.ComponentProver {
        if (out.len < max_components) return error.InvalidProofShape;
        out[0] = context.component.asProverComponent();
        return out[0..1];
    }
};

fn mixStatement(channel: *Channel, statement: Statement) void {
    channel.mixU32s(&[_]u32{
        statement.log_size,
        statement.log_step,
    });
    channel.mixU64(@intCast(statement.offset));
    channel.mixFelts(&.{statement.claimed_sum});
}

test "examples xor: is_first has exactly one leading one" {
    const alloc = std.testing.allocator;
    const values = try genIsFirstColumn(alloc, 5);
    defer alloc.free(values);

    try std.testing.expect(values[0].eql(M31.one()));
    for (values[1..]) |value| {
        try std.testing.expect(value.eql(M31.zero()));
    }
}

test "examples xor: is_step_with_offset rejects invalid step" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(
        Error.InvalidStep,
        genIsStepWithOffsetColumn(alloc, 4, 5, 0),
    );
}

test "examples xor: prove/verify wrapper roundtrip" {
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };
    const statement: Statement = .{
        .log_size = 5,
        .log_step = 2,
        .offset = 3,
    };

    var output = try prove(std.testing.allocator, config, statement);
    var original_owned = true;
    defer if (original_owned) output.proof.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        PROOF_COMMITMENTS,
        output.proof.commitment_scheme_proof.commitments.items.len,
    );
    const codec = @import("stwo_proof_wire").ForHasher(Hasher);
    const encoded = try codec.encodeProofBytes(std.testing.allocator, output.proof);
    defer std.testing.allocator.free(encoded);
    var clone = try codec.decodeProofBytes(std.testing.allocator, encoded);
    var clone_owned = true;
    defer if (clone_owned) clone.deinit(std.testing.allocator);
    original_owned = false;
    try verify(std.testing.allocator, config, output.statement, output.proof);
    var diagnostic: ?@import("stwo_core").error_codes.Entry = @import("stwo_core").error_codes.fromFriConfig(error.InvalidBlowupFactor);
    clone_owned = false;
    try verifyDiagnosed(std.testing.allocator, config, output.statement, clone, &diagnostic);
    try std.testing.expect(diagnostic == null);
}

test "examples xor: prove_ex wrapper roundtrip" {
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };
    const statement: Statement = .{
        .log_size = 5,
        .log_step = 2,
        .offset = 3,
    };

    var output = try proveEx(std.testing.allocator, config, statement, false);
    defer output.proof.aux.deinit(std.testing.allocator);
    try verify(std.testing.allocator, config, output.statement, output.proof.proof);
}

test "examples xor: prove and prove_ex wrappers emit identical proof bytes" {
    const alloc = std.testing.allocator;
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };
    const statement: Statement = .{
        .log_size = 5,
        .log_step = 2,
        .offset = 7,
    };

    var output_prove = try prove(alloc, config, statement);
    defer output_prove.proof.deinit(alloc);

    var output_prove_ex = try proveEx(alloc, config, statement, false);
    defer output_prove_ex.proof.aux.deinit(alloc);
    defer output_prove_ex.proof.proof.deinit(alloc);

    const proof_wire = @import("stwo_proof_wire");
    const prove_bytes = try proof_wire.encodeProofBytes(alloc, output_prove.proof);
    defer alloc.free(prove_bytes);
    const prove_ex_bytes = try proof_wire.encodeProofBytes(alloc, output_prove_ex.proof.proof);
    defer alloc.free(prove_ex_bytes);

    try std.testing.expectEqualSlices(u8, prove_bytes, prove_ex_bytes);
}

test "examples xor: verify wrapper rejects statement mismatch" {
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };
    const statement: Statement = .{
        .log_size = 5,
        .log_step = 2,
        .offset = 11,
    };
    const output = try prove(std.testing.allocator, config, statement);

    var bad_statement = output.statement;
    bad_statement.offset += 1;

    var diagnostic: ?@import("stwo_core").error_codes.Entry = @import("stwo_core").error_codes.fromFriConfig(error.InvalidBlowupFactor);
    try std.testing.expectError(
        error.InvalidPreprocessedCommitment,
        verifyDiagnosed(std.testing.allocator, config, bad_statement, output.proof, &diagnostic),
    );
    try std.testing.expect(diagnostic == null);
}

test "examples xor: verifier rejects a mutated lookup claimed sum" {
    const allocator = std.testing.allocator;
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };
    const output = try prove(allocator, config, .{
        .log_size = 5,
        .log_step = 2,
        .offset = 3,
    });
    var bad_statement = output.statement;
    bad_statement.claimed_sum = QM31.one();
    try std.testing.expectError(
        error.InvalidClaimedSum,
        verify(allocator, config, bad_statement, output.proof),
    );
}

test "examples xor: physical FRI mutation is rejected with owned Core origin" {
    const allocator = std.testing.allocator;
    const config = pcs_core.PcsConfig{ .pow_bits = 0, .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3) };
    var output = try prove(allocator, config, .{ .log_size = 5, .log_step = 2, .offset = 3 });
    var proof_owned = true;
    defer if (proof_owned) output.proof.deinit(allocator);
    const coefficients = output.proof.commitment_scheme_proof.fri_proof.last_layer_poly.coeffs;
    try std.testing.expect(coefficients.len != 0);
    coefficients[0] = coefficients[0].add(QM31.one());
    var diagnostic: ?@import("stwo_core").error_codes.Entry = null;
    proof_owned = false;
    if (verifyDiagnosed(allocator, config, output.statement, output.proof, &diagnostic)) {
        return error.MutatedFriProofAccepted;
    } else |err| {
        const entry = diagnostic orelse return error.MissingOwnedCoreDiagnostic;
        try std.testing.expectEqualStrings(@errorName(err), entry.tag);
        try std.testing.expectEqual(@import("stwo_core").error_codes.Class.verification_failed, entry.class);
        // Only the FRI/Merkle section of the typed PCS table may explain this mutation.
        try std.testing.expect(entry.code >= 0x110f and entry.code <= 0x111a);
    }
}

test "examples xor: diagnosed receiver preserves foreign origin and maps owned Core rejection" {
    const allocator = std.testing.allocator;
    const config = pcs_core.PcsConfig{ .pow_bits = 0, .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3) };
    const statement = Statement{ .log_size = 5, .log_step = 2, .offset = 3 };
    const fixed = try trace_input.generatePreprocessed(allocator, statement);
    defer preprocessed_commitment.freeColumns(allocator, fixed);
    const root = try preprocessed_commitment.root(allocator, config, fixed);
    inline for (.{ false, true }) |owned_core_failure| {
        const commitments = try allocator.alloc(Hasher.Hash, PROOF_COMMITMENTS);
        var commitments_owned = true;
        errdefer if (commitments_owned) allocator.free(commitments);
        @memset(commitments, [_]u8{0} ** 32);
        if (owned_core_failure) commitments[0] = root;
        const core = @import("stwo_core");
        const last_layer = try allocator.alloc(QM31, 1);
        var last_layer_owned = true;
        errdefer if (last_layer_owned) allocator.free(last_layer);
        last_layer[0] = QM31.zero();
        const proof = Proof{ .commitment_scheme_proof = .{
            .config = config,
            .commitments = pcs_core.TreeVec(Hasher.Hash).initOwned(commitments),
            .sampled_values = pcs_core.TreeVec([][]QM31).initOwned(try allocator.alloc([][]QM31, 0)),
            .decommitments = pcs_core.TreeVec(core.vcs_lifted.verifier.MerkleDecommitmentLifted(Hasher)).initOwned(try allocator.alloc(core.vcs_lifted.verifier.MerkleDecommitmentLifted(Hasher), 0)),
            .queried_values = pcs_core.TreeVec([][]M31).initOwned(try allocator.alloc([][]M31, 0)),
            .proof_of_work = 0,
            .fri_proof = .{ .first_layer = .{ .fri_witness = try allocator.alloc(QM31, 0), .decommitment = .{ .hash_witness = try allocator.alloc(Hasher.Hash, 0) }, .commitment = [_]u8{0} ** 32 }, .inner_layers = try allocator.alloc(core.fri.FriLayerProof(Hasher), 0), .last_layer_poly = core.poly.line.LinePoly.initOwned(last_layer) },
        } };
        commitments_owned = false;
        last_layer_owned = false;
        var diagnostic: ?core.error_codes.Entry = core.error_codes.fromFriConfig(error.InvalidBlowupFactor);
        const result = verifyDiagnosed(allocator, config, statement, proof, &diagnostic);
        try std.testing.expectError(if (owned_core_failure) error.InvalidStructure else error.InvalidPreprocessedCommitment, result);
        if (owned_core_failure) try std.testing.expectEqual(@as(u16, 0x1101), diagnostic.?.code) else try std.testing.expect(diagnostic == null);
    }
}
