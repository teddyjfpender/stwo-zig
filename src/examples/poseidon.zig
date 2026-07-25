const std = @import("std");
const core_air_components = @import("stwo_core").air.components;
const channel_blake2s = @import("stwo_core").channel.blake2s;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const pcs_core = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const core_proof = @import("stwo_core").proof;
const core_verifier = @import("stwo_core").verifier;
const blake2_merkle = @import("stwo_core").vcs_lifted.blake2_merkle;
const prover_component = @import("stwo_prover_impl").air.component_prover;
const prover_engine = @import("stwo_prover_impl").engine;
const stage_profile = @import("stwo_prover_impl").stage_profile;
const prover_transaction = @import("common/prover_transaction.zig");
const component_mod = @import("poseidon/component.zig");
const interaction = @import("poseidon/interaction.zig");
const trace_input = @import("poseidon/input.zig");
const CpuBackend = @import("../backends/cpu_scalar/mod.zig").CpuBackend;

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
pub const protocol_name = "raw-stwo-poseidon-logup-split2-v1";

pub fn ProverEngineForBackend(comptime Backend: type) type {
    return prover_engine.ProverEngine(Backend, Hasher, MerkleChannel, Channel);
}

comptime {
    prover_engine.assertProverEngine(CpuProverEngine);
}

pub const Statement = trace_input.Statement;
pub const PreparedInput = trace_input.PreparedInput;
pub const prepareInput = trace_input.prepare;
pub const genTrace = trace_input.genTrace;
pub const deinitTrace = trace_input.deinitTrace;
pub const logNRows = trace_input.logNRows;
pub const N_COLUMNS = trace_input.N_COLUMNS;
pub const N_INTERACTION_COLUMNS = interaction.N_COLUMNS;
pub const N_TRACE_COLUMNS = N_COLUMNS + N_INTERACTION_COLUMNS;
const validateStatement = trace_input.validate;

pub const ProveOutput = struct {
    statement: Statement,
    proof: Proof,
};

pub const ProveExOutput = prover_transaction.Output(Statement, ExtendedProof);

pub const Error = trace_input.Error || error{
    InvalidProofShape,
};

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

/// Proves a prepared Poseidon trace and consumes it on success or failure.
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
    const log_n_rows = try logNRows(statement);
    const composition_log = std.math.add(u32, log_n_rows, 2) catch
        return error.InvalidLogNInstances;
    const commitment_log = std.math.add(
        u32,
        log_n_rows,
        pcs_config.fri_config.log_blowup_factor,
    ) catch return error.InvalidLogNInstances;
    return @max(
        @max(composition_log, commitment_log),
        pcs_config.lifting_log_size orelse 0,
    );
}

pub fn verify(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
    proof_in: Proof,
) anyerror!void {
    const log_n_rows = logNRows(statement) catch {
        var proof = proof_in;
        proof.deinit(allocator);
        return Error.InvalidLogNInstances;
    };
    if (proof_in.commitment_scheme_proof.commitments.items.len != 4) {
        var proof = proof_in;
        proof.deinit(allocator);
        return Error.InvalidProofShape;
    }

    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);

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
        &[_]u32{},
        &channel,
    );

    const main_log_sizes = try allocator.alloc(u32, N_COLUMNS);
    defer allocator.free(main_log_sizes);
    @memset(main_log_sizes, log_n_rows);
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[1],
        main_log_sizes,
        &channel,
    );

    const lookup_elements = try interaction.LookupElements.draw(allocator, &channel);
    const interaction_log_sizes = [_]u32{log_n_rows} ** interaction.N_COLUMNS;
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[2],
        &interaction_log_sizes,
        &channel,
    );

    const component = component_mod.Component{
        .log_n_rows = log_n_rows,
        .lookup_elements = lookup_elements,
        .claimed_sum = statement.claimed_sum,
    };
    const verifier_components = [_]core_air_components.Component{
        component.asVerifierComponent(),
    };

    proof_moved = true;
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
        try validateStatement(request);
    }

    pub fn validatePrepared(prepared: *const trace_input.PreparedInput) Error!void {
        const preprocessed = prepared.trace.preprocessed.columns orelse
            return error.PreparedInputConsumed;
        const main = prepared.trace.main.columns orelse
            return error.PreparedInputConsumed;
        if (preprocessed.len != 0 or main.len != N_COLUMNS)
            return error.InvalidPreparedGeometry;
        const log_n_rows = try logNRows(prepared.request);
        const expected_len = @as(usize, 1) << @intCast(log_n_rows);
        for (main) |column| {
            if (column.log_size != log_n_rows)
                return error.InvalidPreparedGeometry;
        }
        for (prepared.lookup_data.initial) |column| {
            if (column.len != expected_len) return error.InvalidPreparedGeometry;
        }
        for (prepared.lookup_data.final) |column| {
            if (column.len != expected_len) return error.InvalidPreparedGeometry;
        }
    }

    pub fn compositionLog(request: trace_input.Statement) Error!u32 {
        return std.math.add(u32, try logNRows(request), 2) catch
            return error.InvalidLogNInstances;
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
        _: *Channel,
        request: trace_input.Statement,
        prepared_interaction: *const PreparedInteraction,
    ) !void {
        const log_n_rows = try logNRows(request);
        var statement_value = request;
        statement_value.claimed_sum = prepared_interaction.claimed_sum;
        out.* = .{
            .statement_value = statement_value,
            .component = .{
                .log_n_rows = log_n_rows,
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

test "examples poseidon: prove/verify wrapper roundtrip" {
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };
    const statement: Statement = .{ .log_n_instances = 8 };

    const output = try prove(std.testing.allocator, config, statement);
    try std.testing.expectEqual(
        @as(usize, 4),
        output.proof.commitment_scheme_proof.commitments.items.len,
    );
    try std.testing.expectEqual(
        @as(usize, 16),
        output.proof.commitment_scheme_proof.sampled_values.items[3].len,
    );
    try verify(std.testing.allocator, config, output.statement, output.proof);
}

test "examples poseidon: prove_ex wrapper roundtrip" {
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };
    const statement: Statement = .{ .log_n_instances = 8 };

    var output = try proveEx(std.testing.allocator, config, statement, false);
    defer output.proof.aux.deinit(std.testing.allocator);
    try verify(std.testing.allocator, config, output.statement, output.proof.proof);
}

test "examples poseidon: prove and prove_ex wrappers emit identical proof bytes" {
    const alloc = std.testing.allocator;
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };
    const statement: Statement = .{ .log_n_instances = 8 };

    var output_prove = try prove(alloc, config, statement);
    defer output_prove.proof.deinit(alloc);

    var output_prove_ex = try proveEx(alloc, config, statement, false);
    defer output_prove_ex.proof.aux.deinit(alloc);
    defer output_prove_ex.proof.proof.deinit(alloc);

    const proof_wire = @import("../interop/proof_wire.zig");
    const prove_bytes = try proof_wire.encodeProofBytes(alloc, output_prove.proof);
    defer alloc.free(prove_bytes);
    const prove_ex_bytes = try proof_wire.encodeProofBytes(alloc, output_prove_ex.proof.proof);
    defer alloc.free(prove_ex_bytes);

    try std.testing.expectEqualSlices(u8, prove_bytes, prove_ex_bytes);
}

test "examples poseidon: verify wrapper rejects statement mismatch" {
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };
    const statement: Statement = .{ .log_n_instances = 8 };
    const output = try prove(std.testing.allocator, config, statement);

    var bad_statement = output.statement;
    bad_statement.log_n_instances += 1;

    if (verify(std.testing.allocator, config, bad_statement, output.proof)) |_| {
        try std.testing.expect(false);
    } else |err| {
        const verification_error = @import("stwo_core").verifier_types.VerificationError;
        try std.testing.expect(
            err == verification_error.OodsNotMatching or
                err == verification_error.InvalidStructure or
                err == verification_error.ShapeMismatch,
        );
    }
}

test "examples poseidon: transition and relation sample mutations are rejected" {
    const alloc = std.testing.allocator;
    const proof_wire = @import("../interop/proof_wire.zig");
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };
    var output = try prove(alloc, config, .{ .log_n_instances = 8 });
    const statement = output.statement;
    const encoded = try proof_wire.encodeProofBytes(alloc, output.proof);
    output.proof.deinit(alloc);
    defer alloc.free(encoded);

    for ([_]usize{ 1, 2 }) |tree_index| {
        var mutated = try proof_wire.decodeProofBytes(alloc, encoded);
        mutated.commitment_scheme_proof.sampled_values.items[tree_index][0][0] =
            mutated.commitment_scheme_proof.sampled_values.items[tree_index][0][0]
                .add(QM31.one());
        if (verify(alloc, config, statement, mutated)) |_| {
            try std.testing.expect(false);
        } else |_| {}
    }
}
