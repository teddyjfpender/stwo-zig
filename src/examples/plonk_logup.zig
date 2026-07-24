//! Exact pinned upstream Stwo Fibonacci Plonk/LogUp proving protocol.

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
const CpuBackend = @import("../backends/cpu_scalar/mod.zig").CpuBackend;
const prover_transaction = @import("common/prover_transaction.zig");
const component_mod = @import("plonk_logup/component.zig");
const interaction = @import("plonk_logup/interaction.zig");
const input = @import("plonk_logup/input.zig");

pub const protocol_name = "raw-stwo-plonk-logup-v1";

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

pub const Request = input.Request;
pub const PreparedInput = input.PreparedInput;
pub const prepareInput = input.prepare;
pub const genTrace = input.genTrace;
pub const deinitTrace = input.deinitTrace;

pub const Statement = struct {
    log_n_rows: u32,
    claimed_sum: QM31,
};
const ExactStatement = Statement;

pub const ProveOutput = struct {
    statement: Statement,
    proof: Proof,
};
pub const ProveExOutput = prover_transaction.Output(Statement, ExtendedProof);

pub fn ProverEngineForBackend(comptime Backend: type) type {
    return prover_engine.ProverEngine(Backend, Hasher, MerkleChannel, Channel);
}

pub fn prove(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    request: Request,
) anyerror!ProveOutput {
    return proveWithEngine(CpuProverEngine, allocator, pcs_config, request, null);
}

pub fn proveWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    request: Request,
    recorder: ?*stage_profile.Recorder,
) anyerror!ProveOutput {
    const prepared = blk: {
        var stage = try stage_profile.StageScope.begin(
            recorder,
            "trace_generation",
            "Trace generation",
        );
        defer stage.end();
        break :blk try prepareInput(allocator, request);
    };
    var output = try prover_transaction.provePreparedEx(
        Engine,
        ProvingSpec,
        false,
        {},
        allocator,
        pcs_config,
        prepared,
        .{ .recorder = recorder },
    );
    const proof = output.proof.proof;
    output.proof.aux.deinit(allocator);
    return .{ .statement = output.statement, .proof = proof };
}

pub fn verify(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Statement,
    proof_in: Proof,
) anyerror!void {
    input.validate(.{ .log_n_rows = statement.log_n_rows }) catch |err| {
        var invalid = proof_in;
        invalid.deinit(allocator);
        return err;
    };
    if (proof_in.commitment_scheme_proof.commitments.items.len < 3) {
        var invalid = proof_in;
        invalid.deinit(allocator);
        return error.InvalidProofShape;
    }

    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);

    var channel = Channel{};
    pcs_config.mixInto(&channel);
    var scheme = try pcs_verifier.CommitmentSchemeVerifier(Hasher, MerkleChannel).init(
        allocator,
        pcs_config,
    );
    defer scheme.deinit(allocator);

    const four_logs = [_]u32{statement.log_n_rows} ** 4;
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[0],
        &four_logs,
        &channel,
    );
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[1],
        &four_logs,
        &channel,
    );
    const lookup_elements = try interaction.LookupElements.draw(allocator, &channel);
    const eight_logs = [_]u32{statement.log_n_rows} ** 8;
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[2],
        &eight_logs,
        &channel,
    );

    const component = component_mod.Component{
        .log_n_rows = statement.log_n_rows,
        .lookup_elements = lookup_elements,
        .claimed_sum = statement.claimed_sum,
    };
    const components = [_]core_air_components.Component{component.asVerifierComponent()};
    proof_moved = true;
    try core_verifier.verify(
        Hasher,
        MerkleChannel,
        allocator,
        &components,
        &channel,
        &scheme,
        proof,
    );
}

const ProvingSpec = struct {
    pub const Statement = ExactStatement;
    pub const PreparedInput = input.PreparedInput;
    pub const PreparedInteraction = interaction.PreparedInteraction;
    pub const max_components: usize = 1;

    pub const ProverContext = struct {
        statement_value: ExactStatement,
        component: component_mod.Component,
    };

    pub fn validateRequest(request: Request) !void {
        try input.validate(request);
    }

    pub fn validatePrepared(prepared: *const input.PreparedInput) !void {
        const preprocessed = prepared.trace.preprocessed.columns orelse
            return error.PreparedInputConsumed;
        const main = prepared.trace.main.columns orelse
            return error.PreparedInputConsumed;
        if (preprocessed.len != 4 or main.len != 4)
            return error.InvalidPreparedGeometry;
        const expected_len = @as(usize, 1) << @intCast(prepared.request.log_n_rows);
        inline for (@typeInfo(input.CircuitView).@"struct".fields) |field| {
            if (@field(prepared.circuit, field.name).len != expected_len)
                return error.InvalidPreparedGeometry;
        }
    }

    pub fn compositionLog(request: Request) !u32 {
        return std.math.add(u32, request.log_n_rows, 1) catch
            return error.InvalidLogSize;
    }

    pub fn prepareInteraction(
        allocator: std.mem.Allocator,
        channel: *Channel,
        prepared: *const input.PreparedInput,
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
        request: Request,
        prepared_interaction: *const PreparedInteraction,
    ) !void {
        out.* = .{
            .statement_value = .{
                .log_n_rows = request.log_n_rows,
                .claimed_sum = prepared_interaction.claimed_sum,
            },
            .component = .{
                .log_n_rows = request.log_n_rows,
                .lookup_elements = prepared_interaction.lookup_elements,
                .claimed_sum = prepared_interaction.claimed_sum,
            },
        };
    }

    pub fn statement(context: *const ProverContext) ExactStatement {
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

test "exact Plonk LogUp CPU proof roundtrips" {
    const allocator = std.testing.allocator;
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3),
    };
    const output = try prove(allocator, config, .{ .log_n_rows = 4 });
    try verify(allocator, config, output.statement, output.proof);
}
