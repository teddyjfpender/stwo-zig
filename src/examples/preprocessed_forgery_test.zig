//! The first commitment is fixed by the statement, even when the rest of a
//! proof is internally consistent with a different preprocessed trace.

const std = @import("std");
const xor = @import("xor.zig");
const blake = @import("blake.zig");
const plonk = @import("plonk.zig");
const plonk_logup = @import("plonk_logup.zig");
const component_mod = @import("xor/component.zig");
const interaction = @import("xor/interaction.zig");
const trace_input = @import("xor/input.zig");
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_transaction = @import("stwo_prover_engine").transaction;
const pcs_core = @import("stwo_core").pcs;
const FriConfig = @import("stwo_core").fri.FriConfig;

const claimed: xor.Statement = .{ .log_size = 5, .log_step = 2, .offset = 3 };
const actual: xor.Statement = .{ .log_size = 5, .log_step = 2, .offset = 1 };

fn config() !pcs_core.PcsConfig {
    return .{ .pow_bits = 0, .fri_config = try FriConfig.init(0, 1, 3) };
}

fn mixStatement(channel: *xor.Channel, statement: xor.Statement) void {
    channel.mixU32s(&[_]u32{ statement.log_size, statement.log_step });
    channel.mixU64(@intCast(statement.offset));
    channel.mixFelts(&.{statement.claimed_sum});
}

/// The witness columns are for `actual`, while the public transcript says
/// `claimed`. This was accepted before the preprocessed root was checked.
const ForgingSpec = struct {
    pub const Statement = trace_input.Statement;
    pub const PreparedInput = trace_input.PreparedInput;
    pub const PreparedInteraction = interaction.PreparedInteraction;
    pub const max_components: usize = 1;
    pub const ProverContext = struct {
        statement_value: trace_input.Statement,
        component: component_mod.Component,
    };
    pub fn validateRequest(_: trace_input.Statement) !void {}
    pub fn validatePrepared(_: *const trace_input.PreparedInput) !void {}
    pub fn compositionLog(request: trace_input.Statement) !u32 {
        return request.log_size + 1;
    }
    pub fn prepareInteraction(
        allocator: std.mem.Allocator,
        channel: *xor.Channel,
        prepared: *const trace_input.PreparedInput,
    ) !PreparedInteraction {
        var view = prepared.*;
        view.request = actual;
        return interaction.generate(allocator, channel, &view);
    }
    pub fn deinitPreparedInteraction(p: *PreparedInteraction, allocator: std.mem.Allocator) void {
        p.deinit(allocator);
    }
    pub fn initProverContext(
        out: *ProverContext,
        channel: *xor.Channel,
        request: trace_input.Statement,
        pi: *const PreparedInteraction,
    ) !void {
        var statement_value = request;
        statement_value.claimed_sum = pi.claimed_sum;
        mixStatement(channel, statement_value);
        out.* = .{ .statement_value = statement_value, .component = .{
            .log_size = request.log_size,
            .lookup_elements = pi.lookup_elements,
            .claimed_sum = pi.claimed_sum,
        } };
    }
    pub fn statement(context: *const ProverContext) trace_input.Statement {
        return context.statement_value;
    }
    pub fn proverComponents(
        context: *const ProverContext,
        out: []prover_component.ComponentProver,
    ) ![]const prover_component.ComponentProver {
        out[0] = context.component.asProverComponent();
        return out[0..1];
    }
};

test "xor rejects a consistent witness with preprocessed offset different from statement" {
    const allocator = std.testing.allocator;
    var prepared = try xor.prepareInput(allocator, actual);
    prepared.request = claimed;
    var forged = try prover_transaction.provePreparedEx(
        xor.CpuProverEngine,
        ForgingSpec,
        false,
        {},
        allocator,
        try config(),
        prepared,
        .{},
    );
    forged.proof.aux.deinit(allocator);
    try std.testing.expectEqual(claimed.offset, forged.statement.offset);
    try std.testing.expectError(
        error.InvalidPreprocessedCommitment,
        xor.verify(allocator, try config(), forged.statement, forged.proof.proof),
    );
}

test "plonk and logup reject a corrupted first commitment" {
    const allocator = std.testing.allocator;
    const pcs_config = try config();

    var plonk_output = try plonk.prove(allocator, pcs_config, .{ .log_n_rows = 4 });
    plonk_output.proof.commitment_scheme_proof.commitments.items[0][0] ^= 1;
    try std.testing.expectError(
        error.InvalidPreprocessedCommitment,
        plonk.verify(allocator, pcs_config, plonk_output.statement, plonk_output.proof),
    );

    var logup_output = try plonk_logup.prove(allocator, pcs_config, .{ .log_n_rows = 4 });
    logup_output.proof.commitment_scheme_proof.commitments.items[0][0] ^= 1;
    try std.testing.expectError(
        error.InvalidPreprocessedCommitment,
        plonk_logup.verify(allocator, pcs_config, logup_output.statement, logup_output.proof),
    );
}

test "blake rejects a first commitment from a different example" {
    const allocator = std.testing.allocator;
    const pcs_config = try config();
    const output = try xor.prove(allocator, pcs_config, claimed);
    const blake_statement: blake.Statement = .{
        .stmt0 = .{ .log_size = 4 },
        .stmt1 = std.mem.zeroes(blake.exact_statement.Statement1),
    };
    try std.testing.expectError(
        error.InvalidPreprocessedCommitment,
        blake.verify(allocator, pcs_config, blake_statement, output.proof),
    );
}
