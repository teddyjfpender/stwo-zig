//! Example-specific proving and verification dispatch.

const std = @import("std");
const stwo = @import("root").stwo;
const cli_mod = @import("cli.zig");

const pcs = stwo.core.pcs;
const blake = stwo.examples.blake;
const plonk = stwo.examples.plonk;
const poseidon = stwo.examples.poseidon;
const state_machine = stwo.examples.state_machine;
const wide_fibonacci = stwo.examples.wide_fibonacci;
const xor = stwo.examples.xor;
const std_shims_verifier_profile = stwo.std_shims.verifier_profile;
const proof_wire = stwo.interop.proof_wire;

const Cli = cli_mod.Cli;
const Example = cli_mod.Example;
const m31FromCanonical = cli_mod.m31FromCanonical;

pub const ExampleStatement = union(Example) {
    blake: blake.Statement,
    plonk: plonk.Statement,
    poseidon: poseidon.Statement,
    state_machine: state_machine.PreparedStatement,
    wide_fibonacci: wide_fibonacci.Statement,
    xor: xor.Statement,
};

pub const ExampleProveOutput = struct {
    statement: ExampleStatement,
    proof: proof_wire.Proof,
};

pub fn proveExample(
    allocator: std.mem.Allocator,
    config: pcs.PcsConfig,
    cli: Cli,
    example: Example,
) !ExampleProveOutput {
    switch (example) {
        .blake => {
            const statement: blake.Request = .{
                .log_n_rows = cli.blake_log_n_rows,
                .n_rounds = cli.blake_n_rounds,
            };
            return switch (cli.prove_mode) {
                .prove => blk: {
                    const output = try blake.prove(allocator, config, statement);
                    break :blk .{
                        .statement = .{ .blake = output.statement },
                        .proof = output.proof,
                    };
                },
                .prove_ex => blk: {
                    var output = try blake.proveEx(
                        allocator,
                        config,
                        statement,
                        cli.include_all_preprocessed_columns,
                    );
                    const proof = output.proof.proof;
                    output.proof.aux.deinit(allocator);
                    break :blk .{
                        .statement = .{ .blake = output.statement },
                        .proof = proof,
                    };
                },
            };
        },
        .plonk => {
            const statement: plonk.Statement = .{
                .log_n_rows = cli.plonk_log_n_rows,
            };
            return switch (cli.prove_mode) {
                .prove => blk: {
                    const output = try plonk.prove(allocator, config, statement);
                    break :blk .{
                        .statement = .{ .plonk = output.statement },
                        .proof = output.proof,
                    };
                },
                .prove_ex => blk: {
                    var output = try plonk.proveEx(
                        allocator,
                        config,
                        statement,
                        cli.include_all_preprocessed_columns,
                    );
                    const proof = output.proof.proof;
                    output.proof.aux.deinit(allocator);
                    break :blk .{
                        .statement = .{ .plonk = output.statement },
                        .proof = proof,
                    };
                },
            };
        },
        .poseidon => {
            const statement: poseidon.Statement = .{
                .log_n_instances = cli.poseidon_log_n_instances,
            };
            return switch (cli.prove_mode) {
                .prove => blk: {
                    const output = try poseidon.prove(allocator, config, statement);
                    break :blk .{
                        .statement = .{ .poseidon = output.statement },
                        .proof = output.proof,
                    };
                },
                .prove_ex => blk: {
                    var output = try poseidon.proveEx(
                        allocator,
                        config,
                        statement,
                        cli.include_all_preprocessed_columns,
                    );
                    const proof = output.proof.proof;
                    output.proof.aux.deinit(allocator);
                    break :blk .{
                        .statement = .{ .poseidon = output.statement },
                        .proof = proof,
                    };
                },
            };
        },
        .state_machine => {
            const initial_state: state_machine.State = .{
                try m31FromCanonical(cli.sm_initial_0),
                try m31FromCanonical(cli.sm_initial_1),
            };
            return switch (cli.prove_mode) {
                .prove => blk: {
                    const output = try state_machine.prove(
                        allocator,
                        config,
                        cli.sm_log_n_rows,
                        initial_state,
                    );
                    break :blk .{
                        .statement = .{ .state_machine = output.statement },
                        .proof = output.proof,
                    };
                },
                .prove_ex => blk: {
                    var output = try state_machine.proveEx(
                        allocator,
                        config,
                        cli.sm_log_n_rows,
                        initial_state,
                        cli.include_all_preprocessed_columns,
                    );
                    const proof = output.proof.proof;
                    output.proof.aux.deinit(allocator);
                    break :blk .{
                        .statement = .{ .state_machine = output.statement },
                        .proof = proof,
                    };
                },
            };
        },
        .wide_fibonacci => {
            const statement: wide_fibonacci.Statement = .{
                .log_n_rows = cli.wf_log_n_rows,
                .sequence_len = cli.wf_sequence_len,
            };
            return switch (cli.prove_mode) {
                .prove => blk: {
                    const output = try wide_fibonacci.prove(allocator, config, statement);
                    break :blk .{
                        .statement = .{ .wide_fibonacci = output.statement },
                        .proof = output.proof,
                    };
                },
                .prove_ex => blk: {
                    var output = try wide_fibonacci.proveEx(
                        allocator,
                        config,
                        statement,
                        cli.include_all_preprocessed_columns,
                    );
                    const proof = output.proof.proof;
                    output.proof.aux.deinit(allocator);
                    break :blk .{
                        .statement = .{ .wide_fibonacci = output.statement },
                        .proof = proof,
                    };
                },
            };
        },
        .xor => {
            const statement: xor.Statement = .{
                .log_size = cli.xor_log_size,
                .log_step = cli.xor_log_step,
                .offset = cli.xor_offset,
            };
            return switch (cli.prove_mode) {
                .prove => blk: {
                    const output = try xor.prove(allocator, config, statement);
                    break :blk .{
                        .statement = .{ .xor = output.statement },
                        .proof = output.proof,
                    };
                },
                .prove_ex => blk: {
                    var output = try xor.proveEx(
                        allocator,
                        config,
                        statement,
                        cli.include_all_preprocessed_columns,
                    );
                    const proof = output.proof.proof;
                    output.proof.aux.deinit(allocator);
                    break :blk .{
                        .statement = .{ .xor = output.statement },
                        .proof = proof,
                    };
                },
            };
        },
    }
}

pub fn verifyExample(
    allocator: std.mem.Allocator,
    config: pcs.PcsConfig,
    statement: ExampleStatement,
    proof: proof_wire.Proof,
) !void {
    switch (statement) {
        .blake => |s| try blake.verify(allocator, config, s, proof),
        .plonk => |s| try plonk.verify(allocator, config, s, proof),
        .poseidon => |s| try poseidon.verify(allocator, config, s, proof),
        .state_machine => |s| try state_machine.verify(allocator, config, s, proof),
        .wide_fibonacci => |s| try wide_fibonacci.verify(allocator, config, s, proof),
        .xor => |s| try xor.verify(allocator, config, s, proof),
    }
}

pub fn verifyExampleStdShims(
    allocator: std.mem.Allocator,
    config: pcs.PcsConfig,
    statement: ExampleStatement,
    proof: proof_wire.Proof,
) !void {
    switch (statement) {
        .blake => |s| try std_shims_verifier_profile.verifyBlake(allocator, config, s, proof),
        .plonk => |s| try std_shims_verifier_profile.verifyPlonk(allocator, config, s, proof),
        .poseidon => |s| try std_shims_verifier_profile.verifyPoseidon(allocator, config, s, proof),
        .state_machine => |s| try std_shims_verifier_profile.verifyStateMachine(allocator, config, s, proof),
        .wide_fibonacci => |s| try std_shims_verifier_profile.verifyWideFibonacci(allocator, config, s, proof),
        .xor => |s| try std_shims_verifier_profile.verifyXor(allocator, config, s, proof),
    }
}

pub fn exampleName(example: Example) []const u8 {
    return switch (example) {
        .blake => "blake",
        .plonk => "plonk",
        .poseidon => "poseidon",
        .state_machine => "state_machine",
        .wide_fibonacci => "wide_fibonacci",
        .xor => "xor",
    };
}
