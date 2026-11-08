//! Closed workload registry for the native CPU/Metal proof suite.

const std = @import("std");
const stwo = @import("stwo");
const config = @import("config.zig");
const report = @import("report.zig");
const test_support = @import("examples_test_support.zig");

const artifacts = stwo.interop.examples_artifact;
const stage_profile = stwo.prover.stage_profile;
const blake = stwo.examples.blake;
const plonk = stwo.examples.plonk;
const plonk_logup = stwo.examples.plonk_logup;
const poseidon = stwo.examples.poseidon;
const state_machine = stwo.examples.state_machine;
const wide_fibonacci = stwo.examples.wide_fibonacci;
const xor = stwo.examples.xor;

pub const Geometry = struct {
    trace_log_rows: u32,
    trace_rows: u64,
    /// Commitments for witness/preprocessed trees before composition.
    committed_trees: u32 = 2,
    committed_columns: u64,
    committed_trace_cells: u64,
    native_unit: []const u8,
    native_units: u64,
};

pub fn name(workload: config.Workload) []const u8 {
    return switch (workload) {
        .wide_fibonacci => "wide_fibonacci",
        .xor => "xor",
        .plonk => "plonk",
        .plonk_logup => "plonk_logup",
        .state_machine => "state_machine",
        .blake => "blake",
        .poseidon => "poseidon",
    };
}

pub fn parameters(workload: config.Workload) report.WorkloadParameters {
    return switch (workload) {
        .wide_fibonacci => |value| .{ .wide_fibonacci = value },
        .xor => |value| .{ .xor = value },
        .plonk => |value| .{ .plonk = value },
        .plonk_logup => |value| .{ .plonk_logup = value },
        .state_machine => |value| .{ .state_machine = value },
        .blake => |value| .{ .blake = value },
        .poseidon => |value| .{ .poseidon = value },
    };
}

pub fn geometry(workload: config.Workload) !Geometry {
    return switch (workload) {
        .wide_fibonacci => |value| blk: {
            const rows = @as(u64, 1) << @intCast(value.log_n_rows);
            break :blk .{
                .trace_log_rows = value.log_n_rows,
                .trace_rows = rows,
                .committed_columns = value.sequence_len,
                .committed_trace_cells = try std.math.mul(u64, rows, value.sequence_len),
                .native_unit = "trace_rows",
                .native_units = rows,
            };
        },
        .xor => |value| blk: {
            const rows = @as(u64, 1) << @intCast(value.log_size);
            break :blk .{
                .trace_log_rows = value.log_size,
                .trace_rows = rows,
                .committed_trees = 3,
                .committed_columns = 15,
                .committed_trace_cells = try std.math.mul(u64, rows, 15),
                .native_unit = "xor_rows",
                .native_units = rows,
            };
        },
        .plonk => |value| blk: {
            const rows = @as(u64, 1) << @intCast(value.log_n_rows);
            break :blk .{
                .trace_log_rows = value.log_n_rows,
                .trace_rows = rows,
                .committed_columns = 8,
                .committed_trace_cells = try std.math.mul(u64, rows, 8),
                .native_unit = "plonk_rows",
                .native_units = rows,
            };
        },
        .plonk_logup => |value| blk: {
            const rows = @as(u64, 1) << @intCast(value.log_n_rows);
            break :blk .{
                .trace_log_rows = value.log_n_rows,
                .trace_rows = rows,
                .committed_trees = 3,
                .committed_columns = 16,
                .committed_trace_cells = try std.math.mul(u64, rows, 16),
                .native_unit = "plonk_logup_rows",
                .native_units = rows,
            };
        },
        .state_machine => |value| blk: {
            const rows = @as(u64, 1) << @intCast(value.log_n_rows);
            break :blk .{
                .trace_log_rows = value.log_n_rows,
                .trace_rows = rows,
                .committed_trees = 3,
                .committed_columns = 12,
                .committed_trace_cells = try std.math.mul(u64, rows, 9),
                .native_unit = "state_transitions",
                .native_units = try std.math.add(u64, rows, rows / 2),
            };
        },
        .blake => |value| blk: {
            const rows = @as(u64, 1) << @intCast(value.log_n_rows);
            const columns = blake.geometry.PREPROCESSED_COLUMNS +
                blake.geometry.MAIN_COLUMNS +
                blake.geometry.INTERACTION_COLUMNS;
            break :blk .{
                .trace_log_rows = value.log_n_rows,
                .trace_rows = rows,
                .committed_trees = 3,
                .committed_columns = columns,
                .committed_trace_cells = try blake.geometry.committedCells(
                    value.log_n_rows,
                ),
                .native_unit = "blake_round_instances",
                .native_units = try std.math.mul(u64, rows, value.n_rounds),
            };
        },
        .poseidon => |value| blk: {
            const log_n_rows = try poseidon.logNRows(.{
                .log_n_instances = value.log_n_instances,
            });
            const rows = @as(u64, 1) << @intCast(log_n_rows);
            const native_units = @as(u64, 1) << @intCast(value.log_n_instances);
            const columns: u64 = poseidon.N_TRACE_COLUMNS;
            break :blk .{
                .trace_log_rows = log_n_rows,
                .trace_rows = rows,
                .committed_trees = 3,
                .committed_columns = columns,
                .committed_trace_cells = try std.math.mul(u64, rows, columns),
                .native_unit = "poseidon_instances",
                .native_units = native_units,
            };
        },
    };
}

pub fn descriptorDigest(
    workload: config.Workload,
    protocol: config.Protocol,
) [32]u8 {
    const protocol_parameters = protocol.parameters();
    var buffer: [512]u8 = undefined;
    const prefix = switch (workload) {
        .wide_fibonacci => |value| std.fmt.bufPrint(
            &buffer,
            "native-proof-workload-v3|example=wide_fibonacci|log_n_rows={d}|sequence_len={d}",
            .{ value.log_n_rows, value.sequence_len },
        ) catch unreachable,
        .xor => |value| std.fmt.bufPrint(
            &buffer,
            "native-proof-workload-v3|example=xor|log_size={d}|log_step={d}|offset={d}|air_protocol=raw-stwo-xor-lookup-v2",
            .{ value.log_size, value.log_step, value.offset },
        ) catch unreachable,
        .plonk => |value| std.fmt.bufPrint(
            &buffer,
            "native-proof-workload-v3|example=plonk|log_n_rows={d}",
            .{value.log_n_rows},
        ) catch unreachable,
        .plonk_logup => |value| std.fmt.bufPrint(
            &buffer,
            "native-proof-workload-v3|example=plonk_logup|protocol=raw-stwo-plonk-logup-v1|log_n_rows={d}",
            .{value.log_n_rows},
        ) catch unreachable,
        .state_machine => |value| std.fmt.bufPrint(
            &buffer,
            "native-proof-workload-v3|example=state_machine|log_n_rows={d}|initial_x={d}|initial_y={d}|air_protocol=raw-stwo-state-machine-v2",
            .{ value.log_n_rows, value.initial_x, value.initial_y },
        ) catch unreachable,
        .blake => |value| std.fmt.bufPrint(
            &buffer,
            "native-proof-workload-v3|example=blake|log_n_rows={d}|n_rounds={d}",
            .{ value.log_n_rows, value.n_rounds },
        ) catch unreachable,
        .poseidon => |value| std.fmt.bufPrint(
            &buffer,
            "native-proof-workload-v3|example=poseidon|log_n_instances={d}|air_protocol={s}",
            .{ value.log_n_instances, poseidon.protocol_name },
        ) catch unreachable,
    };
    const description = std.fmt.bufPrint(
        buffer[prefix.len..],
        "|protocol={s}|pow_bits={d}|log_blowup_factor={d}|log_last_layer_degree_bound={d}|n_queries={d}|fold_step={d}",
        .{
            @tagName(protocol),
            protocol_parameters.pow_bits,
            protocol_parameters.log_blowup_factor,
            protocol_parameters.log_last_layer_degree_bound,
            protocol_parameters.n_queries,
            protocol_parameters.fold_step,
        },
    ) catch unreachable;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(buffer[0 .. prefix.len + description.len], &digest, .{});
    return digest;
}

pub const WideFibonacciSpec = struct {
    pub const Request = wide_fibonacci.Statement;
    pub const PreparedInput = wide_fibonacci.PreparedInput;
    pub const Statement = wide_fibonacci.Statement;
    pub const Proof = wide_fibonacci.Proof;
    pub const ProveOutput = wide_fibonacci.ProveOutput;
    pub const example_name = "wide_fibonacci";

    pub fn request(value: config.WideFibonacciParameters) Request {
        return .{ .log_n_rows = value.log_n_rows, .sequence_len = value.sequence_len };
    }

    pub fn prepareInput(allocator: std.mem.Allocator, value: Request) !PreparedInput {
        return wide_fibonacci.prepareInput(allocator, value);
    }

    pub fn prepareInputWithEngine(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        value: Request,
    ) !PreparedInput {
        return wide_fibonacci.prepareInputForBackend(Engine.Backend, allocator, value);
    }

    pub fn requiredCircleLog(value: Request, pcs_config: stwo.core.pcs.PcsConfig) !u32 {
        return wide_fibonacci.requiredTwiddleCircleLog(value, pcs_config);
    }

    pub fn provePrepared(
        comptime Engine: type,
        session: *const Engine.Session,
        allocator: std.mem.Allocator,
        pcs_config: stwo.core.pcs.PcsConfig,
        prepared: PreparedInput,
        recorder: ?*stage_profile.Recorder,
    ) !ProveOutput {
        return wide_fibonacci.provePreparedWithSessionAndEngine(
            Engine,
            session,
            allocator,
            pcs_config,
            prepared,
            recorder,
        );
    }

    pub fn validateOutputStatement(value: Request, statement: Statement) !void {
        if (!std.meta.eql(value, statement)) return error.ProverStatementMismatch;
    }

    pub fn verify(
        allocator: std.mem.Allocator,
        pcs_config: stwo.core.pcs.PcsConfig,
        statement: Statement,
        proof: Proof,
    ) !void {
        return wide_fibonacci.verify(allocator, pcs_config, statement, proof);
    }

    pub fn writeArtifact(
        allocator: std.mem.Allocator,
        path: []const u8,
        pcs_config: stwo.core.pcs.PcsConfig,
        statement: Statement,
        proof_bytes: []const u8,
    ) !void {
        return artifacts.writeNativeProofArtifact(
            allocator,
            path,
            pcs_config,
            "prove",
            .{ .wide_fibonacci = statement },
            proof_bytes,
        );
    }
};

pub const XorSpec = struct {
    pub const Request = xor.Statement;
    pub const PreparedInput = xor.PreparedInput;
    pub const Statement = xor.Statement;
    pub const Proof = xor.Proof;
    pub const ProveOutput = xor.ProveOutput;
    pub const example_name = "xor";

    pub fn request(value: config.XorParameters) Request {
        return .{ .log_size = value.log_size, .log_step = value.log_step, .offset = value.offset };
    }

    pub fn prepareInput(allocator: std.mem.Allocator, value: Request) !PreparedInput {
        return xor.prepareInput(allocator, value);
    }

    pub fn requiredCircleLog(value: Request, pcs_config: stwo.core.pcs.PcsConfig) !u32 {
        return xor.requiredTwiddleCircleLog(value, pcs_config);
    }

    pub fn provePrepared(
        comptime Engine: type,
        session: *const Engine.Session,
        allocator: std.mem.Allocator,
        pcs_config: stwo.core.pcs.PcsConfig,
        prepared: PreparedInput,
        recorder: ?*stage_profile.Recorder,
    ) !ProveOutput {
        return xor.provePreparedWithSessionAndEngine(
            Engine,
            session,
            allocator,
            pcs_config,
            prepared,
            recorder,
        );
    }

    pub fn validateOutputStatement(value: Request, statement: Statement) !void {
        if (!std.meta.eql(value, statement)) return error.ProverStatementMismatch;
    }

    pub fn verify(
        allocator: std.mem.Allocator,
        pcs_config: stwo.core.pcs.PcsConfig,
        statement: Statement,
        proof: Proof,
    ) !void {
        return xor.verify(allocator, pcs_config, statement, proof);
    }

    pub fn writeArtifact(
        allocator: std.mem.Allocator,
        path: []const u8,
        pcs_config: stwo.core.pcs.PcsConfig,
        statement: Statement,
        proof_bytes: []const u8,
    ) !void {
        return artifacts.writeNativeProofArtifact(
            allocator,
            path,
            pcs_config,
            "prove",
            .{ .xor = statement },
            proof_bytes,
        );
    }
};

pub const PlonkSpec = struct {
    pub const Request = plonk.Statement;
    pub const PreparedInput = plonk.PreparedInput;
    pub const Statement = plonk.Statement;
    pub const Proof = plonk.Proof;
    pub const ProveOutput = plonk.ProveOutput;
    pub const example_name = "plonk";

    pub fn request(value: config.PlonkParameters) Request {
        return .{ .log_n_rows = value.log_n_rows };
    }

    pub fn prepareInput(allocator: std.mem.Allocator, value: Request) !PreparedInput {
        return plonk.prepareInput(allocator, value);
    }

    pub fn requiredCircleLog(value: Request, pcs_config: stwo.core.pcs.PcsConfig) !u32 {
        return plonk.requiredTwiddleCircleLog(value, pcs_config);
    }

    pub fn provePrepared(
        comptime Engine: type,
        session: *const Engine.Session,
        allocator: std.mem.Allocator,
        pcs_config: stwo.core.pcs.PcsConfig,
        prepared: PreparedInput,
        recorder: ?*stage_profile.Recorder,
    ) !ProveOutput {
        return plonk.provePreparedWithSessionAndEngine(
            Engine,
            session,
            allocator,
            pcs_config,
            prepared,
            recorder,
        );
    }

    pub fn validateOutputStatement(value: Request, statement: Statement) !void {
        if (!std.meta.eql(value, statement)) return error.ProverStatementMismatch;
    }

    pub fn verify(
        allocator: std.mem.Allocator,
        pcs_config: stwo.core.pcs.PcsConfig,
        statement: Statement,
        proof: Proof,
    ) !void {
        return plonk.verify(allocator, pcs_config, statement, proof);
    }

    pub fn writeArtifact(
        allocator: std.mem.Allocator,
        path: []const u8,
        pcs_config: stwo.core.pcs.PcsConfig,
        statement: Statement,
        proof_bytes: []const u8,
    ) !void {
        return artifacts.writeNativeProofArtifact(
            allocator,
            path,
            pcs_config,
            "prove",
            .{ .plonk = statement },
            proof_bytes,
        );
    }
};

pub const PlonkLogupSpec = struct {
    pub const Request = plonk_logup.Request;
    pub const PreparedInput = plonk_logup.PreparedInput;
    pub const Statement = plonk_logup.Statement;
    pub const Proof = plonk_logup.Proof;
    pub const ProveOutput = plonk_logup.ProveOutput;
    pub const example_name = "plonk_logup";

    pub fn request(value: config.PlonkLogupParameters) Request {
        return .{ .log_n_rows = value.log_n_rows };
    }

    pub fn prepareInput(allocator: std.mem.Allocator, value: Request) !PreparedInput {
        return plonk_logup.prepareInput(allocator, value);
    }

    pub fn requiredCircleLog(value: Request, pcs_config: stwo.core.pcs.PcsConfig) !u32 {
        return plonk_logup.requiredTwiddleCircleLog(value, pcs_config);
    }

    pub fn provePrepared(
        comptime Engine: type,
        session: *const Engine.Session,
        allocator: std.mem.Allocator,
        pcs_config: stwo.core.pcs.PcsConfig,
        prepared: PreparedInput,
        recorder: ?*stage_profile.Recorder,
    ) !ProveOutput {
        return plonk_logup.provePreparedWithSessionAndEngine(
            Engine,
            session,
            allocator,
            pcs_config,
            prepared,
            recorder,
        );
    }

    pub fn validateOutputStatement(value: Request, statement: Statement) !void {
        if (value.log_n_rows != statement.log_n_rows)
            return error.ProverStatementMismatch;
    }

    pub fn verify(
        allocator: std.mem.Allocator,
        pcs_config: stwo.core.pcs.PcsConfig,
        statement: Statement,
        proof: Proof,
    ) !void {
        return plonk_logup.verify(allocator, pcs_config, statement, proof);
    }

    pub fn writeArtifact(
        allocator: std.mem.Allocator,
        path: []const u8,
        pcs_config: stwo.core.pcs.PcsConfig,
        statement: Statement,
        proof_bytes: []const u8,
    ) !void {
        return artifacts.writeNativeProofArtifact(
            allocator,
            path,
            pcs_config,
            "prove",
            .{ .plonk_logup = statement },
            proof_bytes,
        );
    }
};

pub const StateMachineSpec = struct {
    pub const Request = state_machine.Request;
    pub const PreparedInput = state_machine.PreparedInput;
    pub const Statement = state_machine.PreparedStatement;
    pub const Proof = state_machine.Proof;
    pub const ProveOutput = state_machine.ProveOutput;
    pub const example_name = "state_machine";

    pub fn request(value: config.StateMachineParameters) Request {
        return .{
            .log_n_rows = value.log_n_rows,
            .initial_state = .{
                stwo.core.fields.m31.M31.fromCanonical(value.initial_x),
                stwo.core.fields.m31.M31.fromCanonical(value.initial_y),
            },
        };
    }

    pub fn prepareInput(allocator: std.mem.Allocator, value: Request) !PreparedInput {
        return state_machine.prepareInput(allocator, value);
    }

    pub fn requiredCircleLog(value: Request, pcs_config: stwo.core.pcs.PcsConfig) !u32 {
        return state_machine.requiredTwiddleCircleLog(value, pcs_config);
    }

    pub fn provePrepared(
        comptime Engine: type,
        session: *const Engine.Session,
        allocator: std.mem.Allocator,
        pcs_config: stwo.core.pcs.PcsConfig,
        prepared: PreparedInput,
        recorder: ?*stage_profile.Recorder,
    ) !ProveOutput {
        return state_machine.provePreparedWithSessionAndEngine(
            Engine,
            session,
            allocator,
            pcs_config,
            prepared,
            recorder,
        );
    }

    pub fn validateOutputStatement(value: Request, statement: Statement) !void {
        if (statement.stmt0.n != value.log_n_rows or
            statement.stmt0.m != value.log_n_rows - 1 or
            !std.meta.eql(statement.public_input[0], value.initial_state))
        {
            return error.ProverStatementMismatch;
        }
        const transitions = try state_machine.transitionStates(
            value.log_n_rows,
            value.initial_state,
        );
        if (!std.meta.eql(statement.public_input[1], transitions.final))
            return error.ProverStatementMismatch;
    }

    pub fn verify(
        allocator: std.mem.Allocator,
        pcs_config: stwo.core.pcs.PcsConfig,
        statement: Statement,
        proof: Proof,
    ) !void {
        return state_machine.verify(allocator, pcs_config, statement, proof);
    }

    pub fn writeArtifact(
        allocator: std.mem.Allocator,
        path: []const u8,
        pcs_config: stwo.core.pcs.PcsConfig,
        statement: Statement,
        proof_bytes: []const u8,
    ) !void {
        return artifacts.writeNativeProofArtifact(
            allocator,
            path,
            pcs_config,
            "prove",
            .{ .state_machine = statement },
            proof_bytes,
        );
    }
};

pub const BlakeSpec = struct {
    pub const Request = blake.Request;
    pub const PreparedInput = blake.PreparedInput;
    pub const Statement = blake.Statement;
    pub const Proof = blake.Proof;
    pub const ProveOutput = blake.ProveOutput;
    pub const example_name = "blake";

    pub fn request(value: config.BlakeParameters) Request {
        return .{ .log_n_rows = value.log_n_rows, .n_rounds = value.n_rounds };
    }

    pub fn prepareInput(allocator: std.mem.Allocator, value: Request) !PreparedInput {
        return blake.prepareInput(allocator, value);
    }

    pub fn requiredCircleLog(value: Request, pcs_config: stwo.core.pcs.PcsConfig) !u32 {
        return blake.requiredTwiddleCircleLog(value, pcs_config);
    }

    pub fn provePrepared(
        comptime Engine: type,
        session: *const Engine.Session,
        allocator: std.mem.Allocator,
        pcs_config: stwo.core.pcs.PcsConfig,
        prepared: PreparedInput,
        recorder: ?*stage_profile.Recorder,
    ) !ProveOutput {
        return blake.provePreparedWithSessionAndEngine(
            Engine,
            session,
            allocator,
            pcs_config,
            prepared,
            recorder,
        );
    }

    pub fn validateOutputStatement(value: Request, statement: Statement) !void {
        try blake.exact_input.validate(value);
        try blake.exact_statement.verify(statement);
        if (value.log_n_rows != statement.stmt0.log_size)
            return error.ProverStatementMismatch;
    }

    pub fn verify(
        allocator: std.mem.Allocator,
        pcs_config: stwo.core.pcs.PcsConfig,
        statement: Statement,
        proof: Proof,
    ) !void {
        return blake.verify(allocator, pcs_config, statement, proof);
    }

    pub fn writeArtifact(
        allocator: std.mem.Allocator,
        path: []const u8,
        pcs_config: stwo.core.pcs.PcsConfig,
        statement: Statement,
        proof_bytes: []const u8,
    ) !void {
        return artifacts.writeNativeProofArtifact(
            allocator,
            path,
            pcs_config,
            "prove",
            .{ .blake = statement },
            proof_bytes,
        );
    }
};

pub const PoseidonSpec = struct {
    pub const Request = poseidon.Statement;
    pub const PreparedInput = poseidon.PreparedInput;
    pub const Statement = poseidon.Statement;
    pub const Proof = poseidon.Proof;
    pub const ProveOutput = poseidon.ProveOutput;
    pub const example_name = "poseidon";

    pub fn request(value: config.PoseidonParameters) Request {
        return .{ .log_n_instances = value.log_n_instances };
    }

    pub fn prepareInput(allocator: std.mem.Allocator, value: Request) !PreparedInput {
        return poseidon.prepareInput(allocator, value);
    }

    pub fn requiredCircleLog(value: Request, pcs_config: stwo.core.pcs.PcsConfig) !u32 {
        return poseidon.requiredTwiddleCircleLog(value, pcs_config);
    }

    pub fn provePrepared(
        comptime Engine: type,
        session: *const Engine.Session,
        allocator: std.mem.Allocator,
        pcs_config: stwo.core.pcs.PcsConfig,
        prepared: PreparedInput,
        recorder: ?*stage_profile.Recorder,
    ) !ProveOutput {
        return poseidon.provePreparedWithSessionAndEngine(
            Engine,
            session,
            allocator,
            pcs_config,
            prepared,
            recorder,
        );
    }

    pub fn validateOutputStatement(value: Request, statement: Statement) !void {
        if (value.log_n_instances != statement.log_n_instances) {
            return error.ProverStatementMismatch;
        }
    }

    pub fn verify(
        allocator: std.mem.Allocator,
        pcs_config: stwo.core.pcs.PcsConfig,
        statement: Statement,
        proof: Proof,
    ) !void {
        return poseidon.verify(allocator, pcs_config, statement, proof);
    }

    pub fn writeArtifact(
        allocator: std.mem.Allocator,
        path: []const u8,
        pcs_config: stwo.core.pcs.PcsConfig,
        statement: Statement,
        proof_bytes: []const u8,
    ) !void {
        return artifacts.writeNativeProofArtifact(
            allocator,
            path,
            pcs_config,
            "prove",
            .{ .poseidon = statement },
            proof_bytes,
        );
    }
};

test "native proof examples: geometry and descriptors are tagged" {
    const wide: config.Workload = .{ .wide_fibonacci = .{ .log_n_rows = 5, .sequence_len = 8 } };
    const xor_workload: config.Workload = .{ .xor = .{ .log_size = 5, .log_step = 2, .offset = 3 } };
    const plonk_workload: config.Workload = .{ .plonk = .{ .log_n_rows = 5 } };
    const state_workload: config.Workload = .{ .state_machine = .{
        .log_n_rows = 5,
        .initial_x = 9,
        .initial_y = 3,
    } };
    const blake_workload: config.Workload = .{ .blake = .{
        .log_n_rows = 5,
        .n_rounds = 10,
    } };
    const poseidon_workload: config.Workload = .{ .poseidon = .{ .log_n_instances = 8 } };
    const wide_geometry = try geometry(wide);
    const xor_geometry = try geometry(xor_workload);
    const plonk_geometry = try geometry(plonk_workload);
    const state_geometry = try geometry(state_workload);
    const blake_geometry = try geometry(blake_workload);
    const poseidon_geometry = try geometry(poseidon_workload);
    try std.testing.expectEqual(@as(u64, 256), wide_geometry.committed_trace_cells);
    try std.testing.expectEqual(@as(u64, 480), xor_geometry.committed_trace_cells);
    try std.testing.expectEqual(@as(u32, 3), xor_geometry.committed_trees);
    try std.testing.expectEqual(@as(u64, 15), xor_geometry.committed_columns);
    try std.testing.expectEqual(@as(u64, 256), plonk_geometry.committed_trace_cells);
    try std.testing.expectEqual(@as(u32, 3), state_geometry.committed_trees);
    try std.testing.expectEqual(@as(u64, 12), state_geometry.committed_columns);
    try std.testing.expectEqual(@as(u64, 288), state_geometry.committed_trace_cells);
    try std.testing.expectEqual(@as(u64, 48), state_geometry.native_units);
    try std.testing.expectEqual(@as(u64, 51_846_144), blake_geometry.committed_trace_cells);
    try std.testing.expectEqual(@as(u64, 320), blake_geometry.native_units);
    try std.testing.expectEqualStrings("blake_round_instances", blake_geometry.native_unit);
    try std.testing.expectEqual(@as(u32, 3), poseidon_geometry.committed_trees);
    try std.testing.expectEqual(@as(u64, 1_296), poseidon_geometry.committed_columns);
    try std.testing.expectEqual(@as(u64, 41_472), poseidon_geometry.committed_trace_cells);
    const blake_admission = try config.admitWorkload(blake_workload, .large);
    try std.testing.expect(blake_geometry.committed_columns ==
        blake_admission.geometry.committed_columns);
    try std.testing.expect(blake_geometry.committed_trace_cells ==
        blake_admission.geometry.committed_cells);
    try std.testing.expectEqual(@as(u64, 256), poseidon_geometry.native_units);
    try std.testing.expectEqualStrings("poseidon_instances", poseidon_geometry.native_unit);
    try std.testing.expect(!std.mem.eql(
        u8,
        &descriptorDigest(wide, .smoke),
        &descriptorDigest(xor_workload, .smoke),
    ));
}

test "native proof examples: descriptor digests match independent fixed vectors" {
    const wide: config.Workload = .{ .wide_fibonacci = .{ .log_n_rows = 10, .sequence_len = 8 } };
    const xor_workload: config.Workload = .{ .xor = .{ .log_size = 10, .log_step = 2, .offset = 3 } };
    const plonk_workload: config.Workload = .{ .plonk = .{ .log_n_rows = 10 } };
    const state_workload: config.Workload = .{ .state_machine = .{
        .log_n_rows = 10,
        .initial_x = 9,
        .initial_y = 3,
    } };
    const blake_workload: config.Workload = .{ .blake = .{
        .log_n_rows = 8,
        .n_rounds = 10,
    } };
    const poseidon_workload: config.Workload = .{ .poseidon = .{ .log_n_instances = 13 } };
    try test_support.expectDigest(
        descriptorDigest(wide, .functional),
        "8586bce9ae8c0673453803b3b65ca8d4fc677638d53e5933e7692af4dd38586f",
    );
    try test_support.expectDigest(
        descriptorDigest(xor_workload, .functional),
        "7cc6f69d95db54edac2908b65701c3c3674215f0c83c29db474680bf5a1405db",
    );
    try test_support.expectDigest(
        descriptorDigest(plonk_workload, .functional),
        "8e22d72f97cfe01bdb3fdf94e362160418ca16022db7cdaccacf073e2ef67cee",
    );
    try test_support.expectDigest(
        descriptorDigest(state_workload, .functional),
        "90501fb81745fd984bd8186e5750f9b7ff6bf2017b0df4df869f313299b771e9",
    );
    try test_support.expectDigest(
        descriptorDigest(blake_workload, .functional),
        "5cfebf8c9565c41c67b574454b43de6f36e2a9d9307e7bfb8aec693cdb92f4aa",
    );
    try test_support.expectDigest(
        descriptorDigest(poseidon_workload, .functional),
        "bb508f796006fc2b8482e04b0fc941be001c86d05be029600bc3ca8af123c7e3",
    );
}

test "native proof examples: Blake output statement is bound to the request" {
    const request_value = BlakeSpec.request(.{ .log_n_rows = 8, .n_rounds = 10 });
    const zero = stwo.core.fields.qm31.QM31.zero();
    const statement: BlakeSpec.Statement = .{
        .stmt0 = .{ .log_size = request_value.log_n_rows },
        .stmt1 = .{
            .scheduler_claimed_sum = zero,
            .round_claimed_sums = .{ zero, zero },
            .xor_claimed_sums = .{ zero, zero, zero, zero, zero },
        },
    };
    try BlakeSpec.validateOutputStatement(request_value, statement);

    var wrong_log = statement;
    wrong_log.stmt0.log_size += 1;
    try std.testing.expectError(
        error.ProverStatementMismatch,
        BlakeSpec.validateOutputStatement(request_value, wrong_log),
    );
}

test "native proof examples: Poseidon output binds geometry and carries generated claim" {
    const request_value = PoseidonSpec.request(.{ .log_n_instances = 8 });
    try PoseidonSpec.validateOutputStatement(request_value, request_value);

    var generated_statement = request_value;
    generated_statement.claimed_sum = stwo.core.fields.qm31.QM31.one();
    try PoseidonSpec.validateOutputStatement(request_value, generated_statement);

    var wrong_instances = request_value;
    wrong_instances.log_n_instances += 1;
    try std.testing.expectError(
        error.ProverStatementMismatch,
        PoseidonSpec.validateOutputStatement(request_value, wrong_instances),
    );
}
