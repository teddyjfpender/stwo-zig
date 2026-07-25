//! State Machine policy for the shared Native CUDA proof lifecycle.

const std = @import("std");
const stwo = @import("stwo_native_cuda");
const cli = @import("cli.zig");

pub const cuda = stwo.integrations.native_cuda.state_machine;
pub const application = "state_machine";
pub const legacy_protocol_name = cuda.legacy_protocol_name;
pub const exact_protocol_name = cuda.exact_protocol_name;
pub const exact_protocol_available = cuda.exact_protocol_available;

comptime {
    if (!std.mem.eql(
        u8,
        legacy_protocol_name,
        cli.legacy_state_machine_protocol_name,
    )) @compileError("State Machine legacy protocol identity drifted");
    if (!std.mem.eql(
        u8,
        exact_protocol_name,
        cli.exact_state_machine_protocol_name,
    )) @compileError("State Machine exact protocol identity drifted");
}

pub fn protocol() stwo.core.pcs.PcsConfig {
    return stwo.core.pcs.PcsConfig.default();
}

pub fn admit(
    request: cli.Prove,
    sealed: stwo.core.pcs.PcsConfig,
) !cuda.geometry.Geometry {
    if (!exact_protocol_available) {
        _ = request;
        _ = sealed;
        return error.StateMachineExactProtocolUnavailable;
    }
    return cuda.geometry.admit(
        .{
            .log_n_rows = request.log_n_rows.?,
            .initial_state = .{
                stwo.core.fields.m31.M31.fromCanonical(
                    request.initial_x.?,
                ),
                stwo.core.fields.m31.M31.fromCanonical(
                    request.initial_y.?,
                ),
            },
        },
        sealed,
    );
}

pub fn proofRequest(
    geometry: cuda.geometry.Geometry,
) cuda.geometry.Request {
    return .{
        .statement = geometry.statement,
        .protocol = geometry.protocol,
    };
}

pub fn verify(
    allocator: std.mem.Allocator,
    pcs_config: stwo.core.pcs.PcsConfig,
    geometry: cuda.geometry.Geometry,
    proof: anytype,
) !void {
    const statement = try deriveStatement(
        allocator,
        pcs_config,
        geometry,
        proof,
    );
    try stwo.examples.state_machine.verify(
        allocator,
        pcs_config,
        statement,
        proof,
    );
}

pub fn writeArtifact(
    allocator: std.mem.Allocator,
    path: []const u8,
    pcs_config: stwo.core.pcs.PcsConfig,
    geometry: cuda.geometry.Geometry,
    canonical: []const u8,
) !void {
    var proof = try stwo.interop.proof_wire.decodeProofBytes(
        allocator,
        canonical,
    );
    defer proof.deinit(allocator);
    const statement = try deriveStatement(
        allocator,
        pcs_config,
        geometry,
        proof,
    );
    try stwo.interop.examples_artifact.writeNativeProofArtifact(
        allocator,
        path,
        pcs_config,
        "prove",
        .{ .state_machine = statement },
        canonical,
    );
}

pub const ReportStatement = struct {
    log_n_rows: u32,
    initial_x: u32,
    initial_y: u32,
    trace_rows: u64,
    trace_cells: u64,
};

pub fn reportStatement(
    geometry: cuda.geometry.Geometry,
) ReportStatement {
    return .{
        .log_n_rows = geometry.statement.log_n_rows,
        .initial_x = geometry.statement.initial_state[0].toU32(),
        .initial_y = geometry.statement.initial_state[1].toU32(),
        .trace_rows = geometry.trace_rows,
        .trace_cells = geometry.trace_elements,
    };
}

fn deriveStatement(
    allocator: std.mem.Allocator,
    pcs_config: stwo.core.pcs.PcsConfig,
    geometry: cuda.geometry.Geometry,
    proof: anytype,
) !stwo.examples.state_machine.PreparedStatement {
    if (proof.commitment_scheme_proof.commitments.items.len < 2)
        return error.InvalidProofShape;
    var channel = stwo.examples.state_machine.Channel{};
    pcs_config.mixInto(&channel);
    var commitment_scheme = try stwo.core.pcs.verifier
        .CommitmentSchemeVerifier(
            stwo.examples.state_machine.Hasher,
            stwo.examples.state_machine.MerkleChannel,
        ).init(allocator, pcs_config);
    defer commitment_scheme.deinit(allocator);
    const log_rows = geometry.statement.log_n_rows;
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[0],
        &.{log_rows},
        &channel,
    );
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[1],
        &.{ log_rows, log_rows },
        &channel,
    );
    channel.mixU32s(&.{ log_rows, log_rows - 1 });
    const elements = try stwo.examples.state_machine.Elements.draw(allocator, &channel);
    return stwo.examples.state_machine.prepareStatement(
        log_rows,
        geometry.statement.initial_state,
        elements,
    );
}

test "state-machine route blocks its legacy protocol" {
    std.testing.refAllDeclsRecursive(cuda);
    try std.testing.expectError(
        error.StateMachineExactProtocolUnavailable,
        admit(.{
            .air = .state_machine,
            .log_n_rows = 8,
            .sequence_len = null,
            .n_rounds = null,
            .log_n_instances = null,
            .log_size = null,
            .log_step = null,
            .offset = null,
            .initial_x = 9,
            .initial_y = 3,
            .output = "proof.json",
            .report_out = null,
            .repeat = 1,
            .execution_mode = .graphs,
        }, protocol()),
    );
}
