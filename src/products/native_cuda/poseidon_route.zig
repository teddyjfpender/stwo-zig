//! Poseidon policy for the shared Native CUDA proof lifecycle.

const std = @import("std");
const stwo = @import("stwo_native_cuda");
const cli = @import("cli.zig");

pub const cuda = stwo.integrations.native_cuda.poseidon;
pub const application = "poseidon";
pub const protocol_name = cli.poseidon_protocol_name;

pub fn protocol() stwo.core.pcs.PcsConfig {
    return stwo.core.pcs.PcsConfig.default();
}

pub fn admit(
    request: cli.Prove,
    sealed: stwo.core.pcs.PcsConfig,
) !cuda.geometry.Geometry {
    return cuda.geometry.admit(
        .{ .log_n_instances = request.log_n_instances.? },
        sealed,
    );
}

pub fn proofRequest(
    geometry: cuda.geometry.Geometry,
) !cuda.geometry.Request {
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
    try stwo.examples.poseidon.verify(
        allocator,
        pcs_config,
        geometry.statement,
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
    try stwo.interop.examples_artifact.writeNativeProofArtifact(
        allocator,
        path,
        pcs_config,
        "prove",
        .{ .poseidon = geometry.statement },
        canonical,
    );
}

pub const ReportStatement = struct {
    log_n_instances: u32,
    trace_rows: u64,
    trace_cells: u64,
};

pub fn reportStatement(
    geometry: cuda.geometry.Geometry,
) ReportStatement {
    return .{
        .log_n_instances = geometry.statement.log_n_instances,
        .trace_rows = geometry.trace_rows,
        .trace_cells = geometry.main_cells,
    };
}

test "Poseidon route seals statement and production protocol" {
    const geometry = try admit(.{
        .air = .poseidon,
        .log_n_rows = null,
        .sequence_len = null,
        .n_rounds = null,
        .log_n_instances = 13,
        .log_size = null,
        .log_step = null,
        .offset = null,
        .output = "proof.json",
        .report_out = null,
        .repeat = 1,
        .execution_mode = .graphs,
    }, protocol());
    try std.testing.expectEqual(@as(u32, 10), geometry.log_n_rows);
    try std.testing.expectEqual(@as(u32, 1264), geometry.main_columns);
    try std.testing.expectEqual(
        @as(usize, 3),
        geometry.protocol.fri_config.n_queries,
    );
}
