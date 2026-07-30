//! XOR policy for the shared Native CUDA proof lifecycle.

const std = @import("std");
const stwo = @import("stwo_native_cuda");
const cli = @import("cli.zig");

pub const cuda = stwo.integrations.native_cuda.xor;
pub const application = "xor";
pub const protocol_name = cli.xor_protocol_name;

pub fn protocol() stwo.core.pcs.PcsConfig {
    return stwo.core.pcs.PcsConfig.default();
}

pub fn admit(
    request: cli.Prove,
    sealed: stwo.core.pcs.PcsConfig,
) !cuda.geometry.Geometry {
    return cuda.geometry.admit(
        .{
            .log_size = request.log_size.?,
            .log_step = request.log_step.?,
            .offset = request.offset.?,
        },
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
    try stwo.examples.xor.verify(
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
        .{ .xor = geometry.statement },
        canonical,
    );
}

pub const ReportStatement = struct {
    log_size: u32,
    log_step: u32,
    offset: u64,
    trace_rows: u64,
    trace_cells: u64,
};

pub fn reportStatement(
    geometry: cuda.geometry.Geometry,
) ReportStatement {
    return .{
        .log_size = geometry.statement.log_size,
        .log_step = geometry.statement.log_step,
        .offset = geometry.statement.offset,
        .trace_rows = geometry.trace_rows,
        .trace_cells = geometry.trace_elements,
    };
}

test "XOR route seals the production protocol" {
    const geometry = try admit(.{
        .air = .xor,
        .log_n_rows = null,
        .sequence_len = null,
        .n_rounds = null,
        .log_size = 8,
        .log_step = 2,
        .offset = 3,
        .output = "proof.json",
        .report_out = null,
        .repeat = 1,
        .execution_mode = .graphs,
    }, protocol());
    try std.testing.expectEqual(@as(u32, 10), geometry.protocol.pow_bits);
    try std.testing.expectEqual(@as(u32, 1), geometry.protocol.fri_config.fold_step);
    try std.testing.expectEqual(@as(usize, 3), geometry.protocol.fri_config.n_queries);
}
