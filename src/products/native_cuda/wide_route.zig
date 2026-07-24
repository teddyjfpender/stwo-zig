//! Wide-Fibonacci policy for the shared Native CUDA proof lifecycle.

const std = @import("std");
const stwo = @import("stwo_native_cuda");
const cli = @import("cli.zig");

pub const cuda = stwo.integrations.native_cuda.wide_fibonacci;
pub const application = "wide_fibonacci";
pub const protocol_name = cli.wide_protocol_name;

pub fn protocol() cuda.request.Protocol {
    return .{
        .pow_bits = 10,
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
        .fold_step = 1,
        .lifting_log_size = null,
    };
}

pub fn admit(
    request: cli.Prove,
    sealed: cuda.request.Protocol,
) !cuda.request.Geometry {
    return cuda.request.admit(.{
        .statement = .{
            .log_n_rows = request.log_n_rows.?,
            .sequence_len = request.sequence_len.?,
        },
        .protocol = sealed,
    });
}

pub fn proofRequest(
    geometry: cuda.request.Geometry,
) cuda.request.Request {
    return .{
        .statement = geometry.statement,
        .protocol = geometry.protocol,
    };
}

pub fn verify(
    allocator: std.mem.Allocator,
    pcs_config: stwo.core.pcs.PcsConfig,
    geometry: cuda.request.Geometry,
    proof: anytype,
) !void {
    try stwo.examples.wide_fibonacci.verify(
        allocator,
        pcs_config,
        .{
            .log_n_rows = geometry.statement.log_n_rows,
            .sequence_len = geometry.statement.sequence_len,
        },
        proof,
    );
}

pub fn writeArtifact(
    allocator: std.mem.Allocator,
    path: []const u8,
    pcs_config: stwo.core.pcs.PcsConfig,
    geometry: cuda.request.Geometry,
    canonical: []const u8,
) !void {
    try stwo.interop.examples_artifact.writeNativeProofArtifact(
        allocator,
        path,
        pcs_config,
        "prove",
        .{ .wide_fibonacci = .{
            .log_n_rows = geometry.statement.log_n_rows,
            .sequence_len = geometry.statement.sequence_len,
        } },
        canonical,
    );
}

pub const ReportStatement = struct {
    log_n_rows: u32,
    sequence_len: u32,
    trace_rows: usize,
    trace_cells: usize,
};

pub fn reportStatement(
    geometry: cuda.request.Geometry,
) ReportStatement {
    return .{
        .log_n_rows = geometry.statement.log_n_rows,
        .sequence_len = geometry.statement.sequence_len,
        .trace_rows = geometry.trace_rows,
        .trace_cells = geometry.trace_cells,
    };
}

test "wide route seals the production protocol" {
    const geometry = try admit(.{
        .air = .wide_fibonacci,
        .log_n_rows = 5,
        .sequence_len = 8,
        .n_rounds = null,
        .log_size = null,
        .log_step = null,
        .offset = null,
        .output = "proof.json",
        .report_out = null,
        .repeat = 1,
        .execution_mode = .graphs,
    }, protocol());
    try std.testing.expectEqual(@as(u32, 10), geometry.protocol.pow_bits);
    try std.testing.expectEqual(@as(u32, 1), geometry.protocol.fold_step);
    try std.testing.expectEqual(@as(usize, 3), geometry.protocol.n_queries);
}
