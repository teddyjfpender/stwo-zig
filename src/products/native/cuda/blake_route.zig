//! Blake policy for the shared Native CUDA proof lifecycle.

const std = @import("std");
const stwo = @import("stwo_native_cuda");
const cli = @import("cli.zig");

pub const cuda = stwo.integrations.native_cuda.blake;
pub const exact_cuda = cuda.exact;
pub const application = "blake";
pub const protocol_name = cli.blake_protocol_name;

pub fn protocol() stwo.core.pcs.PcsConfig {
    return stwo.core.pcs.PcsConfig.default();
}

pub fn admit(
    request: cli.Prove,
    protocol_value: stwo.core.pcs.PcsConfig,
) !cuda.geometry.Geometry {
    _ = try exact_cuda.geometry.admit(.{
        .statement = .{
            .log_n_rows = request.log_n_rows.?,
            .n_rounds = request.n_rounds.?,
        },
        .protocol = protocol_value,
    });
    try exact_cuda.activation.requireProductReady();
    unreachable;
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
    _ = pcs_config;
    _ = geometry;
    var owned_proof = proof;
    owned_proof.deinit(allocator);
    return error.UnsupportedExactBlakeProtocol;
}

pub fn writeArtifact(
    allocator: std.mem.Allocator,
    path: []const u8,
    pcs_config: stwo.core.pcs.PcsConfig,
    geometry: cuda.geometry.Geometry,
    canonical: []const u8,
) !void {
    _ = allocator;
    _ = path;
    _ = pcs_config;
    _ = geometry;
    _ = canonical;
    return error.UnsupportedExactBlakeProtocol;
}

pub const ReportStatement = struct {
    log_n_rows: u32,
    n_rounds: u32,
    trace_rows: u64,
    trace_cells: u64,
};

pub fn reportStatement(
    geometry: cuda.geometry.Geometry,
) ReportStatement {
    return .{
        .log_n_rows = geometry.statement.log_n_rows,
        .n_rounds = geometry.statement.n_rounds,
        .trace_rows = geometry.trace_rows,
        .trace_cells = geometry.main_cells,
    };
}

test "Blake route admits exact geometry then fails closed on kernel authority" {
    try std.testing.expectError(
        error.ExactBlakeCudaInteractionAotUnavailable,
        admit(.{
            .air = .blake,
            .log_n_rows = 10,
            .sequence_len = null,
            .n_rounds = 10,
            .log_size = null,
            .log_step = null,
            .offset = null,
            .output = "proof.json",
            .report_out = null,
            .repeat = 1,
            .execution_mode = .graphs,
        }, protocol()),
    );
}
