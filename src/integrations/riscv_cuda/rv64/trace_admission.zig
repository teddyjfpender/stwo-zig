//! Pure trace-header admission before CUDA allocation or callback dispatch.
const std = @import("std");
const api = @import("stwo_prover_api");
const D = api.device_pcs;
pub const Error = D.TraceColumnError || error{ InvalidTraceCommitRequest, HostWitnessDisallowedInResidentProof };
pub fn validateColumns(request: D.TraceCommitRequest, require_device: bool) Error!void {
    if (request.diagnostic) |sink| sink.* = null;
    const beta = request.config.fri_config.log_blowup_factor;
    if (beta < 1 or beta > 4) return error.InvalidTraceCommitRequest;
    for (request.columns) |column| {
        try column.validateDiagnosed(request.diagnostic);
        if (require_device and column.device == null) return error.HostWitnessDisallowedInResidentProof;
        if (column.log_size + beta > 28) return error.InvalidTraceCommitRequest;
    }
}

test "trace admission actual headers isolate metadata custody and integration policy refusal" {
    var first: ?api.error_codes.DeviceFailure = null;
    var second: ?api.error_codes.DeviceFailure = null;
    var columns = [_]D.TraceColumn{.{ .log_size = 2, .encoding = .coefficients }};
    var request = D.TraceCommitRequest{
        .scope = .{ .statement = @splat(1), .fixed = @splat(2), .main = @splat(3), .ordinal = 4 },
        .tree_index = 1,
        .config = .{ .pow_bits = 0, .fri_config = try @import("stwo_core").fri.FriConfig.init(0, 1, 3) },
        .columns = &columns,
        .diagnostic = &first,
    };
    try std.testing.expectError(error.InvalidDeviceTraceColumn, validateColumns(request, true));
    try std.testing.expectEqual(@as(u16, 0x3501), first.?.entry.code);
    columns[0] = .{ .log_size = 5, .encoding = .coefficients, .device = .{ .words = @ptrFromInt(4096), .count = 32, .context_token = 7, .generation = 1 } };
    try validateColumns(request, true);
    try std.testing.expect(first == null);
    const scope = request.scope;
    const column = columns[0];
    request.diagnostic = &second;
    try validateColumns(request, true);
    try std.testing.expect(second == null and first == null);
    try std.testing.expect(std.meta.eql(scope, request.scope));
    try std.testing.expectEqualDeep(column, columns[0]);
    // Invalid integration policy does not manufacture a provider-owned code.
    second = .{ .cause = error.InvalidDeviceTraceColumn, .entry = api.error_codes.fromDeviceAdmission(error.InvalidDeviceTraceColumn) };
    request.config.fri_config.log_blowup_factor = 5;
    try std.testing.expectError(error.InvalidTraceCommitRequest, validateColumns(request, true));
    try std.testing.expect(second == null);
}
