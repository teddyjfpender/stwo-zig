//! Ingress-only construction of validated OODS scatter topology.

const common = @import("common.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

pub const IndexMap = struct {
    device: common.Words,
    output_capacity: usize,
};

pub const SampleMap = struct {
    indices: IndexMap,
    fold_counts: common.Words,
};

pub fn prepareIndexMap(
    session: anytype,
    host_indices: []const u32,
    device_indices: common.Words,
    output_capacity: usize,
) runtime_error.Error!IndexMap {
    try common.requireStage(session, .ingress);
    try validateIndices(host_indices, output_capacity);
    const exact_device = try device_indices.sub(0, host_indices.len);
    try session.context.uploadSlice(u32, exact_device, host_indices);
    return .{
        .device = exact_device,
        .output_capacity = output_capacity,
    };
}

pub fn prepareSampleMap(
    session: anytype,
    host_indices: []const u32,
    host_fold_counts: []const u32,
    device_indices: common.Words,
    device_fold_counts: common.Words,
    output_capacity: usize,
) runtime_error.Error!SampleMap {
    try common.requireStage(session, telemetry.Stage.ingress);
    if (host_indices.len != host_fold_counts.len)
        return error.InvalidKernelDescriptor;
    try validateIndices(host_indices, output_capacity);
    for (host_fold_counts) |fold_count| {
        if (fold_count > 31) return error.InvalidFoldCount;
    }
    const exact_indices = try device_indices.sub(0, host_indices.len);
    const exact_folds = try device_fold_counts.sub(0, host_fold_counts.len);
    try session.context.uploadSlice(u32, exact_indices, host_indices);
    try session.context.uploadSlice(u32, exact_folds, host_fold_counts);
    return .{
        .indices = .{
            .device = exact_indices,
            .output_capacity = output_capacity,
        },
        .fold_counts = exact_folds,
    };
}

fn validateIndices(
    indices: []const u32,
    output_capacity: usize,
) runtime_error.Error!void {
    if (indices.len == 0 or output_capacity == 0)
        return error.InvalidKernelDescriptor;
    for (indices, 0..) |index, position| {
        if (index >= output_capacity) return error.InvalidOutputIndex;
        for (indices[0..position]) |previous| {
            if (index == previous) return error.DuplicateOutputIndex;
        }
    }
}

test "index validation rejects races and out-of-range scatters" {
    try validateIndices(&.{ 2, 0, 1 }, 3);
    try @import("std").testing.expectError(
        error.DuplicateOutputIndex,
        validateIndices(&.{ 1, 0, 1 }, 3),
    );
    try @import("std").testing.expectError(
        error.InvalidOutputIndex,
        validateIndices(&.{3}, 3),
    );
}
