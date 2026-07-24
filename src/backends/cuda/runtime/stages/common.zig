//! Shared validation for allocation-free resident proof-stage calls.

const std = @import("std");
const field = @import("../../abi/field.zig");
const column = @import("../column.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

pub const Words = column.DeviceSlice(u32);
pub const SecureFields = column.DeviceSlice(field.SecureField);
pub const CirclePoints = column.DeviceSlice(field.CirclePointBaseField);
pub const SecureCirclePoints = column.DeviceSlice(field.SecureCirclePoint);
pub const Hashes = column.DeviceSlice(field.Blake2sHash);
pub const MerkleLayers = column.DeviceSlice(field.MerkleLayerDescriptor);
pub const ProgressiveStates = column.DeviceSlice(field.ProgressiveBlake2sState);
pub const Nonce = column.DeviceSlice(u64);
pub const WordMatrix = struct {
    storage: Words,
    column_stride_words: usize,
};
pub const ConstraintBuffers = struct {
    statement_parameters: Words,
    challenge_parameters: Words,
    composition_coordinates: WordMatrix,
};

pub fn words(
    session: anytype,
    slice: Words,
    minimum: usize,
) runtime_error.Error![*]u32 {
    return session.context.deviceSlicePointer(u32, slice, minimum);
}

pub fn optionalWords(
    session: anytype,
    slice: Words,
) runtime_error.Error!?[*]u32 {
    if (slice.len == 0) return null;
    return try words(session, slice, slice.len);
}

pub fn secure(
    session: anytype,
    slice: SecureFields,
    minimum: usize,
) runtime_error.Error![*]field.SecureField {
    return session.context.deviceSlicePointer(field.SecureField, slice, minimum);
}

pub fn circles(
    session: anytype,
    slice: CirclePoints,
    minimum: usize,
) runtime_error.Error![*]field.CirclePointBaseField {
    return session.context.deviceSlicePointer(
        field.CirclePointBaseField,
        slice,
        minimum,
    );
}

pub fn secureCircles(
    session: anytype,
    slice: SecureCirclePoints,
    minimum: usize,
) runtime_error.Error![*]field.SecureCirclePoint {
    return session.context.deviceSlicePointer(
        field.SecureCirclePoint,
        slice,
        minimum,
    );
}

pub fn hashes(
    session: anytype,
    slice: Hashes,
    minimum: usize,
) runtime_error.Error![*]field.Blake2sHash {
    return session.context.deviceSlicePointer(field.Blake2sHash, slice, minimum);
}

pub fn optionalHashes(
    session: anytype,
    slice: Hashes,
) runtime_error.Error!?[*]field.Blake2sHash {
    if (slice.len == 0) return null;
    return try hashes(session, slice, slice.len);
}

pub fn merkleLayers(
    session: anytype,
    slice: MerkleLayers,
    minimum: usize,
) runtime_error.Error![*]field.MerkleLayerDescriptor {
    return session.context.deviceSlicePointer(
        field.MerkleLayerDescriptor,
        slice,
        minimum,
    );
}

pub fn states(
    session: anytype,
    slice: ProgressiveStates,
    minimum: usize,
) runtime_error.Error![*]field.ProgressiveBlake2sState {
    return session.context.deviceSlicePointer(
        field.ProgressiveBlake2sState,
        slice,
        minimum,
    );
}

pub fn nonce(
    session: anytype,
    slice: Nonce,
) runtime_error.Error!*u64 {
    return @ptrCast(try session.context.deviceSlicePointer(u64, slice, 1));
}

pub fn count(value: usize) runtime_error.Error!u32 {
    return std.math.cast(u32, value) orelse error.SizeOverflow;
}

pub fn requireNonZero(values: []const u32) runtime_error.Error!void {
    for (values) |value| {
        if (value == 0) return error.InvalidKernelDescriptor;
    }
}

pub fn requireStage(
    session: anytype,
    stage: telemetry.Stage,
) runtime_error.Error!void {
    try session.context.requireStage(stage);
}

pub fn record(
    session: anytype,
    stage: telemetry.Stage,
    status: c_int,
) runtime_error.Error!void {
    try session.recordOrdinaryKernel(stage, status);
}

pub fn recordMany(
    session: anytype,
    stage: telemetry.Stage,
    status: c_int,
    launches: u64,
) runtime_error.Error!void {
    try session.recordOrdinaryKernels(stage, status, launches);
}
