//! Stable identity for a compiled mixed-height trace commitment.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const field = @import("stwo_cuda_backend").abi.field;
const telemetry = @import("stwo_cuda_backend").runtime.telemetry;
const types = @import("types.zig");

pub fn compute(
    program: proof_ir.ProofProgram,
    plan_identity: proof_ir.Digest,
    schedule_identity: proof_ir.Digest,
    ordinal: u32,
    input_form: types.InputForm,
    stage: telemetry.Stage,
    cohorts: []const types.Cohort,
    writers: []const types.WriterSpan,
    column_logs: []const u32,
    column_offsets: []const u32,
    layers: []const field.MerkleLayerDescriptor,
    slots: types.Slots,
) proof_ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/mixed-trace-commit/v1\x00");
    hash.update(&program.program_digest);
    hash.update(&plan_identity);
    hash.update(&schedule_identity);
    hashInt(&hash, u32, ordinal);
    hashInt(&hash, u8, @intFromEnum(input_form));
    hashInt(&hash, u8, @intFromEnum(stage));
    for (cohorts) |cohort| {
        hashInt(&hash, u32, cohort.first_column);
        hashInt(&hash, u32, cohort.column_count);
        hashInt(&hash, u32, cohort.trace_log_rows);
        hashInt(&hash, u32, cohort.evaluation_log_rows);
        hashInt(&hash, u64, cohort.coefficient_offset_words);
        hashInt(&hash, u64, cohort.coefficient_words);
        hashInt(&hash, u64, cohort.evaluation_offset_words);
        hashInt(&hash, u64, cohort.evaluation_words);
    }
    for (writers) |writer| {
        hashInt(&hash, u32, writer.schedule_ordinal);
        hashInt(&hash, u32, writer.component_index);
        hashInt(&hash, u32, writer.first_column);
        hashInt(&hash, u32, writer.column_count);
        hashInt(&hash, u32, writer.trace_log_rows);
        hashInt(&hash, u64, writer.coefficient_offset_words);
        hashInt(&hash, u64, writer.coefficient_words);
    }
    for (column_logs) |value| hashInt(&hash, u32, value);
    for (column_offsets) |value| hashInt(&hash, u32, value);
    for (layers) |layer| {
        hashInt(&hash, u64, layer.offset_hashes);
        hashInt(&hash, u32, layer.hash_count);
        hashInt(&hash, u32, layer.reserved);
    }
    inline for (std.meta.fields(types.Slots)) |slot_field| {
        const value = @field(slots, slot_field.name);
        if (slot_field.type == ?u32) {
            hashInt(&hash, u32, value orelse std.math.maxInt(u32));
        } else {
            hashInt(&hash, u32, value);
        }
    }
    return hash.finalResult();
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime F: type,
    value: anytype,
) void {
    var bytes: [@sizeOf(F)]u8 = undefined;
    std.mem.writeInt(F, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
