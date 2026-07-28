//! Authenticated flattened statement payload for resident transcript ingress.

const std = @import("std");
const adapter = @import("stwo_cairo_frontend").adapter;
const compact = @import("stwo_cairo_frontend").compact_verifier_interchange;
const statement = @import("stwo_cairo_frontend").statement_bootstrap;
const composition = @import("stwo_cairo_frontend").witness.composition_bundle;
const common = @import(
    "../../../backends/cuda/runtime/stages/common.zig",
);
const resident_plan = @import("resident_plan.zig");
const slot_binding = @import("pcs_slot_binding.zig");
const transcript_schedule = @import("transcript/schedule.zig");

pub const Binding = struct {
    storage: common.Words,
    inputs: [transcript_schedule.bootstrap_mix_ordinals.len]common.Words,
    statement_identity: [32]u8,
};

pub fn derive(
    allocator: std.mem.Allocator,
    protocol: compact.CompactProtocolV1,
    bundle: *const composition.Bundle,
    input: *const adapter.ProverInput,
) !statement.OwnedStatementBootstrap {
    return statement.initFromCompositionSchedule(allocator, .{
        .channel_salt = protocol.channel_salt,
        .pcs = .{
            .pow_bits = protocol.query_pow_bits,
            .log_blowup_factor = protocol.log_blowup_factor,
            .n_queries = protocol.query_count,
            .log_last_layer_degree_bound = protocol.log_last_layer_degree_bound,
            .fold_step = protocol.fri_fold_step,
            .lifting_log_size = protocol.fri_lifting_log_size,
        },
        .composition = bundle,
        .prover_input = input,
    });
}

pub fn wordCount(
    bootstrap: *const statement.OwnedStatementBootstrap,
) !u64 {
    var total: u64 = 0;
    inline for (statement.ORDINALS) |ordinal| {
        total = std.math.add(
            u64,
            total,
            bootstrap.words(ordinal).?.len,
        ) catch return error.CairoCudaGeometryOverflow;
    }
    return total;
}

pub fn identity(
    bootstrap: *const statement.OwnedStatementBootstrap,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/statement-bootstrap/v1\x00");
    inline for (statement.ORDINALS) |ordinal| {
        const words = bootstrap.words(ordinal).?;
        hashInt(&hash, u32, ordinal);
        hashInt(&hash, u64, words.len);
        hash.update(std.mem.sliceAsBytes(words));
    }
    return hash.finalResult();
}

/// Uploads the nine host-derived statement inputs into one authenticated
/// ingress slot and splices the two resident commitment roots into the exact
/// eleven-operation transcript prefix. No root bytes cross the host.
pub fn uploadAndBind(
    allocator: std.mem.Allocator,
    uploader: anytype,
    provider: anytype,
    plan: *const resident_plan.Plan,
    bootstrap: *const statement.OwnedStatementBootstrap,
    preprocessed_root: common.Words,
    main_root: common.Words,
) !Binding {
    if (preprocessed_root.len != 8 or main_root.len != 8)
        return error.InvalidStatementBootstrapBinding;
    const expected_words = try wordCount(bootstrap);
    const storage = try slot_binding.exactWords(
        provider,
        plan,
        .statement_bootstrap,
        0,
        std.math.cast(usize, expected_words) orelse
            return error.CairoCudaGeometryOverflow,
    );
    const host_words = try allocator.alloc(u32, storage.len);
    defer allocator.free(host_words);
    var result = Binding{
        .storage = storage,
        .inputs = undefined,
        .statement_identity = identity(bootstrap),
    };
    var host_cursor: usize = 0;
    var device_cursor: usize = 0;
    for (
        transcript_schedule.bootstrap_mix_ordinals,
        0..,
    ) |ordinal, output_index| {
        if (ordinal == 3) {
            result.inputs[output_index] = preprocessed_root;
            continue;
        }
        if (ordinal == 20) {
            result.inputs[output_index] = main_root;
            continue;
        }
        const words = bootstrap.words(ordinal) orelse
            return error.InvalidStatementBootstrapBinding;
        @memcpy(host_words[host_cursor..][0..words.len], words);
        result.inputs[output_index] = try storage.sub(
            device_cursor,
            words.len,
        );
        host_cursor += words.len;
        device_cursor += words.len;
    }
    if (host_cursor != host_words.len or device_cursor != storage.len)
        return error.InvalidStatementBootstrapBinding;
    try uploader.uploadSlice(u32, storage, host_words);
    return result;
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
