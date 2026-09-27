//! Independently prepared SHA/Keccak/signer caller column placements for a
//! same-native-root v5 program-fetch request proof. No proof authority here.
const std = @import("std");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const source = @import("block_v5_program_extension_source_v1.zig");
const sha = @import("../air/guest_precompile/sha256_memory_caller.zig");
const keccak = @import("../air/guest_precompile/keccakf_caller.zig");
const keccak_trace = @import("../air/guest_precompile/keccakf_trace.zig");
const signer = @import("../air/guest_precompile/secp256k1_recovery_caller.zig");

pub const Slot = struct {
    kind: source.Kind,
    log_size: u32,
    active_calls: u32,
    fixed_selector_offset: ?usize,
    main_offset: usize,
    main_columns: usize,
    x0_local_custody_version: u32 = 0,
};

/// At most three caller families are active. Fixed/main prefix lengths come
/// from the independently prepared native key, not a proof-carried offset.
pub fn fromPrepared(a: std.mem.Allocator, prepared: anytype) ![]Slot {
    const descriptors = Profile.descriptors(&prepared.extension);
    var extension_fixed: usize = 0;
    var extension_main: usize = 0;
    for (descriptors) |descriptor| {
        extension_fixed = try std.math.add(usize, extension_fixed, descriptor.preprocessed_columns);
        extension_main = try std.math.add(usize, extension_main, descriptor.main_columns);
    }
    if (extension_fixed > prepared.logs[0].len or extension_main > prepared.logs[1].len)
        return error.InvalidV5ProgramExtensionPlacement;
    const fixed_base = prepared.logs[0].len - extension_fixed;
    const main_base = prepared.logs[1].len - extension_main;
    return fromProfile(a, &prepared.extension, prepared.logs[0], prepared.logs[1], fixed_base, main_base);
}

/// Family11 separate arithmetic proofs use bases zero. A legacy combined
/// native proof may use independently prepared prefix lengths instead.
/// Both routes derive the caller roster solely from the pinned profile shape.
pub fn fromProfile(a: std.mem.Allocator, extension: *const Profile.admission.Statement, fixed_logs: []const u32, main_logs: []const u32, fixed_base: usize, main_base: usize) ![]Slot {
    const local_zero = extension.ethereum.localZeroCustody();
    const descriptors = Profile.descriptors(extension);
    var result: std.ArrayList(Slot) = .empty;
    errdefer result.deinit(a);
    var fixed_offset = fixed_base;
    var main_offset = main_base;
    for (descriptors, 0..) |descriptor, index| {
        const active: u32 = switch (index) {
            0 => extension.ethereum.counts.keccak_calls,
            13 => extension.ethereum.counts.signer_calls,
            18 => extension.sha.call_count,
            else => 0,
        };
        if (active != 0) {
            const slot: Slot = switch (index) {
                0 => .{ .kind = .keccak, .log_size = descriptor.log_size, .active_calls = active, .fixed_selector_offset = null, .main_offset = main_offset + keccak_trace.Layout.caller, .main_columns = keccak.Layout.main_columns + @as(usize, if (local_zero) 2 else 0), .x0_local_custody_version = @intFromBool(local_zero) },
                13 => .{ .kind = .signer, .log_size = descriptor.log_size, .active_calls = active, .fixed_selector_offset = null, .main_offset = main_offset, .main_columns = signer.Layout.main_columns + @as(usize, if (local_zero) 2 else 0), .x0_local_custody_version = @intFromBool(local_zero) },
                18 => .{ .kind = .sha, .log_size = descriptor.log_size, .active_calls = active, .fixed_selector_offset = fixed_offset, .main_offset = main_offset, .main_columns = sha.PHYSICAL_MAIN_COLUMN_COUNT + @as(usize, if (local_zero) 4 else 0), .x0_local_custody_version = @intFromBool(local_zero) },
                else => unreachable,
            };
            try validate(slot, fixed_logs, main_logs);
            try result.append(a, slot);
        }
        fixed_offset += descriptor.preprocessed_columns;
        main_offset += descriptor.main_columns;
    }
    if (fixed_offset != fixed_logs.len or main_offset != main_logs.len)
        return error.InvalidV5ProgramExtensionPlacement;
    return result.toOwnedSlice(a);
}

pub fn validate(slot: Slot, fixed_logs: []const u32, main_logs: []const u32) !void {
    if (slot.x0_local_custody_version > 1) return error.InvalidV5ProgramExtensionPlacement;
    const columns: usize = (switch (slot.kind) {
        .sha => sha.PHYSICAL_MAIN_COLUMN_COUNT,
        .keccak => keccak.Layout.main_columns,
        .signer => signer.Layout.main_columns,
    }) + @as(usize, if (slot.x0_local_custody_version == 1) (if (slot.kind == .sha) 4 else 2) else 0);
    if (slot.main_columns != columns or
        (slot.fixed_selector_offset != null) != (slot.kind == .sha))
        return error.InvalidV5ProgramExtensionPlacement;
    if (slot.active_calls == 0 or slot.log_size == 0 or slot.log_size > 24 or
        slot.main_offset + slot.main_columns > main_logs.len)
        return error.InvalidV5ProgramExtensionPlacement;
    for (main_logs[slot.main_offset..][0..slot.main_columns]) |log| if (log != slot.log_size)
        return error.InvalidV5ProgramExtensionPlacement;
    if (slot.fixed_selector_offset) |offset| {
        if (offset >= fixed_logs.len or fixed_logs[offset] != slot.log_size)
            return error.InvalidV5ProgramExtensionPlacement;
    }
}
