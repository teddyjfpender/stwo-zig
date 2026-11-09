//! Argument admission for the single detached leaf producer. No proof or runtime setup.
const std = @import("std");
pub const Profile = @import("stwo_riscv_frontend").recursion.detached_segment_protocol_v1.ProfileV1;
pub const Backend = enum { cpu, metal };

pub const Options = struct {
    address_count: usize,
    segment_count: usize,
    directory: []const u8,
    initial_memory_word: u32,
    proof_profile: Profile,
    native_backend: Backend,
    recursive_backend: Backend,
    child_key_paths: [8]?[]const u8,
    child_key_pins: [8]?[]const u8,
    aot_bundle: ?[]const u8,
    aot_profile: ?[]const u8,
    aot_manifest: ?[32]u8,
};

pub fn parse(args: []const []const u8) !Options {
    var addresses: ?usize = null;
    var count: ?usize = null;
    var directory: ?[]const u8 = null;
    var seed: ?u32 = null;
    var profile: ?Profile = null;
    var native: ?Backend = null;
    var recursive: ?Backend = null;
    var paths: [8]?[]const u8 = @splat(null);
    var pins: [8]?[]const u8 = @splat(null);
    var bundle: ?[]const u8 = null;
    var aot_profile: ?[]const u8 = null;
    var manifest: ?[32]u8 = null;
    if (args.len == 0 or args.len % 2 != 0) return error.InvalidArguments;
    var at: usize = 0;
    while (at < args.len) : (at += 2) {
        const key = args[at];
        const value = args[at + 1];
        if (value.len == 0) return error.InvalidArguments;
        if (std.mem.eql(u8, key, "--memory-addresses")) {
            if (addresses != null) return error.DuplicateArgument;
            addresses = std.fmt.parseInt(usize, value, 10) catch return error.InvalidMemoryAddressCount;
        } else if (std.mem.eql(u8, key, "--segment-count")) {
            if (count != null) return error.DuplicateArgument;
            count = std.fmt.parseInt(usize, value, 10) catch return error.InvalidSegmentCount;
        } else if (std.mem.eql(u8, key, "--segments-output")) {
            if (directory != null) return error.DuplicateArgument;
            directory = value;
        } else if (std.mem.eql(u8, key, "--initial-memory-word")) {
            if (seed != null) return error.DuplicateArgument;
            seed = std.fmt.parseInt(u32, value, 0) catch return error.InvalidInitialMemoryWord;
        } else if (std.mem.eql(u8, key, "--proof-profile")) {
            if (profile != null) return error.DuplicateArgument;
            profile = std.meta.stringToEnum(Profile, value) orelse return error.InvalidProofProfile;
        } else if (std.mem.eql(u8, key, "--native-backend")) {
            if (native != null) return error.DuplicateArgument;
            native = std.meta.stringToEnum(Backend, value) orelse return error.InvalidNativeBackend;
        } else if (std.mem.eql(u8, key, "--recursive-backend")) {
            if (recursive != null) return error.DuplicateArgument;
            recursive = std.meta.stringToEnum(Backend, value) orelse return error.InvalidRecursiveBackend;
        } else if (std.mem.eql(u8, key, "--aot-bundle")) {
            if (bundle != null) return error.DuplicateArgument;
            bundle = value;
        } else if (std.mem.eql(u8, key, "--aot-profile")) {
            if (aot_profile != null) return error.DuplicateArgument;
            if (!std.mem.eql(u8, value, "recursive-framework-v1") and !std.mem.eql(u8, value, "core-v2")) return error.InvalidAotProfile;
            aot_profile = value;
        } else if (std.mem.eql(u8, key, "--aot-manifest-sha256")) {
            if (manifest != null) return error.DuplicateArgument;
            manifest = try pin(value);
        } else if (std.mem.startsWith(u8, key, "--child-")) {
            if (key.len < 13 or key[8] < '0' or key[8] > '7') return error.InvalidArguments;
            const index: usize = key[8] - '0';
            if (std.mem.eql(u8, key[9..], "-key")) {
                if (paths[index] != null) return error.DuplicateArgument;
                paths[index] = value;
            } else if (std.mem.eql(u8, key[9..], "-key-sha256")) {
                if (pins[index] != null) return error.DuplicateArgument;
                _ = try pin(value);
                pins[index] = value;
            } else return error.InvalidArguments;
        } else return error.InvalidArguments;
    }
    const selected_addresses = addresses orelse return error.MissingMemoryAddressCount;
    switch (selected_addresses) {
        1, 4, 16 => {},
        else => return error.InvalidMemoryAddressCount,
    }
    const selected_count = count orelse 2;
    switch (selected_count) {
        1, 2, 4, 8 => {},
        else => return error.InvalidSegmentCount,
    }
    const output = directory orelse return error.SegmentOutputRequired;
    for (paths, pins, 0..) |path, key_pin, index| {
        if (index < selected_count) {
            if (path == null or key_pin == null) return error.MissingDetachedKeyAdmission;
        } else if (path != null or key_pin != null) return error.InvalidArguments;
    }
    const native_backend = native orelse .cpu;
    const recursive_backend = recursive orelse native_backend;
    if (recursive_backend == .metal and native_backend != .metal) return error.RecursiveMetalRequiresNativeMetal;
    if (native_backend == .cpu) {
        if (bundle != null or manifest != null or aot_profile != null) return error.UnexpectedAotArguments;
    } else if (bundle == null or manifest == null) return error.MissingAuthenticatedAot;
    return .{ .address_count = selected_addresses, .segment_count = selected_count, .directory = output, .initial_memory_word = seed orelse 0, .proof_profile = profile orelse .recursive_q193_v1, .native_backend = native_backend, .recursive_backend = recursive_backend, .child_key_paths = paths, .child_key_pins = pins, .aot_bundle = bundle, .aot_profile = aot_profile, .aot_manifest = manifest };
}

fn pin(text: []const u8) ![32]u8 {
    if (text.len != 64) return error.InvalidSha256;
    var bytes: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, text) catch return error.InvalidSha256;
    return bytes;
}
