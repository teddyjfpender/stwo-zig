//! Verifier-owned query profiles and their canonical admission digest.
const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const digest = @import("../../air/lang/digest.zig");
pub const MIN_LOG_SIZE: u32 = 4;
pub const MAX_LOG_SIZE: u32 = 30;
pub const REFERENCE_FORMAT_VERSION: u16 = 1;
pub const REFERENCE_DOMAIN = "stwo-zig/typed-air/recursion-query-bits-reference/v1\x00";
pub const Error = error{ ArithmeticOverflow, AuthorityMismatch, InvalidProfile };

pub const LaneProfile = struct {
    query_count: u32,
    /// Number of low bits retained by the authenticated raw-query to domain-
    /// position projection.  This is verifier-owned protocol shape, not proof
    /// material.
    lifting_log_size: u32,
    trace_tree_count: u32,
    fri_layer_count: u32,

    /// Exact number of query-bit-vector consumers in Stark-V:
    /// every trace tree, DEEP, two uses per FRI layer, and last-layer.
    pub fn useCount(self: LaneProfile) Error!u32 {
        const fri_uses = std.math.mul(u32, self.fri_layer_count, 2) catch
            return error.ArithmeticOverflow;
        const with_trees = std.math.add(u32, self.trace_tree_count, fri_uses) catch
            return error.ArithmeticOverflow;
        return std.math.add(u32, with_trees, 2) catch
            return error.ArithmeticOverflow;
    }
};

pub const Reference = struct {
    vm: LaneProfile,
    recursion: LaneProfile,
    authority_digest: digest.Digest,

    pub fn seal(vm: LaneProfile, recursion: LaneProfile) Error!Reference {
        try validateProfiles(vm, recursion);
        return .{
            .vm = vm,
            .recursion = recursion,
            .authority_digest = referenceDigest(vm, recursion),
        };
    }

    pub fn validate(self: Reference) Error!void {
        try validateProfiles(self.vm, self.recursion);
        if (!std.mem.eql(
            u8,
            &self.authority_digest,
            &referenceDigest(self.vm, self.recursion),
        )) return error.AuthorityMismatch;
    }
};

pub fn validateProfiles(vm: LaneProfile, recursion: LaneProfile) Error!void {
    for ([_]LaneProfile{ vm, recursion }) |profile| {
        const use_count = try profile.useCount();
        if (profile.query_count == 0 or profile.query_count >= m31.Modulus or
            profile.lifting_log_size < MIN_LOG_SIZE or
            profile.lifting_log_size > MAX_LOG_SIZE or
            profile.trace_tree_count == 0 or profile.trace_tree_count >= m31.Modulus or
            profile.fri_layer_count == 0 or profile.fri_layer_count >= m31.Modulus or
            use_count == 0 or use_count >= m31.Modulus)
        {
            return error.InvalidProfile;
        }
    }
    _ = try totalRows(vm, recursion);
}

pub fn totalRows(vm: LaneProfile, recursion: LaneProfile) Error!usize {
    const recursion_rows = std.math.mul(usize, recursion.query_count, 2) catch
        return error.ArithmeticOverflow;
    return std.math.add(usize, vm.query_count, recursion_rows) catch
        return error.ArithmeticOverflow;
}

fn referenceDigest(vm: LaneProfile, recursion: LaneProfile) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(REFERENCE_DOMAIN);
    hashInt(&hash, u16, REFERENCE_FORMAT_VERSION);
    hashProfile(&hash, vm);
    hashProfile(&hash, recursion);
    return hash.finalResult();
}

fn hashProfile(hash: anytype, profile: LaneProfile) void {
    hashInt(hash, u32, profile.query_count);
    hashInt(hash, u32, profile.lifting_log_size);
    hashInt(hash, u32, profile.trace_tree_count);
    hashInt(hash, u32, profile.fri_layer_count);
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

const M31 = m31.M31;
const component = @import("query_bits.zig");
const ProofKind = @import("proof_kind.zig").ProofKind;
pub const RAW_QUERY_KIND: u32 = 5;

pub fn parameterValues(
    reference: Reference,
    kind: ProofKind,
) Error![component.PARAMETER_COUNT]M31 {
    try reference.validate();
    const selectors = kind.selectors();
    const lifting_log_size: u32 = switch (kind) {
        .segment_leaf => reference.vm.lifting_log_size,
        .binary_node => reference.recursion.lifting_log_size,
        .empty_leaf => 0,
    };
    var result: [component.PARAMETER_COUNT]M31 = undefined;
    result[0] = selectors[0];
    result[1] = selectors[1];
    result[2] = M31.fromCanonical(RAW_QUERY_KIND);
    for (result[3..], 0..) |*mask, bit| {
        mask.* = M31.fromCanonical(@intFromBool(bit < lifting_log_size));
    }
    return result;
}
