//! Bounded canonical CSP recursion-profile registry.
//!
//! A profile is selected only from exact production statement facts.  The
//! registry does not estimate dimensions from cycles and does not treat an
//! aggregate maximum as a capacity: all six shape fields must match.  Profile
//! recognition and outer-circuit availability are deliberately separate so a
//! known-but-unimplemented shape fails before native proof construction.

const std = @import("std");

pub const FORMAT_VERSION: u16 = 1;
pub const CANONICAL_CASE_COUNT: u16 = 16;

pub const ProfileId = enum(u16) {
    hash_compact = 1,
    sha256_2048 = 2,
    keccak_2048 = 3,
    poseidon2_2 = 4,
    poseidon2_4 = 5,
    poseidon2_8 = 6,
    poseidon2_12 = 7,
    poseidon2_16 = 8,
    ecdsa_secp256k1_32 = 9,
};

/// Only `outer_wired` may cross the producer's native-proof boundary.
pub const ImplementationStatus = enum(u8) {
    catalogued_outer_not_wired = 0,
    outer_wired = 1,
};

/// Exact proof-independent facts emitted by production statement geometry.
pub const Shape = struct {
    component_count: u32,
    infrastructure_count: u32,
    preprocessed_column_count: u32,
    main_column_count: u32,
    interaction_column_count: u32,
    maximum_column_log_degree: u32,

    pub fn eql(left: Shape, right: Shape) bool {
        return std.meta.eql(left, right);
    }
};

pub const Entry = struct {
    id: ProfileId,
    shape: Shape,
    canonical_case_count: u16,
    implementation_status: ImplementationStatus,

    pub fn name(self: Entry) []const u8 {
        return @tagName(self.id);
    }

    /// Stable profile identity.  This binds the semantic profile name and all
    /// exact selector fields, but intentionally excludes mutable readiness
    /// metadata and workload incidence.
    pub fn shapeSha256(self: Entry) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-zig/riscv/recursive-csp-profile-shape/v1\x00");
        hashInt(&hash, u16, FORMAT_VERSION);
        hashInt(&hash, u16, @intFromEnum(self.id));
        hashInt(&hash, u16, @intCast(self.name().len));
        hash.update(self.name());
        hashShape(&hash, self.shape);
        return hash.finalResult();
    }

    pub fn outerExecutable(self: Entry) bool {
        return self.implementation_status == .outer_wired;
    }
};

/// The nine distinct geometries observed across the sealed 16-case EthProofs
/// CSP manifest.  A common SHA-256/Keccak profile covers eight cases; every
/// other entry covers one.  No maximum-sized universal padding profile exists.
pub const ENTRIES = [_]Entry{
    entry(.hash_compact, 12, 11, 54, 916, 444, 20, 8),
    entry(.sha256_2048, 13, 11, 56, 951, 480, 20, 1),
    entry(.keccak_2048, 14, 11, 58, 999, 512, 20, 1),
    entry(.poseidon2_2, 13, 11, 56, 953, 468, 20, 1),
    entry(.poseidon2_4, 14, 11, 58, 988, 504, 20, 1),
    entry(.poseidon2_8, 15, 11, 60, 1023, 540, 20, 1),
    entry(.poseidon2_12, 18, 11, 66, 1144, 644, 20, 1),
    entry(.poseidon2_16, 21, 11, 72, 1271, 740, 20, 1),
    entry(.ecdsa_secp256k1_32, 94, 11, 218, 4444, 3624, 20, 1),
};

pub const Error = error{
    DuplicateProfileId,
    DuplicateProfileShape,
    InvalidCanonicalCaseCoverage,
    UnknownCanonicalShape,
};

pub fn validate() Error!void {
    var covered_cases: u16 = 0;
    for (ENTRIES, 0..) |candidate, index| {
        covered_cases = std.math.add(
            u16,
            covered_cases,
            candidate.canonical_case_count,
        ) catch return error.InvalidCanonicalCaseCoverage;
        for (ENTRIES[0..index]) |previous| {
            if (candidate.id == previous.id) return error.DuplicateProfileId;
            if (candidate.shape.eql(previous.shape))
                return error.DuplicateProfileShape;
        }
    }
    if (covered_cases != CANONICAL_CASE_COUNT)
        return error.InvalidCanonicalCaseCoverage;
}

pub fn select(shape: Shape) Error!Entry {
    try validate();
    for (ENTRIES) |candidate| {
        if (candidate.shape.eql(shape)) return candidate;
    }
    return error.UnknownCanonicalShape;
}

/// Registry seal includes ordered profile seals plus readiness and incidence.
/// Changing dispatch availability therefore invalidates plans even though the
/// underlying shape identity remains stable.
pub fn registrySha256() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv/recursive-csp-profile-registry/v1\x00");
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, ENTRIES.len);
    for (ENTRIES) |candidate| {
        const profile_digest = candidate.shapeSha256();
        hash.update(&profile_digest);
        hashInt(
            &hash,
            u8,
            @intFromEnum(candidate.implementation_status),
        );
        hashInt(&hash, u16, candidate.canonical_case_count);
    }
    return hash.finalResult();
}

fn entry(
    id: ProfileId,
    component_count: u32,
    infrastructure_count: u32,
    preprocessed_column_count: u32,
    main_column_count: u32,
    interaction_column_count: u32,
    maximum_column_log_degree: u32,
    canonical_case_count: u16,
) Entry {
    return .{
        .id = id,
        .shape = .{
            .component_count = component_count,
            .infrastructure_count = infrastructure_count,
            .preprocessed_column_count = preprocessed_column_count,
            .main_column_count = main_column_count,
            .interaction_column_count = interaction_column_count,
            .maximum_column_log_degree = maximum_column_log_degree,
        },
        .canonical_case_count = canonical_case_count,
        // The current outer integration is instantiated only for the small
        // development fixture (38/625/200), which is intentionally absent
        // from this canonical CSP registry.
        .implementation_status = .catalogued_outer_not_wired,
    };
}

fn hashShape(hash: *std.crypto.hash.sha2.Sha256, shape: Shape) void {
    hashInt(hash, u32, shape.component_count);
    hashInt(hash, u32, shape.infrastructure_count);
    hashInt(hash, u32, shape.preprocessed_column_count);
    hashInt(hash, u32, shape.main_column_count);
    hashInt(hash, u32, shape.interaction_column_count);
    hashInt(hash, u32, shape.maximum_column_log_degree);
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: T,
) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

test "canonical CSP registry is bounded, exact, and rejects near misses" {
    try validate();
    try std.testing.expectEqual(@as(usize, 9), ENTRIES.len);
    const common = try select(.{
        .component_count = 12,
        .infrastructure_count = 11,
        .preprocessed_column_count = 54,
        .main_column_count = 916,
        .interaction_column_count = 444,
        .maximum_column_log_degree = 20,
    });
    try std.testing.expectEqual(ProfileId.hash_compact, common.id);
    try std.testing.expect(!common.outerExecutable());

    var near_miss = common.shape;
    near_miss.interaction_column_count += 1;
    try std.testing.expectError(error.UnknownCanonicalShape, select(near_miss));
}

test "profile and registry seals are deterministic and domain separated" {
    const first = ENTRIES[0].shapeSha256();
    try std.testing.expectEqual(first, ENTRIES[0].shapeSha256());
    try std.testing.expect(!std.mem.allEqual(u8, &first, 0));
    const registry = registrySha256();
    try std.testing.expect(!std.mem.allEqual(u8, &registry, 0));
    try std.testing.expect(!std.mem.eql(u8, &first, &registry));
}
