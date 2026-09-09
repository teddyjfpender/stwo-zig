//! Canonical transport projection of the exact temporal recursion profile plan.
//!
//! Native Poseidon digests never cross the controller boundary as ambiguous
//! limbs.  Each is projected through one domain-separated SHA-256 encoding of
//! its eight canonical little-endian M31 words.  The ordered nine entries are
//! the exact real-h1, empty-h1, and h2--h8 profiles selected by the Zig plan;
//! Python may serialize or compare these values, but never recreates them.

const std = @import("std");

const node_profile = @import("recursive_temporal_node_profile_v1.zig");
const plan_mod = @import("recursive_temporal_statement_plan_v1.zig");
const security_mod = @import("recursive_temporal_proof_security_v1.zig");
const transcript_mod = @import("recursive_temporal_child_transcript_authority_v1.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 2;
pub const SCHEMA = "stwo.recursion.temporal-profile-plan.v2";
pub const ENTRY_COUNT: usize = 2 + plan_mod.UPPER_PROFILE_COUNT;
const NATIVE_DIGEST_DOMAIN =
    "stwo-zig/typed-air/native-m31-digest-transport/v1\x00";
const TRANSCRIPT_DOMAIN =
    "stwo-zig/typed-air/recursive-transcript-transport/v1\x00";
const ENTRY_DOMAIN =
    "stwo-zig/typed-air/recursive-profile-plan-entry/v2\x00";
const PLAN_DOMAIN =
    "stwo-zig/typed-air/recursive-profile-plan-transport/v2\x00";

pub const EntryKindV1 = enum(u8) {
    real_h1 = 1,
    empty_h1 = 2,
    upper = 3,
};

pub const TranscriptProjectionV1 = struct {
    format_version: u16,
    schema_version: u16,
    kind: transcript_mod.Kind,
    domain: u32,
    cohort_format_version: u16,
    cohort_schema_version: u16,
    component_count: u16,
    identity_sha256: [32]u8,

    pub fn init(value: transcript_mod.DescriptorV1) !TranscriptProjectionV1 {
        try value.validateForChildHeight(switch (value.kind) {
            .temporal_parent_v3, .empty_parent_v1 => 1,
            .recursive_node_v1 => 2,
        });
        var result = TranscriptProjectionV1{
            .format_version = value.format_version,
            .schema_version = value.schema_version,
            .kind = value.kind,
            .domain = value.domain,
            .cohort_format_version = value.cohort_format_version,
            .cohort_schema_version = value.cohort_schema_version,
            .component_count = value.component_count,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = transcriptIdentity(&result);
        return result;
    }

    pub fn validate(self: *const TranscriptProjectionV1) !void {
        const value = transcript_mod.DescriptorV1{
            .format_version = self.format_version,
            .schema_version = self.schema_version,
            .kind = self.kind,
            .domain = self.domain,
            .cohort_format_version = self.cohort_format_version,
            .cohort_schema_version = self.cohort_schema_version,
            .component_count = self.component_count,
        };
        try value.validateForChildHeight(switch (self.kind) {
            .temporal_parent_v3, .empty_parent_v1 => 1,
            .recursive_node_v1 => 2,
        });
        if (!std.mem.eql(
            u8,
            &self.identity_sha256,
            &transcriptIdentity(self),
        )) return error.InvalidProfilePlanTransport;
    }
};

pub const EntryV1 = struct {
    ordinal: u8,
    kind: EntryKindV1,
    parent_height: u8,
    node_profile_sha256: [32]u8,
    verification_key_sha256: [32]u8,
    next_parent_vk_sha256: [32]u8,
    child_composition_manifest_sha256: [32]u8,
    parent_outer_manifest_sha256: [32]u8,
    air_program_sha256: [32]u8,
    air_profile_sha256: [32]u8,
    admitted_child_security: security_mod.ProofSecurityV1,
    parent_proof_security: security_mod.ProofSecurityV1,
    transcript: TranscriptProjectionV1,
    entry_sha256: [32]u8,

    pub fn validate(self: *const EntryV1) !void {
        if (self.ordinal >= ENTRY_COUNT or self.parent_height == 0 or
            std.mem.allEqual(u8, &self.node_profile_sha256, 0) or
            std.mem.allEqual(u8, &self.verification_key_sha256, 0) or
            std.mem.allEqual(u8, &self.next_parent_vk_sha256, 0) or
            std.mem.allEqual(
                u8,
                &self.child_composition_manifest_sha256,
                0,
            ) or
            std.mem.allEqual(u8, &self.parent_outer_manifest_sha256, 0) or
            std.mem.allEqual(u8, &self.air_program_sha256, 0) or
            std.mem.allEqual(u8, &self.air_profile_sha256, 0))
        {
            return error.InvalidProfilePlanTransport;
        }
        switch (self.kind) {
            .real_h1, .empty_h1 => if (self.parent_height != 1)
                return error.InvalidProfilePlanTransport,
            .upper => if (self.parent_height < 2 or
                self.parent_height > plan_mod.ROOT_HEIGHT)
            {
                return error.InvalidProfilePlanTransport;
            },
        }
        try self.admitted_child_security.validate();
        try self.parent_proof_security.validate();
        try self.transcript.validate();
        if (!std.mem.eql(u8, &self.entry_sha256, &entryIdentity(self)))
            return error.InvalidProfilePlanTransport;
    }
};

pub const ProfilePlanTransportV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    entries: [ENTRY_COUNT]EntryV1,
    profile_plan_sha256: [32]u8,

    pub fn init(plan: *const plan_mod.ProfilePlanV1) !ProfilePlanTransportV1 {
        try plan.validate();
        var result: ProfilePlanTransportV1 = undefined;
        result.format_version = FORMAT_VERSION;
        result.schema_version = SCHEMA_VERSION;
        result.entries[0] = try entryFromProfile(0, .real_h1, &plan.real_h1);
        result.entries[1] = try entryFromProfile(1, .empty_h1, &plan.empty_h1);
        for (&plan.upper, 0..) |*profile, index| {
            result.entries[index + 2] = try entryFromProfile(
                @intCast(index + 2),
                .upper,
                profile,
            );
        }
        result.profile_plan_sha256 = planIdentity(&result);
        try result.validateAgainst(plan);
        return result;
    }

    pub fn validate(self: *const ProfilePlanTransportV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION)
        {
            return error.InvalidProfilePlanTransport;
        }
        for (&self.entries, 0..) |*entry, index| {
            try entry.validate();
            if (entry.ordinal != index) return error.InvalidProfilePlanTransport;
            if (index == 0 and entry.kind != .real_h1)
                return error.InvalidProfilePlanTransport;
            if (index == 1 and entry.kind != .empty_h1)
                return error.InvalidProfilePlanTransport;
            if (index >= 2 and (entry.kind != .upper or
                entry.parent_height != index))
            {
                return error.InvalidProfilePlanTransport;
            }
        }
        if (!std.mem.eql(
            u8,
            &self.entries[0].next_parent_vk_sha256,
            &self.entries[2].verification_key_sha256,
        ) or !std.mem.eql(
            u8,
            &self.entries[1].next_parent_vk_sha256,
            &self.entries[2].verification_key_sha256,
        ) or !std.meta.eql(
            self.entries[0].parent_proof_security,
            self.entries[2].admitted_child_security,
        ) or !std.meta.eql(
            self.entries[1].parent_proof_security,
            self.entries[2].admitted_child_security,
        )) return error.InvalidProfilePlanTransport;
        for (self.entries[2 .. self.entries.len - 1], self.entries[3..]) |
            current,
            next,
        | if (!std.mem.eql(
            u8,
            &current.next_parent_vk_sha256,
            &next.verification_key_sha256,
        ) or !std.meta.eql(
            current.parent_proof_security,
            next.admitted_child_security,
        )) return error.InvalidProfilePlanTransport;
        if (!std.mem.eql(
            u8,
            &self.profile_plan_sha256,
            &planIdentity(self),
        )) return error.InvalidProfilePlanTransport;
    }

    pub fn validateAgainst(
        self: *const ProfilePlanTransportV1,
        plan: *const plan_mod.ProfilePlanV1,
    ) !void {
        try self.validate();
        try plan.validate();
        const expected = try ProfilePlanTransportV1.initUnchecked(plan);
        if (!std.meta.eql(self.*, expected))
            return error.ProfilePlanTransportMismatch;
    }

    fn initUnchecked(
        plan: *const plan_mod.ProfilePlanV1,
    ) !ProfilePlanTransportV1 {
        var result: ProfilePlanTransportV1 = undefined;
        result.format_version = FORMAT_VERSION;
        result.schema_version = SCHEMA_VERSION;
        result.entries[0] = try entryFromProfile(0, .real_h1, &plan.real_h1);
        result.entries[1] = try entryFromProfile(1, .empty_h1, &plan.empty_h1);
        for (&plan.upper, 0..) |*profile, index|
            result.entries[index + 2] = try entryFromProfile(
                @intCast(index + 2),
                .upper,
                profile,
            );
        result.profile_plan_sha256 = planIdentity(&result);
        return result;
    }
};

/// Canonical newline-terminated JSON. All digest values are lowercase SHA-256
/// hexadecimal strings; no native M31 limb array enters this transport.
pub fn encodeCanonicalJson(
    allocator: std.mem.Allocator,
    value: *const ProfilePlanTransportV1,
) ![]u8 {
    try value.validate();
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    const writer = output.writer(allocator);
    try writer.writeAll("{\"entries\":[");
    for (&value.entries, 0..) |*entry, index| {
        if (index != 0) try writer.writeByte(',');
        try writeEntry(writer, entry);
    }
    const plan_hex = hex(value.profile_plan_sha256);
    try writer.print(
        "],\"format_version\":{d},\"profile_plan_sha256\":\"{s}\",\"schema\":\"{s}\",\"schema_version\":{d}}}\n",
        .{ value.format_version, &plan_hex, SCHEMA, value.schema_version },
    );
    return output.toOwnedSlice(allocator);
}

pub fn nativeDigestSha256(value: [8]u32) ![32]u8 {
    var hash = Sha256.init(.{});
    hash.update(NATIVE_DIGEST_DOMAIN);
    var nonzero = false;
    for (value) |word| {
        if (word >= @import("stwo_core").fields.m31.Modulus)
            return error.InvalidProfilePlanTransport;
        nonzero = nonzero or word != 0;
        hashInt(&hash, u32, word);
    }
    if (!nonzero) return error.InvalidProfilePlanTransport;
    return hash.finalResult();
}

fn entryFromProfile(
    ordinal: u8,
    kind: EntryKindV1,
    profile: *const node_profile.NodeProfileV1,
) !EntryV1 {
    try profile.validate();
    const expected_kind: node_profile.KindV1 = switch (kind) {
        .real_h1 => .real_parent_h1,
        .empty_h1 => .empty_parent_h1,
        .upper => .recursive_parent,
    };
    if (profile.kind != expected_kind) return error.InvalidProfilePlanTransport;
    var result = EntryV1{
        .ordinal = ordinal,
        .kind = kind,
        .parent_height = profile.parent_height,
        .node_profile_sha256 = profile.identity,
        .verification_key_sha256 = try nativeDigestSha256(
            profile.verification_key_id,
        ),
        .next_parent_vk_sha256 = try nativeDigestSha256(
            profile.next_parent_vk_id,
        ),
        .child_composition_manifest_sha256 = profile.child_composition_manifest_sha_id,
        .parent_outer_manifest_sha256 = profile.manifest_sha_id,
        .air_program_sha256 = try nativeDigestSha256(profile.air_program_id),
        .air_profile_sha256 = try nativeDigestSha256(profile.profile_id),
        .admitted_child_security = profile.admitted_child_security,
        .parent_proof_security = profile.parent_proof_security,
        .transcript = try TranscriptProjectionV1.init(profile.transcript),
        .entry_sha256 = undefined,
    };
    result.entry_sha256 = entryIdentity(&result);
    try result.validate();
    return result;
}

fn writeEntry(writer: anytype, entry: *const EntryV1) !void {
    const air_program = hex(entry.air_program_sha256);
    const air_profile = hex(entry.air_profile_sha256);
    const entry_id = hex(entry.entry_sha256);
    const child_composition_manifest =
        hex(entry.child_composition_manifest_sha256);
    const parent_outer_manifest = hex(entry.parent_outer_manifest_sha256);
    const next_vk = hex(entry.next_parent_vk_sha256);
    const node_profile_id = hex(entry.node_profile_sha256);
    const transcript_id = hex(entry.transcript.identity_sha256);
    const verification_key = hex(entry.verification_key_sha256);
    try writer.print(
        "{{\"admitted_child_security\":",
        .{},
    );
    try writeSecurity(writer, &entry.admitted_child_security);
    try writer.print(
        ",\"air_profile_sha256\":\"{s}\",\"air_program_sha256\":\"{s}\",\"child_composition_manifest_sha256\":\"{s}\",\"entry_kind\":\"{s}\",\"entry_sha256\":\"{s}\",\"next_parent_vk_sha256\":\"{s}\",\"node_profile_sha256\":\"{s}\",\"ordinal\":{d},\"parent_height\":{d},\"parent_outer_manifest_sha256\":\"{s}\",\"parent_proof_security\":",
        .{
            &air_profile,
            &air_program,
            &child_composition_manifest,
            entryKindName(entry.kind),
            &entry_id,
            &next_vk,
            &node_profile_id,
            entry.ordinal,
            entry.parent_height,
            &parent_outer_manifest,
        },
    );
    try writeSecurity(writer, &entry.parent_proof_security);
    try writer.print(
        ",\"transcript\":{{\"cohort_format_version\":{d},\"cohort_schema_version\":{d},\"component_count\":{d},\"domain\":{d},\"format_version\":{d},\"identity_sha256\":\"{s}\",\"kind\":\"{s}\",\"schema_version\":{d}}},\"verification_key_sha256\":\"{s}\"}}",
        .{
            entry.transcript.cohort_format_version,
            entry.transcript.cohort_schema_version,
            entry.transcript.component_count,
            entry.transcript.domain,
            entry.transcript.format_version,
            &transcript_id,
            transcriptKindName(entry.transcript.kind),
            entry.transcript.schema_version,
            &verification_key,
        },
    );
}

fn writeSecurity(writer: anytype, value: *const security_mod.ProofSecurityV1) !void {
    const identity = hex(value.identity);
    try writer.print(
        "{{\"configured_pcs_bits\":{d},\"conjectured_security_bits\":{d},\"field_id\":{d},\"format_version\":{d},\"fri_fold_step\":{d},\"fri_log_blowup_factor\":{d},\"fri_log_last_layer_degree_bound\":{d},\"fri_query_count\":{d},\"hash_suite\":\"{s}\",\"identity_sha256\":\"{s}\",\"interaction_pow_bits\":{d},\"kind\":\"{s}\",\"pcs_lifting_mode\":{d},\"pcs_pow_bits\":{d},\"proof_present\":{s},\"recursive_ingress\":\"{s}\",\"schema_version\":{d}}}",
        .{
            value.configured_pcs_bits,
            value.conjectured_security_bits,
            value.field_id,
            value.format_version,
            value.fri_fold_step,
            value.fri_log_blowup_factor,
            value.fri_log_last_layer_degree_bound,
            value.fri_query_count,
            hashSuiteName(value.hash_suite),
            &identity,
            value.interaction_pow_bits,
            securityKindName(value.kind),
            value.pcs_lifting_mode,
            value.pcs_pow_bits,
            if (value.proof_present) "true" else "false",
            ingressName(value.recursive_ingress),
            value.schema_version,
        },
    );
}

fn transcriptIdentity(value: *const TranscriptProjectionV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(TRANSCRIPT_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromEnum(value.kind));
    hashInt(&hash, u32, value.domain);
    hashInt(&hash, u16, value.cohort_format_version);
    hashInt(&hash, u16, value.cohort_schema_version);
    hashInt(&hash, u16, value.component_count);
    return hash.finalResult();
}

fn entryIdentity(value: *const EntryV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(ENTRY_DOMAIN);
    hashInt(&hash, u8, value.ordinal);
    hashInt(&hash, u8, @intFromEnum(value.kind));
    hashInt(&hash, u8, value.parent_height);
    hash.update(&value.node_profile_sha256);
    hash.update(&value.verification_key_sha256);
    hash.update(&value.next_parent_vk_sha256);
    hash.update(&value.child_composition_manifest_sha256);
    hash.update(&value.parent_outer_manifest_sha256);
    hash.update(&value.air_program_sha256);
    hash.update(&value.air_profile_sha256);
    hash.update(&value.admitted_child_security.identity);
    hash.update(&value.parent_proof_security.identity);
    hash.update(&value.transcript.identity_sha256);
    return hash.finalResult();
}

fn planIdentity(value: *const ProfilePlanTransportV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(PLAN_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, ENTRY_COUNT);
    for (value.entries) |entry| hash.update(&entry.entry_sha256);
    return hash.finalResult();
}

fn hex(value: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(value, .lower);
}

fn entryKindName(value: EntryKindV1) []const u8 {
    return switch (value) {
        .real_h1 => "real_h1",
        .empty_h1 => "empty_h1",
        .upper => "upper",
    };
}

fn transcriptKindName(value: transcript_mod.Kind) []const u8 {
    return switch (value) {
        .temporal_parent_v3 => "temporal_parent_v3",
        .empty_parent_v1 => "empty_parent_v1",
        .recursive_node_v1 => "recursive_node_v1",
    };
}

fn securityKindName(value: security_mod.KindV1) []const u8 {
    return @tagName(value);
}

fn hashSuiteName(value: security_mod.HashSuiteV1) []const u8 {
    return @tagName(value);
}

fn ingressName(value: security_mod.RecursiveIngressV1) []const u8 {
    return @tagName(value);
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 1 or SCHEMA_VERSION != 2 or ENTRY_COUNT != 9)
        @compileError("temporal ProfilePlan transport geometry drifted");
}
