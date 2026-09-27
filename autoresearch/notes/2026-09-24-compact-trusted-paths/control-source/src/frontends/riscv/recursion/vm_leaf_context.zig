//! Transactionally captured inputs for native VM-AIR composition replay.
//!
//! A successful core proof capture authenticates the openings and transcript
//! challenges, but the frozen V1 wire intentionally carries only canonical
//! aggregate LogUp claims. Row 18 needs the shard-local claims consumed by the
//! native component evaluators. This owned sidecar is constructed inside the
//! production verifier, from the exact admitted statement, canonical claim,
//! relation draws, and verifier component slice. No proof-byte decoder can
//! populate it.

const std = @import("std");
const stwo_core = @import("stwo_core");
const core_components = stwo_core.air.components;
const m31 = stwo_core.fields.m31;
const QM31 = stwo_core.fields.qm31.QM31;
const relation_challenges = @import("../air/relation_challenges.zig");
const component_order = @import("../air/component_order.zig");
const opcode_entries = @import("../air/lookups/opcode_entries.zig");
const semantic_eval = @import("../air/semantic_eval.zig");
const statement_mod = @import("../air/statement.zig");
const transcript_claims = @import("../air/transcript/claims.zig");
const trace_mod = @import("../runner/trace.zig");
const vm_air_profile = @import("vm_air_profile.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const SCHEMA_VERSION: u16 = 1;
pub const CONTEXT_DOMAIN = "stwo-zig/riscv/recursion/vm-leaf-context/v1\x00";

pub const Error = std.mem.Allocator.Error || vm_air_profile.Error || error{
    ContextDigestMismatch,
    InvalidComponentDescriptor,
    InvalidContextCounts,
    InvalidDescriptorShape,
    InvalidInfraDescriptor,
    InvalidRelationDraw,
};

/// Owned, compact verifier output. Fixed-capacity statement/claim slack is
/// deliberately not retained: only active descriptors and detailed sums cross
/// the native-to-recursive trust boundary.
pub const Context = struct {
    allocator: std.mem.Allocator,
    schema_version: u16,
    profile: vm_air_profile.Profile,
    component_descs: []statement_mod.FamilyComponentDesc,
    infra_descs: []statement_mod.InfraComponentDesc,
    detailed_claims: []QM31,
    /// The exact 28-word transcript claim vector derived from
    /// `detailed_claims`. Keeping this verifier-produced projection beside
    /// the detailed sequence gives the recursive composition graph a single
    /// source for its aggregate-consistency constraints.
    canonical_claims: [transcript_claims.COMPONENT_COUNT]QM31,
    relation_draws: [relation_challenges.DRAW_COUNT]QM31,
    identity_digest: [Sha256.digest_length]u8,

    pub fn initVerified(
        allocator: std.mem.Allocator,
        statement: *const statement_mod.RiscVStatement,
        claim: *const statement_mod.RiscVInteractionClaim,
        relations: *const relation_challenges.Relations,
        components: []const core_components.Component,
    ) Error!Context {
        const profile = try vm_air_profile.derive(statement, components);
        return initWithProfile(allocator, statement, claim, relations, profile);
    }

    fn initWithProfile(
        allocator: std.mem.Allocator,
        statement: *const statement_mod.RiscVStatement,
        claim: *const statement_mod.RiscVInteractionClaim,
        relations: *const relation_challenges.Relations,
        profile: vm_air_profile.Profile,
    ) Error!Context {
        try profile.validate();
        const component_descs = try allocator.dupe(
            statement_mod.FamilyComponentDesc,
            statement.component_descs[0..statement.n_components],
        );
        errdefer allocator.free(component_descs);
        const infra_descs = try allocator.dupe(
            statement_mod.InfraComponentDesc,
            statement.infra_descs[0..statement.n_infra],
        );
        errdefer allocator.free(infra_descs);
        const detailed_claims = try allocator.alloc(QM31, profile.claimed_sum_count);
        errdefer allocator.free(detailed_claims);
        try vm_air_profile.writeDetailedClaims(statement, claim, detailed_claims);
        const canonical_claims = try deriveCanonicalClaims(
            component_descs,
            infra_descs,
            detailed_claims,
        );

        var relation_draws: [relation_challenges.DRAW_COUNT]QM31 = undefined;
        try relations.writeDraws(&relation_draws);
        var result = Context{
            .allocator = allocator,
            .schema_version = SCHEMA_VERSION,
            .profile = profile,
            .component_descs = component_descs,
            .infra_descs = infra_descs,
            .detailed_claims = detailed_claims,
            .canonical_claims = canonical_claims,
            .relation_draws = relation_draws,
            .identity_digest = undefined,
        };
        try result.validateShape();
        result.identity_digest = result.computeIdentityDigest();
        return result;
    }

    pub fn deinit(self: *Context) void {
        self.allocator.free(self.detailed_claims);
        self.allocator.free(self.infra_descs);
        self.allocator.free(self.component_descs);
        self.* = undefined;
    }

    /// Revalidates all mutable storage before recursive witness emission.
    pub fn validate(self: *const Context) Error!void {
        try self.validateShape();
        const actual = self.computeIdentityDigest();
        if (!std.mem.eql(u8, &actual, &self.identity_digest))
            return error.ContextDigestMismatch;
    }

    fn validateShape(self: *const Context) Error!void {
        if (self.schema_version != SCHEMA_VERSION) return error.InvalidDescriptorShape;
        try self.profile.validate();
        if (self.component_descs.len == 0 or
            self.component_descs.len > statement_mod.MAX_COMPONENTS or
            self.infra_descs.len == 0 or
            self.infra_descs.len > statement_mod.MAX_INFRA_COMPONENTS or
            self.profile.component_count !=
                2 * self.component_descs.len + self.infra_descs.len or
            self.detailed_claims.len != self.profile.claimed_sum_count or
            self.profile.relation_challenge_count != relation_challenges.RELATION_COUNT)
        {
            return error.InvalidContextCounts;
        }
        for (self.component_descs) |descriptor| {
            if (!semantic_eval.isTraceCompatible(descriptor.family) or
                descriptor.log_size == 0 or descriptor.log_size >= 31 or
                descriptor.n_rows == 0 or
                descriptor.n_rows > (@as(u32, 1) << @intCast(descriptor.log_size)) or
                descriptor.n_columns != trace_mod.nColumnsForFamily(descriptor.family))
            {
                return error.InvalidComponentDescriptor;
            }
        }
        for (self.infra_descs) |descriptor| {
            // Empty dynamic provider traces are represented by a fully padded
            // minimum-size component.  This is canonical for Merkle,
            // Poseidon, and clock-update providers and is already admitted by
            // the production statement validator. Program, memory, and fixed
            // lookup-table components must remain non-empty.
            const empty_dynamic_provider = switch (descriptor.kind) {
                .merkle, .poseidon2, .clock_update => true,
                else => false,
            };
            if (descriptor.log_size == 0 or descriptor.log_size >= 31 or
                (descriptor.n_rows == 0 and !empty_dynamic_provider) or
                descriptor.n_rows > (@as(u32, 1) << @intCast(descriptor.log_size)) or
                descriptor.n_columns == 0)
            {
                return error.InvalidInfraDescriptor;
            }
        }
        for (self.detailed_claims) |value| try validateQm31(value);
        const canonical_claims = try deriveCanonicalClaims(
            self.component_descs,
            self.infra_descs,
            self.detailed_claims,
        );
        for (self.canonical_claims, canonical_claims) |actual, expected| {
            try validateQm31(actual);
            if (!actual.eql(expected)) return error.ContextDigestMismatch;
        }
        for (self.relation_draws) |value| validateQm31(value) catch
            return error.InvalidRelationDraw;
    }

    fn computeIdentityDigest(self: *const Context) [Sha256.digest_length]u8 {
        var hash = Sha256.init(.{});
        hash.update(CONTEXT_DOMAIN);
        hashInt(&hash, u16, self.schema_version);
        hashProfile(&hash, self.profile);
        hashInt(&hash, u32, @intCast(self.component_descs.len));
        for (self.component_descs) |descriptor| {
            hashInt(&hash, u8, @intFromEnum(descriptor.family));
            hashInt(&hash, u32, descriptor.log_size);
            hashInt(&hash, u32, descriptor.n_rows);
            hashInt(&hash, u32, descriptor.n_columns);
        }
        hashInt(&hash, u32, @intCast(self.infra_descs.len));
        for (self.infra_descs) |descriptor| {
            hashInt(&hash, u32, @intFromEnum(descriptor.kind));
            hashInt(&hash, u32, descriptor.log_size);
            hashInt(&hash, u32, descriptor.n_rows);
            hashInt(&hash, u32, descriptor.n_columns);
        }
        hashInt(&hash, u32, @intCast(self.detailed_claims.len));
        for (self.detailed_claims) |value| hashQm31(&hash, value);
        hashInt(&hash, u32, self.canonical_claims.len);
        for (self.canonical_claims) |value| hashQm31(&hash, value);
        hashInt(&hash, u32, @intCast(self.relation_draws.len));
        for (self.relation_draws) |value| hashQm31(&hash, value);
        return hash.finalResult();
    }
};

/// Derive the transcript's fixed 28 aggregate claims from the exact detailed
/// sequence consumed by native component verification. This is deliberately
/// allocation-free and declaration ordered; both native leaf ingestion and
/// recursive graph construction use the retained result above.
fn deriveCanonicalClaims(
    component_descs: []const statement_mod.FamilyComponentDesc,
    infra_descs: []const statement_mod.InfraComponentDesc,
    detailed_claims: []const QM31,
) Error![transcript_claims.COMPONENT_COUNT]QM31 {
    var result = [_]QM31{QM31.zero()} ** transcript_claims.COMPONENT_COUNT;
    var cursor: usize = 0;
    for (component_descs) |descriptor| {
        const count = opcode_entries.batchCount(descriptor.family);
        const end = std.math.add(usize, cursor, count) catch
            return error.InvalidContextCounts;
        if (end > detailed_claims.len) return error.InvalidContextCounts;
        const component = component_order.transcriptComponentForOpcodeFamily(
            descriptor.family,
        );
        for (detailed_claims[cursor..end]) |value| {
            result[@intFromEnum(component)] =
                result[@intFromEnum(component)].add(value);
        }
        cursor = end;
    }
    for (infra_descs) |descriptor| {
        const count = statement_mod.nClaimedSumsForInfra(descriptor.kind);
        const end = std.math.add(usize, cursor, count) catch
            return error.InvalidContextCounts;
        if (end > detailed_claims.len) return error.InvalidContextCounts;
        const component = transcriptComponentForInfra(descriptor.kind);
        for (detailed_claims[cursor..end]) |value| {
            result[@intFromEnum(component)] =
                result[@intFromEnum(component)].add(value);
        }
        cursor = end;
    }
    if (cursor != detailed_claims.len) return error.InvalidContextCounts;
    return result;
}

fn transcriptComponentForInfra(
    kind: statement_mod.InfraKind,
) transcript_claims.Component {
    return switch (kind) {
        .program => .program,
        .memory => .memory,
        .merkle => .merkle,
        .poseidon2 => .poseidon2,
        .clock_update => .clock_update,
        .bitwise => .bitwise,
        .range_check_20 => .range_check_20,
        .range_check_8_11 => .range_check_8_11,
        .range_check_8_8_4 => .range_check_8_8_4,
        .range_check_8_8 => .range_check_8_8,
        .range_check_m31 => .range_check_m31,
    };
}

fn hashProfile(hash: *Sha256, profile: vm_air_profile.Profile) void {
    hashInt(hash, u16, profile.schema_version);
    hashInt(hash, u32, profile.component_count);
    hashInt(hash, u32, profile.air_instruction_count);
    hashInt(hash, u32, profile.claimed_sum_count);
    hashInt(hash, u32, profile.relation_challenge_count);
    hashInt(hash, u32, profile.composition_log_split);
    hashInt(hash, u32, profile.composition_log_degree_bound);
    hashInt(hash, u32, profile.max_log_degree_bound);
    hash.update(&profile.manifest_digest);
}

fn hashQm31(hash: *Sha256, value: QM31) void {
    for (value.toM31Array()) |limb| hashInt(hash, u32, limb.toU32());
}

fn validateQm31(value: QM31) error{InvalidRelationDraw}!void {
    for (value.toM31Array()) |limb| {
        if (limb.toU32() >= m31.Modulus) return error.InvalidRelationDraw;
    }
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

/// Narrow facts seam used only by compile-isolated mutation tests. Production
/// construction always derives the profile from native verifier vtables.
pub const testing = struct {
    pub fn initFromProfile(
        allocator: std.mem.Allocator,
        statement: *const statement_mod.RiscVStatement,
        claim: *const statement_mod.RiscVInteractionClaim,
        relations: *const relation_challenges.Relations,
        profile: vm_air_profile.Profile,
    ) Error!Context {
        return Context.initWithProfile(allocator, statement, claim, relations, profile);
    }
};
