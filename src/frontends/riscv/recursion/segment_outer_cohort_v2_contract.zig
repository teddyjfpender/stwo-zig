//! Internal segment outer cohort v2 authority shard; use segment_outer_cohort_v2.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");

pub const M31 = stwo_core.fields.m31.M31;
pub const QM31 = stwo_core.fields.qm31.QM31;

pub const digest = @import("../air/lang/digest.zig");
pub const relation = @import("../air/lang/relation.zig");
pub const manifest_mod = @import("air/segment_outer_adapter_manifest_v2.zig");
pub const catalog_mod = @import("air/segment_outer_typed_catalog_v2.zig");
pub const roster = @import("air/universal_roster.zig");
pub const universal = @import("air/universal_challenges.zig");
pub const relation_interaction = @import("air/relation_interaction.zig");

// These imports deliberately make landed implementation surfaces part of the
// compile-time contract without treating their current `PRODUCTION_ACTIVATION`
// flags as stronger evidence than they are.
pub const transcript_components = @import("segment_transcript_outer_components_v2.zig");
pub const transcript_source = @import("segment_transcript_outer_source_v2.zig");
pub const statement_source = @import("segment_statement_outer_source_v2.zig");
pub const statement_components = @import("segment_statement_outer_components_v2.zig");
pub const public_components = @import("segment_public_outer_components_v2.zig");
pub const range_authority = @import("segment_range_authority_v2.zig");
pub const shared_schedule = @import("segment_shared_poseidon_schedule_v2.zig");
pub const boundary_components = @import("air/segment_boundary_components_v2.zig");
pub const verifier_input_provider =
    @import("air/segment_publication_input_provider_component_v2.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const ROSTER_FORMAT_VERSION: u16 = 1;
pub const TREE_PLAN_FORMAT_VERSION: u16 = 1;
pub const PROVIDER_SCHEDULE_FORMAT_VERSION: u16 = 1;
pub const GATE_RECEIPT_FORMAT_VERSION: u16 = 1;
pub const CLOSURE_RECEIPT_FORMAT_VERSION: u16 = 1;
pub const PUBLIC_WIRE_BOUNDARY_FORMAT_VERSION: u16 = 1;
pub const READINESS_RECEIPT_FORMAT_VERSION: u16 = 1;

pub const COMPONENT_COUNT: usize = manifest_mod.COMPONENT_COUNT;
pub const DOMAIN_COUNT: usize = universal.RELATION_COUNT;
pub const TREE_COUNT: usize = manifest_mod.TREE_COUNT;
pub const ALL_COMPONENT_MASK: u64 = rangeMask(0, COMPONENT_COUNT);
pub const ALL_DOMAIN_MASK: u64 = rangeMask(0, DOMAIN_COUNT);

pub const TRANSCRIPT_ROWS_MASK: u64 = rangeMask(0, 10);
pub const STATEMENT_ROWS_MASK: u64 = rangeMask(10, 12);
pub const PUBLIC_ROWS_MASK: u64 = rangeMask(12, 18);
pub const CORE_ROWS_MASK: u64 = rangeMask(18, 35);
pub const RANGE_ROW_MASK: u64 = componentBit(35);
pub const BOUNDARY_ROWS_MASK: u64 = rangeMask(36, 38);
pub const VERIFIER_INPUT_PROVIDER_ROW_MASK: u64 = componentBit(38);

pub const ROW_34: u8 = @intFromEnum(roster.Component.poseidon2);
pub const ROW_35: u8 = @intFromEnum(roster.Component.range_check_8_8);
pub const ROW_10: u8 = @intFromEnum(roster.Component.statement_input);

/// Measured canonical SegmentV2 ingress. These are measurement evidence, not
/// protocol constants: admission derives counts from the authenticated shared
/// layout and validates the resulting minimal log size.
pub const MEASURED_TRANSCRIPT_POSEIDON_CALLS: u32 = 885;
pub const MEASURED_AUTHORITY_POSEIDON_CALLS: u32 = 14;
pub const MEASURED_CORE_POSEIDON_CALLS: u32 = 294;
pub const MEASURED_TOTAL_POSEIDON_CALLS: u32 = 1_193;
pub const MEASURED_POSEIDON_LOG_SIZE: u32 = 11;

pub const HOT_ASSEMBLY_HEAP_ALLOCATIONS: usize = 0;
pub const HOT_VALIDATION_HEAP_ALLOCATIONS: usize = 0;
pub const HOT_IDENTITY_HEAP_ALLOCATIONS: usize = 0;
pub const FAILS_BEFORE_FIRST_EXTERNAL_WRITE = true;
pub const PRODUCTION_ACTIVATION = false;

pub const PLAN_ID_DOMAIN =
    "stwo-zig/typed-air/segment-v2-cohort-plan/v1\x00";
pub const ROSTER_ID_DOMAIN =
    "stwo-zig/typed-air/segment-v2-cohort-roster/v1\x00";
pub const TREE_PLAN_ID_DOMAIN =
    "stwo-zig/typed-air/segment-v2-cohort-tree-plan/v1\x00";
pub const CAPABILITY_ID_DOMAIN =
    "stwo-zig/typed-air/segment-v2-cohort-capabilities/v1\x00";
pub const GATE_RECEIPT_ID_DOMAIN =
    "stwo-zig/typed-air/segment-v2-cohort-gate/v1\x00";
pub const CLOSURE_RECEIPT_ID_DOMAIN =
    "stwo-zig/typed-air/segment-v2-cohort-closure/v1\x00";
pub const AUDIT_ID_DOMAIN =
    "stwo-zig/typed-air/segment-v2-cohort-audits/v1\x00";
pub const PUBLIC_WIRE_BOUNDARY_ID_DOMAIN =
    "stwo-zig/typed-air/segment-v2-public-wire-boundary/v1\x00";
pub const BOUNDARY_AUDIT_ID_DOMAIN =
    "stwo-zig/typed-air/segment-v2-boundary-audits/v1\x00";
pub const READINESS_RECEIPT_ID_DOMAIN =
    "stwo-zig/typed-air/segment-v2-cohort-readiness/v1\x00";
pub const CLOSURE_DIAGNOSTIC_ENV =
    "STWO_RECURSION_OUTER_SCALAR_CLOSURE_DIAGNOSTIC";

pub const Error = manifest_mod.Error || catalog_mod.Error || error{
    ArithmeticOverflow,
    CapabilityEscalation,
    ClaimMismatch,
    ClosureIdentityMismatch,
    CohortIdentityMismatch,
    ComponentCoverageMismatch,
    DomainOrderMismatch,
    GateIdentityMismatch,
    InvalidAuditGeometry,
    InvalidProviderSchedule,
    NonCanonicalField,
    ProductionReadinessUnavailable,
    PublicWireBoundaryMismatch,
    ProviderDomainMismatch,
    RelationNotClosed,
    RosterIdentityMismatch,
    SourceManifestMismatch,
    TreeAccountingMismatch,
    TreePlanIdentityMismatch,
};

pub const RowAuthority = enum(u8) {
    transcript_v2 = 1,
    statement_v2 = 2,
    public_v2 = 3,
    core_universal_v1_identity = 4,
    range_v2 = 5,
    boundary_v2 = 6,
    verifier_input_provider_v2 = 7,
};

pub const RosterPlanV2 = struct {
    format_version: u16 = ROSTER_FORMAT_VERSION,
    component_count: u8 = COMPONENT_COUNT,
    row_mask: u64 = ALL_COMPONENT_MASK,
    authorities: [COMPONENT_COUNT]RowAuthority,
    catalog_identity: digest.Digest,
    manifest_seal: digest.Digest,
    identity: digest.Digest,

    pub fn init(manifest: *const manifest_mod.Manifest) Error!RosterPlanV2 {
        try manifest.validate();
        var result = RosterPlanV2{
            .authorities = undefined,
            .catalog_identity = manifest.catalog_identity,
            .manifest_seal = manifest.seal,
            .identity = undefined,
        };
        for (&result.authorities, 0..) |*authority, row|
            authority.* = rowAuthority(@intCast(row));
        result.identity = rosterIdentity(&result);
        try result.validateAgainst(manifest);
        return result;
    }

    pub fn validateAgainst(
        self: *const RosterPlanV2,
        manifest: *const manifest_mod.Manifest,
    ) Error!void {
        try manifest.validate();
        if (self.format_version != ROSTER_FORMAT_VERSION or
            self.component_count != COMPONENT_COUNT or
            self.row_mask != ALL_COMPONENT_MASK or
            !std.mem.eql(u8, &self.catalog_identity, &manifest.catalog_identity) or
            !std.mem.eql(u8, &self.manifest_seal, &manifest.seal))
        {
            return error.RosterIdentityMismatch;
        }
        for (self.authorities, 0..) |authority, row| {
            if (authority != rowAuthority(@intCast(row)) or
                manifest.roster_rows[row] != row or
                manifest.placements[row] == null or
                manifest.placements[row].?.claimed_sum_index != row)
            {
                return error.ComponentCoverageMismatch;
            }
        }
        if (!std.mem.eql(u8, &self.identity, &rosterIdentity(self)))
            return error.RosterIdentityMismatch;
    }
};

pub const RowTreeGeometryV2 = struct {
    log_size: u32,
    offsets: [TREE_COUNT]u32,
    columns: [TREE_COUNT]u16,
};

pub const TreePlanV2 = struct {
    format_version: u16 = TREE_PLAN_FORMAT_VERSION,
    component_count: u8 = COMPONENT_COUNT,
    tree_count: u8 = TREE_COUNT,
    padding: u8 = 0,
    manifest_seal: digest.Digest,
    rows: [COMPONENT_COUNT]RowTreeGeometryV2,
    total_columns: [TREE_COUNT]u32,
    identity: digest.Digest,

    pub fn init(manifest: *const manifest_mod.Manifest) Error!TreePlanV2 {
        try manifest.validate();
        var result = TreePlanV2{
            .manifest_seal = manifest.seal,
            .rows = undefined,
            .total_columns = .{
                manifest.total_preprocessed_columns,
                manifest.total_main_columns,
                manifest.total_interaction_columns,
            },
            .identity = undefined,
        };
        for (&result.rows, 0..) |*row, index| {
            const placement = manifest.placements[index].?;
            row.* = .{
                .log_size = placement.geometry.log_size,
                .offsets = .{
                    placement.preprocessed_offset,
                    placement.main_offset,
                    placement.interaction_offset,
                },
                .columns = .{
                    placement.geometry.preprocessed_columns,
                    placement.geometry.main_columns,
                    placement.geometry.interaction_columns,
                },
            };
        }
        result.identity = treePlanIdentity(&result);
        try result.validateAgainst(manifest);
        return result;
    }

    pub fn validateAgainst(
        self: *const TreePlanV2,
        manifest: *const manifest_mod.Manifest,
    ) Error!void {
        try manifest.validate();
        if (self.format_version != TREE_PLAN_FORMAT_VERSION or
            self.component_count != COMPONENT_COUNT or
            self.tree_count != TREE_COUNT or self.padding != 0 or
            !std.mem.eql(u8, &self.manifest_seal, &manifest.seal))
        {
            return error.TreeAccountingMismatch;
        }
        var next = [_]u32{0} ** TREE_COUNT;
        for (self.rows, 0..) |row, index| {
            const placement = manifest.placements[index].?;
            const expected = RowTreeGeometryV2{
                .log_size = placement.geometry.log_size,
                .offsets = .{
                    placement.preprocessed_offset,
                    placement.main_offset,
                    placement.interaction_offset,
                },
                .columns = .{
                    placement.geometry.preprocessed_columns,
                    placement.geometry.main_columns,
                    placement.geometry.interaction_columns,
                },
            };
            if (!std.meta.eql(row, expected) or !std.meta.eql(row.offsets, next))
                return error.TreeAccountingMismatch;
            inline for (0..TREE_COUNT) |tree|
                next[tree] = try checkedAdd(next[tree], row.columns[tree]);
        }
        if (!std.meta.eql(self.total_columns, next) or
            self.total_columns[0] != manifest.total_preprocessed_columns or
            self.total_columns[1] != manifest.total_main_columns or
            self.total_columns[2] != manifest.total_interaction_columns)
        {
            return error.TreeAccountingMismatch;
        }
        if (!std.mem.eql(u8, &self.identity, &treePlanIdentity(self)))
            return error.TreePlanIdentityMismatch;
    }
};

pub const ProviderOrigin = enum(u8) {
    transcript = 0,
    authority = 1,
    core = 2,
};

pub const ProviderRangeV2 = struct {
    origin: ProviderOrigin,
    first: u32,
    count: u32,

    pub fn end(self: ProviderRangeV2) Error!u32 {
        return checkedAdd(self.first, self.count);
    }
};

pub const ProviderCallCountsV2 = struct {
    transcript: u32,
    authority: u32,
    core: u32,

    pub fn measuredCanonical() ProviderCallCountsV2 {
        return .{
            .transcript = MEASURED_TRANSCRIPT_POSEIDON_CALLS,
            .authority = MEASURED_AUTHORITY_POSEIDON_CALLS,
            .core = MEASURED_CORE_POSEIDON_CALLS,
        };
    }

    pub fn fromLayout(
        layout: *const shared_schedule.SharedPoseidonCallLayoutV2,
    ) Error!ProviderCallCountsV2 {
        layout.validateReceipt() catch return error.InvalidProviderSchedule;
        return .{
            .transcript = std.math.cast(
                u32,
                layout.transcript.count() catch
                    return error.InvalidProviderSchedule,
            ) orelse return error.ArithmeticOverflow,
            .authority = std.math.cast(
                u32,
                layout.statement_authority.count() catch
                    return error.InvalidProviderSchedule,
            ) orelse return error.ArithmeticOverflow,
            .core = std.math.cast(
                u32,
                layout.verifier_core.count() catch
                    return error.InvalidProviderSchedule,
            ) orelse return error.ArithmeticOverflow,
        };
    }
};

/// One contiguous provider instance, with three non-overlapping source-owned
/// ranges. It never permits separate row-34 components or corrective claims.
pub const ProviderScheduleV2 = struct {
    format_version: u16 = PROVIDER_SCHEDULE_FORMAT_VERSION,
    component_index: u8 = ROW_34,
    provider_instance_count: u8 = 1,
    source_count: u8 = 3,
    log_size: u32,
    logical_call_count: u32,
    ranges: [3]ProviderRangeV2,
    manifest_seal: digest.Digest,
    semantic_digest: digest.Digest,
    /// The sole ordering/buffer identity. This is embedded verbatim instead
    /// of independently re-hashing a second cohort schedule receipt.
    shared_layout: shared_schedule.SharedPoseidonCallLayoutV2,

    /// Admits the already-authenticated CPU ingress layout without importing
    /// the integration layer back into the frontend.  The layout's own
    /// `validate(calls)` is invoked first; then every half-open range is
    /// compared with this row-34 proof geometry. This is a consumer of that
    /// receipt, not an alternate call-order authority.
    pub fn initFromAuthenticatedLayout(
        manifest: *const manifest_mod.Manifest,
        layout: *const shared_schedule.SharedPoseidonCallLayoutV2,
        calls: []const shared_schedule.Call,
    ) Error!ProviderScheduleV2 {
        layout.validate(calls) catch return error.SourceManifestMismatch;
        if (!layout.call_set_complete or
            !layout.verifier_core_range_populated or
            layout.transcript.start != 0 or
            layout.transcript.end != layout.statement_authority.start or
            layout.statement_authority.end != layout.verifier_core.start or
            layout.verifier_core.end != layout.total_call_count or
            layout.total_call_count != calls.len)
        {
            return error.InvalidProviderSchedule;
        }
        const counts = try ProviderCallCountsV2.fromLayout(layout);
        const transcript_end = try checkedAdd(@as(u32, 0), counts.transcript);
        const authority_end = try checkedAdd(transcript_end, counts.authority);
        const total = try checkedAdd(authority_end, counts.core);
        const placement = manifest.placements[ROW_34].?;
        const result = ProviderScheduleV2{
            .log_size = placement.geometry.log_size,
            .logical_call_count = total,
            .ranges = .{
                .{ .origin = .transcript, .first = 0, .count = counts.transcript },
                .{ .origin = .authority, .first = transcript_end, .count = counts.authority },
                .{ .origin = .core, .first = authority_end, .count = counts.core },
            },
            .manifest_seal = manifest.seal,
            .semantic_digest = placement.geometry.semantic_digest,
            .shared_layout = layout.*,
        };
        if (result.ranges[0].first != layout.transcript.start or
            try result.ranges[0].end() != layout.transcript.end or
            result.ranges[1].first != layout.statement_authority.start or
            try result.ranges[1].end() != layout.statement_authority.end or
            result.ranges[2].first != layout.verifier_core.start or
            try result.ranges[2].end() != layout.verifier_core.end)
        {
            return error.InvalidProviderSchedule;
        }
        try result.validateAgainst(manifest);
        return result;
    }

    pub fn validateAgainst(
        self: *const ProviderScheduleV2,
        manifest: *const manifest_mod.Manifest,
    ) Error!void {
        try manifest.validate();
        self.shared_layout.validateReceipt() catch
            return error.InvalidProviderSchedule;
        const placement = manifest.placements[ROW_34].?;
        if (self.format_version != PROVIDER_SCHEDULE_FORMAT_VERSION or
            self.component_index != ROW_34 or self.provider_instance_count != 1 or
            self.source_count != self.ranges.len or
            self.log_size != placement.geometry.log_size or
            !std.mem.eql(u8, &self.manifest_seal, &manifest.seal) or
            !std.mem.eql(
                u8,
                &self.semantic_digest,
                &placement.geometry.semantic_digest,
            ) or !self.shared_layout.call_set_complete or
            !self.shared_layout.verifier_core_range_populated or
            self.shared_layout.total_call_count != self.logical_call_count)
        {
            return error.InvalidProviderSchedule;
        }
        var next: u32 = 0;
        for (self.ranges, 0..) |item, index| {
            if (@intFromEnum(item.origin) != index or item.first != next or
                item.count == 0)
            {
                return error.InvalidProviderSchedule;
            }
            next = try item.end();
        }
        if (next != self.logical_call_count or
            try minimalLogSize(self.logical_call_count) != self.log_size or
            self.ranges[0].first != self.shared_layout.transcript.start or
            try self.ranges[0].end() != self.shared_layout.transcript.end or
            self.ranges[1].first != self.shared_layout.statement_authority.start or
            try self.ranges[1].end() != self.shared_layout.statement_authority.end or
            self.ranges[2].first != self.shared_layout.verifier_core.start or
            try self.ranges[2].end() != self.shared_layout.verifier_core.end)
        {
            return error.InvalidProviderSchedule;
        }
    }

    pub fn validateAuthenticated(
        self: *const ProviderScheduleV2,
        manifest: *const manifest_mod.Manifest,
        calls: []const shared_schedule.Call,
    ) Error!void {
        try self.validateAgainst(manifest);
        self.shared_layout.validate(calls) catch
            return error.InvalidProviderSchedule;
    }
};

pub const Capability = enum(u8) {
    typed_catalog = 0,
    fixed_manifest = 1,
    transcript_components = 2,
    statement_components = 3,
    public_components = 4,
    core_components = 5,
    range_provider = 6,
    boundary_components = 7,
    complete_tree_writers = 8,
    provider_schedule_custody = 9,
    committed_verifier_input_provider = 10,
    all_domain_audits = 11,
    verifier_domain_audit_custody = 12,
    complete_proof_gate = 13,
    committed_tree_custody = 14,
    independent_outer_prove_verify = 15,
};

pub const CAPABILITY_COUNT: usize = @typeInfo(Capability).@"enum".fields.len;
pub const ALL_CAPABILITY_MASK: u64 = rangeMask(0, CAPABILITY_COUNT);

/// APIs which are present in the tree today. Availability is kept separate
/// from proof evidence: no bit here says that one concrete proof populated a
/// row, closed a domain, or produced a commitment.
pub const LANDED_CAPABILITY_MASK: u64 =
    capabilityBit(.typed_catalog) |
    capabilityBit(.fixed_manifest) |
    capabilityBit(.transcript_components) |
    capabilityBit(.statement_components) |
    capabilityBit(.public_components) |
    capabilityBit(.range_provider) |
    capabilityBit(.boundary_components) |
    capabilityBit(.provider_schedule_custody) |
    capabilityBit(.committed_verifier_input_provider);

pub const LANDED_COMPONENT_ROW_MASK: u64 =
    TRANSCRIPT_ROWS_MASK | STATEMENT_ROWS_MASK | PUBLIC_ROWS_MASK | RANGE_ROW_MASK |
    BOUNDARY_ROWS_MASK | VERIFIER_INPUT_PROVIDER_ROW_MASK;
pub const MISSING_COMPONENT_ROW_MASK: u64 =
    ALL_COMPONENT_MASK & ~LANDED_COMPONENT_ROW_MASK;

pub fn rowAuthority(row: u8) RowAuthority {
    return if (row < 10)
        .transcript_v2
    else if (row < 12)
        .statement_v2
    else if (row < 18)
        .public_v2
    else if (row < 35)
        .core_universal_v1_identity
    else if (row == 35)
        .range_v2
    else if (row < 38)
        .boundary_v2
    else
        .verifier_input_provider_v2;
}

pub fn rosterIdentity(value: *const RosterPlanV2) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(ROSTER_ID_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u8, value.component_count);
    hashInt(&hash, u64, value.row_mask);
    hash.update(&value.catalog_identity);
    hash.update(&value.manifest_seal);
    for (value.authorities) |authority|
        hashInt(&hash, u8, @intFromEnum(authority));
    return hash.finalResult();
}

pub fn treePlanIdentity(value: *const TreePlanV2) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(TREE_PLAN_ID_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u8, value.component_count);
    hashInt(&hash, u8, value.tree_count);
    hashInt(&hash, u8, value.padding);
    hash.update(&value.manifest_seal);
    for (value.rows) |row| {
        hashInt(&hash, u32, row.log_size);
        for (row.offsets) |offset| hashInt(&hash, u32, offset);
        for (row.columns) |columns| hashInt(&hash, u16, columns);
    }
    for (value.total_columns) |columns| hashInt(&hash, u32, columns);
    return hash.finalResult();
}

pub fn minimalLogSize(count: u32) Error!u32 {
    if (count == 0) return error.InvalidProviderSchedule;
    var log_size: u32 = 0;
    var capacity: u32 = 1;
    while (capacity < count) : (log_size += 1) {
        capacity = std.math.mul(u32, capacity, 2) catch
            return error.ArithmeticOverflow;
    }
    return log_size;
}

pub fn checkedAdd(left: anytype, right: anytype) Error!@TypeOf(left) {
    const T = @TypeOf(left);
    const converted = std.math.cast(T, right) orelse
        return error.ArithmeticOverflow;
    return std.math.add(T, left, converted) catch error.ArithmeticOverflow;
}

pub fn componentBit(index: anytype) u64 {
    return @as(u64, 1) << @intCast(index);
}

pub fn capabilityBit(capability: Capability) u64 {
    return componentBit(@intFromEnum(capability));
}

pub fn rangeMask(comptime first: usize, comptime end: usize) u64 {
    var result: u64 = 0;
    inline for (first..end) |index| result |= componentBit(index);
    return result;
}

pub fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}
