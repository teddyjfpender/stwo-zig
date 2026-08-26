//! Internal segment public outer components v2 authority shard; use segment_public_outer_components_v2.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");

pub const m31 = stwo_core.fields.m31;
pub const M31 = m31.M31;
pub const QM31 = stwo_core.fields.qm31.QM31;

pub const air_v2 = @import("air/segment_public_outer_air_v2.zig");
pub const binding = @import("air/universal_relation_binding.zig");
pub const direct_program = @import("air/direct_constraint_program.zig");
pub const framework = @import("air/framework_interaction.zig");
pub const manifest_mod = @import("air/segment_outer_adapter_manifest_v2.zig");
pub const relation_interaction = @import("air/relation_interaction.zig");
pub const relation = @import("../air/lang/relation.zig");
pub const typed_component = @import("air/universal_typed_component.zig");
pub const universal = @import("air/universal_challenges.zig");
pub const source_v2 = @import("segment_public_outer_source_v2.zig");
pub const native_sum_authority = @import("segment_public_native_sum_authority_v2.zig");
pub const claim_hash_authority = @import("segment_public_claim_hash_authority_v2.zig");
pub const control_witness_v2 = @import("air/vm_public_logup_control_witness_v2.zig");
pub const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const FIRST_ROW: usize = source_v2.FIRST_ROW;
pub const ROW_COUNT: usize = source_v2.ROW_COUNT;
pub const LAST_ROW: usize = source_v2.LAST_ROW;
pub const HOT_HEAP_ALLOCATIONS: usize = 0;
pub const TREE_WRITES_FAIL_BEFORE_FIRST_WRITE = true;
pub const PRODUCTION_ACTIVATION = false;

pub const WORKSPACE_DOMAIN =
    "stwo-zig/typed-air/segment-public-components-v2/workspace/v1\x00";

pub const HeaderRelation = binding.Binding(air_v2.PublicationHeader);
pub const SumsRelation = binding.Binding(air_v2.NativePublicSums);
pub const SealRelation = binding.Binding(air_v2.PublicationSeal);
pub const BoundaryRelation = binding.Binding(air_v2.StatementBoundary);
pub const ChallengesRelation = binding.Binding(air_v2.NativeChallenges);
pub const ControlRelation = binding.Binding(air_v2.ControlRelay);

pub const RelayRuntime = HeaderRelation.Runtime;
pub const RelayFramework = framework.Runtime(RelayRuntime);
pub const RelayRow = RelayRuntime.Row;
pub const RelayPlan = RelayRuntime.Plan;
pub const SumsRuntime = SumsRelation.Runtime;
pub const SumsFramework = framework.Runtime(SumsRuntime);
pub const SumsRow = SumsRuntime.Row;
pub const SumsPlan = SumsRuntime.Plan;
pub const ControlRuntime = ControlRelation.Runtime;
pub const ControlFramework = framework.Runtime(ControlRuntime);
pub const ControlRow = ControlRuntime.Row;
pub const ControlPlan = ControlRuntime.Plan;
pub const RELAY_COMPONENT_INDICES = [ROW_COUNT - 2]usize{ 0, 2, 3, 4 };

pub const HeaderAdapter = typed_component.ComponentForManifest(
    air_v2.PublicationHeader,
    HeaderRelation,
    manifest_mod,
);
pub const SumsAdapter = typed_component.ComponentForManifest(
    air_v2.NativePublicSums,
    SumsRelation,
    manifest_mod,
);
pub const SealAdapter = typed_component.ComponentForManifest(
    air_v2.PublicationSeal,
    SealRelation,
    manifest_mod,
);
pub const BoundaryAdapter = typed_component.ComponentForManifest(
    air_v2.StatementBoundary,
    BoundaryRelation,
    manifest_mod,
);
pub const ChallengesAdapter = typed_component.ComponentForManifest(
    air_v2.NativeChallenges,
    ChallengesRelation,
    manifest_mod,
);
pub const ControlAdapter = typed_component.ComponentForManifest(
    air_v2.ControlRelay,
    ControlRelation,
    manifest_mod,
);

pub const Error = error{
    ArithmeticOverflow,
    CacheNotPrepared,
    ConstraintViolation,
    DestinationAlias,
    DestinationColumnCountMismatch,
    DestinationLogSizeMismatch,
    EventProjectionMismatch,
    InvalidTreeIndex,
    ManifestGeometryMismatch,
    PreparedAuthorityMismatch,
    WorkspaceGeometryMismatch,
    WorkspaceSealMismatch,
};

pub inline fn evaluateRelationOp(
    op: relation_interaction.EvalOp,
    values: anytype,
) M31 {
    return switch (op) {
        .constant => |value| M31.fromU64(value),
        .add => |binary| values[binary.lhs].add(values[binary.rhs]),
        .sub => |binary| values[binary.lhs].sub(values[binary.rhs]),
        .mul => |binary| values[binary.lhs].mul(values[binary.rhs]),
        .neg => |operand| values[operand].neg(),
        .select => |selection| values[selection.selector]
            .mul(values[selection.when_true])
            .add(M31.one().sub(values[selection.selector])
            .mul(values[selection.when_false])),
    };
}

pub const Claims = struct {
    publication_header: QM31,
    native_public_sums: QM31,
    publication_seal: QM31,
    boundary_bridge: QM31,
    native_challenges: QM31,
    control_relay: QM31,

    pub fn asArray(self: Claims) [ROW_COUNT]QM31 {
        return .{
            self.publication_header,
            self.native_public_sums,
            self.publication_seal,
            self.boundary_bridge,
            self.native_challenges,
            self.control_relay,
        };
    }

    pub fn bindInto(self: Claims, vector: *manifest_mod.ClaimVector) !void {
        for (self.asArray(), 0..) |claim, index|
            try vector.bind(@enumFromInt(FIRST_ROW + index), claim);
    }
};

pub const DomainAudits = [ROW_COUNT]relation_interaction.DomainAudit;

pub const Components = struct {
    publication_header: HeaderAdapter,
    native_public_sums: SumsAdapter,
    publication_seal: SealAdapter,
    boundary_bridge: BoundaryAdapter,
    native_challenges: ChallengesAdapter,
    control_relay: ControlAdapter,

    pub fn appendToGate(
        self: *const Components,
        manifest: *const manifest_mod.Manifest,
        gate: *manifest_mod.ProofGate,
    ) !void {
        try gate.append(manifest, try self.publication_header.binding(manifest));
        try gate.append(manifest, try self.native_public_sums.binding(manifest));
        try gate.append(manifest, try self.publication_seal.binding(manifest));
        try gate.append(manifest, try self.boundary_bridge.binding(manifest));
        try gate.append(manifest, try self.native_challenges.binding(manifest));
        try gate.append(manifest, try self.control_relay.binding(manifest));
    }
};

pub fn AirOwner(comptime Air: type, comptime Relation: type) type {
    return struct {
        definition: Air.Definition,
        relation: Relation.Plan,
        direct: direct_program.Program,

        fn init(allocator: std.mem.Allocator) !@This() {
            var definition = try Air.build(allocator);
            errdefer definition.deinit();
            return .{
                .relation = try Relation.authenticate(&definition),
                .direct = try direct_program.authenticate(
                    &definition.arena,
                    Air.SEMANTIC_DIGEST,
                    Air.LOGICAL_INPUT_COUNT,
                ),
                .definition = definition,
            };
        }

        fn validate(self: *const @This()) !void {
            try self.definition.validate();
            try self.relation.validateAgainst(
                &self.definition.arena,
                Air.SEMANTIC_DIGEST,
                Relation.events(&self.definition),
            );
            const expected = try direct_program.authenticate(
                &self.definition.arena,
                Air.SEMANTIC_DIGEST,
                Air.LOGICAL_INPUT_COUNT,
            );
            if (!std.meta.eql(expected, self.direct))
                return error.PreparedAuthorityMismatch;
        }

        fn deinit(self: *@This()) void {
            self.definition.deinit();
            self.* = undefined;
        }
    };
}

pub const Owners = struct {
    publication_header: AirOwner(air_v2.PublicationHeader, HeaderRelation),
    native_public_sums: AirOwner(air_v2.NativePublicSums, SumsRelation),
    publication_seal: AirOwner(air_v2.PublicationSeal, SealRelation),
    boundary_bridge: AirOwner(air_v2.StatementBoundary, BoundaryRelation),
    native_challenges: AirOwner(air_v2.NativeChallenges, ChallengesRelation),
    control_relay: AirOwner(air_v2.ControlRelay, ControlRelation),

    fn init(allocator: std.mem.Allocator) !Owners {
        var publication_header = try AirOwner(
            air_v2.PublicationHeader,
            HeaderRelation,
        ).init(allocator);
        errdefer publication_header.deinit();
        var native_public_sums = try AirOwner(
            air_v2.NativePublicSums,
            SumsRelation,
        ).init(allocator);
        errdefer native_public_sums.deinit();
        var publication_seal = try AirOwner(
            air_v2.PublicationSeal,
            SealRelation,
        ).init(allocator);
        errdefer publication_seal.deinit();
        var boundary_bridge = try AirOwner(
            air_v2.StatementBoundary,
            BoundaryRelation,
        ).init(allocator);
        errdefer boundary_bridge.deinit();
        var native_challenges = try AirOwner(
            air_v2.NativeChallenges,
            ChallengesRelation,
        ).init(allocator);
        errdefer native_challenges.deinit();
        var control_relay = try AirOwner(
            air_v2.ControlRelay,
            ControlRelation,
        ).init(allocator);
        errdefer control_relay.deinit();
        return .{
            .publication_header = publication_header,
            .native_public_sums = native_public_sums,
            .publication_seal = publication_seal,
            .boundary_bridge = boundary_bridge,
            .native_challenges = native_challenges,
            .control_relay = control_relay,
        };
    }

    fn validate(self: *const Owners) !void {
        try self.publication_header.validate();
        try self.native_public_sums.validate();
        try self.publication_seal.validate();
        try self.boundary_bridge.validate();
        try self.native_challenges.validate();
        try self.control_relay.validate();
    }

    pub fn relayPlans(self: *const Owners) [ROW_COUNT - 2]*const RelayPlan {
        return .{
            &self.publication_header.relation,
            &self.publication_seal.relation,
            &self.boundary_bridge.relation,
            &self.native_challenges.relation,
        };
    }

    pub fn relayDirects(self: *const Owners) [ROW_COUNT - 2]*const direct_program.Program {
        return .{
            &self.publication_header.direct,
            &self.publication_seal.direct,
            &self.boundary_bridge.direct,
            &self.native_challenges.direct,
        };
    }

    fn deinit(self: *Owners) void {
        self.control_relay.deinit();
        self.native_challenges.deinit();
        self.boundary_bridge.deinit();
        self.publication_seal.deinit();
        self.native_public_sums.deinit();
        self.publication_header.deinit();
        self.* = undefined;
    }
};

pub const Parameters = struct {
    publication_header: [HeaderAdapter.PARAMETER_COLUMN_COUNT]M31,
    native_public_sums: [SumsAdapter.PARAMETER_COLUMN_COUNT]M31,
    publication_seal: [SealAdapter.PARAMETER_COLUMN_COUNT]M31,
    boundary_bridge: [BoundaryAdapter.PARAMETER_COLUMN_COUNT]M31,
    native_challenges: [ChallengesAdapter.PARAMETER_COLUMN_COUNT]M31,
    control_relay: [ControlAdapter.PARAMETER_COLUMN_COUNT]M31,

    pub fn segmentV2() Parameters {
        const zero = [_]M31{M31.zero()};
        return .{
            .publication_header = zero,
            .native_public_sums = zero,
            .publication_seal = zero,
            .boundary_bridge = zero,
            .native_challenges = zero,
            .control_relay = .{},
        };
    }
};

pub const Source = struct {
    allocator: std.mem.Allocator,
    source_id: source_v2.Digest,
    public_manifest_id: source_v2.Digest,
    log_sizes: [ROW_COUNT]u32,
    parameters: Parameters,
    owners: Owners,

    pub fn init(
        allocator: std.mem.Allocator,
        prepared: *const source_v2.PreparedV2,
        manifest: *const manifest_mod.Manifest,
    ) !Source {
        try prepared.manifest.validate();
        var owners = try Owners.init(allocator);
        errdefer owners.deinit();
        var result = Source{
            .allocator = allocator,
            .source_id = prepared.source_id,
            .public_manifest_id = prepared.manifest.identity,
            .log_sizes = undefined,
            .parameters = Parameters.segmentV2(),
            .owners = owners,
        };
        for (&result.log_sizes, prepared.manifest.log_sizes) |*target, value|
            target.* = value;
        try result.validateAgainst(prepared, manifest);
        return result;
    }

    pub fn deinit(self: *Source) void {
        self.owners.deinit();
        self.* = undefined;
    }

    pub fn productionReady(_: *const Source) bool {
        return PRODUCTION_ACTIVATION;
    }

    pub fn validateAgainst(
        self: *const Source,
        prepared: *const source_v2.PreparedV2,
        manifest: *const manifest_mod.Manifest,
    ) !void {
        try prepared.manifest.validate();
        try manifest.validate();
        if (!std.meta.eql(self.source_id, prepared.source_id) or
            !std.meta.eql(self.public_manifest_id, prepared.manifest.identity) or
            !std.meta.eql(self.parameters, Parameters.segmentV2()))
        {
            return error.PreparedAuthorityMismatch;
        }
        if (comptime @hasField(manifest_mod.Manifest, "public_manifest_id")) {
            if (!std.meta.eql(
                @field(manifest.*, "public_manifest_id"),
                prepared.manifest.identity,
            )) return error.PreparedAuthorityMismatch;
        }
        for (self.log_sizes, prepared.manifest.log_sizes, 0..) |
            actual,
            expected,
            index,
        | {
            if (actual != expected) return error.PreparedAuthorityMismatch;
            const key: manifest_mod.ComponentKey = @enumFromInt(FIRST_ROW + index);
            const placement = manifest.placements[FIRST_ROW + index] orelse
                return error.ManifestGeometryMismatch;
            if (placement.geometry.log_size != actual or
                !std.meta.eql(placement.geometry, expectedGeometry(key, actual)))
            {
                return error.ManifestGeometryMismatch;
            }
        }
        try self.owners.validate();
    }

    pub fn initComponents(
        self: *const Source,
        prepared: *const source_v2.PreparedV2,
        manifest: *const manifest_mod.Manifest,
        relations: *const universal.UniversalRelations,
        claims: Claims,
    ) !Components {
        try self.validateAgainst(prepared, manifest);
        try relations.validate();
        return .{
            .publication_header = try HeaderAdapter.init(
                &self.owners.publication_header.definition,
                self.owners.publication_header.relation,
                manifest,
                .vm_public_claim_input,
                self.log_sizes[0],
                self.parameters.publication_header,
                relations,
                claims.publication_header,
            ),
            .native_public_sums = try SumsAdapter.init(
                &self.owners.native_public_sums.definition,
                self.owners.native_public_sums.relation,
                manifest,
                .vm_public_claim_hash,
                self.log_sizes[1],
                self.parameters.native_public_sums,
                relations,
                claims.native_public_sums,
            ),
            .publication_seal = try SealAdapter.init(
                &self.owners.publication_seal.definition,
                self.owners.publication_seal.relation,
                manifest,
                .vm_public_io_hash,
                self.log_sizes[2],
                self.parameters.publication_seal,
                relations,
                claims.publication_seal,
            ),
            .boundary_bridge = try BoundaryAdapter.init(
                &self.owners.boundary_bridge.definition,
                self.owners.boundary_bridge.relation,
                manifest,
                .vm_public_claim_semantics_input,
                self.log_sizes[3],
                self.parameters.boundary_bridge,
                relations,
                claims.boundary_bridge,
            ),
            .native_challenges = try ChallengesAdapter.init(
                &self.owners.native_challenges.definition,
                self.owners.native_challenges.relation,
                manifest,
                .vm_public_logup_input,
                self.log_sizes[4],
                self.parameters.native_challenges,
                relations,
                claims.native_challenges,
            ),
            .control_relay = try ControlAdapter.init(
                &self.owners.control_relay.definition,
                self.owners.control_relay.relation,
                manifest,
                .vm_public_logup_control,
                self.log_sizes[5],
                self.parameters.control_relay,
                relations,
                claims.control_relay,
            ),
        };
    }
};

pub fn logicalRow(row: source_v2.RelayRowV2) RelayRow {
    var result: RelayRow = undefined;
    result[0] = felt(row.enabler);
    result[1] = row.value;
    result[2] = felt(row.enabler);
    result[3] = felt(row.arithmetic_mask);
    result[4] = felt(row.control_mask);
    for (row.source_fields, 0..) |value, index|
        result[5 + index] = felt(value);
    result[10] = felt(row.arithmetic_circuit_id);
    result[11] = felt(row.arithmetic_node_id);
    result[12] = felt(row.arithmetic_use_count);
    result[13] = felt(row.control_circuit_id);
    result[14] = felt(row.control_node_id);
    result[15] = felt(row.control_use_count);
    result[16] = M31.zero();
    return result;
}

pub fn validateDirect(
    program: *const direct_program.Program,
    rows: []const RelayRow,
) !void {
    var scratch: [direct_program.MAX_NODES]M31 = undefined;
    var roots: [air_v2.PublicationHeader.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    for (rows) |row| {
        try program.evaluateBaseInto(&row, &scratch, &roots);
        for (roots) |root| if (!root.isZero())
            return error.ConstraintViolation;
    }
}

pub fn validateDirectGeneric(
    comptime Air: type,
    program: *const direct_program.Program,
    rows: []const [Air.LOGICAL_INPUT_COUNT]M31,
) !void {
    var scratch: [direct_program.MAX_NODES]M31 = undefined;
    var roots: [Air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    for (rows) |row| {
        try program.evaluateBaseInto(&row, &scratch, &roots);
        for (roots) |root| if (!root.isZero())
            return error.ConstraintViolation;
    }
}

pub fn validateClaimHashEvents(
    plan: *const SumsPlan,
    rows: []const SumsRow,
    relay_row_count: usize,
    relay_events: []const source_v2.RelationEventV2,
    relay_cursor: *usize,
    authority_events: []const claim_hash_authority.RelationEventV2,
) !void {
    const slot_count = SumsRuntime.LOGICAL_INPUT_COUNT +
        relation_interaction.MAX_COMPILED_NODES;
    var slots: [slot_count]M31 = undefined;
    var authority_cursor: usize = 0;
    for (rows, 0..) |row, logical_row| {
        @memcpy(slots[0..SumsRuntime.LOGICAL_INPUT_COUNT], &row);
        for (plan.compiled_nodes[0..plan.compiled_node_count]) |node|
            slots[node.destination] = evaluateRelationOp(node.op, &slots);
        for (plan.events) |expected| {
            const magnitude = slots[expected.numerator_slot];
            if (expected.ordinal < 3) {
                if (logical_row >= relay_row_count) {
                    if (!magnitude.isZero()) return error.EventProjectionMismatch;
                    continue;
                }
                if (relay_cursor.* >= relay_events.len)
                    return error.EventProjectionMismatch;
                try expectProjectedEvent(
                    relay_events[relay_cursor.*],
                    FIRST_ROW + 1,
                    logical_row,
                    expected,
                    magnitude,
                    &slots,
                );
                relay_cursor.* += 1;
            } else {
                if (magnitude.isZero()) continue;
                if (authority_cursor >= authority_events.len)
                    return error.EventProjectionMismatch;
                try expectProjectedEvent(
                    authority_events[authority_cursor],
                    FIRST_ROW + 1,
                    logical_row,
                    expected,
                    magnitude,
                    &slots,
                );
                authority_cursor += 1;
            }
        }
    }
    if (authority_cursor != authority_events.len)
        return error.EventProjectionMismatch;
}

pub fn expectProjectedEvent(
    actual: anytype,
    roster_row: usize,
    logical_row: usize,
    expected: relation_interaction.EventPlan,
    magnitude: M31,
    slots: []const M31,
) !void {
    actual.validate() catch return error.EventProjectionMismatch;
    if (actual.roster_row != roster_row or actual.logical_row != logical_row or
        actual.event_ordinal != expected.ordinal or
        actual.domain != expected.domain or actual.role != expected.role or
        actual.arity != expected.arity or
        actual.multiplicity != magnitude.toU32())
    {
        return error.EventProjectionMismatch;
    }
    for (
        actual.tuple[0..actual.arity],
        expected.value_slots[0..expected.arity],
    ) |got, slot| if (!got.eql(slots[slot]))
        return error.EventProjectionMismatch;
}

pub fn expectedGeometry(
    key: manifest_mod.ComponentKey,
    log_size: u32,
) manifest_mod.Geometry {
    return switch (key) {
        .vm_public_claim_input => HeaderAdapter.manifestGeometry(
            .vm_public_claim_input,
            log_size,
        ),
        .vm_public_claim_hash => SumsAdapter.manifestGeometry(
            .vm_public_claim_hash,
            log_size,
        ),
        .vm_public_io_hash => SealAdapter.manifestGeometry(
            .vm_public_io_hash,
            log_size,
        ),
        .vm_public_claim_semantics_input => BoundaryAdapter.manifestGeometry(
            .vm_public_claim_semantics_input,
            log_size,
        ),
        .vm_public_logup_input => ChallengesAdapter.manifestGeometry(
            .vm_public_logup_input,
            log_size,
        ),
        .vm_public_logup_control => ControlAdapter.manifestGeometry(
            .vm_public_logup_control,
            log_size,
        ),
        else => unreachable,
    };
}

pub fn felt(value: anytype) M31 {
    const canonical: u32 = @intCast(value);
    std.debug.assert(canonical < m31.Modulus);
    return M31.fromCanonical(canonical);
}
