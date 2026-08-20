//! Internal segment public outer components v2 authority shard; use segment_public_outer_components_v2.zig publicly.

const dependency_0 = @import("segment_public_outer_components_v2_contract.zig");
const dependency_1 = @import("segment_public_outer_components_v2_validate_events_for.zig");

const ControlFramework = dependency_0.ControlFramework;
const ControlRow = dependency_0.ControlRow;
const Error = dependency_0.Error;
const FIRST_ROW = dependency_0.FIRST_ROW;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const M31 = dependency_0.M31;
const RELAY_COMPONENT_INDICES = dependency_0.RELAY_COMPONENT_INDICES;
const ROW_COUNT = dependency_0.ROW_COUNT;
const RelayFramework = dependency_0.RelayFramework;
const RelayPlan = dependency_0.RelayPlan;
const RelayRow = dependency_0.RelayRow;
const SCHEMA_VERSION = dependency_0.SCHEMA_VERSION;
const Source = dependency_0.Source;
const SumsFramework = dependency_0.SumsFramework;
const SumsRow = dependency_0.SumsRow;
const WORKSPACE_DOMAIN = dependency_0.WORKSPACE_DOMAIN;
const air_v2 = dependency_0.air_v2;
const checkedAdd = dependency_1.checkedAdd;
const claim_hash_authority = dependency_0.claim_hash_authority;
const control_witness_v2 = dependency_0.control_witness_v2;
const framework = dependency_0.framework;
const hashInt = dependency_1.hashInt;
const hashNativeDigest = dependency_1.hashNativeDigest;
const logicalRow = dependency_0.logicalRow;
const manifest_mod = dependency_0.manifest_mod;
const native_sum_authority = dependency_0.native_sum_authority;
const poseidon2_air = dependency_0.poseidon2_air;
const relation = dependency_0.relation;
const source_v2 = dependency_0.source_v2;
const std = dependency_0.std;
const validateActiveControlEvents = dependency_1.validateActiveControlEvents;
const validateClaimHashEvents = dependency_0.validateClaimHashEvents;
const validateDirect = dependency_0.validateDirect;
const validateDirectGeneric = dependency_0.validateDirectGeneric;
const validateEventsFor = dependency_1.validateEventsFor;

/// Reusable single-worker cache. `init` owns every allocation; `prepare` and
/// all tree/claim writers are allocation free.
pub const Workspace = struct {
    allocator: std.mem.Allocator,
    source_id: source_v2.Digest,
    public_manifest_id: source_v2.Digest,
    log_sizes: [ROW_COUNT]u32,
    source_rows: [ROW_COUNT - 1][]source_v2.RelayRowV2,
    relation_events: []source_v2.RelationEventV2,
    logical_rows: [ROW_COUNT - 1][]RelayRow,
    claim_hash_prepared: claim_hash_authority.PreparedV2,
    claim_hash_call_scratch: []poseidon2_air.Call,
    claim_hash_logical_rows: []SumsRow,
    claim_hash_relation_events: []claim_hash_authority.RelationEventV2,
    control_main: [air_v2.ControlRelay.PHYSICAL_MAIN_COLUMN_COUNT][]M31,
    control_preprocessed: [air_v2.ControlRelay.PREPROCESSED_COLUMN_COUNT][]M31,
    control_physical_rows: []ControlRow,
    control_logical_rows: []ControlRow,
    control_relation_events: []control_witness_v2.RelationEventV2,
    interactions: [ROW_COUNT - 2]RelayFramework.Workspace,
    claim_hash_interaction: SumsFramework.Workspace,
    control_interaction: ControlFramework.Workspace,
    interaction_offsets: [ROW_COUNT]usize,
    interaction_stage: []M31,
    arithmetic_use_count_scratch: []u32,
    arithmetic_authority_id: [32]u8,
    arithmetic_binding_id: [32]u8,
    arithmetic_graph_bound: bool,
    seal: [32]u8,
    ready: bool,

    pub fn init(
        allocator: std.mem.Allocator,
        prepared: *const source_v2.PreparedV2,
    ) !Workspace {
        return initInternal(allocator, prepared, null);
    }

    /// Cold construction for the production rows 13--16 -> 30--32 path.
    /// The retained scratch makes every subsequent graph audit and relay fill
    /// allocation-free.
    pub fn initBound(
        allocator: std.mem.Allocator,
        prepared: *const source_v2.PreparedV2,
        arithmetic: *const native_sum_authority.SourceV2,
    ) !Workspace {
        return initInternal(allocator, prepared, arithmetic);
    }

    fn initInternal(
        allocator: std.mem.Allocator,
        prepared: *const source_v2.PreparedV2,
        arithmetic: ?*const native_sum_authority.SourceV2,
    ) !Workspace {
        try prepared.manifest.validate();
        const graph_binding = if (arithmetic) |owner|
            try owner.publicBinding(prepared)
        else
            null;
        const counts = prepared.counts();
        const row_counts = counts.asRows();

        var source_rows: [ROW_COUNT - 1][]source_v2.RelayRowV2 = undefined;
        var source_count: usize = 0;
        errdefer while (source_count > 0) {
            source_count -= 1;
            allocator.free(source_rows[source_count]);
        };
        for (&source_rows, row_counts[0 .. ROW_COUNT - 1]) |*rows, count| {
            rows.* = try allocator.alloc(source_v2.RelayRowV2, count);
            source_count += 1;
        }

        const relation_events = try allocator.alloc(
            source_v2.RelationEventV2,
            counts.relay_relation_events,
        );
        errdefer allocator.free(relation_events);

        var logical_rows: [ROW_COUNT - 1][]RelayRow = undefined;
        var logical_count: usize = 0;
        errdefer while (logical_count > 0) {
            logical_count -= 1;
            allocator.free(logical_rows[logical_count]);
        };
        for (&logical_rows, row_counts[0 .. ROW_COUNT - 1]) |*rows, count| {
            rows.* = try allocator.alloc(RelayRow, count);
            logical_count += 1;
        }

        const claim_hash_prepared =
            try claim_hash_authority.PreparedV2.initFromPublic(prepared);
        const claim_hash_call_scratch = try allocator.alloc(
            poseidon2_air.Call,
            try claim_hash_prepared.callCount(),
        );
        errdefer allocator.free(claim_hash_call_scratch);
        const claim_hash_logical_rows = try allocator.alloc(
            SumsRow,
            claim_hash_prepared.logical_row_count,
        );
        errdefer allocator.free(claim_hash_logical_rows);
        const claim_hash_relation_events = try allocator.alloc(
            claim_hash_authority.RelationEventV2,
            try claim_hash_prepared.eventCount(),
        );
        errdefer allocator.free(claim_hash_relation_events);

        var control_main: [air_v2.ControlRelay.PHYSICAL_MAIN_COLUMN_COUNT][]M31 =
            undefined;
        var control_main_count: usize = 0;
        errdefer while (control_main_count > 0) {
            control_main_count -= 1;
            allocator.free(control_main[control_main_count]);
        };
        for (&control_main) |*column| {
            column.* = try allocator.alloc(M31, control_witness_v2.TRACE_ROW_COUNT);
            control_main_count += 1;
        }
        var control_preprocessed: [air_v2.ControlRelay.PREPROCESSED_COLUMN_COUNT][]M31 =
            undefined;
        var control_preprocessed_count: usize = 0;
        errdefer while (control_preprocessed_count > 0) {
            control_preprocessed_count -= 1;
            allocator.free(control_preprocessed[control_preprocessed_count]);
        };
        for (&control_preprocessed) |*column| {
            column.* = try allocator.alloc(M31, control_witness_v2.TRACE_ROW_COUNT);
            control_preprocessed_count += 1;
        }
        const control_physical_rows = try allocator.alloc(
            ControlRow,
            control_witness_v2.TRACE_ROW_COUNT,
        );
        errdefer allocator.free(control_physical_rows);
        const control_relation_events = try allocator.alloc(
            control_witness_v2.RelationEventV2,
            control_witness_v2.ACTIVE_RELATION_EVENT_COUNT,
        );
        errdefer allocator.free(control_relation_events);

        var interactions: [ROW_COUNT - 2]RelayFramework.Workspace = undefined;
        var interaction_count: usize = 0;
        errdefer while (interaction_count > 0) {
            interaction_count -= 1;
            interactions[interaction_count].deinit();
        };
        for (&interactions, RELAY_COMPONENT_INDICES) |*workspace, index| {
            workspace.* = try RelayFramework.Workspace.init(
                allocator,
                prepared.manifest.log_sizes[index],
            );
            interaction_count += 1;
        }
        var claim_hash_interaction = try SumsFramework.Workspace.init(
            allocator,
            prepared.manifest.log_sizes[1],
        );
        errdefer claim_hash_interaction.deinit();
        var control_interaction = try ControlFramework.Workspace.init(
            allocator,
            control_witness_v2.TRACE_LOG_SIZE,
        );
        errdefer control_interaction.deinit();

        var interaction_offsets: [ROW_COUNT]usize = undefined;
        var stage_len: usize = 0;
        for (&interaction_offsets, prepared.manifest.log_sizes, 0..) |
            *offset,
            log_size,
            index,
        | {
            offset.* = stage_len;
            stage_len = try checkedAdd(
                stage_len,
                if (index == 1)
                    try SumsFramework.requiredStorageElementCount(log_size)
                else if (index == ROW_COUNT - 1)
                    try ControlFramework.requiredStorageElementCount(log_size)
                else
                    try RelayFramework.requiredStorageElementCount(log_size),
            );
        }
        const interaction_stage = try allocator.alloc(M31, stage_len);
        errdefer allocator.free(interaction_stage);

        const arithmetic_use_count_scratch = if (arithmetic) |owner|
            try allocator.alloc(u32, owner.nodeCount())
        else
            try allocator.alloc(u32, 0);
        errdefer allocator.free(arithmetic_use_count_scratch);

        var log_sizes: [ROW_COUNT]u32 = undefined;
        for (&log_sizes, prepared.manifest.log_sizes) |*target, value|
            target.* = value;
        return .{
            .allocator = allocator,
            .source_id = prepared.source_id,
            .public_manifest_id = prepared.manifest.identity,
            .log_sizes = log_sizes,
            .source_rows = source_rows,
            .relation_events = relation_events,
            .logical_rows = logical_rows,
            .claim_hash_prepared = claim_hash_prepared,
            .claim_hash_call_scratch = claim_hash_call_scratch,
            .claim_hash_logical_rows = claim_hash_logical_rows,
            .claim_hash_relation_events = claim_hash_relation_events,
            .control_main = control_main,
            .control_preprocessed = control_preprocessed,
            .control_physical_rows = control_physical_rows,
            .control_logical_rows = control_physical_rows[0..control_witness_v2.LOGICAL_ROW_COUNT],
            .control_relation_events = control_relation_events,
            .interactions = interactions,
            .claim_hash_interaction = claim_hash_interaction,
            .control_interaction = control_interaction,
            .interaction_offsets = interaction_offsets,
            .interaction_stage = interaction_stage,
            .arithmetic_use_count_scratch = arithmetic_use_count_scratch,
            .arithmetic_authority_id = if (arithmetic) |owner|
                owner.authority_digest
            else
                .{0} ** 32,
            .arithmetic_binding_id = if (graph_binding) |value|
                value.identity
            else
                .{0} ** 32,
            .arithmetic_graph_bound = arithmetic != null,
            .seal = .{0} ** 32,
            .ready = false,
        };
    }

    pub fn deinit(self: *Workspace) void {
        self.allocator.free(self.arithmetic_use_count_scratch);
        self.allocator.free(self.interaction_stage);
        self.control_interaction.deinit();
        self.claim_hash_interaction.deinit();
        var index = self.interactions.len;
        while (index > 0) {
            index -= 1;
            self.interactions[index].deinit();
        }
        self.allocator.free(self.control_relation_events);
        self.allocator.free(self.control_physical_rows);
        for (self.control_preprocessed) |column| self.allocator.free(column);
        for (self.control_main) |column| self.allocator.free(column);
        self.allocator.free(self.claim_hash_relation_events);
        self.allocator.free(self.claim_hash_logical_rows);
        self.allocator.free(self.claim_hash_call_scratch);
        for (self.logical_rows) |rows| self.allocator.free(rows);
        self.allocator.free(self.relation_events);
        for (self.source_rows) |rows| self.allocator.free(rows);
        self.* = undefined;
    }

    pub fn prepare(
        self: *Workspace,
        owner: *const Source,
        prepared: *const source_v2.PreparedV2,
        manifest: *const manifest_mod.Manifest,
        inputs: source_v2.InputsV2,
    ) !void {
        self.ready = false;
        self.seal = .{0} ** 32;
        if (self.arithmetic_graph_bound)
            return error.PreparedAuthorityMismatch;
        try owner.validateAgainst(prepared, manifest);
        try self.validateGeometry(prepared);
        try source_v2.writeInto(
            prepared,
            self.sourceDestinations(),
            inputs,
        );
        for (self.logical_rows, self.source_rows) |logical, source_rows| {
            for (logical, source_rows) |*target, row| target.* = logicalRow(row);
        }
        try claim_hash_authority.writeInto(
            &self.claim_hash_prepared,
            prepared,
            inputs,
            self.source_rows[1],
            self.claim_hash_call_scratch,
            self.claim_hash_logical_rows,
            self.claim_hash_relation_events,
        );
        try validateDirectRows(owner, self);
        try validateEventProjection(owner, self);
        self.seal = workspaceDigest(self, prepared);
        self.ready = true;
    }

    /// Allocation-free graph-bound preparation. The native-sum owner both
    /// authenticates the graph and supplies its exact dense input use counts;
    /// the component cache then authenticates the resulting direct/event rows.
    pub fn prepareBound(
        self: *Workspace,
        owner: *const Source,
        prepared: *const source_v2.PreparedV2,
        manifest: *const manifest_mod.Manifest,
        inputs: source_v2.InputsV2,
        arithmetic: *const native_sum_authority.SourceV2,
    ) !void {
        self.ready = false;
        self.seal = .{0} ** 32;
        try owner.validateAgainst(prepared, manifest);
        try self.validateBoundGeometry(prepared, arithmetic);
        try arithmetic.writePublicRowsInto(
            prepared,
            self.sourceDestinations(),
            inputs,
            self.arithmetic_use_count_scratch,
        );
        for (self.logical_rows, self.source_rows) |logical, source_rows| {
            for (logical, source_rows) |*target, row| target.* = logicalRow(row);
        }
        try claim_hash_authority.writeInto(
            &self.claim_hash_prepared,
            prepared,
            inputs,
            self.source_rows[1],
            self.claim_hash_call_scratch,
            self.claim_hash_logical_rows,
            self.claim_hash_relation_events,
        );
        try validateDirectRows(owner, self);
        try validateEventProjection(owner, self);
        self.seal = workspaceDigest(self, prepared);
        self.ready = true;
    }

    pub fn validateAgainst(
        self: *const Workspace,
        prepared: *const source_v2.PreparedV2,
    ) !void {
        if (!self.ready) return error.CacheNotPrepared;
        try self.validateGeometry(prepared);
        const actual = workspaceDigest(self, prepared);
        if (!std.mem.eql(u8, &actual, &self.seal))
            return error.WorkspaceSealMismatch;
    }

    pub fn validateBoundAgainst(
        self: *const Workspace,
        prepared: *const source_v2.PreparedV2,
        arithmetic: *const native_sum_authority.SourceV2,
    ) !void {
        try self.validateAgainst(prepared);
        try self.validateBoundGeometry(prepared, arithmetic);
    }

    fn validateBoundGeometry(
        self: *const Workspace,
        prepared: *const source_v2.PreparedV2,
        arithmetic: *const native_sum_authority.SourceV2,
    ) !void {
        const graph_binding = try arithmetic.publicBinding(prepared);
        if (!self.arithmetic_graph_bound or
            self.arithmetic_use_count_scratch.len != arithmetic.nodeCount() or
            !std.mem.eql(
                u8,
                &self.arithmetic_authority_id,
                &arithmetic.authority_digest,
            ) or !std.mem.eql(
            u8,
            &self.arithmetic_binding_id,
            &graph_binding.identity,
        )) return error.PreparedAuthorityMismatch;
    }

    fn validateGeometry(
        self: *const Workspace,
        prepared: *const source_v2.PreparedV2,
    ) !void {
        try prepared.manifest.validate();
        const counts = prepared.counts();
        const row_counts = counts.asRows();
        const expected_claim_hash =
            try claim_hash_authority.PreparedV2.initFromPublic(prepared);
        if (!std.meta.eql(self.source_id, prepared.source_id) or
            !std.meta.eql(self.public_manifest_id, prepared.manifest.identity) or
            self.relation_events.len != counts.relay_relation_events or
            !std.meta.eql(self.claim_hash_prepared, expected_claim_hash) or
            self.claim_hash_call_scratch.len !=
                expected_claim_hash.plan.poseidon_call_count or
            self.claim_hash_logical_rows.len !=
                expected_claim_hash.logical_row_count or
            self.claim_hash_relation_events.len !=
                counts.authority_relation_events or
            self.control_physical_rows.len != control_witness_v2.TRACE_ROW_COUNT or
            self.control_logical_rows.len != control_witness_v2.LOGICAL_ROW_COUNT or
            self.control_logical_rows.ptr != self.control_physical_rows.ptr or
            self.control_relation_events.len != counts.control_relation_events)
        {
            return error.WorkspaceGeometryMismatch;
        }
        var stage_len: usize = 0;
        for (0..ROW_COUNT - 1) |index| {
            if (self.log_sizes[index] != prepared.manifest.log_sizes[index] or
                self.source_rows[index].len != row_counts[index] or
                self.logical_rows[index].len != row_counts[index] or
                self.interaction_offsets[index] != stage_len)
            {
                return error.WorkspaceGeometryMismatch;
            }
            stage_len = try checkedAdd(
                stage_len,
                if (index == 1)
                    try SumsFramework.requiredStorageElementCount(
                        self.log_sizes[index],
                    )
                else
                    try RelayFramework.requiredStorageElementCount(
                        self.log_sizes[index],
                    ),
            );
        }
        if (self.log_sizes[ROW_COUNT - 1] != control_witness_v2.TRACE_LOG_SIZE or
            self.interaction_offsets[ROW_COUNT - 1] != stage_len)
        {
            return error.WorkspaceGeometryMismatch;
        }
        stage_len = try checkedAdd(
            stage_len,
            try ControlFramework.requiredStorageElementCount(
                self.log_sizes[ROW_COUNT - 1],
            ),
        );
        for (self.control_main) |column| if (column.len != control_witness_v2.TRACE_ROW_COUNT) return error.WorkspaceGeometryMismatch;
        for (self.control_preprocessed) |column| if (column.len != control_witness_v2.TRACE_ROW_COUNT) return error.WorkspaceGeometryMismatch;
        if (self.interaction_stage.len != stage_len)
            return error.WorkspaceGeometryMismatch;
        if (self.arithmetic_graph_bound) {
            if (self.arithmetic_use_count_scratch.len == 0 or
                std.mem.allEqual(u8, &self.arithmetic_authority_id, 0) or
                std.mem.allEqual(u8, &self.arithmetic_binding_id, 0))
            {
                return error.WorkspaceGeometryMismatch;
            }
        } else if (self.arithmetic_use_count_scratch.len != 0 or
            !std.mem.allEqual(u8, &self.arithmetic_authority_id, 0) or
            !std.mem.allEqual(u8, &self.arithmetic_binding_id, 0))
        {
            return error.WorkspaceGeometryMismatch;
        }
    }

    fn sourceDestinations(self: *Workspace) source_v2.DestinationsV2 {
        return .{
            .publication_header = self.source_rows[0],
            .native_public_sums = self.source_rows[1],
            .publication_seal = self.source_rows[2],
            .boundary_bridge = self.source_rows[3],
            .native_challenges = self.source_rows[4],
            .relation_events = self.relation_events,
            .control = .{
                .main = self.control_main,
                .preprocessed = self.control_preprocessed,
                .logical_rows = self.control_physical_rows,
                .relation_events = self.control_relation_events,
            },
        };
    }

    pub fn controlActiveRows(self: *const Workspace) []const ControlRow {
        return self.control_logical_rows;
    }
};

pub fn writePhysicalFor(
    comptime Air: type,
    rows: []const [Air.LOGICAL_INPUT_COUNT]M31,
    placement: manifest_mod.Placement,
    tree: usize,
    destination: []const []M31,
) void {
    const local_count = switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => Air.PREPROCESSED_COLUMN_COUNT,
        manifest_mod.MAIN_TREE_INDEX => Air.PHYSICAL_MAIN_COLUMN_COUNT,
        else => unreachable,
    };
    const input_start = if (tree == manifest_mod.PREPROCESSED_TREE_INDEX)
        Air.PHYSICAL_MAIN_COLUMN_COUNT
    else
        0;
    const output_start: usize = switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
        manifest_mod.MAIN_TREE_INDEX => placement.main_offset,
        else => unreachable,
    };
    for (destination[output_start..][0..local_count]) |column|
        @memset(column, M31.zero());
    for (rows, 0..) |row, logical_row| {
        const committed_row = framework.committedRow(
            logical_row,
            placement.geometry.log_size,
        );
        for (0..local_count) |column|
            destination[output_start + column][committed_row] =
                row[input_start + column];
    }
}

pub fn validateDirectRows(owner: *const Source, workspace: *const Workspace) !void {
    const programs = owner.owners.relayDirects();
    for (programs, RELAY_COMPONENT_INDICES) |program, index|
        try validateDirect(program, workspace.logical_rows[index]);
    try validateDirectGeneric(
        air_v2.NativePublicSums,
        &owner.owners.native_public_sums.direct,
        workspace.claim_hash_logical_rows,
    );
    try validateDirectGeneric(
        air_v2.ControlRelay,
        &owner.owners.control_relay.direct,
        workspace.controlActiveRows(),
    );
}

pub fn validateEventProjection(
    owner: *const Source,
    workspace: *const Workspace,
) !void {
    var cursor: usize = 0;
    try validateEventsFor(
        &owner.owners.publication_header.relation,
        workspace.logical_rows[0],
        workspace.relation_events,
        &cursor,
        .vm_public_claim_input,
    );
    try validateClaimHashEvents(
        &owner.owners.native_public_sums.relation,
        workspace.claim_hash_logical_rows,
        workspace.source_rows[1].len,
        workspace.relation_events,
        &cursor,
        workspace.claim_hash_relation_events,
    );
    const tail_plans = [_]*const RelayPlan{
        &owner.owners.publication_seal.relation,
        &owner.owners.boundary_bridge.relation,
        &owner.owners.native_challenges.relation,
    };
    inline for (tail_plans, 2..) |plan, index| try validateEventsFor(
        plan,
        workspace.logical_rows[index],
        workspace.relation_events,
        &cursor,
        @enumFromInt(FIRST_ROW + index),
    );
    try validateActiveControlEvents(
        &owner.owners.control_relay.relation,
        workspace.controlActiveRows(),
        workspace.control_relation_events,
    );
    if (cursor != workspace.relation_events.len)
        return error.EventProjectionMismatch;
}

pub fn workspaceDigest(
    workspace: *const Workspace,
    prepared: *const source_v2.PreparedV2,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(WORKSPACE_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashNativeDigest(&hash, workspace.source_id);
    hashNativeDigest(&hash, workspace.public_manifest_id);
    hashNativeDigest(&hash, prepared.source_id);
    hashNativeDigest(&hash, prepared.manifest.identity);
    hashInt(&hash, u8, @intFromBool(workspace.arithmetic_graph_bound));
    hash.update(&workspace.arithmetic_authority_id);
    hash.update(&workspace.arithmetic_binding_id);
    for (workspace.log_sizes) |log_size| hashInt(&hash, u32, log_size);
    for (workspace.logical_rows) |rows| for (rows) |row| for (row) |word|
        hashInt(&hash, u32, word.toU32());
    for (workspace.claim_hash_logical_rows) |row| for (row) |word|
        hashInt(&hash, u32, word.toU32());
    for (workspace.control_logical_rows) |row| for (row) |word|
        hashInt(&hash, u32, word.toU32());
    for (workspace.relation_events) |event| {
        hashInt(&hash, u8, event.roster_row);
        hashInt(&hash, u32, event.logical_row);
        hashInt(&hash, u8, event.event_ordinal);
        hashInt(&hash, u8, @intFromEnum(event.domain));
        hashInt(&hash, u8, @intFromEnum(event.role));
        hashInt(&hash, u32, event.multiplicity);
        hashInt(&hash, u8, event.arity);
        for (event.tuple) |word| hashInt(&hash, u32, word.toU32());
    }
    for (workspace.control_relation_events) |event| {
        hashInt(&hash, u8, event.roster_row);
        hashInt(&hash, u32, event.logical_row);
        hashInt(&hash, u8, event.event_ordinal);
        hashInt(&hash, u8, @intFromEnum(event.domain));
        hashInt(&hash, u8, @intFromEnum(event.role));
        hashInt(&hash, u32, event.multiplicity);
        hashInt(&hash, u8, event.arity);
        for (event.tuple) |word| hashInt(&hash, u32, word.toU32());
    }
    for (workspace.claim_hash_relation_events) |event| {
        hashInt(&hash, u8, event.roster_row);
        hashInt(&hash, u32, event.logical_row);
        hashInt(&hash, u8, event.event_ordinal);
        hashInt(&hash, u8, @intFromEnum(event.domain));
        hashInt(&hash, u8, @intFromEnum(event.role));
        hashInt(&hash, u32, event.multiplicity);
        hashInt(&hash, u8, event.arity);
        for (event.tuple) |word| hashInt(&hash, u32, word.toU32());
    }
    return hash.finalResult();
}

pub fn checkedMul(left: usize, right: usize) Error!usize {
    return std.math.mul(usize, left, right) catch error.ArithmeticOverflow;
}
