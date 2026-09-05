//! Typed component authority for schema-3 role-0 rows 10--17.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const manifest_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const rows_mod =
    @import("recursive_common_ethereum_incremental_leaf_suffix_rows_v4.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const air = frontend.recursion.air;
const direct_program = air.direct_constraint_program;
const typed_component = air.universal_typed_component;
const universal = air.universal_challenges;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const FIRST_ROW: usize = 10;
pub const LAST_ROW: usize = 17;
pub const ROW_COUNT: usize = 8;
pub const ROWS_BASED_CONSTRUCTOR_AVAILABLE = true;
pub const PRODUCTION_ACTIVATION = false;

pub const StatementInputRelation = rows_mod.StatementInputRelation;
pub const StatementSemanticsRelation = rows_mod.StatementSemanticsRelation;
pub const ClaimInputRelation = rows_mod.ClaimInputRelation;
pub const ClaimHashRelation = rows_mod.ClaimHashRelation;
pub const IoHashRelation = rows_mod.IoHashRelation;
pub const ClaimSemanticsRelation = rows_mod.ClaimSemanticsRelation;
pub const PublicLogupRelation = rows_mod.PublicLogupRelation;
pub const PublicLogupControlAir = rows_mod.PublicLogupControlAir;
pub const PublicLogupControlRelation = rows_mod.PublicLogupControlRelation;

pub const StatementInputFramework =
    air.framework_interaction.Runtime(StatementInputRelation.Runtime);
pub const StatementSemanticsFramework =
    air.framework_interaction.Runtime(StatementSemanticsRelation.Runtime);
pub const ClaimInputFramework =
    air.framework_interaction.Runtime(ClaimInputRelation.Runtime);
pub const ClaimHashFramework =
    air.framework_interaction.Runtime(ClaimHashRelation.Runtime);
pub const IoHashFramework =
    air.framework_interaction.Runtime(IoHashRelation.Runtime);
pub const ClaimSemanticsFramework =
    air.framework_interaction.Runtime(ClaimSemanticsRelation.Runtime);
pub const PublicLogupFramework =
    air.framework_interaction.Runtime(PublicLogupRelation.Runtime);
pub const PublicLogupControlFramework =
    air.framework_interaction.Runtime(PublicLogupControlRelation.Runtime);

const StatementInputAdapter = typed_component.ComponentForManifest(
    air.statement_input,
    StatementInputRelation,
    manifest_mod,
);
const StatementSemanticsAdapter = typed_component.ComponentForManifest(
    air.statement_semantics_input,
    StatementSemanticsRelation,
    manifest_mod,
);
const ClaimInputAdapter = typed_component.ComponentForManifest(
    air.vm_public_claim_input,
    ClaimInputRelation,
    manifest_mod,
);
const ClaimHashAdapter = typed_component.ComponentForManifest(
    air.vm_public_claim_hash,
    ClaimHashRelation,
    manifest_mod,
);
const IoHashAdapter = typed_component.ComponentForManifest(
    air.vm_public_io_hash,
    IoHashRelation,
    manifest_mod,
);
const ClaimSemanticsAdapter = typed_component.ComponentForManifest(
    air.vm_public_claim_semantics_input,
    ClaimSemanticsRelation,
    manifest_mod,
);
const PublicLogupAdapter = typed_component.ComponentForManifest(
    air.vm_public_logup_input,
    PublicLogupRelation,
    manifest_mod,
);
const PublicLogupControlAdapter = typed_component.ComponentForManifest(
    PublicLogupControlAir,
    PublicLogupControlRelation,
    manifest_mod,
);

pub const Error = error{
    EthereumIncrementalSuffixComponentsMismatchV4,
};

pub const ClaimsV4 = struct {
    values: [ROW_COUNT]QM31,

    pub fn bindInto(
        self: ClaimsV4,
        destination: *manifest_mod.ClaimVector,
    ) !void {
        for (self.values, 0..) |value, index|
            try destination.bind(@enumFromInt(FIRST_ROW + index), value);
    }
};

pub const ComponentsV4 = struct {
    statement_input: StatementInputAdapter,
    statement_semantics: StatementSemanticsAdapter,
    claim_input: ClaimInputAdapter,
    claim_hash: ClaimHashAdapter,
    io_hash: IoHashAdapter,
    claim_semantics: ClaimSemanticsAdapter,
    public_logup: PublicLogupAdapter,
    public_logup_control: PublicLogupControlAdapter,

    pub fn appendToGate(
        self: *const ComponentsV4,
        manifest: *const manifest_mod.Manifest,
        gate: *manifest_mod.ProofGate,
    ) !void {
        try gate.append(manifest, try self.statement_input.binding(manifest));
        try gate.append(
            manifest,
            try self.statement_semantics.binding(manifest),
        );
        try gate.append(manifest, try self.claim_input.binding(manifest));
        try gate.append(manifest, try self.claim_hash.binding(manifest));
        try gate.append(manifest, try self.io_hash.binding(manifest));
        try gate.append(manifest, try self.claim_semantics.binding(manifest));
        try gate.append(manifest, try self.public_logup.binding(manifest));
        try gate.append(
            manifest,
            try self.public_logup_control.binding(manifest),
        );
    }
};

pub fn OwnerV4(comptime Engine: type) type {
    const Rows = rows_mod.PreparedV4(Engine);

    return struct {
        allocator: std.mem.Allocator,
        rows: *const Rows,
        manifest: *const manifest_mod.Manifest,
        log_sizes: [ROW_COUNT]u32,
        parameters: ParametersV4,
        owners: OwnersV4,

        pub fn init(
            allocator: std.mem.Allocator,
            rows: *const Rows,
            manifest: *const manifest_mod.Manifest,
        ) !@This() {
            try rows.validate();
            try manifest.validate();
            var selected_logs: [ROW_COUNT]u32 = undefined;
            inline for (0..ROW_COUNT) |index| {
                const key: manifest_mod.ComponentKey =
                    @enumFromInt(FIRST_ROW + index);
                selected_logs[index] = (try manifest.placement(key))
                    .geometry.log_size;
            }
            var owners = try OwnersV4.init(allocator);
            errdefer owners.deinit();
            var result = @This(){
                .allocator = allocator,
                .rows = rows,
                .manifest = manifest,
                .log_sizes = selected_logs,
                .parameters = ParametersV4.role0(),
                .owners = owners,
            };
            try result.validate();
            return result;
        }

        pub fn deinit(self: *@This()) void {
            self.owners.deinit();
            self.* = undefined;
        }

        pub fn validate(self: *const @This()) !void {
            try self.rows.validate();
            try self.manifest.validate();
            try self.owners.validate();
            if (!std.meta.eql(self.parameters, ParametersV4.role0()))
                return mismatch();
            inline for (0..ROW_COUNT) |index| {
                const key: manifest_mod.ComponentKey =
                    @enumFromInt(FIRST_ROW + index);
                const placement = try self.manifest.placement(key);
                const source_logs = try self.rows.source.logSizes();
                if (self.log_sizes[index] < source_logs[index] or
                    self.log_sizes[index] >= 31 or
                    placement.geometry.log_size != self.log_sizes[index] or
                    !std.meta.eql(
                        placement.geometry,
                        expectedGeometry(key, self.log_sizes[index]),
                    ))
                {
                    return mismatch();
                }
            }
        }

        pub fn initComponents(
            self: *const @This(),
            relations: *const universal.UniversalRelations,
            claims: ClaimsV4,
        ) !ComponentsV4 {
            try self.validate();
            try relations.validate();
            return .{
                .statement_input = try StatementInputAdapter.init(
                    &self.owners.statement_input.definition,
                    self.owners.statement_input.relation,
                    self.manifest,
                    .statement_input,
                    self.log_sizes[0],
                    self.parameters.statement_input,
                    relations,
                    claims.values[0],
                ),
                .statement_semantics = try StatementSemanticsAdapter.init(
                    &self.owners.statement_semantics.definition,
                    self.owners.statement_semantics.relation,
                    self.manifest,
                    .statement_semantics_input,
                    self.log_sizes[1],
                    self.parameters.statement_semantics,
                    relations,
                    claims.values[1],
                ),
                .claim_input = try ClaimInputAdapter.init(
                    &self.owners.claim_input.definition,
                    self.owners.claim_input.relation,
                    self.manifest,
                    .vm_public_claim_input,
                    self.log_sizes[2],
                    self.parameters.claim_input,
                    relations,
                    claims.values[2],
                ),
                .claim_hash = try ClaimHashAdapter.init(
                    &self.owners.claim_hash.definition,
                    self.owners.claim_hash.relation,
                    self.manifest,
                    .vm_public_claim_hash,
                    self.log_sizes[3],
                    self.parameters.claim_hash,
                    relations,
                    claims.values[3],
                ),
                .io_hash = try IoHashAdapter.init(
                    &self.owners.io_hash.definition,
                    self.owners.io_hash.relation,
                    self.manifest,
                    .vm_public_io_hash,
                    self.log_sizes[4],
                    self.parameters.io_hash,
                    relations,
                    claims.values[4],
                ),
                .claim_semantics = try ClaimSemanticsAdapter.init(
                    &self.owners.claim_semantics.definition,
                    self.owners.claim_semantics.relation,
                    self.manifest,
                    .vm_public_claim_semantics_input,
                    self.log_sizes[5],
                    self.parameters.claim_semantics,
                    relations,
                    claims.values[5],
                ),
                .public_logup = try PublicLogupAdapter.init(
                    &self.owners.public_logup.definition,
                    self.owners.public_logup.relation,
                    self.manifest,
                    .vm_public_logup_input,
                    self.log_sizes[6],
                    self.parameters.public_logup,
                    relations,
                    claims.values[6],
                ),
                .public_logup_control = try PublicLogupControlAdapter.init(
                    &self.owners.public_logup_control.definition,
                    self.owners.public_logup_control.relation,
                    self.manifest,
                    .vm_public_logup_control,
                    self.log_sizes[7],
                    self.parameters.public_logup_control,
                    relations,
                    claims.values[7],
                ),
            };
        }
    };
}

pub const ParametersV4 = struct {
    statement_input: [StatementInputAdapter.PARAMETER_COLUMN_COUNT]M31,
    statement_semantics: [StatementSemanticsAdapter.PARAMETER_COLUMN_COUNT]M31,
    claim_input: [ClaimInputAdapter.PARAMETER_COLUMN_COUNT]M31,
    claim_hash: [ClaimHashAdapter.PARAMETER_COLUMN_COUNT]M31,
    io_hash: [IoHashAdapter.PARAMETER_COLUMN_COUNT]M31,
    claim_semantics: [ClaimSemanticsAdapter.PARAMETER_COLUMN_COUNT]M31,
    public_logup: [PublicLogupAdapter.PARAMETER_COLUMN_COUNT]M31,
    public_logup_control: [PublicLogupControlAdapter.PARAMETER_COLUMN_COUNT]M31,

    pub fn role0() ParametersV4 {
        const selectors = air.control_slice_witness.ProofKind.segment_leaf
            .selectors();
        return .{
            .statement_input = .{
                selectors[0],
                selectors[1],
                M31.fromCanonical(air.statement_input.STATEMENT_INPUT_KIND),
                M31.fromCanonical(air.statement_input.STATEMENT_INPUT_ITEM),
                M31.fromCanonical(
                    air.statement_input.VM_CLAIM_STATEMENT_SCOPE,
                ),
            },
            .statement_semantics = .{
                selectors[0],
                selectors[1],
                selectors[2],
                M31.zero(),
            },
            .claim_input = .{
                selectors[0],
                M31.fromCanonical(
                    air.vm_public_claim_input.VM_CLAIM_SEMANTICS_SCOPE,
                ),
                M31.fromCanonical(
                    air.vm_public_claim_input.VM_CLAIM_HASH_SCOPE,
                ),
                M31.fromCanonical(
                    air.vm_public_claim_input.VM_PUBLIC_LOGUP_SCOPE,
                ),
                M31.fromCanonical(
                    air.vm_public_claim_input.VM_PUBLIC_INPUT_KIND,
                ),
                M31.fromCanonical(
                    air.vm_public_claim_input.VM_PUBLIC_OUTPUT_KIND,
                ),
                M31.fromCanonical(air.vm_public_claim_input.LOW_BYTE_INDEX),
                M31.fromCanonical(air.vm_public_claim_input.HIGH_BYTE_INDEX),
            },
            .claim_hash = .{
                selectors[0],
                M31.fromCanonical(
                    air.vm_public_claim_hash.VM_PUBLIC_CLAIM_HASH_DOMAIN,
                ),
                M31.fromCanonical(
                    air.vm_public_claim_hash.VM_CLAIM_HASH_SCOPE,
                ),
                M31.fromCanonical(air.vm_public_claim_hash.SEGMENT_VERIFIER_ID),
                M31.fromCanonical(
                    air.vm_public_claim_hash.VM_PUBLIC_CLAIM_DIGEST_INPUT_KIND,
                ),
            },
            .io_hash = .{selectors[0]},
            .claim_semantics = .{
                selectors[0],
                M31.fromCanonical(
                    air.vm_public_claim_input.VM_CLAIM_SEMANTICS_SCOPE,
                ),
                M31.fromCanonical(
                    air.statement_input.VM_CLAIM_STATEMENT_SCOPE,
                ),
            },
            .public_logup = .{
                selectors[0],
                M31.fromCanonical(
                    air.vm_public_claim_input.VM_PUBLIC_LOGUP_SCOPE,
                ),
                M31.fromCanonical(
                    air.control_slice_witness.SEGMENT_VERIFIER_ID,
                ),
                M31.fromCanonical(
                    air.relation_challenge_witness
                        .VM_PUBLIC_LOGUP_CHALLENGE_SCOPE,
                ),
                M31.fromCanonical(@intFromEnum(
                    air.transcript_payload.VerifierInputKind.claimed_sum,
                )),
            },
            .public_logup_control = .{ selectors[0], selectors[1] },
        };
    }
};

fn AirOwner(comptime Air: type, comptime Relation: type) type {
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
            if (!std.meta.eql(expected, self.direct)) return mismatch();
        }

        fn deinit(self: *@This()) void {
            self.definition.deinit();
            self.* = undefined;
        }
    };
}

pub const OwnersV4 = struct {
    statement_input: AirOwner(air.statement_input, StatementInputRelation),
    statement_semantics: AirOwner(
        air.statement_semantics_input,
        StatementSemanticsRelation,
    ),
    claim_input: AirOwner(air.vm_public_claim_input, ClaimInputRelation),
    claim_hash: AirOwner(air.vm_public_claim_hash, ClaimHashRelation),
    io_hash: AirOwner(air.vm_public_io_hash, IoHashRelation),
    claim_semantics: AirOwner(
        air.vm_public_claim_semantics_input,
        ClaimSemanticsRelation,
    ),
    public_logup: AirOwner(air.vm_public_logup_input, PublicLogupRelation),
    public_logup_control: AirOwner(
        PublicLogupControlAir,
        PublicLogupControlRelation,
    ),

    fn init(allocator: std.mem.Allocator) !OwnersV4 {
        var statement_input = try AirOwner(
            air.statement_input,
            StatementInputRelation,
        ).init(allocator);
        errdefer statement_input.deinit();
        var statement_semantics = try AirOwner(
            air.statement_semantics_input,
            StatementSemanticsRelation,
        ).init(allocator);
        errdefer statement_semantics.deinit();
        var claim_input = try AirOwner(
            air.vm_public_claim_input,
            ClaimInputRelation,
        ).init(allocator);
        errdefer claim_input.deinit();
        var claim_hash = try AirOwner(
            air.vm_public_claim_hash,
            ClaimHashRelation,
        ).init(allocator);
        errdefer claim_hash.deinit();
        var io_hash = try AirOwner(
            air.vm_public_io_hash,
            IoHashRelation,
        ).init(allocator);
        errdefer io_hash.deinit();
        var claim_semantics = try AirOwner(
            air.vm_public_claim_semantics_input,
            ClaimSemanticsRelation,
        ).init(allocator);
        errdefer claim_semantics.deinit();
        var public_logup = try AirOwner(
            air.vm_public_logup_input,
            PublicLogupRelation,
        ).init(allocator);
        errdefer public_logup.deinit();
        var public_logup_control = try AirOwner(
            PublicLogupControlAir,
            PublicLogupControlRelation,
        ).init(allocator);
        errdefer public_logup_control.deinit();
        return .{
            .statement_input = statement_input,
            .statement_semantics = statement_semantics,
            .claim_input = claim_input,
            .claim_hash = claim_hash,
            .io_hash = io_hash,
            .claim_semantics = claim_semantics,
            .public_logup = public_logup,
            .public_logup_control = public_logup_control,
        };
    }

    fn validate(self: *const OwnersV4) !void {
        try self.statement_input.validate();
        try self.statement_semantics.validate();
        try self.claim_input.validate();
        try self.claim_hash.validate();
        try self.io_hash.validate();
        try self.claim_semantics.validate();
        try self.public_logup.validate();
        try self.public_logup_control.validate();
    }

    fn deinit(self: *OwnersV4) void {
        self.public_logup_control.deinit();
        self.public_logup.deinit();
        self.claim_semantics.deinit();
        self.io_hash.deinit();
        self.claim_hash.deinit();
        self.claim_input.deinit();
        self.statement_semantics.deinit();
        self.statement_input.deinit();
        self.* = undefined;
    }
};

fn expectedGeometry(
    key: manifest_mod.ComponentKey,
    log_size: u32,
) manifest_mod.Geometry {
    return switch (key) {
        .statement_input => StatementInputAdapter.manifestGeometry(
            .statement_input,
            log_size,
        ),
        .statement_semantics_input => StatementSemanticsAdapter.manifestGeometry(
            .statement_semantics_input,
            log_size,
        ),
        .vm_public_claim_input => ClaimInputAdapter.manifestGeometry(
            .vm_public_claim_input,
            log_size,
        ),
        .vm_public_claim_hash => ClaimHashAdapter.manifestGeometry(
            .vm_public_claim_hash,
            log_size,
        ),
        .vm_public_io_hash => IoHashAdapter.manifestGeometry(
            .vm_public_io_hash,
            log_size,
        ),
        .vm_public_claim_semantics_input => ClaimSemanticsAdapter.manifestGeometry(
            .vm_public_claim_semantics_input,
            log_size,
        ),
        .vm_public_logup_input => PublicLogupAdapter.manifestGeometry(
            .vm_public_logup_input,
            log_size,
        ),
        .vm_public_logup_control => PublicLogupControlAdapter.manifestGeometry(
            .vm_public_logup_control,
            log_size,
        ),
        else => unreachable,
    };
}

fn mismatch() Error {
    return error.EthereumIncrementalSuffixComponentsMismatchV4;
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or FIRST_ROW != 10 or
        LAST_ROW != 17 or ROW_COUNT != 8 or !ROWS_BASED_CONSTRUCTOR_AVAILABLE or
        PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum incremental suffix components V4 drifted");
    }
}
