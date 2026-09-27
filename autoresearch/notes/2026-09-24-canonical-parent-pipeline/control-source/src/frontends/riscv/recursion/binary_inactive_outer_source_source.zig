//! Internal shard of binary_inactive_outer_source.zig; use the public facade.

const dependency_0 = @import("binary_inactive_outer_source_claims.zig");
const dependency_2 = @import("binary_inactive_outer_source_stage.zig");

const std = dependency_0.std;
const M31 = dependency_0.M31;
const leaf_authority = dependency_0.leaf_authority;
const segment_source = dependency_0.segment_source;
const air = dependency_0.air;
const manifest_mod = dependency_0.manifest_mod;
const relation_interaction = dependency_0.relation_interaction;
const roster = dependency_0.roster;
const schedule = dependency_0.schedule;
const universal = dependency_0.universal;
const universal_manifest = dependency_0.universal_manifest;
const claim_input_air = dependency_0.claim_input_air;
const claim_input_witness = dependency_0.claim_input_witness;
const claim_hash_air = dependency_0.claim_hash_air;
const claim_hash_witness = dependency_0.claim_hash_witness;
const io_hash_air = dependency_0.io_hash_air;
const io_hash_witness = dependency_0.io_hash_witness;
const claim_semantics_air = dependency_0.claim_semantics_air;
const claim_semantics_witness = dependency_0.claim_semantics_witness;
const public_logup_air = dependency_0.public_logup_air;
const public_logup_witness = dependency_0.public_logup_witness;
const public_logup_control_air = dependency_0.public_logup_control_air;
const control_witness = dependency_0.control_witness;
const prepared_init = dependency_0.prepared_init;
const domain_audit = dependency_0.domain_audit;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const FIRST_ROW = dependency_0.FIRST_ROW;
const ROW_COUNT = dependency_0.ROW_COUNT;
const ClaimInputRelation = dependency_0.ClaimInputRelation;
const ClaimHashRelation = dependency_0.ClaimHashRelation;
const IoHashRelation = dependency_0.IoHashRelation;
const ClaimSemanticsRelation = dependency_0.ClaimSemanticsRelation;
const PublicLogupRelation = dependency_0.PublicLogupRelation;
const PublicLogupControlRelation = dependency_0.PublicLogupControlRelation;
const ClaimInputFramework = dependency_0.ClaimInputFramework;
const ClaimHashFramework = dependency_0.ClaimHashFramework;
const IoHashFramework = dependency_0.IoHashFramework;
const ClaimSemanticsFramework = dependency_0.ClaimSemanticsFramework;
const PublicLogupFramework = dependency_0.PublicLogupFramework;
const PublicLogupControlFramework = dependency_0.PublicLogupControlFramework;
const ClaimInputAdapter = dependency_0.ClaimInputAdapter;
const ClaimHashAdapter = dependency_0.ClaimHashAdapter;
const IoHashAdapter = dependency_0.IoHashAdapter;
const ClaimSemanticsAdapter = dependency_0.ClaimSemanticsAdapter;
const PublicLogupAdapter = dependency_0.PublicLogupAdapter;
const PublicLogupControlAdapter = dependency_0.PublicLogupControlAdapter;
const LogSizes = dependency_0.LogSizes;
const DomainAudits = dependency_0.DomainAudits;
const Parameters = dependency_0.Parameters;
const Claims = dependency_0.Claims;
const Components = dependency_0.Components;
const appendTupleContributions = dependency_2.appendTupleContributions;
const generateIntoStage = dependency_2.generateIntoStage;
const Stage = dependency_2.Stage;
const preflightDestination = dependency_2.preflightDestination;
const leafPreprocessingDigest = dependency_2.leafPreprocessingDigest;
const hashRows = dependency_2.hashRows;
const hashInt = dependency_2.hashInt;

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    claim_input: claim_input_witness.MainWitness,
    claim_hash: claim_hash_witness.MainWitness,
    io_hash: io_hash_witness.MainWitness,
    claim_semantics: claim_semantics_witness.MainWitness,
    public_logup: public_logup_witness.MainWitness,
    claim_input_rows: []ClaimInputRelation.Row,
    claim_hash_rows: []ClaimHashRelation.Row,
    io_hash_rows: []IoHashRelation.Row,
    claim_semantics_rows: []ClaimSemanticsRelation.Row,
    public_logup_rows: []PublicLogupRelation.Row,
    authority_seal: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        source: *const Source,
        typed: *const segment_source.Source,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        preprocessing: *const leaf_authority.Preprocessing,
    ) !Prepared {
        var result = try prepared_init.init(
            Prepared,
            allocator,
            source,
            typed,
            vm_plan,
            recursion_plan,
            preprocessing,
        );
        result.authority_seal = preparedDigest(&result, source);
        try result.validateAgainst(
            source,
            typed,
            vm_plan,
            recursion_plan,
            preprocessing,
        );
        return result;
    }

    pub fn deinit(self: *Prepared) void {
        self.allocator.free(self.public_logup_rows);
        self.allocator.free(self.claim_semantics_rows);
        self.allocator.free(self.io_hash_rows);
        self.allocator.free(self.claim_hash_rows);
        self.allocator.free(self.claim_input_rows);
        self.public_logup.deinit();
        self.claim_semantics.deinit();
        self.io_hash.deinit();
        self.claim_hash.deinit();
        self.claim_input.deinit();
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const Prepared,
        source: *const Source,
        typed: *const segment_source.Source,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        preprocessing: *const leaf_authority.Preprocessing,
    ) !void {
        try source.validateAgainst(typed, vm_plan, recursion_plan, preprocessing);
        try self.validateHotAgainstSealedPlans(
            source,
            typed,
            vm_plan,
            recursion_plan,
            preprocessing,
        );
    }

    /// Allocation-free continuation for sources whose complete schedules were
    /// authenticated at cold construction.
    pub fn validateHotAgainstSealedPlans(
        self: *const Prepared,
        source: *const Source,
        typed: *const segment_source.Source,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        preprocessing: *const leaf_authority.Preprocessing,
    ) !void {
        try source.validateHotAgainstSealedPlans(
            typed,
            vm_plan,
            recursion_plan,
            preprocessing,
        );
        try self.claim_input.validateAgainst(&preprocessing.claim_input);
        try self.claim_hash.validateAgainstSource(
            &preprocessing.claim_hash,
            .{ .binary_node = {} },
        );
        try self.io_hash.validateAgainstSource(
            &preprocessing.io_hash,
            .{ .binary_node = {} },
        );
        try self.claim_semantics.validateAgainst(
            &typed.claim_reference.row_preprocessing,
        );
        try self.public_logup.validateAgainst(&typed.public_logup_preprocessing);
        if (self.claim_input.proof_kind != .binary_node or
            self.claim_hash.proof_kind != .binary_node or
            self.io_hash.proof_kind != .binary_node or
            self.claim_semantics.proof_kind != .binary_node or
            self.public_logup.proof_kind != .binary_node)
        {
            return error.PreparedAuthorityMismatch;
        }
        try self.validateCachedRows(source, typed, preprocessing);
        if (!std.mem.eql(
            u8,
            &self.authority_seal,
            &preparedDigest(self, source),
        )) return error.PreparedAuthorityMismatch;
    }

    fn validateCachedRows(
        self: *const Prepared,
        source: *const Source,
        typed: *const segment_source.Source,
        preprocessing: *const leaf_authority.Preprocessing,
    ) !void {
        if (self.claim_input_rows.len != self.claim_input.rows.len or
            self.claim_hash_rows.len != self.claim_hash.rows.len or
            self.io_hash_rows.len != self.io_hash.rows.len or
            self.claim_semantics_rows.len != self.claim_semantics.rows.len or
            self.public_logup_rows.len != self.public_logup.rows.len)
        {
            return error.PreparedAuthorityMismatch;
        }
        for (
            self.claim_input_rows,
            self.claim_input.rows,
            preprocessing.claim_input.rows,
        ) |actual, main, pp| if (!std.meta.eql(
            actual,
            claim_input_witness.logicalInputs(main, pp, .binary_node),
        )) return error.PreparedAuthorityMismatch;
        for (
            self.claim_hash_rows,
            self.claim_hash.rows,
            preprocessing.claim_hash.rows,
        ) |actual, main, pp| if (!std.meta.eql(
            actual,
            claim_hash_witness.logicalInputs(main, pp, .binary_node),
        )) return error.PreparedAuthorityMismatch;
        for (
            self.io_hash_rows,
            self.io_hash.rows,
            preprocessing.io_hash.rows,
        ) |actual, main, pp| if (!std.meta.eql(
            actual,
            io_hash_witness.logicalInputs(main, pp, .binary_node),
        )) return error.PreparedAuthorityMismatch;
        for (
            self.claim_semantics_rows,
            self.claim_semantics.rows,
            typed.claim_reference.row_preprocessing.rows,
        ) |actual, main, pp| if (!std.meta.eql(
            actual,
            claim_semantics_witness.logicalInputs(
                main,
                pp,
                .binary_node,
                source.parameters.claim_semantics[1],
                source.parameters.claim_semantics[2],
            ),
        )) return error.PreparedAuthorityMismatch;
        for (
            self.public_logup_rows,
            self.public_logup.rows,
            typed.public_logup_preprocessing.rows,
        ) |actual, main, pp| if (!std.meta.eql(
            actual,
            public_logup_witness.logicalInputs(
                main,
                pp,
                .binary_node,
                source.parameters.public_logup[1],
                source.parameters.public_logup[2],
                source.parameters.public_logup[3],
                source.parameters.public_logup[4],
            ),
        )) return error.PreparedAuthorityMismatch;
    }
};

pub const Source = struct {
    allocator: std.mem.Allocator,
    typed_authority_seal: [32]u8,
    vm_schedule_digest: [8]u32,
    recursion_schedule_digest: [8]u32,
    leaf_preprocessing_digest: [32]u8,
    parameters: Parameters,
    log_sizes: LogSizes,
    public_logup_control_rows: []PublicLogupControlRelation.Row,
    authority_seal: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        typed: *const segment_source.Source,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        preprocessing: *const leaf_authority.Preprocessing,
    ) !Source {
        try typed.validateAgainst(vm_plan, recursion_plan, preprocessing);
        const rows = try allocator.alloc(
            PublicLogupControlRelation.Row,
            typed.public_logup_control.rows.len,
        );
        errdefer allocator.free(rows);
        for (rows, typed.public_logup_control.rows) |*destination, row|
            destination.* = control_witness.logicalRow(row, .binary_node);

        var result = Source{
            .allocator = allocator,
            .typed_authority_seal = typed.authority_seal,
            .vm_schedule_digest = vm_plan.authority_digest,
            .recursion_schedule_digest = recursion_plan.authority_digest,
            .leaf_preprocessing_digest = leafPreprocessingDigest(preprocessing),
            .parameters = Parameters.binaryNode(),
            .log_sizes = typed.log_sizes,
            .public_logup_control_rows = rows,
            .authority_seal = undefined,
        };
        result.authority_seal = sourceDigest(&result);
        try result.validateAgainst(typed, vm_plan, recursion_plan, preprocessing);
        return result;
    }

    pub fn deinit(self: *Source) void {
        self.allocator.free(self.public_logup_control_rows);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const Source,
        typed: *const segment_source.Source,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        preprocessing: *const leaf_authority.Preprocessing,
    ) !void {
        try typed.validateAgainst(vm_plan, recursion_plan, preprocessing);
        try self.validateHotAgainstSealedPlans(
            typed,
            vm_plan,
            recursion_plan,
            preprocessing,
        );
    }

    /// Allocation-free revalidation of the retained binary rows after cold
    /// plan admission. The source reads no live schedule step during a tree
    /// fill; it binds their authenticated digests and the typed cached rows.
    pub fn validateHotAgainstSealedPlans(
        self: *const Source,
        typed: *const segment_source.Source,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        preprocessing: *const leaf_authority.Preprocessing,
    ) !void {
        try typed.validateHotAgainstSealedPlans(
            vm_plan,
            recursion_plan,
            preprocessing,
        );
        if (!std.mem.eql(u8, &self.typed_authority_seal, &typed.authority_seal) or
            !std.meta.eql(self.vm_schedule_digest, vm_plan.authority_digest) or
            !std.meta.eql(
                self.recursion_schedule_digest,
                recursion_plan.authority_digest,
            ) or
            !std.mem.eql(
                u8,
                &self.leaf_preprocessing_digest,
                &leafPreprocessingDigest(preprocessing),
            ) or
            !std.meta.eql(self.parameters, Parameters.binaryNode()) or
            !std.meta.eql(self.log_sizes, typed.log_sizes) or
            self.public_logup_control_rows.len !=
                typed.public_logup_control.rows.len)
        {
            return error.AuthorityMismatch;
        }
        for (
            self.public_logup_control_rows,
            typed.public_logup_control.rows,
        ) |actual, row| if (!std.meta.eql(
            actual,
            control_witness.logicalRow(row, .binary_node),
        )) return error.AuthorityMismatch;
        if (!std.mem.eql(u8, &self.authority_seal, &sourceDigest(self)))
            return error.AuthorityMismatch;
    }

    pub fn installLogSizes(
        self: *const Source,
        destination: *universal_manifest.LogSizes,
    ) void {
        inline for (0..ROW_COUNT) |index|
            destination[FIRST_ROW + index] = self.log_sizes[index];
    }

    pub fn validateManifest(
        self: *const Source,
        manifest: *const manifest_mod.Manifest,
    ) !void {
        try manifest.validate();
        inline for (0..ROW_COUNT) |index| {
            const row: roster.Component = @enumFromInt(FIRST_ROW + index);
            const placement = try manifest.placement(row);
            if (placement.geometry.roster_row != FIRST_ROW + index or
                placement.geometry.log_size != self.log_sizes[index])
            {
                return error.ManifestGeometryMismatch;
            }
        }
    }

    pub fn fillPreprocessedInto(
        self: *const Source,
        typed: *const segment_source.Source,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        preprocessing: *const leaf_authority.Preprocessing,
        manifest: *const manifest_mod.Manifest,
        destination: []const []M31,
    ) !void {
        try self.validateAgainst(typed, vm_plan, recursion_plan, preprocessing);
        try self.validateManifest(manifest);
        try preflightDestination(
            manifest,
            manifest_mod.PREPROCESSED_TREE_INDEX,
            destination,
        );
        var stage = try Stage.init(
            self.allocator,
            manifest,
            manifest_mod.PREPROCESSED_TREE_INDEX,
        );
        defer stage.deinit();

        var row12 = try stage.columns(
            claim_input_air.PREPROCESSED_COLUMN_COUNT,
            .vm_public_claim_input,
        );
        try preprocessing.claim_input.generateInto(
            &row12,
            &typed.executors.claim_input,
        );
        var row13 = try stage.columns(
            claim_hash_air.PREPROCESSED_COLUMN_COUNT,
            .vm_public_claim_hash,
        );
        try typed.executors.claim_hash.generatePreprocessedInto(
            &preprocessing.claim_hash,
            &row13,
        );
        var row14 = try stage.columns(
            io_hash_air.PREPROCESSED_COLUMN_COUNT,
            .vm_public_io_hash,
        );
        try typed.executors.io_hash.generatePreprocessedInto(
            &preprocessing.io_hash,
            &row14,
        );
        var row15 = try stage.columns(
            claim_semantics_air.PREPROCESSED_COLUMN_COUNT,
            .vm_public_claim_semantics_input,
        );
        try typed.claim_reference.row_preprocessing.generateInto(
            &row15,
            try self.claimSemanticsReference(typed),
        );
        var row16 = try stage.columns(
            public_logup_air.PREPROCESSED_COLUMN_COUNT,
            .vm_public_logup_input,
        );
        try typed.public_logup_preprocessing.generateInto(
            &row16,
            try self.publicLogupReference(typed),
        );
        var row17 = try stage.columns(
            public_logup_control_air.PREPROCESSED_COLUMN_COUNT,
            .vm_public_logup_control,
        );
        try typed.public_logup_control.generateInto(
            &row17,
            vm_plan,
            recursion_plan,
        );
        stage.commit(manifest, destination);
    }

    pub fn fillMainInto(
        self: *const Source,
        typed: *const segment_source.Source,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        preprocessing: *const leaf_authority.Preprocessing,
        prepared: *const Prepared,
        manifest: *const manifest_mod.Manifest,
        destination: []const []M31,
    ) !void {
        try prepared.validateAgainst(
            self,
            typed,
            vm_plan,
            recursion_plan,
            preprocessing,
        );
        try self.validateManifest(manifest);
        try preflightDestination(
            manifest,
            manifest_mod.MAIN_TREE_INDEX,
            destination,
        );
        var stage = try Stage.init(
            self.allocator,
            manifest,
            manifest_mod.MAIN_TREE_INDEX,
        );
        defer stage.deinit();

        var row12 = try stage.columns(
            claim_input_air.PHYSICAL_MAIN_COLUMN_COUNT,
            .vm_public_claim_input,
        );
        try prepared.claim_input.generateInto(
            &row12,
            &preprocessing.claim_input,
            &typed.executors.claim_input,
        );
        var row13 = try stage.columns(
            claim_hash_air.PHYSICAL_MAIN_COLUMN_COUNT,
            .vm_public_claim_hash,
        );
        try typed.executors.claim_hash.generateMainInto(
            &prepared.claim_hash,
            &preprocessing.claim_hash,
            &row13,
        );
        var row14 = try stage.columns(
            io_hash_air.PHYSICAL_MAIN_COLUMN_COUNT,
            .vm_public_io_hash,
        );
        try typed.executors.io_hash.generateMainInto(
            &prepared.io_hash,
            &preprocessing.io_hash,
            &row14,
        );
        var row15 = try stage.columns(
            claim_semantics_air.PHYSICAL_MAIN_COLUMN_COUNT,
            .vm_public_claim_semantics_input,
        );
        try prepared.claim_semantics.generateInto(
            &row15,
            &typed.claim_reference.row_preprocessing,
        );
        var row16 = try stage.columns(
            public_logup_air.PHYSICAL_MAIN_COLUMN_COUNT,
            .vm_public_logup_input,
        );
        try prepared.public_logup.generateInto(
            &row16,
            &typed.public_logup_preprocessing,
        );
        stage.commit(manifest, destination);
    }

    pub fn fillInteractionInto(
        self: *const Source,
        typed: *const segment_source.Source,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        preprocessing: *const leaf_authority.Preprocessing,
        prepared: *const Prepared,
        manifest: *const manifest_mod.Manifest,
        relations: *const universal.UniversalRelations,
        destination: []const []M31,
    ) !Claims {
        try prepared.validateAgainst(
            self,
            typed,
            vm_plan,
            recursion_plan,
            preprocessing,
        );
        try self.validateManifest(manifest);
        try relations.validate();
        try preflightDestination(
            manifest,
            manifest_mod.INTERACTION_TREE_INDEX,
            destination,
        );
        var stage = try Stage.init(
            self.allocator,
            manifest,
            manifest_mod.INTERACTION_TREE_INDEX,
        );
        defer stage.deinit();

        const claims = Claims{
            .claim_input = try generateIntoStage(
                ClaimInputFramework,
                self.allocator,
                &typed.owners.claim_input.relation,
                prepared.claim_input_rows,
                self.log_sizes[0],
                relations,
                &stage,
                .vm_public_claim_input,
            ),
            .claim_hash = try generateIntoStage(
                ClaimHashFramework,
                self.allocator,
                &typed.owners.claim_hash.relation,
                prepared.claim_hash_rows,
                self.log_sizes[1],
                relations,
                &stage,
                .vm_public_claim_hash,
            ),
            .io_hash = try generateIntoStage(
                IoHashFramework,
                self.allocator,
                &typed.owners.io_hash.relation,
                prepared.io_hash_rows,
                self.log_sizes[2],
                relations,
                &stage,
                .vm_public_io_hash,
            ),
            .claim_semantics = try generateIntoStage(
                ClaimSemanticsFramework,
                self.allocator,
                &typed.owners.claim_semantics.relation,
                prepared.claim_semantics_rows,
                self.log_sizes[3],
                relations,
                &stage,
                .vm_public_claim_semantics_input,
            ),
            .public_logup = try generateIntoStage(
                PublicLogupFramework,
                self.allocator,
                &typed.owners.public_logup.relation,
                prepared.public_logup_rows,
                self.log_sizes[4],
                relations,
                &stage,
                .vm_public_logup_input,
            ),
            .public_logup_control = try generateIntoStage(
                PublicLogupControlFramework,
                self.allocator,
                &typed.owners.public_logup_control.relation,
                self.public_logup_control_rows,
                self.log_sizes[5],
                relations,
                &stage,
                .vm_public_logup_control,
            ),
        };
        try claims.validateInactive();
        stage.commit(manifest, destination);
        return claims;
    }

    pub fn auditInteractionDomains(
        self: *const Source,
        typed: *const segment_source.Source,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        preprocessing: *const leaf_authority.Preprocessing,
        prepared: *const Prepared,
        relations: *const universal.UniversalRelations,
        claims: Claims,
        tuple_ledger: ?*relation_interaction.TupleLedger,
    ) !DomainAudits {
        return domain_audit.audit(
            self,
            typed,
            vm_plan,
            recursion_plan,
            preprocessing,
            prepared,
            relations,
            claims,
            tuple_ledger,
            DomainAudits,
            appendTupleContributions,
        );
    }

    pub fn initComponents(
        self: *const Source,
        typed: *const segment_source.Source,
        manifest: *const manifest_mod.Manifest,
        relations: *const universal.UniversalRelations,
        claims: Claims,
    ) !Components {
        try self.validateManifest(manifest);
        try claims.validateInactive();
        try relations.validate();
        return .{
            .claim_input = try ClaimInputAdapter.init(
                &typed.owners.claim_input.definition,
                typed.owners.claim_input.relation,
                manifest,
                .vm_public_claim_input,
                self.log_sizes[0],
                self.parameters.claim_input,
                relations,
                claims.claim_input,
            ),
            .claim_hash = try ClaimHashAdapter.init(
                &typed.owners.claim_hash.definition,
                typed.owners.claim_hash.relation,
                manifest,
                .vm_public_claim_hash,
                self.log_sizes[1],
                self.parameters.claim_hash,
                relations,
                claims.claim_hash,
            ),
            .io_hash = try IoHashAdapter.init(
                &typed.owners.io_hash.definition,
                typed.owners.io_hash.relation,
                manifest,
                .vm_public_io_hash,
                self.log_sizes[2],
                self.parameters.io_hash,
                relations,
                claims.io_hash,
            ),
            .claim_semantics = try ClaimSemanticsAdapter.init(
                &typed.owners.claim_semantics.definition,
                typed.owners.claim_semantics.relation,
                manifest,
                .vm_public_claim_semantics_input,
                self.log_sizes[3],
                self.parameters.claim_semantics,
                relations,
                claims.claim_semantics,
            ),
            .public_logup = try PublicLogupAdapter.init(
                &typed.owners.public_logup.definition,
                typed.owners.public_logup.relation,
                manifest,
                .vm_public_logup_input,
                self.log_sizes[4],
                self.parameters.public_logup,
                relations,
                claims.public_logup,
            ),
            .public_logup_control = try PublicLogupControlAdapter.init(
                &typed.owners.public_logup_control.definition,
                typed.owners.public_logup_control.relation,
                manifest,
                .vm_public_logup_control,
                self.log_sizes[5],
                self.parameters.public_logup_control,
                relations,
                claims.public_logup_control,
            ),
        };
    }

    pub fn claimSemanticsReference(
        _: *const Source,
        typed: *const segment_source.Source,
    ) !claim_semantics_witness.Reference {
        return claim_semantics_witness.Reference.seal(
            typed.claim_reference.circuit_id,
            typed.claim_reference.row_bindings,
        );
    }

    pub fn publicLogupReference(
        _: *const Source,
        typed: *const segment_source.Source,
    ) !public_logup_witness.Reference {
        return public_logup_witness.Reference.seal(
            typed.logup_reference.circuit_id,
            typed.logup_reference.claim_kinds,
            typed.logup_reference.claimed_sum_count,
            typed.logup_reference.row_bindings,
        );
    }
};

pub fn sourceDigest(source: *const Source) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/binary-inactive-outer-source/v1\x00");
    hashInt(&hash, u16, FORMAT_VERSION);
    hash.update(&source.typed_authority_seal);
    for (source.vm_schedule_digest) |word| hashInt(&hash, u32, word);
    for (source.recursion_schedule_digest) |word| hashInt(&hash, u32, word);
    hash.update(&source.leaf_preprocessing_digest);
    inline for (std.meta.fields(Parameters)) |field| {
        for (@field(source.parameters, field.name)) |word|
            hashInt(&hash, u32, word.toU32());
    }
    for (source.log_sizes) |value| hashInt(&hash, u32, value);
    hashRows(&hash, source.public_logup_control_rows);
    return hash.finalResult();
}

pub fn preparedDigest(prepared: *const Prepared, source: *const Source) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/binary-inactive-outer-prepared/v1\x00");
    hash.update(&source.authority_seal);
    hashRows(&hash, prepared.claim_input_rows);
    hashRows(&hash, prepared.claim_hash_rows);
    hashRows(&hash, prepared.io_hash_rows);
    hashRows(&hash, prepared.claim_semantics_rows);
    hashRows(&hash, prepared.public_logup_rows);
    return hash.finalResult();
}
