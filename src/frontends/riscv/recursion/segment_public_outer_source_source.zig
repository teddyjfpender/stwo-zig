//! Internal shard of segment_public_outer_source.zig; use the public facade.

const dependency_0 = @import("segment_public_outer_source_owners.zig");
const dependency_2 = @import("segment_public_outer_source_stage.zig");

const std = dependency_0.std;
const M31 = dependency_0.M31;
const QM31 = dependency_0.QM31;
const public_data_mod = dependency_0.public_data_mod;
const native_relation_challenges = dependency_0.native_relation_challenges;
const leaf_authority = dependency_0.leaf_authority;
const semantics = dependency_0.semantics;
const arithmetic = dependency_0.arithmetic;
const air = dependency_0.air;
const relation_interaction = dependency_0.relation_interaction;
const manifest_mod = dependency_0.manifest_mod;
const roster = dependency_0.roster;
const schedule = dependency_0.schedule;
const universal = dependency_0.universal;
const universal_manifest = dependency_0.universal_manifest;
const lowering = dependency_0.lowering;
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
const CLAIM_CIRCUIT_ID = dependency_0.CLAIM_CIRCUIT_ID;
const PUBLIC_LOGUP_CIRCUIT_ID = dependency_0.PUBLIC_LOGUP_CIRCUIT_ID;
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
const Owners = dependency_0.Owners;
const Executors = dependency_0.Executors;
const OwnedGraph = dependency_0.OwnedGraph;
const appendTupleContributions = dependency_2.appendTupleContributions;
const generateIntoStage = dependency_2.generateIntoStage;
const Stage = dependency_2.Stage;
const preflightDestination = dependency_2.preflightDestination;
const baseValue = dependency_2.baseValue;
const validateArithmeticEvaluation = dependency_2.validateArithmeticEvaluation;
const planClaimedSumCount = dependency_2.planClaimedSumCount;
const slicesOverlapBytes = dependency_2.slicesOverlapBytes;
const leafPreprocessingDigest = dependency_2.leafPreprocessingDigest;
const hashParameters = dependency_2.hashParameters;
const hashM31Rows = dependency_2.hashM31Rows;
const hashMainRows = dependency_2.hashMainRows;
const hashM31Slice = dependency_2.hashM31Slice;
const hashQM31Slice = dependency_2.hashQM31Slice;
const hashInt = dependency_2.hashInt;

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    claim_semantics: semantics.ClaimPrepared,
    public_logup: semantics.LogupPrepared,
    public_logup_main: public_logup_witness.MainWitness,
    claim_input_rows: []ClaimInputRelation.Row,
    claim_hash_rows: []ClaimHashRelation.Row,
    io_hash_rows: []IoHashRelation.Row,
    claim_semantics_rows: []ClaimSemanticsRelation.Row,
    public_logup_rows: []PublicLogupRelation.Row,
    authority_seal: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        source: *const Source,
        preprocessing: *const leaf_authority.Preprocessing,
        leaf: *const leaf_authority.Prepared,
        data: *const public_data_mod.PublicData,
        native_relations: *const native_relation_challenges.Relations,
        claimed_sums: []const QM31,
    ) !Prepared {
        var result = try prepared_init.init(
            Prepared,
            allocator,
            source,
            preprocessing,
            leaf,
            data,
            native_relations,
            claimed_sums,
            baseValue,
        );
        result.authority_seal = preparedDigest(&result, source, leaf);
        try result.validateAgainst(source, preprocessing, leaf, data);
        return result;
    }

    pub fn deinit(self: *Prepared) void {
        self.allocator.free(self.public_logup_rows);
        self.allocator.free(self.claim_semantics_rows);
        self.allocator.free(self.io_hash_rows);
        self.allocator.free(self.claim_hash_rows);
        self.allocator.free(self.claim_input_rows);
        self.public_logup_main.deinit();
        self.public_logup.deinit();
        self.claim_semantics.deinit();
        self.* = undefined;
    }

    /// Allocation-free sealed-graph and cached-row mutation admission.
    pub fn validateAgainst(
        self: *const Prepared,
        source: *const Source,
        preprocessing: *const leaf_authority.Preprocessing,
        leaf: *const leaf_authority.Prepared,
        data: *const public_data_mod.PublicData,
    ) !void {
        try source.validateLeaf(preprocessing);
        try leaf.validateAgainst(preprocessing, data);
        try self.claim_semantics.validateAgainst(&source.claim_reference);
        if (!std.mem.eql(
            u8,
            &self.public_logup.authority_digest,
            &source.logup_reference.authority_digest,
        ) or !try source.logup_reference.circuit.outputsAreZero(
            self.public_logup.evaluation.values,
        )) return error.PreparedAuthorityMismatch;
        try self.public_logup_main.validateAgainst(&source.public_logup_preprocessing);
        try validateArithmeticEvaluation(
            &source.claim_reference.circuit,
            self.claim_semantics.input_values,
            self.claim_semantics.evaluation.values,
        );
        try validateArithmeticEvaluation(
            &source.logup_reference.circuit,
            self.public_logup.input_values,
            self.public_logup.evaluation.values,
        );
        for (
            source.claim_reference.circuit.inputNodes(),
            self.claim_semantics.input_values,
            self.claim_semantics.row_witness.rows,
        ) |node_id, value, main| {
            if (!self.claim_semantics.evaluation.values[node_id].eql(value) or
                !main.value.eql(try baseValue(value)))
            {
                return error.PreparedAuthorityMismatch;
            }
        }
        for (
            source.logup_reference.circuit.inputNodes(),
            self.public_logup.input_values,
            self.public_logup_main.rows,
        ) |node_id, value, main| {
            if (!self.public_logup.evaluation.values[node_id].eql(value) or
                !main.value.eql(try baseValue(value)))
            {
                return error.PreparedAuthorityMismatch;
            }
        }
        try self.validateCachedRows(source, preprocessing, leaf);
        if (!std.mem.eql(
            u8,
            &self.authority_seal,
            &preparedDigest(self, source, leaf),
        )) return error.PreparedAuthorityMismatch;
    }

    fn validateCachedRows(
        self: *const Prepared,
        source: *const Source,
        preprocessing: *const leaf_authority.Preprocessing,
        leaf: *const leaf_authority.Prepared,
    ) !void {
        if (self.claim_input_rows.len != preprocessing.claim_input.rows.len or
            self.claim_hash_rows.len != preprocessing.claim_hash.rows.len or
            self.io_hash_rows.len != preprocessing.io_hash.rows.len or
            self.claim_semantics_rows.len != source.claim_reference.row_preprocessing.rows.len or
            self.public_logup_rows.len != source.public_logup_preprocessing.rows.len)
        {
            return error.PreparedAuthorityMismatch;
        }
        for (
            self.claim_input_rows,
            leaf.claim_input.rows,
            preprocessing.claim_input.rows,
        ) |actual, main, pp| if (!std.meta.eql(
            actual,
            claim_input_witness.logicalInputs(main, pp, .segment_leaf),
        )) return error.PreparedAuthorityMismatch;
        for (
            self.claim_hash_rows,
            leaf.claim_hash.rows,
            preprocessing.claim_hash.rows,
        ) |actual, main, pp| if (!std.meta.eql(
            actual,
            claim_hash_witness.logicalInputs(main, pp, .segment_leaf),
        )) return error.PreparedAuthorityMismatch;
        for (
            self.io_hash_rows,
            leaf.io_hash.rows,
            preprocessing.io_hash.rows,
        ) |actual, main, pp| if (!std.meta.eql(
            actual,
            io_hash_witness.logicalInputs(main, pp, .segment_leaf),
        )) return error.PreparedAuthorityMismatch;
        for (
            self.claim_semantics_rows,
            self.claim_semantics.row_witness.rows,
            source.claim_reference.row_preprocessing.rows,
        ) |actual, main, pp| if (!std.meta.eql(
            actual,
            claim_semantics_witness.logicalInputs(
                main,
                pp,
                .segment_leaf,
                source.parameters.claim_semantics[1],
                source.parameters.claim_semantics[2],
            ),
        )) return error.PreparedAuthorityMismatch;
        for (
            self.public_logup_rows,
            self.public_logup_main.rows,
            source.public_logup_preprocessing.rows,
        ) |actual, main, pp| if (!std.meta.eql(
            actual,
            public_logup_witness.logicalInputs(
                main,
                pp,
                .segment_leaf,
                source.parameters.public_logup[1],
                source.parameters.public_logup[2],
                source.parameters.public_logup[3],
                source.parameters.public_logup[4],
            ),
        )) return error.PreparedAuthorityMismatch;
    }

    pub fn loweringEvaluations(
        self: *const Prepared,
        source: *const Source,
    ) [2]lowering.Evaluation {
        return .{
            .{
                .circuit_identity = source.claim_reference.authority_digest,
                .values = self.claim_semantics.evaluation.values,
            },
            .{
                .circuit_identity = source.logup_reference.authority_digest,
                .values = self.public_logup.evaluation.values,
            },
        };
    }

    pub fn poseidonCallCount(self: *const Prepared, leaf: *const leaf_authority.Prepared) usize {
        _ = self;
        return leaf.claim_hash.poseidon_calls.len + leaf.io_hash.poseidon_calls.len;
    }

    /// Allocation-free append into a non-aliasing shared Poseidon-call lane.
    pub fn appendPoseidonCallsInto(
        self: *const Prepared,
        leaf: *const leaf_authority.Prepared,
        destination: []claim_hash_witness.PoseidonCall,
    ) !void {
        const count = self.poseidonCallCount(leaf);
        if (destination.len != count) return error.PoseidonCallCountMismatch;
        if (slicesOverlapBytes(destination, leaf.claim_hash.poseidon_calls) or
            slicesOverlapBytes(destination, leaf.io_hash.poseidon_calls))
        {
            return error.AliasedDestination;
        }
        @memcpy(destination[0..leaf.claim_hash.poseidon_calls.len], leaf.claim_hash.poseidon_calls);
        @memcpy(destination[leaf.claim_hash.poseidon_calls.len..], leaf.io_hash.poseidon_calls);
    }
};

pub const Source = struct {
    allocator: std.mem.Allocator,
    shape: claim_input_witness.Shape,
    claimed_sum_count: u32,
    vm_schedule_digest: [8]u32,
    recursion_schedule_digest: [8]u32,
    leaf_preprocessing_digest: [32]u8,
    parameters: Parameters,
    log_sizes: LogSizes,
    owners: Owners,
    executors: Executors,
    claim_reference: semantics.ClaimReference,
    logup_reference: semantics.LogupReference,
    public_logup_preprocessing: public_logup_witness.Preprocessed,
    public_logup_control: control_witness.PublicLogupPreprocessed,
    public_logup_control_rows: []PublicLogupControlRelation.Row,
    claim_graph: OwnedGraph,
    logup_graph: OwnedGraph,
    authority_seal: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        preprocessing: *const leaf_authority.Preprocessing,
        claimed_sum_count: u32,
    ) !Source {
        try vm_plan.validate();
        try recursion_plan.validate();
        try preprocessing.validate();
        const shape = preprocessing.claim_input.shape;
        if (claimed_sum_count != try planClaimedSumCount(vm_plan))
            return error.ClaimedSumCountMismatch;

        var claim_reference = try semantics.ClaimReference.init(
            allocator,
            shape,
            CLAIM_CIRCUIT_ID,
        );
        errdefer claim_reference.deinit();
        var logup_reference = try semantics.LogupReference.init(
            allocator,
            shape,
            PUBLIC_LOGUP_CIRCUIT_ID,
            claimed_sum_count,
        );
        errdefer logup_reference.deinit();
        const row16_reference = try public_logup_witness.Reference.seal(
            logup_reference.circuit_id,
            logup_reference.claim_kinds,
            logup_reference.claimed_sum_count,
            logup_reference.row_bindings,
        );
        var public_logup_preprocessing = try public_logup_witness.Preprocessed.init(
            allocator,
            row16_reference,
        );
        errdefer public_logup_preprocessing.deinit();
        var public_logup_control = try logup_reference.prepareRow17(
            allocator,
            vm_plan,
            recursion_plan,
        );
        errdefer public_logup_control.deinit();

        var owners = try Owners.init(allocator);
        errdefer owners.deinit();
        const executors = try Executors.init(&owners);
        var claim_graph = try OwnedGraph.init(allocator, &claim_reference.circuit);
        errdefer claim_graph.deinit();
        var logup_graph = try OwnedGraph.init(allocator, &logup_reference.circuit);
        errdefer logup_graph.deinit();

        const control_rows = try allocator.alloc(
            PublicLogupControlRelation.Row,
            public_logup_control.rows.len,
        );
        errdefer allocator.free(control_rows);
        for (control_rows, public_logup_control.rows) |*destination, row|
            destination.* = control_witness.logicalRow(row, .segment_leaf);

        const log_sizes = LogSizes{
            preprocessing.claim_input.log_size,
            preprocessing.claim_hash.log_size,
            preprocessing.io_hash.log_size,
            claim_reference.row_preprocessing.log_size,
            public_logup_preprocessing.log_size,
            public_logup_control.log_size,
        };
        var result = Source{
            .allocator = allocator,
            .shape = shape,
            .claimed_sum_count = claimed_sum_count,
            .vm_schedule_digest = vm_plan.authority_digest,
            .recursion_schedule_digest = recursion_plan.authority_digest,
            .leaf_preprocessing_digest = leafPreprocessingDigest(preprocessing),
            .parameters = Parameters.segmentLeaf(),
            .log_sizes = log_sizes,
            .owners = owners,
            .executors = executors,
            .claim_reference = claim_reference,
            .logup_reference = logup_reference,
            .public_logup_preprocessing = public_logup_preprocessing,
            .public_logup_control = public_logup_control,
            .public_logup_control_rows = control_rows,
            .claim_graph = claim_graph,
            .logup_graph = logup_graph,
            .authority_seal = undefined,
        };
        result.authority_seal = sourceDigest(&result);
        try result.validateAgainst(vm_plan, recursion_plan, preprocessing);
        return result;
    }

    pub fn deinit(self: *Source) void {
        self.logup_graph.deinit();
        self.claim_graph.deinit();
        self.allocator.free(self.public_logup_control_rows);
        self.public_logup_control.deinit();
        self.public_logup_preprocessing.deinit();
        self.logup_reference.deinit();
        self.claim_reference.deinit();
        self.owners.deinit();
        self.* = undefined;
    }

    pub fn installLogSizes(self: *const Source, destination: *universal_manifest.LogSizes) void {
        inline for (0..ROW_COUNT) |index| destination[FIRST_ROW + index] = self.log_sizes[index];
    }

    pub fn validateAgainst(
        self: *const Source,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        preprocessing: *const leaf_authority.Preprocessing,
    ) !void {
        try vm_plan.validate();
        try recursion_plan.validate();
        try self.validateHotAgainstSealedPlans(
            vm_plan,
            recursion_plan,
            preprocessing,
        );
    }

    /// Hot revalidation of cached rows and public-LogUp schedule slices.
    pub fn validateHotAgainstSealedPlans(
        self: *const Source,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        preprocessing: *const leaf_authority.Preprocessing,
    ) !void {
        try self.validateLeaf(preprocessing);
        if (!std.meta.eql(self.vm_schedule_digest, vm_plan.authority_digest) or
            !std.meta.eql(self.recursion_schedule_digest, recursion_plan.authority_digest))
        {
            return error.ScheduleAuthorityMismatch;
        }
        try self.claim_reference.validate();
        try self.logup_reference.validate();
        try self.public_logup_preprocessing.validateAgainst(try self.logupRowReference());
        try self.public_logup_control.validateAgainstSealedPlans(
            vm_plan,
            recursion_plan,
        );
        try self.owners.validate();
        try self.executors.validate(&self.owners);
        try self.claim_graph.validate();
        try self.logup_graph.validate();
        if (!std.meta.eql(self.parameters, Parameters.segmentLeaf()) or
            !std.mem.eql(u8, &self.authority_seal, &sourceDigest(self)))
        {
            return error.PreparedAuthorityMismatch;
        }
    }

    fn validateLeaf(
        self: *const Source,
        preprocessing: *const leaf_authority.Preprocessing,
    ) !void {
        try preprocessing.validate();
        if (!std.meta.eql(self.shape, preprocessing.claim_input.shape) or
            !std.mem.eql(
                u8,
                &self.leaf_preprocessing_digest,
                &leafPreprocessingDigest(preprocessing),
            ) or self.log_sizes[0] != preprocessing.claim_input.log_size or
            self.log_sizes[1] != preprocessing.claim_hash.log_size or
            self.log_sizes[2] != preprocessing.io_hash.log_size)
        {
            return error.PreparedAuthorityMismatch;
        }
    }

    fn logupRowReference(self: *const Source) !public_logup_witness.Reference {
        return public_logup_witness.Reference.seal(
            self.logup_reference.circuit_id,
            self.logup_reference.claim_kinds,
            self.logup_reference.claimed_sum_count,
            self.logup_reference.row_bindings,
        );
    }

    /// Append both shared arithmetic lanes to the outer lowering reference.
    pub fn loweringLanes(self: *const Source) [2]lowering.Lane {
        return .{
            .{
                .circuit_id = CLAIM_CIRCUIT_ID,
                .active_in = .segment,
                .circuit_identity = self.claim_reference.authority_digest,
                .graph = self.claim_graph.graph,
            },
            .{
                .circuit_id = PUBLIC_LOGUP_CIRCUIT_ID,
                .active_in = .segment,
                .circuit_identity = self.logup_reference.authority_digest,
                .graph = self.logup_graph.graph,
            },
        };
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
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        preprocessing: *const leaf_authority.Preprocessing,
        manifest: *const manifest_mod.Manifest,
        destination: []const []M31,
    ) !void {
        try self.validateAgainst(vm_plan, recursion_plan, preprocessing);
        try self.validateManifest(manifest);
        try preflightDestination(manifest, manifest_mod.PREPROCESSED_TREE_INDEX, destination);
        var stage = try Stage.init(
            self.allocator,
            manifest,
            manifest_mod.PREPROCESSED_TREE_INDEX,
        );
        defer stage.deinit();

        var row12 = try stage.columns(claim_input_air.PREPROCESSED_COLUMN_COUNT, .vm_public_claim_input);
        try preprocessing.claim_input.generateInto(&row12, &self.executors.claim_input);
        var row13 = try stage.columns(claim_hash_air.PREPROCESSED_COLUMN_COUNT, .vm_public_claim_hash);
        try self.executors.claim_hash.generatePreprocessedInto(&preprocessing.claim_hash, &row13);
        var row14 = try stage.columns(io_hash_air.PREPROCESSED_COLUMN_COUNT, .vm_public_io_hash);
        try self.executors.io_hash.generatePreprocessedInto(&preprocessing.io_hash, &row14);
        var row15 = try stage.columns(claim_semantics_air.PREPROCESSED_COLUMN_COUNT, .vm_public_claim_semantics_input);
        try self.claim_reference.row_preprocessing.generateInto(
            &row15,
            try claim_semantics_witness.Reference.seal(
                self.claim_reference.circuit_id,
                self.claim_reference.row_bindings,
            ),
        );
        var row16 = try stage.columns(public_logup_air.PREPROCESSED_COLUMN_COUNT, .vm_public_logup_input);
        try self.public_logup_preprocessing.generateInto(&row16, try self.logupRowReference());
        var row17 = try stage.columns(public_logup_control_air.PREPROCESSED_COLUMN_COUNT, .vm_public_logup_control);
        try self.public_logup_control.generateInto(&row17, vm_plan, recursion_plan);
        stage.commit(manifest, destination);
    }

    pub fn fillMainInto(
        self: *const Source,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        preprocessing: *const leaf_authority.Preprocessing,
        leaf: *const leaf_authority.Prepared,
        prepared: *const Prepared,
        data: *const public_data_mod.PublicData,
        manifest: *const manifest_mod.Manifest,
        destination: []const []M31,
    ) !void {
        try self.validateAgainst(vm_plan, recursion_plan, preprocessing);
        try prepared.validateAgainst(self, preprocessing, leaf, data);
        try self.validateManifest(manifest);
        try preflightDestination(manifest, manifest_mod.MAIN_TREE_INDEX, destination);
        var stage = try Stage.init(self.allocator, manifest, manifest_mod.MAIN_TREE_INDEX);
        defer stage.deinit();

        var row12 = try stage.columns(claim_input_air.PHYSICAL_MAIN_COLUMN_COUNT, .vm_public_claim_input);
        try leaf.claim_input.generateInto(&row12, &preprocessing.claim_input, &self.executors.claim_input);
        var row13 = try stage.columns(claim_hash_air.PHYSICAL_MAIN_COLUMN_COUNT, .vm_public_claim_hash);
        try self.executors.claim_hash.generateMainInto(&leaf.claim_hash, &preprocessing.claim_hash, &row13);
        var row14 = try stage.columns(io_hash_air.PHYSICAL_MAIN_COLUMN_COUNT, .vm_public_io_hash);
        try self.executors.io_hash.generateMainInto(&leaf.io_hash, &preprocessing.io_hash, &row14);
        var row15 = try stage.columns(claim_semantics_air.PHYSICAL_MAIN_COLUMN_COUNT, .vm_public_claim_semantics_input);
        try prepared.claim_semantics.row_witness.generateInto(
            &row15,
            &self.claim_reference.row_preprocessing,
        );
        var row16 = try stage.columns(public_logup_air.PHYSICAL_MAIN_COLUMN_COUNT, .vm_public_logup_input);
        try prepared.public_logup_main.generateInto(&row16, &self.public_logup_preprocessing);
        stage.commit(manifest, destination);
    }

    pub fn fillInteractionInto(
        self: *const Source,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        preprocessing: *const leaf_authority.Preprocessing,
        leaf: *const leaf_authority.Prepared,
        prepared: *const Prepared,
        data: *const public_data_mod.PublicData,
        manifest: *const manifest_mod.Manifest,
        relations: *const universal.UniversalRelations,
        destination: []const []M31,
    ) !Claims {
        try self.validateAgainst(vm_plan, recursion_plan, preprocessing);
        try prepared.validateAgainst(self, preprocessing, leaf, data);
        try self.validateManifest(manifest);
        try relations.validate();
        try preflightDestination(manifest, manifest_mod.INTERACTION_TREE_INDEX, destination);
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
                &self.owners.claim_input.relation,
                prepared.claim_input_rows,
                self.log_sizes[0],
                relations,
                &stage,
                .vm_public_claim_input,
            ),
            .claim_hash = try generateIntoStage(
                ClaimHashFramework,
                self.allocator,
                &self.owners.claim_hash.relation,
                prepared.claim_hash_rows,
                self.log_sizes[1],
                relations,
                &stage,
                .vm_public_claim_hash,
            ),
            .io_hash = try generateIntoStage(
                IoHashFramework,
                self.allocator,
                &self.owners.io_hash.relation,
                prepared.io_hash_rows,
                self.log_sizes[2],
                relations,
                &stage,
                .vm_public_io_hash,
            ),
            .claim_semantics = try generateIntoStage(
                ClaimSemanticsFramework,
                self.allocator,
                &self.owners.claim_semantics.relation,
                prepared.claim_semantics_rows,
                self.log_sizes[3],
                relations,
                &stage,
                .vm_public_claim_semantics_input,
            ),
            .public_logup = try generateIntoStage(
                PublicLogupFramework,
                self.allocator,
                &self.owners.public_logup.relation,
                prepared.public_logup_rows,
                self.log_sizes[4],
                relations,
                &stage,
                .vm_public_logup_input,
            ),
            .public_logup_control = try generateIntoStage(
                PublicLogupControlFramework,
                self.allocator,
                &self.owners.public_logup_control.relation,
                self.public_logup_control_rows,
                self.log_sizes[5],
                relations,
                &stage,
                .vm_public_logup_control,
            ),
        };
        stage.commit(manifest, destination);
        return claims;
    }

    /// Recompose and audit the exact cached rows 12--17 by relation domain.
    pub fn auditInteractionDomains(
        self: *const Source,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
        preprocessing: *const leaf_authority.Preprocessing,
        leaf: *const leaf_authority.Prepared,
        prepared: *const Prepared,
        data: *const public_data_mod.PublicData,
        relations: *const universal.UniversalRelations,
        claims: Claims,
        tuple_ledger: ?*relation_interaction.TupleLedger,
    ) !DomainAudits {
        return domain_audit.audit(
            self,
            vm_plan,
            recursion_plan,
            preprocessing,
            leaf,
            prepared,
            data,
            relations,
            claims,
            tuple_ledger,
            DomainAudits,
            appendTupleContributions,
        );
    }

    pub fn initComponents(
        self: *const Source,
        manifest: *const manifest_mod.Manifest,
        relations: *const universal.UniversalRelations,
        claims: Claims,
    ) !Components {
        try self.validateManifest(manifest);
        try relations.validate();
        return .{
            .claim_input = try ClaimInputAdapter.init(
                &self.owners.claim_input.definition,
                self.owners.claim_input.relation,
                manifest,
                .vm_public_claim_input,
                self.log_sizes[0],
                self.parameters.claim_input,
                relations,
                claims.claim_input,
            ),
            .claim_hash = try ClaimHashAdapter.init(
                &self.owners.claim_hash.definition,
                self.owners.claim_hash.relation,
                manifest,
                .vm_public_claim_hash,
                self.log_sizes[1],
                self.parameters.claim_hash,
                relations,
                claims.claim_hash,
            ),
            .io_hash = try IoHashAdapter.init(
                &self.owners.io_hash.definition,
                self.owners.io_hash.relation,
                manifest,
                .vm_public_io_hash,
                self.log_sizes[2],
                self.parameters.io_hash,
                relations,
                claims.io_hash,
            ),
            .claim_semantics = try ClaimSemanticsAdapter.init(
                &self.owners.claim_semantics.definition,
                self.owners.claim_semantics.relation,
                manifest,
                .vm_public_claim_semantics_input,
                self.log_sizes[3],
                self.parameters.claim_semantics,
                relations,
                claims.claim_semantics,
            ),
            .public_logup = try PublicLogupAdapter.init(
                &self.owners.public_logup.definition,
                self.owners.public_logup.relation,
                manifest,
                .vm_public_logup_input,
                self.log_sizes[4],
                self.parameters.public_logup,
                relations,
                claims.public_logup,
            ),
            .public_logup_control = try PublicLogupControlAdapter.init(
                &self.owners.public_logup_control.definition,
                self.owners.public_logup_control.relation,
                manifest,
                .vm_public_logup_control,
                self.log_sizes[5],
                self.parameters.public_logup_control,
                relations,
                claims.public_logup_control,
            ),
        };
    }
};

pub fn sourceDigest(source: *const Source) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/segment-public-outer-source/v1\x00");
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u32, source.shape.max_input_words);
    hashInt(&hash, u32, source.shape.max_output_words);
    hashInt(&hash, u32, source.claimed_sum_count);
    for (source.vm_schedule_digest) |word| hashInt(&hash, u32, word);
    for (source.recursion_schedule_digest) |word| hashInt(&hash, u32, word);
    hash.update(&source.leaf_preprocessing_digest);
    hash.update(&source.claim_reference.authority_digest);
    hash.update(&source.logup_reference.authority_digest);
    hash.update(&source.claim_graph.graph.identity_digest);
    hash.update(&source.logup_graph.graph.identity_digest);
    for (source.log_sizes) |value| hashInt(&hash, u32, value);
    hashParameters(&hash, source.parameters);
    for (source.public_logup_control_rows) |row| hashM31Slice(&hash, &row);
    return hash.finalResult();
}

pub fn preparedDigest(
    prepared: *const Prepared,
    source: *const Source,
    leaf: *const leaf_authority.Prepared,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/segment-public-outer-prepared/v1\x00");
    hash.update(&source.authority_seal);
    for (leaf.claim.digest) |word| hashInt(&hash, u32, word);
    for (leaf.statement.words) |value| hashInt(&hash, u32, value.toU32());
    hashQM31Slice(&hash, prepared.claim_semantics.input_values);
    hashQM31Slice(&hash, prepared.claim_semantics.evaluation.values);
    hashQM31Slice(&hash, prepared.public_logup.input_values);
    hashQM31Slice(&hash, prepared.public_logup.evaluation.values);
    hashMainRows(&hash, prepared.claim_semantics.row_witness.rows);
    hashMainRows(&hash, prepared.public_logup_main.rows);
    hashM31Rows(&hash, prepared.claim_input_rows);
    hashM31Rows(&hash, prepared.claim_hash_rows);
    hashM31Rows(&hash, prepared.io_hash_rows);
    hashM31Rows(&hash, prepared.claim_semantics_rows);
    hashM31Rows(&hash, prepared.public_logup_rows);
    return hash.finalResult();
}
