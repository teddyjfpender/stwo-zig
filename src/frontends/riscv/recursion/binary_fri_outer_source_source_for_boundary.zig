//! Internal shard of binary_fri_outer_source.zig; use the public facade.
const dependency_0 = @import("binary_fri_outer_source_claims.zig");
const dependency_1 = @import("binary_fri_outer_source_trusted_composition_profile_v1.zig");
const dependency_2 = @import("binary_fri_outer_source_composition_rows_authority.zig");
const dependency_3 = @import("binary_fri_outer_source_fri_rows_authority.zig");
const dependency_4 = @import("binary_fri_outer_source_arithmetic_rows_authority.zig");
const dependency_6 = @import("binary_fri_outer_source_retain_non_path_poseidon_calls.zig");
const dependency_7 = @import("binary_fri_outer_source_materialize_child_paths.zig");
const dependency_8 = @import("binary_fri_outer_source_composition_source_value.zig");
const dependency_9 = @import("binary_fri_outer_source_validate_captured_against_wire.zig");
const workspace_context = @import("binary_fri_outer_source_workspace_context.zig");

const std = dependency_0.std;
const vm_binary_fri_source = dependency_0.vm_binary_fri_source;
const composition_workspace_mod = dependency_0.composition_workspace_mod;
const fri_workspace_mod = dependency_0.fri_workspace_mod;
const arithmetic_workspace_mod = dependency_0.arithmetic_workspace_mod;
const merkle_workspace_mod = dependency_0.merkle_workspace_mod;
const relation_workspaces = dependency_0.relation_workspaces;
const interaction_operations = dependency_0.interaction_operations;
const merkle_operations = dependency_0.merkle_operations;
const arithmetic_operations = dependency_0.arithmetic_operations;
const fri_operations = dependency_0.fri_operations;
const boundary_operations = dependency_0.boundary_operations;
const composition_operations = dependency_0.composition_operations;
const constructors_operations = dependency_0.constructors_operations;
const boundary_merkle_operations =
    @import("binary_fri_outer_source_boundary_merkle_operations.zig");
const M31 = dependency_0.M31;
const QM31 = dependency_0.QM31;
const air_digest = dependency_0.air_digest;
const relation = dependency_0.relation;
const fixed_wire = dependency_0.fixed_wire;
const protocol = dependency_0.protocol;
const composition = dependency_0.composition;
const composition_input_air = dependency_0.composition_input_air;
const composition_input_relation = dependency_0.composition_input_relation;
const composition_input_witness = dependency_0.composition_input_witness;
const composition_control_air = dependency_0.composition_control_air;
const composition_control_witness = dependency_0.composition_control_witness;
const query_bits_air = dependency_0.query_bits_air;
const query_bits_relation = dependency_0.query_bits_relation;
const query_bits_witness = dependency_0.query_bits_witness;
const query_mapping_air = dependency_0.query_mapping_air;
const query_mapping_relation = dependency_0.query_mapping_relation;
const query_mapping_witness = dependency_0.query_mapping_witness;
const merkle_root_air = dependency_0.merkle_root_air;
const merkle_root_relation = dependency_0.merkle_root_relation;
const merkle_root_witness = dependency_0.merkle_root_witness;
const trace_merkle_air = dependency_0.trace_merkle_air;
const trace_merkle_relation = dependency_0.trace_merkle_relation;
const trace_merkle_witness = dependency_0.trace_merkle_witness;
const pcs_air = dependency_0.pcs_air;
const pcs_relation = dependency_0.pcs_relation;
const pcs_witness = dependency_0.pcs_witness;
const fri_leaf_air = dependency_0.fri_leaf_air;
const fri_leaf_relation = dependency_0.fri_leaf_relation;
const fri_leaf_witness = dependency_0.fri_leaf_witness;
const fri_node_air = dependency_0.fri_node_air;
const fri_node_relation = dependency_0.fri_node_relation;
const fri_node_witness = dependency_0.fri_node_witness;
const fri_anchor_air = dependency_0.fri_anchor_air;
const fri_anchor_relation = dependency_0.fri_anchor_relation;
const fri_anchor_witness = dependency_0.fri_anchor_witness;
const fri_control_air = dependency_0.fri_control_air;
const fri_control_relation = dependency_0.fri_control_relation;
const fri_control_witness = dependency_0.fri_control_witness;
const fri_input_air = dependency_0.fri_input_air;
const fri_input_relation = dependency_0.fri_input_relation;
const fri_input_witness = dependency_0.fri_input_witness;
const multiply_air = dependency_0.multiply_air;
const multiply_witness = dependency_0.multiply_witness;
const inverse_air = dependency_0.inverse_air;
const inverse_witness = dependency_0.inverse_witness;
const linear_air = dependency_0.linear_air;
const linear_witness = dependency_0.linear_witness;
const lowering = dependency_0.lowering;
const merkle_path_air = dependency_0.merkle_path_air;
const merkle_path_relation = dependency_0.merkle_path_relation;
const merkle_path_witness = dependency_0.merkle_path_witness;
const merkle_path_poseidon = dependency_0.merkle_path_poseidon;
const schedule = dependency_0.schedule;
const universal = dependency_0.universal;
const universal_roster = dependency_0.universal_roster;
const framework = dependency_0.framework;
const relation_interaction = dependency_0.relation_interaction;
const CompositionControlRelation = dependency_0.CompositionControlRelation;
const MultiplyRelation = dependency_0.MultiplyRelation;
const InverseRelation = dependency_0.InverseRelation;
const LinearRelation = dependency_0.LinearRelation;
const CompositionInputFramework = dependency_0.CompositionInputFramework;
const CompositionControlFramework = dependency_0.CompositionControlFramework;
const QueryBitsFramework = dependency_0.QueryBitsFramework;
const QueryMappingFramework = dependency_0.QueryMappingFramework;
const MerkleRootFramework = dependency_0.MerkleRootFramework;
const TraceMerkleFramework = dependency_0.TraceMerkleFramework;
const PcsFramework = dependency_0.PcsFramework;
const FriLeafFramework = dependency_0.FriLeafFramework;
const FriNodeFramework = dependency_0.FriNodeFramework;
const FriAnchorFramework = dependency_0.FriAnchorFramework;
const FriControlFramework = dependency_0.FriControlFramework;
const FriInputFramework = dependency_0.FriInputFramework;
const MultiplyFramework = dependency_0.MultiplyFramework;
const InverseFramework = dependency_0.InverseFramework;
const LinearFramework = dependency_0.LinearFramework;
const MerklePathFramework = dependency_0.MerklePathFramework;
const FIRST_ROW = dependency_0.FIRST_ROW;
const CHILD_COUNT = dependency_0.CHILD_COUNT;
const LEFT_CHILD = dependency_0.LEFT_CHILD;
const RIGHT_CHILD = dependency_0.RIGHT_CHILD;
const LEFT_RECURSION_VERIFIER_ID = dependency_0.LEFT_RECURSION_VERIFIER_ID;
const RIGHT_RECURSION_VERIFIER_ID = dependency_0.RIGHT_RECURSION_VERIFIER_ID;
const POSEIDON2_PARTIAL_COUNT = dependency_0.POSEIDON2_PARTIAL_COUNT;
const ROW_COUNT = dependency_0.ROW_COUNT;
const TYPED_RELATION_ROW_COUNT = dependency_0.TYPED_RELATION_ROW_COUNT;
const UNIVERSAL_ROSTER_ROW_COUNT = dependency_0.UNIVERSAL_ROSTER_ROW_COUNT;
const COMPOSITION_ROW_COUNT = dependency_0.COMPOSITION_ROW_COUNT;
const MERKLE_PATH_MAIN_COLUMN_COUNT = dependency_0.MERKLE_PATH_MAIN_COLUMN_COUNT;
const COMPOSITION_PREPROCESSED_COLUMN_COUNT = dependency_0.COMPOSITION_PREPROCESSED_COLUMN_COUNT;
const COMPOSITION_MAIN_COLUMN_COUNT = dependency_0.COMPOSITION_MAIN_COLUMN_COUNT;
const COMPOSITION_PREPROCESSED_COLUMNS_PER_ROW = dependency_0.COMPOSITION_PREPROCESSED_COLUMNS_PER_ROW;
const COMPOSITION_MAIN_COLUMNS_PER_ROW = dependency_0.COMPOSITION_MAIN_COLUMNS_PER_ROW;
const FRI_ROW_COUNT = dependency_0.FRI_ROW_COUNT;
const ARITHMETIC_ROW_COUNT = dependency_0.ARITHMETIC_ROW_COUNT;
const ARITHMETIC_PREPROCESSED_COLUMN_COUNT = dependency_0.ARITHMETIC_PREPROCESSED_COLUMN_COUNT;
const ARITHMETIC_MAIN_COLUMN_COUNT = dependency_0.ARITHMETIC_MAIN_COLUMN_COUNT;
const ARITHMETIC_PREPROCESSED_COLUMNS_PER_ROW = dependency_0.ARITHMETIC_PREPROCESSED_COLUMNS_PER_ROW;
const ARITHMETIC_MAIN_COLUMNS_PER_ROW = dependency_0.ARITHMETIC_MAIN_COLUMNS_PER_ROW;
const PREPROCESSED_COLUMN_COUNT = dependency_0.PREPROCESSED_COLUMN_COUNT;
const MAIN_COLUMN_COUNT = dependency_0.MAIN_COLUMN_COUNT;
const PREPROCESSED_COLUMNS_PER_ROW = dependency_0.PREPROCESSED_COLUMNS_PER_ROW;
const MAIN_COLUMNS_PER_ROW = dependency_0.MAIN_COLUMNS_PER_ROW;
const TYPED_INTERACTION_COLUMNS_PER_ROW = dependency_0.TYPED_INTERACTION_COLUMNS_PER_ROW;
const TYPED_INTERACTION_COLUMN_COUNT = dependency_0.TYPED_INTERACTION_COLUMN_COUNT;
const ColumnOffset = dependency_0.ColumnOffset;
const ArithmeticColumnOffset = dependency_0.ArithmeticColumnOffset;
const SharedArithmeticInput = dependency_1.SharedArithmeticInput;
const PublicBoundaryEvidence = dependency_1.PublicBoundaryEvidence;
const AuthenticatedRecorderVerifierInputBoundaryDescriptor = dependency_1.AuthenticatedRecorderVerifierInputBoundaryDescriptor;
const AuthenticatedRecorderVerifierInputBoundaryEvidence = dependency_1.AuthenticatedRecorderVerifierInputBoundaryEvidence;
const CompositionRowsAuthority = dependency_2.CompositionRowsAuthority;
const FriRowsAuthority = dependency_3.FriRowsAuthority;
const ArithmeticRowsAuthority = dependency_4.ArithmeticRowsAuthority;
const MerkleRowsAuthority = dependency_4.MerkleRowsAuthority;
const FrozenV1Boundary = dependency_4.FrozenV1Boundary;
const addTypedRowStorage = dependency_6.addTypedRowStorage;
const carveTypedRows = dependency_6.carveTypedRows;
const validateTypedRowsInStorage = dependency_6.validateTypedRowsInStorage;
const columnLogicalRow = dependency_6.columnLogicalRow;
const relationRowsDigest = dependency_6.relationRowsDigest;
const friPathLeafDigest = dependency_6.friPathLeafDigest;
const merkleLeafCount = dependency_6.merkleLeafCount;
const merkleInvocationCount = dependency_6.merkleInvocationCount;
const sharedPoseidonCallCount = dependency_6.sharedPoseidonCallCount;
const materializeMerkleWorkspace = dependency_6.materializeMerkleWorkspace;
const merkleWorkspaceDigest = dependency_7.merkleWorkspaceDigest;
const validateMerkleWorkspaceAliases = dependency_7.validateMerkleWorkspaceAliases;
const validateMerkleDestination = dependency_7.validateMerkleDestination;
const columnStorageCount = dependency_7.columnStorageCount;
const carveColumnViews = dependency_7.carveColumnViews;
const validateColumnViews = dependency_7.validateColumnViews;
const validateDestination = dependency_7.validateDestination;
const validateArithmeticDestination = dependency_7.validateArithmeticDestination;
const copyColumns = dependency_7.copyColumns;
const scatterColumnsToCommitmentOrder = dependency_8.scatterColumnsToCommitmentOrder;
const columnArray = dependency_8.columnArray;
const typedSlicesOverlap = dependency_8.typedSlicesOverlap;
const validatePairBoundary = dependency_8.validatePairBoundary;
const validateChildProfiles = dependency_8.validateChildProfiles;
const poseidonPartialClaimRanges = dependency_8.poseidonPartialClaimRanges;
const validateCapturedAgainstWire = dependency_9.validateCapturedAgainstWire;
const validateExecutionAgainstCapture = dependency_9.validateExecutionAgainstCapture;
const m31SliceEql = dependency_9.m31SliceEql;
const traceLogSize = dependency_9.traceLogSize;
const preparedAuthorityDigest = dependency_9.preparedAuthorityDigest;
const sourceAuthorityDigest = dependency_9.sourceAuthorityDigest;
const hashInt = dependency_9.hashInt;

/// Cold, fail-atomic custody source for the frozen V1 boundary.
pub fn Source(comptime dimensions: fixed_wire.Dimensions) type {
    return SourceForBoundary(dimensions, FrozenV1Boundary(dimensions));
}

pub fn SourceForBoundary(
    comptime dimensions: fixed_wire.Dimensions,
    comptime Boundary: type,
) type {
    dimensions.validate();
    const PairPrepared = Boundary.PairPrepared;
    const RootPin = Boundary.RootPin;
    const Wire = Boundary.Wire;
    const Child = Boundary.Child;

    return struct {
        pub const IS_LEGACY_BOUNDARY = Boundary.IS_LEGACY;
        pub const INCLUDE_PAIR_TRANSCRIPT_POSEIDON_CALLS =
            Boundary.INCLUDE_PAIR_TRANSCRIPT_POSEIDON_CALLS;

        allocator: std.mem.Allocator,
        pair: *const PairPrepared,
        root_pin: RootPin,
        vm_plan: *const schedule.Plan,
        recursion_plans: [2]*const schedule.Plan,
        children: [2]Child,
        query_word_storage: []M31,
        query_words: [2][]const M31,
        shared_arithmetic: ?SharedArithmeticInput,
        composition_rows: ?CompositionRowsAuthority,
        fri_rows: FriRowsAuthority,
        arithmetic_rows: ?ArithmeticRowsAuthority,
        merkle_rows: MerkleRowsAuthority,
        source_authority_digest: air_digest.Digest,

        const Self = @This();
        const BoundaryMerkleOperations = boundary_merkle_operations.Operations(
            struct {
                pub const Source = Self;
                pub const BoundaryType = Boundary;
                pub const dimensions_value = dimensions;
                pub const fallback = dependency_6;
            },
        );
        const WorkspaceContext = workspace_context.Type(struct {
            pub const Source = Self;
            pub const PreparedAuthorityType = PreparedAuthority;
            pub const Claims = vm_binary_fri_source;
            pub const Retained = dependency_6;
            pub const Materialized = dependency_7;
            pub const CompositionValues = dependency_8;
            pub const Validation = dependency_9;
            pub const merkleLeafCount = BoundaryMerkleOperations.merkleLeafCount;
            pub const merkleInvocationCount = BoundaryMerkleOperations.merkleInvocationCount;
            pub const sharedPoseidonCallCount = BoundaryMerkleOperations.sharedPoseidonCallCount;
            pub const bundleLogSizesAssumeAuthority =
                Self.bundleLogSizesAssumeAuthority;
        });

        const AuthenticatedVerifierInputBoundaryFold = struct {
            descriptor: AuthenticatedRecorderVerifierInputBoundaryDescriptor,
            claimed_sum: QM31,
        };

        /// Immutable, process-local capability produced by one complete cold
        /// authority validation. Hot bundle writers may use it while `source`
        /// remains borrowed as `*const`; hostile or deliberately mutated
        /// memory must cross `validateAgainstAuthority` again before a fresh
        /// capability is issued.
        pub const PreparedAuthority = struct {
            source: *const Self,
            source_authority_digest: air_digest.Digest,
            composition_authority_digest: air_digest.Digest,
            fri_authority_digest: air_digest.Digest,
            arithmetic_authority_digest: air_digest.Digest,
            merkle_authority_digest: air_digest.Digest,
            bundle_log_sizes: [ROW_COUNT]u32,
            identity_digest: air_digest.Digest,

            pub fn validateFor(
                self: *const PreparedAuthority,
                source: *const Self,
            ) !void {
                const composition_rows = source.composition_rows orelse
                    return error.MissingCompositionAuthority;
                const arithmetic_rows = source.arithmetic_rows orelse
                    return error.MissingCompositionAuthority;
                if (self.source != source or
                    !std.mem.eql(
                        u8,
                        &self.source_authority_digest,
                        &source.source_authority_digest,
                    ) or !std.mem.eql(
                    u8,
                    &self.composition_authority_digest,
                    &composition_rows.authority_digest,
                ) or !std.mem.eql(
                    u8,
                    &self.fri_authority_digest,
                    &source.fri_rows.authority_digest,
                ) or !std.mem.eql(
                    u8,
                    &self.arithmetic_authority_digest,
                    &arithmetic_rows.authority_digest,
                ) or !std.mem.eql(
                    u8,
                    &self.merkle_authority_digest,
                    &source.merkle_rows.authority_digest,
                ) or !std.meta.eql(
                    self.bundle_log_sizes,
                    try source.bundleLogSizesAssumeAuthority(),
                ) or !std.mem.eql(
                    u8,
                    &self.identity_digest,
                    &preparedAuthorityDigest(self),
                )) return error.SourceAuthorityMismatch;
            }
        };

        /// One cold slab for rows 18--19.  Row 18 has preprocessed and main
        /// columns; row 19 is verifier-owned preprocessing only.  Both public
        /// group writers stage the complete group before publication.
        pub const CompositionWorkspace =
            composition_workspace_mod.Type(WorkspaceContext);

        /// One caller-owned staging slab for all rows 20--29.  Construction is
        /// cold; both preprocessed and main fills are allocation-free on every
        /// reuse.  The destination is published only after all ten typed row
        /// writers succeed, preserving whole-group failure atomicity.
        pub const Workspace = fri_workspace_mod.Type(WorkspaceContext);

        /// Cold owner for rows 30--32.  The three typed invocation buffers and
        /// one M31 staging slab are retained across fills, so both trees are
        /// allocation-free after construction.  `materializeInto` derives all
        /// invocations from verifier-owned graph evaluations immediately
        /// before direct execution; callers cannot inject arithmetic rows.
        pub const ArithmeticWorkspace =
            arithmetic_workspace_mod.Type(WorkspaceContext);

        /// Prepared row-33 witness and row-34 request contribution.  The
        /// logical rows are cached during the one unavoidable leaf-to-root
        /// authentication walk.  Publishing row 33 therefore does not repeat
        /// any Poseidon permutation; the shared provider performs the only
        /// subsequent permutation pass when the complete outer bundle is
        /// assembled.
        pub const MerkleWorkspace =
            merkle_workspace_mod.Type(WorkspaceContext, Workspace);

        /// One compact M31 slab retaining the exact logical rows consumed by
        /// every typed interaction plan from rows 18 through 33.  The slab is
        /// populated only from the already-admitted direct-witness buffers;
        /// it is then sealed for both prover interaction generation and
        /// independent verifier/domain-audit replay.
        const RelationWorkspaceTypes =
            relation_workspaces.Types(WorkspaceContext);
        pub const RelationRows = RelationWorkspaceTypes.RelationRows;

        /// Retained scratch and one transaction staging tree for rows 18--33.
        /// Construction performs exactly one allocation per typed framework
        /// plus one compact M31 allocation; repeated interaction generation
        /// performs no heap allocation and publishes the group only after all
        /// sixteen claims have closed successfully.
        pub const RelationInteractionWorkspace =
            RelationWorkspaceTypes.RelationInteractionWorkspace;

        /// Constructs rows 18--34 from a profile-specific authority that was
        /// already admitted outside frozen V1. The boundary creates the
        /// composition rows from its retained recorder capability; this
        /// source creates every remaining AIR owner exactly once and retains
        /// one immutable capture pointer per child.
        const ConstructorsOperations = constructors_operations.Operations(struct {
            pub const Source = Self;
            pub const dimensions_value = dimensions;
            pub const BoundaryType = Boundary;
            pub const PairPreparedType = PairPrepared;
            pub const RootPinType = RootPin;
            pub const ChildType = Child;
            pub const std = vm_binary_fri_source.std;
            pub const M31 = vm_binary_fri_source.M31;
            pub const fixed_wire = vm_binary_fri_source.fixed_wire;
            pub const protocol = vm_binary_fri_source.protocol;
            pub const composition = vm_binary_fri_source.composition;
            pub const schedule = vm_binary_fri_source.schedule;
            pub const CHILD_COUNT = vm_binary_fri_source.CHILD_COUNT;
            pub const LEFT_CHILD = vm_binary_fri_source.LEFT_CHILD;
            pub const RIGHT_CHILD = vm_binary_fri_source.RIGHT_CHILD;
            pub const SharedArithmeticInput = dependency_1.SharedArithmeticInput;
            pub const CompositionRowsAuthority = dependency_2.CompositionRowsAuthority;
            pub const FriRowsAuthority = dependency_3.FriRowsAuthority;
            pub const ArithmeticRowsAuthority = dependency_4.ArithmeticRowsAuthority;
            pub const MerkleRowsAuthority = dependency_4.MerkleRowsAuthority;
            pub const validatePairBoundary = dependency_8.validatePairBoundary;
            pub const validateChildProfiles = dependency_8.validateChildProfiles;
            pub const validateCapturedAgainstWire = dependency_9.validateCapturedAgainstWire;
            pub const validateExecutionAgainstCapture = dependency_9.validateExecutionAgainstCapture;
        });

        // Preserve the pre-split constructor surface while retaining the
        // constructor implementation in its focused operations shard.
        pub const initAuthenticated = ConstructorsOperations.initAuthenticated;
        pub const init = ConstructorsOperations.init;
        pub const initWithSharedArithmetic =
            ConstructorsOperations.initWithSharedArithmetic;

        /// Constructs the canonical all-36-row source. `shared_arithmetic`
        /// is row 11's admitted statement circuit and is lowered in the same
        /// immutable plan as the composition/PCS/FRI circuits in rows 30--32.
        pub fn deinit(self: *Self) void {
            self.merkle_rows.deinit();
            if (self.composition_rows) |*rows| rows.deinit();
            if (self.arithmetic_rows) |*rows| rows.deinit();
            self.fri_rows.deinit();
            self.allocator.free(self.query_word_storage);
            self.* = undefined;
        }

        /// Revalidates borrowed authorities and detects mutation before a hot
        /// row writer touches caller-owned output.
        pub fn validate(self: *const Self) !void {
            if (self.query_word_storage.len != CHILD_COUNT * dimensions.query_count or
                self.query_words[0].ptr != self.query_word_storage.ptr or
                self.query_words[0].len != dimensions.query_count or
                self.query_words[1].ptr != self.query_word_storage.ptr + dimensions.query_count or
                self.query_words[1].len != dimensions.query_count)
            {
                return error.SourceAuthorityMismatch;
            }
            if (comptime Boundary.IS_LEGACY) {
                try validatePairBoundary(
                    self.pair,
                    self.root_pin,
                    self.vm_plan,
                    self.recursion_plans,
                );
                try validateChildProfiles(self.children);
            } else {
                try Boundary.validateSource(dimensions, self);
            }
            if (comptime !Boundary.IS_LEGACY and
                @hasDecl(Boundary, "validateFriRows"))
            {
                try Boundary.validateFriRows(dimensions, self, &self.fri_rows);
            } else {
                try self.fri_rows.validate(
                    self.vm_plan,
                    self.recursion_plans[0],
                    self.children,
                );
            }
            if (self.shared_arithmetic) |input| try input.validate();
            if (self.arithmetic_rows) |*rows| {
                if (comptime !Boundary.IS_LEGACY and
                    @hasDecl(Boundary, "validateArithmeticRows"))
                {
                    try Boundary.validateArithmeticRows(
                        dimensions,
                        self,
                        rows,
                    );
                } else {
                    try rows.validate(self.children, self.shared_arithmetic);
                }
            } else if (self.children[LEFT_CHILD].composition != null) {
                return error.SourceAuthorityMismatch;
            }
            if (self.composition_rows) |*rows| {
                if (comptime Boundary.IS_LEGACY) {
                    try rows.validate(
                        self.pair,
                        self.vm_plan,
                        self.recursion_plans[0],
                        self.children,
                    );
                } else {
                    try Boundary.validateCompositionRows(
                        dimensions,
                        self,
                        rows,
                    );
                }
            }
            try self.merkle_rows.validate();
            if (comptime Boundary.IS_LEGACY) {
                for (self.children, &self.pair.authority.children, &self.pair.executions, 0..) |
                    child,
                    *verified_child,
                    *execution,
                    child_index,
                | {
                    try validateCapturedAgainstWire(
                        dimensions,
                        child.capture,
                        child.shape,
                        child.wire,
                    );
                    var scratch: [dimensions.query_count]M31 = undefined;
                    try validateExecutionAgainstCapture(execution, child.capture, &scratch);
                    if (!m31SliceEql(&scratch, self.query_words[child_index]))
                        return error.CaptureTranscriptMismatch;
                    if (child.composition) |composition_authority| {
                        const trusted = child.trusted_composition_profile orelse
                            return error.MissingCompositionAuthority;
                        try composition_authority.validateAgainst(
                            trusted,
                            verified_child.*,
                            child.shape,
                        );
                    } else if (child.trusted_composition_profile != null) {
                        return error.MissingCompositionAuthority;
                    }
                }
            }
            if (!std.mem.eql(
                u8,
                &self.source_authority_digest,
                &self.computeSourceAuthorityDigest(),
            )) return error.SourceAuthorityMismatch;
        }

        pub fn computeSourceAuthorityDigest(self: *const Self) air_digest.Digest {
            if (comptime Boundary.IS_LEGACY)
                return sourceAuthorityDigest(self);
            return Boundary.sourceAuthorityDigest(dimensions, self);
        }

        /// Explicit hostile-boundary validation. This name distinguishes the
        /// full deep revalidation above from the constant-size prepared seal
        /// used after the source has been borrowed immutably by a bundle.
        pub fn validateAgainstAuthority(self: *const Self) !void {
            return self.validate();
        }

        /// Performs one complete cold validation and issues an immutable hot
        /// capability. The capability never authenticates a different source
        /// address and binds every row-family seal plus the exact 17-row
        /// geometry.
        pub fn prepareAuthority(self: *const Self) !PreparedAuthority {
            try self.validateAgainstAuthority();
            const composition_rows = self.composition_rows orelse
                return error.MissingCompositionAuthority;
            const arithmetic_rows = self.arithmetic_rows orelse
                return error.MissingCompositionAuthority;
            var result = PreparedAuthority{
                .source = self,
                .source_authority_digest = self.source_authority_digest,
                .composition_authority_digest = composition_rows.authority_digest,
                .fri_authority_digest = self.fri_rows.authority_digest,
                .arithmetic_authority_digest = arithmetic_rows.authority_digest,
                .merkle_authority_digest = self.merkle_rows.authority_digest,
                .bundle_log_sizes = try self.bundleLogSizesAssumeAuthority(),
                .identity_digest = undefined,
            };
            result.identity_digest = preparedAuthorityDigest(&result);
            try result.validateFor(self);
            return result;
        }

        pub fn requireCompositionAuthorities(self: *const Self) !void {
            try self.validate();
            for (self.children) |child| if (child.composition == null)
                return error.MissingCompositionAuthority;
            if (self.arithmetic_rows == null)
                return error.MissingCompositionAuthority;
        }

        pub fn requireFullBundleAuthority(self: *const Self) !void {
            try self.requireCompositionAuthorities();
            if (self.composition_rows == null)
                return error.MissingCompositionAuthority;
        }

        pub fn wire(self: *const Self, child_index: usize) *const Wire {
            std.debug.assert(child_index < CHILD_COUNT);
            return self.children[child_index].wire;
        }

        const CompositionOperations = composition_operations.Operations(struct {
            pub const Source = Self;
            pub const M31 = vm_binary_fri_source.M31;
            pub const composition_input_witness = vm_binary_fri_source.composition_input_witness;
            pub const composition_control_witness = vm_binary_fri_source.composition_control_witness;
            pub const COMPOSITION_ROW_COUNT = vm_binary_fri_source.COMPOSITION_ROW_COUNT;
            pub const COMPOSITION_PREPROCESSED_COLUMNS_PER_ROW = vm_binary_fri_source.COMPOSITION_PREPROCESSED_COLUMNS_PER_ROW;
            pub const COMPOSITION_MAIN_COLUMNS_PER_ROW = vm_binary_fri_source.COMPOSITION_MAIN_COLUMNS_PER_ROW;
            pub const PREPROCESSED_COLUMN_COUNT = vm_binary_fri_source.PREPROCESSED_COLUMN_COUNT;
            pub const validateDestination = dependency_7.validateDestination;
            pub const scatterColumnsToCommitmentOrder = dependency_8.scatterColumnsToCommitmentOrder;
            pub const columnArray = dependency_8.columnArray;
        });
        pub const compositionLogSizes = CompositionOperations.compositionLogSizes;
        pub const fillCompositionPreprocessedInto =
            CompositionOperations.fillCompositionPreprocessedInto;
        pub const fillCompositionPreprocessedPreparedInto =
            CompositionOperations.fillCompositionPreprocessedPreparedInto;
        pub const fillCompositionMainInto =
            CompositionOperations.fillCompositionMainInto;
        pub const fillCompositionMainPreparedInto =
            CompositionOperations.fillCompositionMainPreparedInto;

        const FriOperations = fri_operations.Operations(struct {
            pub const Source = Self;
            pub const BoundaryType = Boundary;
            pub const M31 = vm_binary_fri_source.M31;
            pub const query_bits_witness = vm_binary_fri_source.query_bits_witness;
            pub const query_mapping_witness = vm_binary_fri_source.query_mapping_witness;
            pub const merkle_root_witness = vm_binary_fri_source.merkle_root_witness;
            pub const trace_merkle_witness = vm_binary_fri_source.trace_merkle_witness;
            pub const pcs_witness = vm_binary_fri_source.pcs_witness;
            pub const fri_leaf_witness = vm_binary_fri_source.fri_leaf_witness;
            pub const fri_node_witness = vm_binary_fri_source.fri_node_witness;
            pub const fri_anchor_witness = vm_binary_fri_source.fri_anchor_witness;
            pub const fri_control_witness = vm_binary_fri_source.fri_control_witness;
            pub const fri_input_witness = vm_binary_fri_source.fri_input_witness;
            pub const LEFT_CHILD = vm_binary_fri_source.LEFT_CHILD;
            pub const RIGHT_CHILD = vm_binary_fri_source.RIGHT_CHILD;
            pub const FRI_ROW_COUNT = vm_binary_fri_source.FRI_ROW_COUNT;
            pub const PREPROCESSED_COLUMN_COUNT = vm_binary_fri_source.PREPROCESSED_COLUMN_COUNT;
            pub const MAIN_COLUMN_COUNT = vm_binary_fri_source.MAIN_COLUMN_COUNT;
            pub const PREPROCESSED_COLUMNS_PER_ROW = vm_binary_fri_source.PREPROCESSED_COLUMNS_PER_ROW;
            pub const MAIN_COLUMNS_PER_ROW = vm_binary_fri_source.MAIN_COLUMNS_PER_ROW;
            pub const ColumnOffset = vm_binary_fri_source.ColumnOffset;
            pub const friPathLeafDigest = dependency_6.friPathLeafDigest;
            pub const validateDestination = dependency_7.validateDestination;
            pub const scatterColumnsToCommitmentOrder = dependency_8.scatterColumnsToCommitmentOrder;
            pub const columnArray = dependency_8.columnArray;
        });
        pub const friLogSizes = FriOperations.friLogSizes;
        pub const fillFriPreprocessedInto = FriOperations.fillFriPreprocessedInto;
        pub const fillFriPreprocessedPreparedInto =
            FriOperations.fillFriPreprocessedPreparedInto;
        pub const fillFriMainInto = FriOperations.fillFriMainInto;
        pub const fillFriMainPreparedInto = FriOperations.fillFriMainPreparedInto;

        const ArithmeticOperations = arithmetic_operations.Operations(struct {
            pub const Source = Self;
            pub const BoundaryType = Boundary;
            pub const M31 = vm_binary_fri_source.M31;
            pub const composition = vm_binary_fri_source.composition;
            pub const multiply_witness = vm_binary_fri_source.multiply_witness;
            pub const inverse_witness = vm_binary_fri_source.inverse_witness;
            pub const linear_witness = vm_binary_fri_source.linear_witness;
            pub const lowering = vm_binary_fri_source.lowering;
            pub const LEFT_CHILD = vm_binary_fri_source.LEFT_CHILD;
            pub const RIGHT_CHILD = vm_binary_fri_source.RIGHT_CHILD;
            pub const ARITHMETIC_ROW_COUNT = vm_binary_fri_source.ARITHMETIC_ROW_COUNT;
            pub const ARITHMETIC_PREPROCESSED_COLUMN_COUNT = vm_binary_fri_source.ARITHMETIC_PREPROCESSED_COLUMN_COUNT;
            pub const ARITHMETIC_MAIN_COLUMN_COUNT = vm_binary_fri_source.ARITHMETIC_MAIN_COLUMN_COUNT;
            pub const ARITHMETIC_PREPROCESSED_COLUMNS_PER_ROW = vm_binary_fri_source.ARITHMETIC_PREPROCESSED_COLUMNS_PER_ROW;
            pub const ARITHMETIC_MAIN_COLUMNS_PER_ROW = vm_binary_fri_source.ARITHMETIC_MAIN_COLUMNS_PER_ROW;
            pub const PREPROCESSED_COLUMN_COUNT = vm_binary_fri_source.PREPROCESSED_COLUMN_COUNT;
            pub const MAIN_COLUMN_COUNT = vm_binary_fri_source.MAIN_COLUMN_COUNT;
            pub const ArithmeticColumnOffset = vm_binary_fri_source.ArithmeticColumnOffset;
            pub const validateDestination = dependency_7.validateDestination;
            pub const validateArithmeticDestination = dependency_7.validateArithmeticDestination;
            pub const scatterColumnsToCommitmentOrder = dependency_8.scatterColumnsToCommitmentOrder;
            pub const columnArray = dependency_8.columnArray;
        });
        pub const arithmeticLogSizes = ArithmeticOperations.arithmeticLogSizes;
        pub const fillArithmeticPreprocessedInto =
            ArithmeticOperations.fillArithmeticPreprocessedInto;
        pub const fillArithmeticPreprocessedPreparedInto =
            ArithmeticOperations.fillArithmeticPreprocessedPreparedInto;
        pub const fillArithmeticMainInto = ArithmeticOperations.fillArithmeticMainInto;
        pub const fillArithmeticMainPreparedInto =
            ArithmeticOperations.fillArithmeticMainPreparedInto;

        /// Publishes the constants and zero-output anchors selected directly
        /// from the authenticated all-36 arithmetic lowering plan.
        const BoundaryOperations = boundary_operations.Operations(struct {
            pub const Source = Self;
            pub const BoundaryType = Boundary;
            pub const AuthenticatedVerifierInputBoundaryFoldType =
                AuthenticatedVerifierInputBoundaryFold;
            pub const std = vm_binary_fri_source.std;
            pub const M31 = vm_binary_fri_source.M31;
            pub const QM31 = vm_binary_fri_source.QM31;
            pub const relation = vm_binary_fri_source.relation;
            pub const composition = vm_binary_fri_source.composition;
            pub const composition_input_witness = vm_binary_fri_source.composition_input_witness;
            pub const lowering = vm_binary_fri_source.lowering;
            pub const universal = vm_binary_fri_source.universal;
            pub const CHILD_COUNT = vm_binary_fri_source.CHILD_COUNT;
            pub const LEFT_CHILD = vm_binary_fri_source.LEFT_CHILD;
            pub const RIGHT_CHILD = vm_binary_fri_source.RIGHT_CHILD;
            pub const LEFT_RECURSION_VERIFIER_ID = vm_binary_fri_source.LEFT_RECURSION_VERIFIER_ID;
            pub const RIGHT_RECURSION_VERIFIER_ID = vm_binary_fri_source.RIGHT_RECURSION_VERIFIER_ID;
            pub const POSEIDON2_PARTIAL_COUNT = vm_binary_fri_source.POSEIDON2_PARTIAL_COUNT;
            pub const PHYSICAL_CLAIM_COUNT: u32 = @intCast(
                dimensions.claimed_sum_count,
            );
            pub const PublicBoundaryEvidence = dependency_1.PublicBoundaryEvidence;
            pub const AuthenticatedRecorderVerifierInputBoundaryDescriptor = dependency_1.AuthenticatedRecorderVerifierInputBoundaryDescriptor;
            pub const AuthenticatedRecorderVerifierInputBoundaryEvidence = dependency_1.AuthenticatedRecorderVerifierInputBoundaryEvidence;
            pub const poseidonPartialClaimRanges = dependency_8.poseidonPartialClaimRanges;
            pub const hashInt = dependency_9.hashInt;
        });
        pub const wireBoundaryEvidence = BoundaryOperations.wireBoundaryEvidence;
        pub const verifierInputBoundaryEvidence =
            BoundaryOperations.verifierInputBoundaryEvidence;
        pub const authenticatedRecorderVerifierInputBoundaryDescriptor =
            BoundaryOperations.authenticatedRecorderVerifierInputBoundaryDescriptor;
        pub const authenticatedRecorderVerifierInputBoundaryEvidence =
            BoundaryOperations.authenticatedRecorderVerifierInputBoundaryEvidence;

        pub fn typedRelationLogSizes(
            self: *const Self,
        ) ![TYPED_RELATION_ROW_COUNT]u32 {
            try self.requireFullBundleAuthority();
            return self.composition_rows.?.log_sizes ++
                self.fri_rows.log_sizes ++
                self.arithmetic_rows.?.log_sizes ++
                .{try self.merkleLogSize()};
        }

        pub fn bundleLogSizes(self: *const Self) ![ROW_COUNT]u32 {
            const typed = try self.typedRelationLogSizes();
            return typed ++ .{try traceLogSize(
                try BoundaryMerkleOperations.sharedPoseidonCallCount(self),
            )};
        }

        pub fn bundleLogSizesAssumeAuthority(self: *const Self) ![ROW_COUNT]u32 {
            const composition_rows = self.composition_rows orelse
                return error.MissingCompositionAuthority;
            const arithmetic_rows = self.arithmetic_rows orelse
                return error.MissingCompositionAuthority;
            const typed = composition_rows.log_sizes ++
                self.fri_rows.log_sizes ++
                arithmetic_rows.log_sizes ++
                .{try traceLogSize(
                    try BoundaryMerkleOperations.merkleInvocationCount(self),
                )};
            return typed ++ .{try traceLogSize(
                try BoundaryMerkleOperations.sharedPoseidonCallCount(self),
            )};
        }

        /// Installs the exact contiguous rows 18--34 geometry into the full
        /// universal roster without allocating or modifying any other row.
        pub fn installLogSizes(
            self: *const Self,
            destination: *[UNIVERSAL_ROSTER_ROW_COUNT]u32,
        ) !void {
            const logs = try self.bundleLogSizes();
            inline for (logs, FIRST_ROW..) |log_size, row|
                destination[row] = log_size;
        }

        const MerkleOperations = merkle_operations.Operations(struct {
            pub const Source = Self;
            pub const BoundaryType = Boundary;
            pub const M31 = vm_binary_fri_source.M31;
            pub const composition = vm_binary_fri_source.composition;
            pub const composition_input_witness = vm_binary_fri_source.composition_input_witness;
            pub const composition_control_witness = vm_binary_fri_source.composition_control_witness;
            pub const query_bits_witness = vm_binary_fri_source.query_bits_witness;
            pub const query_mapping_witness = vm_binary_fri_source.query_mapping_witness;
            pub const merkle_root_witness = vm_binary_fri_source.merkle_root_witness;
            pub const trace_merkle_witness = vm_binary_fri_source.trace_merkle_witness;
            pub const pcs_witness = vm_binary_fri_source.pcs_witness;
            pub const fri_leaf_witness = vm_binary_fri_source.fri_leaf_witness;
            pub const fri_node_witness = vm_binary_fri_source.fri_node_witness;
            pub const fri_anchor_witness = vm_binary_fri_source.fri_anchor_witness;
            pub const fri_control_witness = vm_binary_fri_source.fri_control_witness;
            pub const fri_input_witness = vm_binary_fri_source.fri_input_witness;
            pub const multiply_witness = vm_binary_fri_source.multiply_witness;
            pub const inverse_witness = vm_binary_fri_source.inverse_witness;
            pub const linear_witness = vm_binary_fri_source.linear_witness;
            pub const merkle_path_poseidon = vm_binary_fri_source.merkle_path_poseidon;
            pub const framework = vm_binary_fri_source.framework;
            pub const LEFT_CHILD = vm_binary_fri_source.LEFT_CHILD;
            pub const RIGHT_CHILD = vm_binary_fri_source.RIGHT_CHILD;
            pub const MERKLE_PATH_MAIN_COLUMN_COUNT = vm_binary_fri_source.MERKLE_PATH_MAIN_COLUMN_COUNT;
            pub const MAIN_COLUMN_COUNT = vm_binary_fri_source.MAIN_COLUMN_COUNT;
            pub const ColumnOffset = vm_binary_fri_source.ColumnOffset;
            pub const columnLogicalRow = dependency_6.columnLogicalRow;
            pub const relationRowsDigest = dependency_6.relationRowsDigest;
            pub const merkleInvocationCount = BoundaryMerkleOperations.merkleInvocationCount;
            pub const materializeMerkleWorkspace = BoundaryMerkleOperations.materializeMerkleWorkspace;
            pub const merkleWorkspaceDigest = dependency_7.merkleWorkspaceDigest;
            pub const validateMerkleDestination = dependency_7.validateMerkleDestination;
            pub const validateDestination = dependency_7.validateDestination;
            pub const traceLogSize = dependency_9.traceLogSize;
        });
        pub const prepareMerkleWorkspace = MerkleOperations.prepareMerkleWorkspace;
        pub const prepareMerkleWorkspacePrepared =
            MerkleOperations.prepareMerkleWorkspacePrepared;
        pub const merkleLogSize = MerkleOperations.merkleLogSize;
        pub const fillMerkleMainInto = MerkleOperations.fillMerkleMainInto;
        pub const fillMerkleMainPreparedInto =
            MerkleOperations.fillMerkleMainPreparedInto;
        pub const merklePoseidonCalls = MerkleOperations.merklePoseidonCalls;
        pub const merklePoseidonCallsPrepared =
            MerkleOperations.merklePoseidonCallsPrepared;
        pub const merklePoseidonOutputs = MerkleOperations.merklePoseidonOutputs;
        pub const merklePoseidonOutputsPrepared =
            MerkleOperations.merklePoseidonOutputsPrepared;
        pub const merkleRelationRows = MerkleOperations.merkleRelationRows;
        pub const prepareRelationRows = MerkleOperations.prepareRelationRows;
        pub const prepareRelationRowsPrepared =
            MerkleOperations.prepareRelationRowsPrepared;
        pub const retainedRelationRows = MerkleOperations.retainedRelationRows;
        pub const retainedRelationRowsPrepared =
            MerkleOperations.retainedRelationRowsPrepared;

        const InteractionOperations = interaction_operations.Operations(struct {
            pub const Source = Self;
            pub const std = vm_binary_fri_source.std;
            pub const M31 = vm_binary_fri_source.M31;
            pub const QM31 = vm_binary_fri_source.QM31;
            pub const relation = vm_binary_fri_source.relation;
            pub const composition_input_air = vm_binary_fri_source.composition_input_air;
            pub const composition_control_air = vm_binary_fri_source.composition_control_air;
            pub const query_bits_air = vm_binary_fri_source.query_bits_air;
            pub const query_bits_relation = vm_binary_fri_source.query_bits_relation;
            pub const query_mapping_air = vm_binary_fri_source.query_mapping_air;
            pub const query_mapping_relation = vm_binary_fri_source.query_mapping_relation;
            pub const merkle_root_air = vm_binary_fri_source.merkle_root_air;
            pub const merkle_root_relation = vm_binary_fri_source.merkle_root_relation;
            pub const trace_merkle_air = vm_binary_fri_source.trace_merkle_air;
            pub const trace_merkle_relation = vm_binary_fri_source.trace_merkle_relation;
            pub const pcs_air = vm_binary_fri_source.pcs_air;
            pub const pcs_relation = vm_binary_fri_source.pcs_relation;
            pub const fri_leaf_air = vm_binary_fri_source.fri_leaf_air;
            pub const fri_leaf_relation = vm_binary_fri_source.fri_leaf_relation;
            pub const fri_node_air = vm_binary_fri_source.fri_node_air;
            pub const fri_node_relation = vm_binary_fri_source.fri_node_relation;
            pub const fri_anchor_air = vm_binary_fri_source.fri_anchor_air;
            pub const fri_anchor_relation = vm_binary_fri_source.fri_anchor_relation;
            pub const fri_control_air = vm_binary_fri_source.fri_control_air;
            pub const fri_input_air = vm_binary_fri_source.fri_input_air;
            pub const multiply_air = vm_binary_fri_source.multiply_air;
            pub const inverse_air = vm_binary_fri_source.inverse_air;
            pub const linear_air = vm_binary_fri_source.linear_air;
            pub const merkle_path_air = vm_binary_fri_source.merkle_path_air;
            pub const universal = vm_binary_fri_source.universal;
            pub const universal_roster = vm_binary_fri_source.universal_roster;
            pub const relation_interaction = vm_binary_fri_source.relation_interaction;
            pub const CompositionInputFramework = vm_binary_fri_source.CompositionInputFramework;
            pub const CompositionControlFramework = vm_binary_fri_source.CompositionControlFramework;
            pub const QueryBitsFramework = vm_binary_fri_source.QueryBitsFramework;
            pub const QueryMappingFramework = vm_binary_fri_source.QueryMappingFramework;
            pub const MerkleRootFramework = vm_binary_fri_source.MerkleRootFramework;
            pub const TraceMerkleFramework = vm_binary_fri_source.TraceMerkleFramework;
            pub const PcsFramework = vm_binary_fri_source.PcsFramework;
            pub const FriLeafFramework = vm_binary_fri_source.FriLeafFramework;
            pub const FriNodeFramework = vm_binary_fri_source.FriNodeFramework;
            pub const FriAnchorFramework = vm_binary_fri_source.FriAnchorFramework;
            pub const FriControlFramework = vm_binary_fri_source.FriControlFramework;
            pub const FriInputFramework = vm_binary_fri_source.FriInputFramework;
            pub const MultiplyFramework = vm_binary_fri_source.MultiplyFramework;
            pub const InverseFramework = vm_binary_fri_source.InverseFramework;
            pub const LinearFramework = vm_binary_fri_source.LinearFramework;
            pub const MerklePathFramework = vm_binary_fri_source.MerklePathFramework;
            pub const TYPED_RELATION_ROW_COUNT = vm_binary_fri_source.TYPED_RELATION_ROW_COUNT;
            pub const TYPED_INTERACTION_COLUMNS_PER_ROW = vm_binary_fri_source.TYPED_INTERACTION_COLUMNS_PER_ROW;
            pub const validateDestination = dependency_7.validateDestination;
            pub const copyColumns = dependency_7.copyColumns;
            pub const columnArray = dependency_8.columnArray;
        });
        pub const fillTypedInteractionsInto =
            InteractionOperations.fillTypedInteractionsInto;
        pub const fillTypedInteractionsPreparedInto =
            InteractionOperations.fillTypedInteractionsPreparedInto;
        pub const auditTypedInteractionDomains =
            InteractionOperations.auditTypedInteractionDomains;
        pub const auditTypedInteractionDomainsPrepared =
            InteractionOperations.auditTypedInteractionDomainsPrepared;
        pub const auditTypedInteractionDomainsPreparedWithTupleLedger =
            InteractionOperations.auditTypedInteractionDomainsPreparedWithTupleLedger;
    };
}
