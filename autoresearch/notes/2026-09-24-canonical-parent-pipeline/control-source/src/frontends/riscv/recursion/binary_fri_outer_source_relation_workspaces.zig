//! Retained typed rows and interaction scratch for the binary FRI source.

pub fn Types(comptime Context: type) type {
    const Self = Context.Source;
    const PreparedAuthority = Context.PreparedAuthorityType;
    const std = Context.std;
    const M31 = Context.M31;
    const air_digest = Context.air_digest;
    const composition_input_relation = Context.composition_input_relation;
    const query_bits_relation = Context.query_bits_relation;
    const query_mapping_relation = Context.query_mapping_relation;
    const merkle_root_relation = Context.merkle_root_relation;
    const trace_merkle_relation = Context.trace_merkle_relation;
    const pcs_relation = Context.pcs_relation;
    const fri_leaf_relation = Context.fri_leaf_relation;
    const fri_node_relation = Context.fri_node_relation;
    const fri_anchor_relation = Context.fri_anchor_relation;
    const fri_control_relation = Context.fri_control_relation;
    const fri_input_relation = Context.fri_input_relation;
    const merkle_path_relation = Context.merkle_path_relation;
    const CompositionControlRelation = Context.CompositionControlRelation;
    const MultiplyRelation = Context.MultiplyRelation;
    const InverseRelation = Context.InverseRelation;
    const LinearRelation = Context.LinearRelation;
    const addTypedRowStorage = Context.addTypedRowStorage;
    const carveTypedRows = Context.carveTypedRows;
    const validateTypedRowsInStorage = Context.validateTypedRowsInStorage;
    const relationRowsDigest = Context.relationRowsDigest;
    const merkleInvocationCount = Context.merkleInvocationCount;
    const CompositionInputFramework = Context.CompositionInputFramework;
    const CompositionControlFramework = Context.CompositionControlFramework;
    const QueryBitsFramework = Context.QueryBitsFramework;
    const QueryMappingFramework = Context.QueryMappingFramework;
    const MerkleRootFramework = Context.MerkleRootFramework;
    const TraceMerkleFramework = Context.TraceMerkleFramework;
    const PcsFramework = Context.PcsFramework;
    const FriLeafFramework = Context.FriLeafFramework;
    const FriNodeFramework = Context.FriNodeFramework;
    const FriAnchorFramework = Context.FriAnchorFramework;
    const FriControlFramework = Context.FriControlFramework;
    const FriInputFramework = Context.FriInputFramework;
    const MultiplyFramework = Context.MultiplyFramework;
    const InverseFramework = Context.InverseFramework;
    const LinearFramework = Context.LinearFramework;
    const MerklePathFramework = Context.MerklePathFramework;
    const TYPED_RELATION_ROW_COUNT = Context.TYPED_RELATION_ROW_COUNT;
    const TYPED_INTERACTION_COLUMNS_PER_ROW = Context.TYPED_INTERACTION_COLUMNS_PER_ROW;
    const TYPED_INTERACTION_COLUMN_COUNT = Context.TYPED_INTERACTION_COLUMN_COUNT;
    const columnStorageCount = Context.columnStorageCount;
    const carveColumnViews = Context.carveColumnViews;
    const validateColumnViews = Context.validateColumnViews;
    const bundleLogSizesAssumeAuthority = Context.bundleLogSizesAssumeAuthority;

    return struct {
        pub const RelationRows = struct {
            allocator: std.mem.Allocator,
            storage: []M31,
            composition_input: []composition_input_relation.Row,
            composition_control: []CompositionControlRelation.Row,
            query_bits: []query_bits_relation.Row,
            query_mapping: []query_mapping_relation.Row,
            merkle_root: []merkle_root_relation.Row,
            trace_merkle: []trace_merkle_relation.Row,
            pcs_deep: []pcs_relation.Row,
            fri_leaf: []fri_leaf_relation.Row,
            fri_node: []fri_node_relation.Row,
            fri_anchor: []fri_anchor_relation.Row,
            fri_control: []fri_control_relation.Row,
            fri_input: []fri_input_relation.Row,
            multiply: []MultiplyRelation.Row,
            inverse: []InverseRelation.Row,
            linear: []LinearRelation.Row,
            merkle_path: []merkle_path_relation.Row,
            source_authority_digest: air_digest.Digest,
            authority_digest: air_digest.Digest,
            ready: bool,

            pub fn init(
                allocator: std.mem.Allocator,
                source: *const Self,
            ) !RelationRows {
                try source.requireFullBundleAuthority();
                return initAssumeAuthority(allocator, source);
            }

            pub fn initPrepared(
                allocator: std.mem.Allocator,
                source: *const Self,
                authority: *const PreparedAuthority,
            ) !RelationRows {
                try authority.validateFor(source);
                return initAssumeAuthority(allocator, source);
            }

            fn initAssumeAuthority(
                allocator: std.mem.Allocator,
                source: *const Self,
            ) !RelationRows {
                const composition_rows = source.composition_rows.?;
                const arithmetic_rows = source.arithmetic_rows.?;
                var element_count: usize = 0;
                try addTypedRowStorage(
                    composition_input_relation.Row,
                    &element_count,
                    composition_rows.input_preprocessing.rows.len,
                );
                try addTypedRowStorage(
                    CompositionControlRelation.Row,
                    &element_count,
                    composition_rows.control_preprocessing.rows.len,
                );
                try addTypedRowStorage(
                    query_bits_relation.Row,
                    &element_count,
                    source.fri_rows.query_bits_preprocessing.rows.len,
                );
                try addTypedRowStorage(
                    query_mapping_relation.Row,
                    &element_count,
                    source.fri_rows.query_mapping_preprocessing.rows.len,
                );
                try addTypedRowStorage(
                    merkle_root_relation.Row,
                    &element_count,
                    source.fri_rows.merkle_root_preprocessing.rows.len,
                );
                try addTypedRowStorage(
                    trace_merkle_relation.Row,
                    &element_count,
                    source.fri_rows.trace_merkle_preprocessing.rows.len,
                );
                try addTypedRowStorage(
                    pcs_relation.Row,
                    &element_count,
                    source.fri_rows.pcs_preprocessing.rows.len,
                );
                try addTypedRowStorage(
                    fri_leaf_relation.Row,
                    &element_count,
                    source.fri_rows.fri_leaf_preprocessing.rows.len,
                );
                try addTypedRowStorage(
                    fri_node_relation.Row,
                    &element_count,
                    source.fri_rows.fri_node_preprocessing.rows.len,
                );
                try addTypedRowStorage(
                    fri_anchor_relation.Row,
                    &element_count,
                    source.fri_rows.fri_anchor_preprocessing.rows.len,
                );
                try addTypedRowStorage(
                    fri_control_relation.Row,
                    &element_count,
                    source.fri_rows.control_preprocessing.rows.len,
                );
                try addTypedRowStorage(
                    fri_input_relation.Row,
                    &element_count,
                    source.fri_rows.input_preprocessing.rows.len,
                );
                try addTypedRowStorage(
                    MultiplyRelation.Row,
                    &element_count,
                    arithmetic_rows.plan.counts(.binary_node).multiply,
                );
                try addTypedRowStorage(
                    InverseRelation.Row,
                    &element_count,
                    arithmetic_rows.plan.counts(.binary_node).inverse,
                );
                try addTypedRowStorage(
                    LinearRelation.Row,
                    &element_count,
                    arithmetic_rows.plan.counts(.binary_node).linear,
                );
                try addTypedRowStorage(
                    merkle_path_relation.Row,
                    &element_count,
                    try merkleInvocationCount(source),
                );
                const storage = try allocator.alloc(M31, element_count);
                errdefer allocator.free(storage);
                var at: usize = 0;
                var result = RelationRows{
                    .allocator = allocator,
                    .storage = storage,
                    .composition_input = carveTypedRows(
                        composition_input_relation.Row,
                        storage,
                        &at,
                        composition_rows.input_preprocessing.rows.len,
                    ),
                    .composition_control = carveTypedRows(
                        CompositionControlRelation.Row,
                        storage,
                        &at,
                        composition_rows.control_preprocessing.rows.len,
                    ),
                    .query_bits = carveTypedRows(
                        query_bits_relation.Row,
                        storage,
                        &at,
                        source.fri_rows.query_bits_preprocessing.rows.len,
                    ),
                    .query_mapping = carveTypedRows(
                        query_mapping_relation.Row,
                        storage,
                        &at,
                        source.fri_rows.query_mapping_preprocessing.rows.len,
                    ),
                    .merkle_root = carveTypedRows(
                        merkle_root_relation.Row,
                        storage,
                        &at,
                        source.fri_rows.merkle_root_preprocessing.rows.len,
                    ),
                    .trace_merkle = carveTypedRows(
                        trace_merkle_relation.Row,
                        storage,
                        &at,
                        source.fri_rows.trace_merkle_preprocessing.rows.len,
                    ),
                    .pcs_deep = carveTypedRows(
                        pcs_relation.Row,
                        storage,
                        &at,
                        source.fri_rows.pcs_preprocessing.rows.len,
                    ),
                    .fri_leaf = carveTypedRows(
                        fri_leaf_relation.Row,
                        storage,
                        &at,
                        source.fri_rows.fri_leaf_preprocessing.rows.len,
                    ),
                    .fri_node = carveTypedRows(
                        fri_node_relation.Row,
                        storage,
                        &at,
                        source.fri_rows.fri_node_preprocessing.rows.len,
                    ),
                    .fri_anchor = carveTypedRows(
                        fri_anchor_relation.Row,
                        storage,
                        &at,
                        source.fri_rows.fri_anchor_preprocessing.rows.len,
                    ),
                    .fri_control = carveTypedRows(
                        fri_control_relation.Row,
                        storage,
                        &at,
                        source.fri_rows.control_preprocessing.rows.len,
                    ),
                    .fri_input = carveTypedRows(
                        fri_input_relation.Row,
                        storage,
                        &at,
                        source.fri_rows.input_preprocessing.rows.len,
                    ),
                    .multiply = carveTypedRows(
                        MultiplyRelation.Row,
                        storage,
                        &at,
                        arithmetic_rows.plan.counts(.binary_node).multiply,
                    ),
                    .inverse = carveTypedRows(
                        InverseRelation.Row,
                        storage,
                        &at,
                        arithmetic_rows.plan.counts(.binary_node).inverse,
                    ),
                    .linear = carveTypedRows(
                        LinearRelation.Row,
                        storage,
                        &at,
                        arithmetic_rows.plan.counts(.binary_node).linear,
                    ),
                    .merkle_path = carveTypedRows(
                        merkle_path_relation.Row,
                        storage,
                        &at,
                        try merkleInvocationCount(source),
                    ),
                    .source_authority_digest = source.source_authority_digest,
                    .authority_digest = [_]u8{0} ** @sizeOf(air_digest.Digest),
                    .ready = false,
                };
                std.debug.assert(at == storage.len);
                try result.validateGeometryFor(source);
                return result;
            }

            pub fn deinit(self: *RelationRows) void {
                self.allocator.free(self.storage);
                self.* = undefined;
            }

            pub fn validateGeometryFor(
                self: *const RelationRows,
                source: *const Self,
            ) !void {
                if (!std.mem.eql(
                    u8,
                    &self.source_authority_digest,
                    &source.source_authority_digest,
                )) return error.WorkspaceAuthorityMismatch;
                var at: usize = 0;
                inline for (.{
                    self.composition_input,
                    self.composition_control,
                    self.query_bits,
                    self.query_mapping,
                    self.merkle_root,
                    self.trace_merkle,
                    self.pcs_deep,
                    self.fri_leaf,
                    self.fri_node,
                    self.fri_anchor,
                    self.fri_control,
                    self.fri_input,
                    self.multiply,
                    self.inverse,
                    self.linear,
                    self.merkle_path,
                }) |rows| try validateTypedRowsInStorage(
                    @TypeOf(rows[0]),
                    rows,
                    self.storage,
                    &at,
                );
                if (at != self.storage.len)
                    return error.WorkspaceAuthorityMismatch;
            }

            pub fn validateReadyFor(
                self: *const RelationRows,
                source: *const Self,
            ) !void {
                try self.validateGeometryFor(source);
                if (!self.ready or !std.mem.eql(
                    u8,
                    &self.authority_digest,
                    &relationRowsDigest(self),
                )) return error.WorkspaceAuthorityMismatch;
            }
        };

        pub const RelationInteractionWorkspace = struct {
            allocator: std.mem.Allocator,
            storage: []M31,
            columns: [TYPED_INTERACTION_COLUMN_COUNT][]M31,
            composition_input: CompositionInputFramework.Workspace,
            composition_control: CompositionControlFramework.Workspace,
            query_bits: QueryBitsFramework.Workspace,
            query_mapping: QueryMappingFramework.Workspace,
            merkle_root: MerkleRootFramework.Workspace,
            trace_merkle: TraceMerkleFramework.Workspace,
            pcs_deep: PcsFramework.Workspace,
            fri_leaf: FriLeafFramework.Workspace,
            fri_node: FriNodeFramework.Workspace,
            fri_anchor: FriAnchorFramework.Workspace,
            fri_control: FriControlFramework.Workspace,
            fri_input: FriInputFramework.Workspace,
            multiply: MultiplyFramework.Workspace,
            inverse: InverseFramework.Workspace,
            linear: LinearFramework.Workspace,
            merkle_path: MerklePathFramework.Workspace,
            source_authority_digest: air_digest.Digest,
            relation_rows_digest: air_digest.Digest,
            log_sizes: [TYPED_RELATION_ROW_COUNT]u32,
            rows_bound: bool,

            pub fn init(
                allocator: std.mem.Allocator,
                source: *const Self,
                rows: *const RelationRows,
            ) !RelationInteractionWorkspace {
                var result = try initCold(allocator, source);
                errdefer result.deinit();
                try result.bindRows(source, rows);
                return result;
            }

            /// Allocates every interaction scratch buffer before main-trace
            /// materialization.  This keeps the later rows-18--34 bundle hot
            /// path heap-allocation-free; `bindRows` installs the retained-row
            /// seal after the exact main witnesses have been admitted.
            pub fn initCold(
                allocator: std.mem.Allocator,
                source: *const Self,
            ) !RelationInteractionWorkspace {
                try source.requireFullBundleAuthority();
                const log_sizes = try source.typedRelationLogSizes();
                return initColdWithLogSizes(allocator, source, log_sizes);
            }

            pub fn initColdPrepared(
                allocator: std.mem.Allocator,
                source: *const Self,
                authority: *const PreparedAuthority,
            ) !RelationInteractionWorkspace {
                try authority.validateFor(source);
                const log_sizes = authority.bundle_log_sizes[0..TYPED_RELATION_ROW_COUNT].*;
                return initColdWithLogSizes(allocator, source, log_sizes);
            }

            fn initColdWithLogSizes(
                allocator: std.mem.Allocator,
                source: *const Self,
                log_sizes: [TYPED_RELATION_ROW_COUNT]u32,
            ) !RelationInteractionWorkspace {
                var composition_input_workspace = try CompositionInputFramework.Workspace.init(
                    allocator,
                    log_sizes[0],
                );
                errdefer composition_input_workspace.deinit();
                var composition_control_workspace = try CompositionControlFramework.Workspace.init(
                    allocator,
                    log_sizes[1],
                );
                errdefer composition_control_workspace.deinit();
                var query_bits_workspace = try QueryBitsFramework.Workspace.init(
                    allocator,
                    log_sizes[2],
                );
                errdefer query_bits_workspace.deinit();
                var query_mapping_workspace = try QueryMappingFramework.Workspace.init(
                    allocator,
                    log_sizes[3],
                );
                errdefer query_mapping_workspace.deinit();
                var merkle_root_workspace = try MerkleRootFramework.Workspace.init(
                    allocator,
                    log_sizes[4],
                );
                errdefer merkle_root_workspace.deinit();
                var trace_merkle_workspace = try TraceMerkleFramework.Workspace.init(
                    allocator,
                    log_sizes[5],
                );
                errdefer trace_merkle_workspace.deinit();
                var pcs_workspace = try PcsFramework.Workspace.init(
                    allocator,
                    log_sizes[6],
                );
                errdefer pcs_workspace.deinit();
                var fri_leaf_workspace = try FriLeafFramework.Workspace.init(
                    allocator,
                    log_sizes[7],
                );
                errdefer fri_leaf_workspace.deinit();
                var fri_node_workspace = try FriNodeFramework.Workspace.init(
                    allocator,
                    log_sizes[8],
                );
                errdefer fri_node_workspace.deinit();
                var fri_anchor_workspace = try FriAnchorFramework.Workspace.init(
                    allocator,
                    log_sizes[9],
                );
                errdefer fri_anchor_workspace.deinit();
                var fri_control_workspace = try FriControlFramework.Workspace.init(
                    allocator,
                    log_sizes[10],
                );
                errdefer fri_control_workspace.deinit();
                var fri_input_workspace = try FriInputFramework.Workspace.init(
                    allocator,
                    log_sizes[11],
                );
                errdefer fri_input_workspace.deinit();
                var multiply_workspace = try MultiplyFramework.Workspace.init(
                    allocator,
                    log_sizes[12],
                );
                errdefer multiply_workspace.deinit();
                var inverse_workspace = try InverseFramework.Workspace.init(
                    allocator,
                    log_sizes[13],
                );
                errdefer inverse_workspace.deinit();
                var linear_workspace = try LinearFramework.Workspace.init(
                    allocator,
                    log_sizes[14],
                );
                errdefer linear_workspace.deinit();
                var merkle_path_workspace = try MerklePathFramework.Workspace.init(
                    allocator,
                    log_sizes[15],
                );
                errdefer merkle_path_workspace.deinit();

                const storage_count = try columnStorageCount(
                    log_sizes,
                    TYPED_INTERACTION_COLUMNS_PER_ROW,
                );
                const storage = try allocator.alloc(M31, storage_count);
                errdefer allocator.free(storage);
                var result = RelationInteractionWorkspace{
                    .allocator = allocator,
                    .storage = storage,
                    .columns = undefined,
                    .composition_input = composition_input_workspace,
                    .composition_control = composition_control_workspace,
                    .query_bits = query_bits_workspace,
                    .query_mapping = query_mapping_workspace,
                    .merkle_root = merkle_root_workspace,
                    .trace_merkle = trace_merkle_workspace,
                    .pcs_deep = pcs_workspace,
                    .fri_leaf = fri_leaf_workspace,
                    .fri_node = fri_node_workspace,
                    .fri_anchor = fri_anchor_workspace,
                    .fri_control = fri_control_workspace,
                    .fri_input = fri_input_workspace,
                    .multiply = multiply_workspace,
                    .inverse = inverse_workspace,
                    .linear = linear_workspace,
                    .merkle_path = merkle_path_workspace,
                    .source_authority_digest = source.source_authority_digest,
                    .relation_rows_digest = [_]u8{0} ** @sizeOf(air_digest.Digest),
                    .log_sizes = log_sizes,
                    .rows_bound = false,
                };
                var at: usize = 0;
                try carveColumnViews(
                    &result.columns,
                    storage,
                    &at,
                    log_sizes,
                    TYPED_INTERACTION_COLUMNS_PER_ROW,
                );
                std.debug.assert(at == storage.len);
                try result.validateGeometryFor(source);
                return result;
            }

            /// Binds the already allocated scratch to one sealed retained-row
            /// publication. Rebinding to a different publication is rejected;
            /// callers must construct a fresh cold workspace instead.
            pub fn bindRows(
                self: *RelationInteractionWorkspace,
                source: *const Self,
                rows: *const RelationRows,
            ) !void {
                try self.validateGeometryFor(source);
                try rows.validateReadyFor(source);
                if (self.rows_bound) {
                    if (!std.mem.eql(
                        u8,
                        &self.relation_rows_digest,
                        &rows.authority_digest,
                    )) return error.WorkspaceAuthorityMismatch;
                    return;
                }
                self.relation_rows_digest = rows.authority_digest;
                self.rows_bound = true;
                try self.validateFor(source, rows);
            }

            pub fn deinit(self: *RelationInteractionWorkspace) void {
                self.allocator.free(self.storage);
                self.merkle_path.deinit();
                self.linear.deinit();
                self.inverse.deinit();
                self.multiply.deinit();
                self.fri_input.deinit();
                self.fri_control.deinit();
                self.fri_anchor.deinit();
                self.fri_node.deinit();
                self.fri_leaf.deinit();
                self.pcs_deep.deinit();
                self.trace_merkle.deinit();
                self.merkle_root.deinit();
                self.query_mapping.deinit();
                self.query_bits.deinit();
                self.composition_control.deinit();
                self.composition_input.deinit();
                self.* = undefined;
            }

            fn validateGeometryFor(
                self: *const RelationInteractionWorkspace,
                source: *const Self,
            ) !void {
                if (!std.mem.eql(
                    u8,
                    &self.source_authority_digest,
                    &source.source_authority_digest,
                ) or !std.meta.eql(
                    self.log_sizes,
                    (try bundleLogSizesAssumeAuthority(source))[0..TYPED_RELATION_ROW_COUNT].*,
                )) return error.WorkspaceAuthorityMismatch;
                var at: usize = 0;
                try validateColumnViews(
                    &self.columns,
                    self.storage,
                    &at,
                    self.log_sizes,
                    TYPED_INTERACTION_COLUMNS_PER_ROW,
                );
                if (at != self.storage.len)
                    return error.WorkspaceAuthorityMismatch;
            }

            pub fn validateFor(
                self: *const RelationInteractionWorkspace,
                source: *const Self,
                rows: *const RelationRows,
            ) !void {
                try self.validateGeometryFor(source);
                try rows.validateReadyFor(source);
                if (!self.rows_bound or !std.mem.eql(
                    u8,
                    &self.relation_rows_digest,
                    &rows.authority_digest,
                )) return error.WorkspaceAuthorityMismatch;
            }
        };
    };
}
