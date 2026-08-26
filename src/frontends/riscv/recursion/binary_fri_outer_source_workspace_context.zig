//! Shared dependency map for the retained binary-FRI workspaces.
//!
//! This focused shard keeps the four workspace implementations on one exact
//! source/authority vocabulary without making the source owner carry the
//! complete dependency table inline.

pub fn Type(comptime Context: type) type {
    const claims = Context.Claims;
    const retained = Context.Retained;
    const materialized = Context.Materialized;
    const composition_values = Context.CompositionValues;
    const validation = Context.Validation;

    return struct {
        pub const Source = Context.Source;
        pub const PreparedAuthorityType = Context.PreparedAuthorityType;
        pub const std = claims.std;
        pub const M31 = claims.M31;
        pub const air_digest = claims.air_digest;
        pub const COMPOSITION_ROW_COUNT = claims.COMPOSITION_ROW_COUNT;
        pub const COMPOSITION_PREPROCESSED_COLUMN_COUNT = claims.COMPOSITION_PREPROCESSED_COLUMN_COUNT;
        pub const COMPOSITION_MAIN_COLUMN_COUNT = claims.COMPOSITION_MAIN_COLUMN_COUNT;
        pub const COMPOSITION_PREPROCESSED_COLUMNS_PER_ROW = claims.COMPOSITION_PREPROCESSED_COLUMNS_PER_ROW;
        pub const COMPOSITION_MAIN_COLUMNS_PER_ROW = claims.COMPOSITION_MAIN_COLUMNS_PER_ROW;
        pub const columnStorageCount = materialized.columnStorageCount;
        pub const carveColumnViews = materialized.carveColumnViews;
        pub const validateColumnViews = materialized.validateColumnViews;
        pub const FRI_ROW_COUNT = claims.FRI_ROW_COUNT;
        pub const PREPROCESSED_COLUMN_COUNT = claims.PREPROCESSED_COLUMN_COUNT;
        pub const MAIN_COLUMN_COUNT = claims.MAIN_COLUMN_COUNT;
        pub const PREPROCESSED_COLUMNS_PER_ROW = claims.PREPROCESSED_COLUMNS_PER_ROW;
        pub const MAIN_COLUMNS_PER_ROW = claims.MAIN_COLUMNS_PER_ROW;
        pub const friPathLeafDigest = retained.friPathLeafDigest;
        pub const multiply_witness = claims.multiply_witness;
        pub const inverse_witness = claims.inverse_witness;
        pub const linear_witness = claims.linear_witness;
        pub const lowering = claims.lowering;
        pub const ARITHMETIC_ROW_COUNT = claims.ARITHMETIC_ROW_COUNT;
        pub const ARITHMETIC_PREPROCESSED_COLUMN_COUNT = claims.ARITHMETIC_PREPROCESSED_COLUMN_COUNT;
        pub const ARITHMETIC_MAIN_COLUMN_COUNT = claims.ARITHMETIC_MAIN_COLUMN_COUNT;
        pub const ARITHMETIC_PREPROCESSED_COLUMNS_PER_ROW = claims.ARITHMETIC_PREPROCESSED_COLUMNS_PER_ROW;
        pub const ARITHMETIC_MAIN_COLUMNS_PER_ROW = claims.ARITHMETIC_MAIN_COLUMNS_PER_ROW;
        pub const typedSlicesOverlap = composition_values.typedSlicesOverlap;
        pub const merkle_path_witness = claims.merkle_path_witness;
        pub const merkle_path_poseidon = claims.merkle_path_poseidon;
        pub const MERKLE_PATH_MAIN_COLUMN_COUNT = claims.MERKLE_PATH_MAIN_COLUMN_COUNT;
        pub const merkleLeafCount = retained.merkleLeafCount;
        pub const merkleInvocationCount = retained.merkleInvocationCount;
        pub const sharedPoseidonCallCount = retained.sharedPoseidonCallCount;
        pub const merkleWorkspaceDigest = materialized.merkleWorkspaceDigest;
        pub const validateMerkleWorkspaceAliases = materialized.validateMerkleWorkspaceAliases;
        pub const traceLogSize = validation.traceLogSize;
        pub const composition_input_relation = claims.composition_input_relation;
        pub const query_bits_relation = claims.query_bits_relation;
        pub const query_mapping_relation = claims.query_mapping_relation;
        pub const merkle_root_relation = claims.merkle_root_relation;
        pub const trace_merkle_relation = claims.trace_merkle_relation;
        pub const pcs_relation = claims.pcs_relation;
        pub const fri_leaf_relation = claims.fri_leaf_relation;
        pub const fri_node_relation = claims.fri_node_relation;
        pub const fri_anchor_relation = claims.fri_anchor_relation;
        pub const fri_control_relation = claims.fri_control_relation;
        pub const fri_input_relation = claims.fri_input_relation;
        pub const merkle_path_relation = claims.merkle_path_relation;
        pub const CompositionControlRelation = claims.CompositionControlRelation;
        pub const MultiplyRelation = claims.MultiplyRelation;
        pub const InverseRelation = claims.InverseRelation;
        pub const LinearRelation = claims.LinearRelation;
        pub const addTypedRowStorage = retained.addTypedRowStorage;
        pub const carveTypedRows = retained.carveTypedRows;
        pub const validateTypedRowsInStorage = retained.validateTypedRowsInStorage;
        pub const relationRowsDigest = retained.relationRowsDigest;
        pub const CompositionInputFramework = claims.CompositionInputFramework;
        pub const CompositionControlFramework = claims.CompositionControlFramework;
        pub const QueryBitsFramework = claims.QueryBitsFramework;
        pub const QueryMappingFramework = claims.QueryMappingFramework;
        pub const MerkleRootFramework = claims.MerkleRootFramework;
        pub const TraceMerkleFramework = claims.TraceMerkleFramework;
        pub const PcsFramework = claims.PcsFramework;
        pub const FriLeafFramework = claims.FriLeafFramework;
        pub const FriNodeFramework = claims.FriNodeFramework;
        pub const FriAnchorFramework = claims.FriAnchorFramework;
        pub const FriControlFramework = claims.FriControlFramework;
        pub const FriInputFramework = claims.FriInputFramework;
        pub const MultiplyFramework = claims.MultiplyFramework;
        pub const InverseFramework = claims.InverseFramework;
        pub const LinearFramework = claims.LinearFramework;
        pub const MerklePathFramework = claims.MerklePathFramework;
        pub const TYPED_RELATION_ROW_COUNT = claims.TYPED_RELATION_ROW_COUNT;
        pub const TYPED_INTERACTION_COLUMNS_PER_ROW = claims.TYPED_INTERACTION_COLUMNS_PER_ROW;
        pub const TYPED_INTERACTION_COLUMN_COUNT = claims.TYPED_INTERACTION_COLUMN_COUNT;
        pub const bundleLogSizesAssumeAuthority = Context.bundleLogSizesAssumeAuthority;
    };
}
