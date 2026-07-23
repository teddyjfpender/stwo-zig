//! CUDA proving backend for stwo, ported from the stwo-cuda prototype and adapted to
//! this repository's backend extension points. Compile-gated: without nvcc the kernels
//! crate provides panicking stubs, so this crate builds everywhere but only proves on
//! a CUDA machine. Conformance gate: `stwo_backend_testkit::assert_backend_conformance`
//! (proof byte-equality vs CpuBackend on both Blake2s channels), run on a CUDA box.

mod backend;

pub use backend::aot;
pub use backend::commit_graph::{
    CommitGraphError, CommitGraphPlan, CommitHashFromTileTelemetry, CommitLaunchKind,
    CommitLdeBatch, CommitLeafGroup, CommitLeafUpdateMode, CommitTailPlan, RetainedLdeHashMode,
};
pub use backend::decommit_gather::{
    column_row_gather_requirements, gather_column_rows_host, ColumnRowGatherError,
    ColumnRowGatherRequirements, ColumnRowGatherSlots, PreparedColumnRowGather,
};
pub use backend::device_transcript::{
    replay_blake2s_reference, Blake2sTranscriptRequirements, Blake2sTranscriptSchedule,
    Blake2sTranscriptWorkspaceSlots, DeviceTranscriptError, PreparedBlake2sTranscript,
    TranscriptArenaSlotRequirement, TranscriptBoundaryId, TranscriptBoundaryState,
    TranscriptInputBinding, TranscriptInputId, TranscriptIoRequirement, TranscriptMirrorReport,
    TranscriptOperation, TranscriptOutputBinding, TranscriptOutputId, TranscriptReferenceTrace,
    TranscriptSegmentCursor, TranscriptSegmentStart, TranscriptStart,
    BLAKE2S_TRANSCRIPT_ALIGNMENT_WORDS, BLAKE2S_TRANSCRIPT_PROTOCOL_TAG,
    BLAKE2S_TRANSCRIPT_STATE_WORDS,
};
pub use backend::exec_context::{
    cuda_device_snapshot, ArenaError, ArenaLayout, ArenaRangeSpec, ArenaSlice, ArenaSlotId,
    ArenaSlotSpec, CudaDeviceSnapshot, CudaExecContext, CudaExecTelemetry, CudaGraphCapture,
    CudaGraphExec, CudaLaunchContext, CudaPoolMemory, CudaRuntimeError, DeviceArena,
};
pub use backend::ipc_exchange::{
    cuda_context_device_identity, cuda_context_device_uuid, CudaDeviceIdentityReceipt,
    CudaDeviceUuid, CudaIpcExchangeImport, CudaIpcExchangeOwner, IpcExchangeDescriptor,
    IpcExchangeError, IpcExchangeImportState, IpcExchangeInstallDomain, IpcExchangeKey,
    IpcExchangeOwnerState, IpcExchangePhase, IpcExchangePhaseReceipt, IpcPeerCloseReceipt,
    CUDA_DEVICE_UUID_BYTES, CUDA_IPC_HANDLE_BYTES, IPC_EXCHANGE_ALLOCATION_ALIGNMENT,
    IPC_EXCHANGE_CLOSE_RECEIPT_BYTES, IPC_EXCHANGE_DESCRIPTOR_BYTES,
    IPC_EXCHANGE_INSTALL_DOMAIN_BYTES,
};
pub use backend::pcs_driver::{
    prove_values_with_config as prove_cuda_pcs_values, CudaPcsDriverConfig, CudaPcsDriverError,
    CudaPcsDriverOutput, CudaPcsDriverTelemetry, CudaPcsGraphHookError, CudaPcsGraphHooks,
    CudaPcsRuntimeMode,
};
pub use backend::prepared_casm_input::{
    witness_casm_input_requirements, PendingWitnessCasmInputIngressReceipt,
    PreparedWitnessCasmInputError, PreparedWitnessCasmInputStage, WitnessCasmInputAbi,
    WitnessCasmInputAbiAccess, WitnessCasmInputAbiArgument, WitnessCasmInputAbiArgumentKind,
    WitnessCasmInputAuthorityError, WitnessCasmInputColumnEffect, WitnessCasmInputColumnValue,
    WitnessCasmInputContract, WitnessCasmInputEffectAbi, WitnessCasmInputEffectGeometry,
    WitnessCasmInputFixedField, WitnessCasmInputIngressReceipt, WitnessCasmInputKernelLaunch,
    WitnessCasmInputLinkedContract, WitnessCasmInputRequirements, WitnessCasmInputRowDomain,
    WitnessCasmInputSlots, WITNESS_CASM_BASE_INPUT_COLUMNS, WITNESS_CASM_INPUT_FIXED_ORDER,
    WITNESS_CASM_STATE_WORDS,
};
pub use backend::prepared_commit::{
    commit_workspace_requirements, merkle_from_leaves_requirements, CommitArenaSlotRequirement,
    CommitBatchRequirements, CommitBatchSlots, CommitCoefficientColumn, CommitCoefficientGroup,
    CommitEvaluationGroup, CommitGroupRequirements, CommitGroupSlots, CommitLayerRequirements,
    CommitWorkspaceConfig, CommitWorkspaceRequirements, CommitWorkspaceSlots,
    MerkleFromLeavesRequirements, MerkleFromLeavesSlots, PreparedCommitError, PreparedCommitGraph,
    PreparedMerkleFromLeaves, COMMIT_HASH_ALIGNMENT_WORDS, COMMIT_POINTER_ALIGNMENT_WORDS,
};
pub use backend::prepared_decommit::{
    decommit_workspace_requirements, DecommitArenaSlotRequirement, DecommitAssembly,
    DecommitColumnGeometry, DecommitColumnSource, DecommitDirectPackModel, DecommitSourceMode,
    DecommitTreeGeometry, DecommitTreeMeta, DecommitTreeRequirements, DecommitTreeSlots,
    DecommitTreeSources, DecommitWorkspaceConfig, DecommitWorkspaceRequirements,
    DecommitWorkspaceSlots, FriDecommitGeometry, FriDecommitOwnedSources, FriDecommitSlots,
    FriTreeRequirements, PreparedDecommitError, PreparedDecommitGraph, TraceDecommitGeometry,
    TraceDecommitSlots, TraceDecommitSources, TraceGroupRequirements, TraceSourceGroup,
    TraceSourceGroupGeometry, TraceSourceGroupSlots, TraceTreeRequirements, TraceTreeRole,
    DECOMMIT_HASH_ALIGNMENT_WORDS, DECOMMIT_POINTER_ALIGNMENT_WORDS,
};
pub use backend::prepared_ec_op::{
    ec_op_workspace_requirements, EcOpAbiAccess, EcOpAbiArgument, EcOpAbiArgumentKind,
    EcOpArenaSlotRequirement, EcOpAuthorityError, EcOpCompositeAbi, EcOpCompositeContract,
    EcOpEffectAbi, EcOpExecutionTableShape, EcOpKernelLaunch, EcOpKernelStage,
    EcOpMultiplicityGeometry, EcOpSegmentStartReceipt, EcOpWorkspaceRequirements,
    EcOpWorkspaceSlots, PreparedEcOpError, PreparedEcOpGraph, PreparedEcOpIngestTelemetry,
    PreparedEcOpLaunchTelemetry, EC_OP_LOOKUP_WORDS_PER_ROW, EC_OP_PARTIAL_INPUT_COLUMNS,
    EC_OP_PARTIAL_PADDED_ROUNDS, EC_OP_PARTIAL_REAL_ROUNDS, EC_OP_TRACE_COLUMNS,
};
pub use backend::prepared_execution_tables::{
    execution_tables_workspace_requirements, ExecutionTablesAbi, ExecutionTablesAbiAccess,
    ExecutionTablesAbiArgument, ExecutionTablesAbiArgumentKind,
    ExecutionTablesArenaSlotRequirement, ExecutionTablesAuthorityError,
    ExecutionTablesColumnEffect, ExecutionTablesContract, ExecutionTablesEffectAbi,
    ExecutionTablesFixedField, ExecutionTablesHostData, ExecutionTablesHostIngressEncoding,
    ExecutionTablesHostIngressField, ExecutionTablesHostIngressGeometry,
    ExecutionTablesHostIngressRole, ExecutionTablesIngestReceipt, ExecutionTablesKernelLaunch,
    ExecutionTablesLinkedContract, ExecutionTablesRowDomain, ExecutionTablesStage,
    ExecutionTablesStageContract, ExecutionTablesStageEffect, ExecutionTablesWorkspaceRequirements,
    ExecutionTablesWorkspaceSlots, PreparedExecutionTablesError, PreparedExecutionTablesGraph,
    PreparedExecutionTablesIngestTelemetry, PreparedExecutionTablesLaunchTelemetry,
    PreparedExecutionTablesView, EXECUTION_TABLES_FIXED_ORDER, EXECUTION_TABLES_STAGE_ORDER,
    EXECUTION_TABLE_BIG_LIMBS, EXECUTION_TABLE_POINTERS, EXECUTION_TABLE_POINTER_ALIGNMENT_WORDS,
    EXECUTION_TABLE_SMALL_LIMBS, EXECUTION_TABLE_STRIDES,
};
pub use backend::prepared_fixed_table::{
    fixed_table_workspace_requirements, FixedTableArenaSlotRequirement,
    FixedTableContiguousWorkspaceSlots, FixedTableLookupSource, FixedTableMaterializationConfig,
    FixedTableMaterializerAbi, FixedTableMaterializerAbiAccess, FixedTableMaterializerAbiArgument,
    FixedTableMaterializerAbiArgumentKind, FixedTableMaterializerAuthorityError,
    FixedTableMaterializerContract, FixedTableMaterializerKernelLaunch,
    FixedTableMaterializerLinkedContract, FixedTableSourceColumn, FixedTableWorkspaceRequirements,
    FixedTableWorkspaceSlots, PreparedFixedTableError, PreparedFixedTableGraph,
    FIXED_TABLE_LOOKUP_DESCRIPTOR_WORDS, FIXED_TABLE_POINTER_ALIGNMENT_WORDS,
};
pub use backend::prepared_fri::{
    fri_workspace_requirements, FriArenaSlotRequirement, FriFoldLaunchMode,
    FriMerkleLayerRequirements, FriMerkleTreeRequirements, FriMerkleTreeSlots,
    FriRoundRequirements, FriWorkspaceConfig, FriWorkspaceRequirements, FriWorkspaceSlots,
    PreparedFriError, PreparedFriEvaluation, PreparedFriGraph, FRI_CHALLENGE_WORDS,
    FRI_HASH_ALIGNMENT_WORDS, FRI_POINTER_ALIGNMENT_WORDS,
};
pub use backend::prepared_fri_final::{
    fri_final_workspace_requirements, FriFinalArenaSlotRequirement, FriFinalWorkspaceRequirements,
    FriFinalWorkspaceSlots, PreparedFriFinalError, PreparedFriFinalGraph,
};
pub use backend::prepared_interaction_commit_authority::{
    InteractionCommitAuthorityError, InteractionCommitLinkedAuthority,
    InteractionCommitProgramAuthority,
};
pub use backend::prepared_interpolation::{
    b2n_chunk_ranges, b2n_stage_intervals, InterpolationAbiAccess, InterpolationAbiArgument,
    InterpolationAbiArgumentKind, InterpolationAuthorityError, InterpolationBatch,
    InterpolationBatchAuthority, InterpolationColumn, InterpolationEffectAbi,
    InterpolationLaunchMode, InterpolationPrimitiveAbi, InterpolationPrimitiveAuthority,
    PreparedInterpolationError, PreparedInterpolationGraph, INTERPOLATION_MAX_BATCH_COLUMNS,
    INTERPOLATION_POINTER_ALIGNMENT_WORDS,
};
pub use backend::prepared_memory_trace::{
    MemoryBaseTraceAbi, MemoryBaseTraceAbiAccess, MemoryBaseTraceAbiArgument,
    MemoryBaseTraceAbiArgumentKind, MemoryBaseTraceAuthorityError, MemoryBaseTraceContract,
    MemoryBaseTraceEffectAccess, MemoryBaseTraceEffectRole, MemoryBaseTraceKernelLaunch,
    MemoryBaseTraceLinkedContract, MemoryBaseTracePart, MemoryBaseTraceRequirements,
    MemoryBaseTraceStepContract, MemoryBaseTraceStepKind, MemoryBaseTraceValuePartRequirements,
    PreparedMemoryBaseTraceError, PreparedMemoryBaseTraceGraph, MEMORY_ADDRESS_BASE_COLUMNS,
    MEMORY_BIG_BASE_COLUMNS, MEMORY_SMALL_BASE_COLUMNS,
};
pub use backend::prepared_oods::{
    oods_canonical_sample_order, oods_workspace_requirements, OodsArenaSlotRequirement,
    OodsCanonicalSample, OodsCoefficientColumn, OodsColumnSampleRange, OodsColumnSource,
    OodsColumnTopology, OodsEvaluationGroupRequirements, OodsExecutionAbi, OodsExecutionAbiAccess,
    OodsExecutionAbiArgument, OodsExecutionAbiArgumentKind, OodsExecutionAccess,
    OodsExecutionAccessKind, OodsExecutionAuthority, OodsExecutionAuthorityError,
    OodsExecutionColumn, OodsExecutionHostCall, OodsExecutionHostCallKind, OodsExecutionInvocation,
    OodsExecutionInvocationArgument, OodsExecutionInvocationValue, OodsExecutionKernelLaunch,
    OodsExecutionLinkedAuthority, OodsExecutionScratch, OodsExecutionValueLayout,
    OodsExecutionValueOwnership, OodsExecutionValueRole, OodsLogGroupRequirements,
    OodsMaskTopology, OodsPassCollapseBatchReceipt, OodsPassCollapseCohortReceipt,
    OodsPassCollapseCohortRejection, OodsPassCollapseError, OodsPassCollapseGroupReceipt,
    OodsPassCollapseIdentity, OodsPassCollapseProgram, OodsPassCollapseReceipt,
    OodsPolynomialColumn, OodsSourceKind, OodsWorkspaceConfig, OodsWorkspaceRequirements,
    OodsWorkspaceSlots, PreparedOodsError, PreparedOodsGraph, OODS_COLLAPSED_AUX_SHARED_QM31,
    OODS_COLLAPSED_CORE_SHARED_QM31, OODS_COLLAPSED_DYNAMIC_SHARED_BYTES,
    OODS_CUDA_DEFAULT_DYNAMIC_SHARED_LIMIT_BYTES, OODS_PARAMETER_WORDS,
    OODS_POINTER_ALIGNMENT_WORDS,
};
pub use backend::prepared_pow::{
    blake2s_pow_workspace_requirements, pow_index_to_nonce, Blake2sPowArenaSlotRequirement,
    Blake2sPowFleetAttempt, Blake2sPowRankTile, Blake2sPowWorkspaceRequirements,
    Blake2sPowWorkspaceSlots, PreparedBlake2sPowError, PreparedBlake2sPowGraph, POW_GRIND_LOW_BITS,
    POW_INDEX_LIMIT, POW_NONCE_WORDS, POW_THREADS_PER_BLOCK, POW_U64_ALIGNMENT_WORDS,
};
pub use backend::prepared_progressive_commit::{
    compact_domain_arena_slot_requirements, direct_compact_domain_arena_slot_requirements,
    direct_terminal_expand_absorb_arena_slot_requirements, fused_compact_domain_arch_supported,
    fused_compact_domain_arena_slot_requirements, fused_compact_domain_materialized_only_admission,
    progressive_commit_workspace_requirements_for_mode, progressive_leaf_workspace_requirements,
    progressive_leaf_workspace_requirements_for_mode, progressive_prepare_mode_admission,
    progressive_prepare_mode_admission_for_mode, BaseCommitAbi, BaseCommitAbiAccess,
    BaseCommitAbiArgument, BaseCommitAbiArgumentKind, BaseCommitAccess, BaseCommitAccessKind,
    BaseCommitAliasAuthority, BaseCommitAliasDiscipline, BaseCommitAliasRequirement,
    BaseCommitAuthorityError, BaseCommitDependencyRange, BaseCommitDependencyRole,
    BaseCommitEffect, BaseCommitExecutionBuffer, BaseCommitExecutionStep,
    BaseCommitInstalledAccess, BaseCommitInvocation, BaseCommitInvocationArgument,
    BaseCommitInvocationValue, BaseCommitKernelArgument, BaseCommitKernelArgumentValue,
    BaseCommitKernelLaunch, BaseCommitLayout, BaseCommitLinkedAuthority, BaseCommitOperation,
    BaseCommitOperationKind, BaseCommitPartitionAuthority, BaseCommitPointerBinding,
    BaseCommitPointerTarget, BaseCommitProgramAuthority, BaseCommitRetainedEvaluation,
    BaseCommitRetainedLayer, BaseCommitValueRole, CommitProgram, CommitProgramBindingError,
    CommitProgramError, CommitProgramFixture, CommitProgramIdentity, CommitProgramLayer,
    CommitProgramOperation, CommitProgramOracle, CommitProgramOracleLayer, CommitProgramStep,
    CommitProgramTraffic, CompactBlake2sTailDescriptor, CompactDomainBindingError,
    CompactDomainComparison, CompactDomainOperation, CompactDomainPreparedLaunchKind,
    CompactDomainProgram, CompactDomainProgramError, CompactDomainStep, CompactDomainTail,
    CompositionSplitColumns, CompositionSplitError, CompositionSplitLaunchMode,
    CompositionSplitOracle, CompositionSplitPointerSlots, CompositionSplitProgram,
    CompositionSplitSchedule, CompositionSplitTraffic, DirectCompactDomainBindingError,
    DirectCompactTerminalBatchMode, DirectCompactTerminalBatchReceipt, DirectCompactTerminalError,
    DirectCompactTerminalFallbackReason, DirectCompactTerminalProgram,
    DirectCompactTerminalReceipt, DirectCompactTerminalSupport, DirectRetainedB2nBatchPlan,
    DirectRetainedB2nColumn, DirectRetainedB2nError, DirectRetainedB2nLaunchKind,
    DirectRetainedB2nOracle, DirectRetainedB2nProgram, DirectTerminalExpandAbsorbError,
    DirectTerminalExpandAbsorbOperation, DirectTerminalExpandAbsorbProgram,
    DirectTerminalExpandAbsorbReceipt, DirectTerminalExpandAbsorbTransition,
    DomainCooperativeBindingError, DomainCooperativeComparison, DomainCooperativeOperation,
    DomainCooperativeProgram, DomainCooperativeProgramError, DomainCooperativeResourceModel,
    DomainCooperativeSlabSlice, DomainCooperativeStep, FusedCompactDomainBindingError,
    FusedCompactDomainOperation, FusedCompactDomainProgram, FusedCompactDomainProgramError,
    FusedCompactDomainReceipt, FusedCompactDomainStep, FusedCompactDomainTransition,
    ModeAwareCommitWorkspaceRequirements, ModeAwareCommitWorkspaceSlots, PreparedCommitProgramView,
    PreparedCompactDomainCommitGraph, PreparedCompositionSplitGraph,
    PreparedDirectCompactDomainCommitGraph, PreparedDirectRetainedB2nGraph,
    PreparedDirectTerminalExpandAbsorbGraph, PreparedFusedCompactDomainCommitGraph,
    PreparedPrecomputedCompactDomainCommitGraph, PreparedProgressiveCommitError,
    PreparedProgressiveCommitGraph, PreparedProgressiveLeaves, ProgressiveBatchRequirements,
    ProgressiveBatchSlots, ProgressiveCommitStorageMode, ProgressiveCommitWorkspaceRequirements,
    ProgressiveCommitWorkspaceSlots, ProgressiveLeafLaunchKind,
    ProgressiveLeafWorkspaceRequirements, ProgressiveLeafWorkspaceSlots, ShapeWideColumn,
    ShapeWideColumnDescriptorAbi, ShapeWideColumnStorage, ShapeWideCommitComparison,
    ShapeWideCommitProgram, ShapeWideCommitProgramError, ShapeWideLeafOperation, ShapeWideLeafStep,
    ShapeWideSlabLayout, COMPOSITION_RETAINED_COLUMNS, COMPOSITION_SOURCE_COORDINATES,
    FUSED_COMPACT_DOMAIN_MIN_SM_MAJOR,
};
pub use backend::prepared_quotient::{
    quotient_workspace_requirements, PreparedQuotientError, PreparedQuotientGraph,
    QuotientArenaSlotRequirement, QuotientCombinePassBytes, QuotientNumeratorSource,
    QuotientSampleConstants, QuotientWorkspaceConfig, QuotientWorkspaceRequirements,
    QuotientWorkspaceSlots, QUOTIENT_POINTER_ALIGNMENT_WORDS,
};
pub use backend::prepared_quotient_numerator::{
    quotient_numerator_workspace_requirements, PreparedNumeratorSchedule,
    PreparedPrepackedQuotientNumeratorReceipt, PreparedQuotientNumeratorError,
    PreparedQuotientNumeratorGraph, QuotientNumeratorArenaSlotRequirement,
    QuotientNumeratorBatchRequirements, QuotientNumeratorColumn, QuotientNumeratorColumnSource,
    QuotientNumeratorColumnTopology, QuotientNumeratorDestination,
    QuotientNumeratorGroupRequirements, QuotientNumeratorSourceKind,
    QuotientNumeratorWorkspaceConfig, QuotientNumeratorWorkspaceRequirements,
    QuotientNumeratorWorkspaceSlots, QuotientOodsSample,
    QUOTIENT_NUMERATOR_POINTER_ALIGNMENT_WORDS,
};
pub use backend::prepared_witness::{
    blake_g_fusion_program_is_exact, phase_scratch_words, witness_workspace_requirements,
    BlakeGDirectAbiAccess, BlakeGDirectAbiArgument, BlakeGDirectAbiArgumentKind,
    BlakeGDirectAuthorityError, BlakeGDirectCompositeAbi, BlakeGDirectCompositeContract,
    BlakeGDirectCountDestination, BlakeGDirectEffectAbi, BlakeGDirectLut, BlakeGDirectRowDomain,
    BlakeGDirectWrapperLaunch, PreparedWitnessError, PreparedWitnessGraph,
    PreparedWitnessLaunchTelemetry, PreparedWitnessMode, PreparedWitnessPhaseProgram,
    WitnessArenaSlotRequirement, WitnessKernelIdentity, WitnessWorkspaceRequirements,
    WitnessWorkspaceSlots, BLAKE_G_DIRECT_BLOCK_THREADS, BLAKE_G_DIRECT_COUNT_ORDER,
    BLAKE_G_DIRECT_COUNT_WORDS, BLAKE_G_DIRECT_LUT_ORDER, BLAKE_G_DIRECT_LUT_WORDS,
    WITNESS_POINTER_ALIGNMENT_WORDS,
};
pub use backend::prepared_witness_feed::{
    clear_witness_feed_destinations_once, witness_feed_clear_workspace_requirements,
    witness_feed_descriptor_fits_shared, witness_feed_privatized_footprint_words,
    witness_feed_workspace_requirements, BlakeGDirectLutContentError,
    BlakeGDirectLutContentIdentity, PreparedBlakeGFusedFeed, PreparedWitnessFeedClearGraph,
    PreparedWitnessFeedError, PreparedWitnessFeedGraph, WitnessFeedAbi, WitnessFeedAbiAccess,
    WitnessFeedAbiArgument, WitnessFeedAbiArgumentKind, WitnessFeedArenaSlotRequirement,
    WitnessFeedAuthorityError, WitnessFeedClearAbi, WitnessFeedClearAbiAccess,
    WitnessFeedClearAbiArgument, WitnessFeedClearAbiArgumentKind, WitnessFeedClearAuthorityError,
    WitnessFeedClearContract, WitnessFeedClearDestinationEffect, WitnessFeedClearEffectAbi,
    WitnessFeedClearEffectGeometry, WitnessFeedClearKernelLaunch, WitnessFeedClearLinkedContract,
    WitnessFeedClearWorkspaceRequirements, WitnessFeedClearWorkspaceSlots, WitnessFeedContract,
    WitnessFeedDescriptorField, WitnessFeedDescriptorKind, WitnessFeedDestinationEffect,
    WitnessFeedDestinationRange, WitnessFeedEffectAbi, WitnessFeedEffectGeometry,
    WitnessFeedKernelLaunch, WitnessFeedLaunchMode, WitnessFeedLinkedContract, WitnessFeedLutRead,
    WitnessFeedRowDomain, WitnessFeedSourceRead, WitnessFeedSourceUploadReceipt,
    WitnessFeedWorkspaceRequirements, WitnessFeedWorkspaceSlots,
    WITNESS_FEED_DESCRIPTOR_FIELD_ORDER, WITNESS_FEED_DESCRIPTOR_WORDS,
    WITNESS_FEED_MAX_TUPLE_WORDS, WITNESS_FEED_NO_LUT, WITNESS_FEED_POINTER_ALIGNMENT_WORDS,
    WITNESS_FEED_PRIVATIZED_SHARED_BYTES, WITNESS_FEED_PRIVATIZED_SHARED_WORDS,
};
pub use backend::prepared_witness_input::{
    witness_input_compact_requirements, witness_input_gather_requirements,
    witness_input_seed_requirements, PreparedWitnessInputCompactGraph,
    PreparedWitnessInputGatherError, PreparedWitnessInputGatherGraph,
    PreparedWitnessInputSeedGraph, WitnessInputCompactAbi, WitnessInputCompactAbiAccess,
    WitnessInputCompactAbiArgument, WitnessInputCompactAbiArgumentKind,
    WitnessInputCompactAuthorityError, WitnessInputCompactContract, WitnessInputCompactCubStage,
    WitnessInputCompactEffectAbi, WitnessInputCompactEffectGeometry, WitnessInputCompactExecution,
    WitnessInputCompactFixedField, WitnessInputCompactIndexBuffer, WitnessInputCompactKernelLaunch,
    WitnessInputCompactKernelStage, WitnessInputCompactKeyBuffer, WitnessInputCompactLayout,
    WitnessInputCompactLinkedContract, WitnessInputCompactOutputEffect,
    WitnessInputCompactRequirements, WitnessInputCompactRowDomain,
    WitnessInputCompactScratchEffect, WitnessInputCompactSlots, WitnessInputCompactSourceEffect,
    WitnessInputCompactStage, WitnessInputGatherAbi, WitnessInputGatherAbiAccess,
    WitnessInputGatherAbiArgument, WitnessInputGatherAbiArgumentKind,
    WitnessInputGatherArenaSlotRequirement, WitnessInputGatherAuthorityError,
    WitnessInputGatherContract, WitnessInputGatherDescriptorField, WitnessInputGatherEdge,
    WitnessInputGatherEdgePlan, WitnessInputGatherEffectAbi, WitnessInputGatherEffectGeometry,
    WitnessInputGatherLinkedContract, WitnessInputGatherOutputEffect,
    WitnessInputGatherPackedEdgeEffect, WitnessInputGatherRequirements,
    WitnessInputGatherRowDomain, WitnessInputGatherSlots, WitnessInputGatherWrapperLaunch,
    WitnessInputSeedAbi, WitnessInputSeedAbiAccess, WitnessInputSeedAbiArgument,
    WitnessInputSeedAbiArgumentKind, WitnessInputSeedAuthorityError, WitnessInputSeedColumnEffect,
    WitnessInputSeedColumnValue, WitnessInputSeedContract, WitnessInputSeedEffectAbi,
    WitnessInputSeedEffectGeometry, WitnessInputSeedFixedField, WitnessInputSeedKernelLaunch,
    WitnessInputSeedLinkedContract, WitnessInputSeedRequirements, WitnessInputSeedRowDomain,
    WitnessInputSeedSlots, WITNESS_INPUT_COMPACT_FIXED_ORDER,
    WITNESS_INPUT_GATHER_DESCRIPTOR_ORDER, WITNESS_INPUT_GATHER_DESCRIPTOR_WORDS,
    WITNESS_INPUT_GATHER_PACKED_LANES, WITNESS_INPUT_GATHER_POINTER_ALIGNMENT_WORDS,
    WITNESS_INPUT_SEED_FIXED_ORDER,
};
pub use backend::progressive_commit::{
    full_lifting_leaf_oracle, lifted_column_index, merkle_root, plan_progressive_commit,
    progressive_commit_cache_key, progressive_leaf_oracle, Blake2sStateExpansion,
    CanonicalLeafBlock, ProgressiveBlockSegment, ProgressiveColumn, ProgressiveCommitAccounting,
    ProgressiveCommitError, ProgressiveCommitGeometry, ProgressiveCommitGroupGeometry,
    ProgressiveCommitMode, ProgressiveCommitPlan, SameLogLdeBatch, StateExpansion,
    BLAKE2S_BLOCK_BYTES, LEGACY_PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES,
    PROGRESSIVE_BLAKE2S_H_OFFSET, PROGRESSIVE_BLAKE2S_PENDING_BLOCK_OFFSET,
    PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES,
};
pub use backend::progressive_commit_in_place::{
    expansion_band_plan, finalize_band_plan, merkle_band_plan, progressive_in_place_cache_key,
    progressive_in_place_slab_words, InPlaceBand, InPlaceBandPlan, InPlacePlanError,
    PROGRESSIVE_IN_PLACE_SCRATCH_BYTES, PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
};
pub use backend::progressive_ntt_leaf_fusion::{
    progressive_ntt_leaf_fusion_telemetry, ProgressiveNttLeafFusionMode,
    ProgressiveNttLeafFusionTelemetry, PROGRESSIVE_NTT_LEAF_FUSED_COLUMNS,
    PROGRESSIVE_NTT_LEAF_FUSED_MIN_LOG_SIZE,
};
pub use backend::proof_assembly::{
    assemble_blake2s_stark_proof, Blake2sFriAssemblyShape, Blake2sProofAssemblyError,
    Blake2sProofAssemblyInput, Blake2sProofAssemblyShape, Blake2sTraceAssemblyShape,
};
pub use backend::quotient_numerator_prepacked_terms::{
    quotient_numerator_prepacked_plan_identity, quotient_numerator_prepacked_row_oracle,
    quotient_numerator_prepacked_term_layout, quotient_numerator_prepacked_term_oracle,
    QuotientNumeratorLineCoefficientsWords, QuotientNumeratorPrepackedStatusCode,
    QuotientNumeratorPrepackedTerm, QuotientNumeratorPrepackedTermError,
    QuotientNumeratorPrepackedTermLayout, QuotientNumeratorPrepackedTermOracle,
    QUOTIENT_NUMERATOR_PREPACKED_GROUP_WORDS, QUOTIENT_NUMERATOR_PREPACKED_STATUS_WORDS,
    QUOTIENT_NUMERATOR_PREPACKED_TERM_WORDS,
};
pub use backend::quotient_numerator_run_sum::{
    quotient_numerator_run_sum_plan, QuotientNumeratorRunSumError,
    QuotientNumeratorRunSumExpansionEntry, QuotientNumeratorRunSumExpansionManifest,
    QuotientNumeratorRunSumLiveness, QuotientNumeratorRunSumReceipt,
    QUOTIENT_NUMERATOR_RUN_SUM_EXPANSION_KERNEL_PARAMETER_BYTES,
    QUOTIENT_NUMERATOR_RUN_SUM_EXPANSION_MANIFEST_BYTES, QUOTIENT_NUMERATOR_RUN_SUM_MAX_RUNS,
};
pub use backend::quotient_numerator_single_write::{
    quotient_numerator_hybrid_plan, quotient_numerator_single_write_plan,
    quotient_numerator_single_write_report, QuotientNumeratorHybridBatch,
    QuotientNumeratorHybridPlan, QuotientNumeratorHybridReport,
    QuotientNumeratorSingleWriteEligibility, QuotientNumeratorSingleWriteError,
    QuotientNumeratorSingleWritePlan, QuotientNumeratorSingleWriteReport,
    QUOTIENT_NUMERATOR_SINGLE_WRITE_TERM_WORDS,
};
pub use backend::quotient_numerator_staged_single_write::{
    quotient_numerator_staged_single_write_plan,
    quotient_numerator_staged_single_write_plan_with_overflow_capacities,
    QuotientNumeratorStagedLde, QuotientNumeratorStagedSingleWriteError,
    QuotientNumeratorStagedSingleWritePlan, QuotientNumeratorStagedSingleWriteReport,
    QuotientNumeratorStagedSource, QuotientNumeratorStagingRole,
};
pub use backend::quotient_producer_b2n::{
    quotient_producer_b2n_oracle, QuotientProducerB2nAttestationError, QuotientProducerB2nError,
    QuotientProducerB2nFunctionAttributes, QuotientProducerB2nKernelResourcePolicy,
    QuotientProducerB2nKernelRole, QuotientProducerB2nLaunchAttestation,
    QuotientProducerB2nProgram, QuotientProducerB2nReceipt, QuotientProducerB2nResourceContract,
    QuotientProducerB2nResourcePolicy, QuotientProducerB2nRuntimeAttestation,
    QuotientProducerB2nSchedule, QuotientProducerB2nTraffic,
    QUOTIENT_PRODUCER_B2N_CONTINUATION_SHARED_CAP, QUOTIENT_PRODUCER_B2N_CONTINUATION_THREADS,
    QUOTIENT_PRODUCER_B2N_FIRST_STAGES, QUOTIENT_PRODUCER_B2N_LAUNCH_THREADS,
    QUOTIENT_PRODUCER_B2N_REQUIRED_SM_ARCH, QUOTIENT_PRODUCER_BATCH_INVERSE_CHUNK,
};
pub use backend::relation_graph::{
    blake_g_inputs_batch_is_exact, relation_batch_fused_eligible, relation_batch_one_read_eligible,
    relation_graph_requirements, PreparedRelationGraph, PreparedRelationOutput, RelationAbi,
    RelationAbiAccess, RelationAbiArgument, RelationAbiArgumentKind, RelationAccess,
    RelationAccessKind, RelationArenaSlotRequirement, RelationBatchProgram,
    RelationChallengeAbiAccess, RelationChallengeAbiArgument, RelationChallengeAbiArgumentKind,
    RelationChallengeAccess, RelationChallengeAccessKind, RelationChallengeAuthorityError,
    RelationChallengeExpansionAuthority, RelationChallengeInvocationArgument,
    RelationChallengeInvocationValue, RelationChallengeKernelLaunch,
    RelationChallengeLinkedAuthority, RelationChallengeValueRole, RelationChallenges,
    RelationColumnDescriptor, RelationExecutionAuthority, RelationExecutionAuthorityError,
    RelationExecutionInstance, RelationExecutionStage, RelationGraphError,
    RelationGraphRequirements, RelationGraphSlots, RelationInstanceRequirement,
    RelationInstanceSlots, RelationInstanceSources, RelationInvocation, RelationInvocationArgument,
    RelationInvocationValue, RelationKernelArgument, RelationKernelArgumentValue,
    RelationKernelLaunch, RelationKernelProgram, RelationLaunchMode,
    RelationLinkedExecutionAuthority, RelationMultiplicityKind, RelationPartitionAuthority,
    RelationPointerTableKind, RelationRowExtent, RelationSourceLayout, RelationTailMode,
    RelationTupleKind, RelationUseDescriptor, RelationValueLayout, RelationValueOwnership,
    RelationValueRole, RelationWrapperExecution, RELATION_CHALLENGE_ARGUMENTS,
    RELATION_FUSED_MASK_WORDS, RELATION_FUSED_MAX_COLUMNS, RELATION_FUSED_MAX_INSTANCES,
    RELATION_FUSED_MAX_TUPLE_WORDS, RELATION_POINTER_ALIGNMENT_WORDS,
};
#[cfg(feature = "test-only-relation-ab")]
pub use backend::relation_graph::{RelationFusedTestFunctionResources, RelationFusedTestStrategy};
pub use backend::vmm_allocation::{
    PinnedDmaWindow, PinnedDmaWindowState, VmmAllocation, VmmAllocationError, VmmAllocationState,
};
mod columns;

pub use backend::{
    blake_witness, exec_tables, finalize_raw_logup, jit_witness, logup_pairs, memory_witness,
    pedersen_module_publication, pedersen_table, pedersen_witness, CudaBackend,
};
pub use columns::{BaseFieldVec, Blake2sHashVec, SecureFieldVec};

/// (free_bytes, total_bytes) of GPU memory; (0, 0) without CUDA.
pub fn gpu_memory_info() -> (usize, usize) {
    if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        return (0, 0);
    }
    let mut free = 0usize;
    let mut total = 0usize;
    unsafe { columns::bindings::cuda_get_memory_info(&mut free, &mut total) };
    (free, total)
}

/// Never-release-pool high-water marks since process start, in bytes:
/// (peak allocated in flight, peak reserved from the device). Driver-maintained
/// and exact, unlike sampler-based probes (the harness's 25ms sampler measured
/// up to 11GB low on SN_PIE_2); (0, 0) without CUDA. The VRAM-diet metric.
pub fn gpu_pool_highwater() -> (usize, usize) {
    if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        return (0, 0);
    }
    let mut used = 0usize;
    let mut reserved = 0usize;
    unsafe { columns::bindings::cuda_pool_highwater(&mut used, &mut reserved) };
    (used, reserved)
}

/// Reset the pool high-water marks to current usage — per-phase VRAM
/// attribution (design §1.1 R5): read + reset at phase boundaries.
pub fn gpu_pool_highwater_reset() {
    if stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        unsafe { columns::bindings::cuda_pool_highwater_reset() };
    }
}

/// Checked current used/reserved bytes for the process-wide default CUDA pool.
/// Unlike [`gpu_pool_highwater`], this is the resident footprint now rather than
/// the largest cold-setup overlap seen earlier in the process.
pub fn gpu_default_pool_memory() -> Result<CudaPoolMemory, CudaRuntimeError> {
    if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        return Err(CudaRuntimeError::Unavailable);
    }
    let mut used_bytes = 0usize;
    let mut reserved_bytes = 0usize;
    let code = unsafe {
        stwo_backend_cuda_kernels::raw::cuda_default_pool_current(
            &mut used_bytes,
            &mut reserved_bytes,
        )
    };
    backend::exec_context::check_cuda("default_pool_current", code)?;
    Ok(CudaPoolMemory {
        used_bytes,
        reserved_bytes,
    })
}

/// Initialize and admit the process-wide default CUDA pool.
///
/// The native initializer caches only success, so a transient failure can be
/// retried safely before any process-lifetime table or resident workspace is
/// created. Stub builds fail without entering a panic stub.
pub fn ensure_gpu_default_pool() -> Result<(), CudaRuntimeError> {
    columns::bindings::try_ensure_mem_pool_init()
}

/// Fence legacy stream 0, explicitly trim unused default-pool backing memory,
/// and return the checked post-trim current footprint.
///
/// This does not remove live allocations and therefore does not reduce the cold
/// setup peak; it only returns already-freed pool reserve to the device.
pub fn trim_gpu_default_pool(min_bytes_to_keep: usize) -> Result<CudaPoolMemory, CudaRuntimeError> {
    if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        return Err(CudaRuntimeError::Unavailable);
    }
    let mut used_bytes = 0usize;
    let mut reserved_bytes = 0usize;
    let code = unsafe {
        stwo_backend_cuda_kernels::raw::cuda_default_pool_trim(
            min_bytes_to_keep,
            &mut used_bytes,
            &mut reserved_bytes,
        )
    };
    backend::exec_context::check_cuda("default_pool_trim", code)?;
    Ok(CudaPoolMemory {
        used_bytes,
        reserved_bytes,
    })
}

/// Fence work issued by the migration-era CUDA backend default stream before
/// handing its buffers to an isolated [`CudaExecContext`].
///
/// The resident prover does not launch proof work on the legacy stream.  This
/// boundary exists solely while witness producers still return owning
/// `BaseFieldVec`s allocated by the old backend; once those producers target
/// arena slices directly this function and the associated D2D staging copy are
/// removed.  Stub builds have no device work to fence.
pub fn synchronize_legacy_stream_for_arena_handoff() {
    if stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        // The native wrapper checks the CUDA status and aborts rather than
        // allowing a failed producer to race an arena consumer.
        unsafe { columns::bindings::stwo_legacy_stream_sync() };
    }
}

#[cfg(test)]
mod pool_tests {
    use super::*;

    #[test]
    fn checked_default_pool_apis_are_unavailable_without_cuda() {
        if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
            assert_eq!(
                ensure_gpu_default_pool(),
                Err(CudaRuntimeError::Unavailable)
            );
            assert_eq!(
                gpu_default_pool_memory(),
                Err(CudaRuntimeError::Unavailable)
            );
            assert_eq!(trim_gpu_default_pool(0), Err(CudaRuntimeError::Unavailable));
        }
    }

    #[cfg(stwo_cuda_link)]
    #[test]
    fn checked_default_pool_initialization_is_idempotent() {
        ensure_gpu_default_pool().unwrap();
        ensure_gpu_default_pool().unwrap();
        gpu_default_pool_memory().unwrap();
    }
}
