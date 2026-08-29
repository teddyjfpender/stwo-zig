//! Public Metal runtime facade.
//!
//! Resource ownership and API names stay here; protocol-stage implementations
//! live under `runtime/` so callers do not depend on Objective-C or dispatch details.

const abi = @import("runtime/abi.zig");
const command_epoch = @import("command_epoch.zig");
const shader_manifest = @import("shaders/manifest.zig");

comptime {
    if (shader_manifest.core_shader_abi != 14) @compileError("Metal core shader ABI drift");
}

pub const CommandEpoch = command_epoch.CommandEpoch;
pub const CommandEpochStats = command_epoch.Stats;
pub const ArenaCopyRange = abi.ArenaCopyRange;
pub const DecommitFriRoundParams = abi.DecommitFriRoundParams;
pub const DecommitTraceGroupParams = abi.DecommitTraceGroupParams;
pub const PipelineCacheStats = abi.PipelineCacheStats;
pub const ArchiveStoreStatsV1 = abi.ArchiveStoreStatsV1;
pub const PreparedStateRange = abi.PreparedStateRange;
pub const QuotientCoefficientTask = abi.QuotientCoefficientTask;
pub const QuotientCoefficientTerm = abi.QuotientCoefficientTerm;

pub const lifted_merkle_prefix_bytes: u32 = 64;

pub const MetalError = error{
    RuntimeInitializationFailed,
    RuntimeIdentityFailed,
    CommitmentFailed,
    RootReadFailed,
    InvalidColumns,
    ColumnTooLarge,
    QuotientFailed,
    TimerUnsupported,
    PolynomialEvaluationFailed,
    CircleTransformFailed,
    CompositionEvaluationFailed,
    WitnessFeedFailed,
    TraceGenerationFailed,
    CommandEpochFailed,
    ProofOfWorkFailed,
};

const resource_plans = @import("runtime/resource_plans.zig").ResourcePlans(MetalError);

pub const ArenaCopyPlan = resource_plans.ArenaCopyPlan;
pub const WitnessFeedPlan = resource_plans.WitnessFeedPlan;
pub const WitnessFeedBatchPlan = resource_plans.WitnessFeedBatchPlan;
pub const CircleLdePlan = resource_plans.CircleLdePlan;
pub const CircleIfftPlan = resource_plans.CircleIfftPlan;
pub const FixedTablePlan = resource_plans.FixedTablePlan;
pub const FixedTableBatchPlan = resource_plans.FixedTableBatchPlan;
pub const MerkleParentChainPlan = resource_plans.MerkleParentChainPlan;
pub const MerkleLeafPlan = resource_plans.MerkleLeafPlan;
pub const ResidentMerklePlan = resource_plans.ResidentMerklePlan;
pub const EcOpPlan = resource_plans.EcOpPlan;
pub const CompactLayout = resource_plans.CompactLayout;
pub const CompactPlan = resource_plans.CompactPlan;
pub const EvalLayout = resource_plans.EvalLayout;
pub const WitnessLayout = resource_plans.WitnessLayout;
pub const EvalLibrary = resource_plans.EvalLibrary;
pub const EvalPlan = resource_plans.EvalPlan;
pub const BasePolynomialPlan = resource_plans.BasePolynomialPlan;
pub const BasePolynomialDispatch = resource_plans.BasePolynomialDispatch;
pub const BasePolynomialOutput = resource_plans.BasePolynomialOutput;
pub const LookupPolynomialPlan = resource_plans.LookupPolynomialPlan;
pub const LookupPolynomialDispatch = resource_plans.LookupPolynomialDispatch;
pub const WitnessPlan = resource_plans.WitnessPlan;
pub const EvalBatchPlan = resource_plans.EvalBatchPlan;
pub const CompositionFinalizePlan = resource_plans.CompositionFinalizePlan;
pub const CompositionLdeOptions = resource_plans.CompositionLdeOptions;
pub const CompositionLdePlan = resource_plans.CompositionLdePlan;
pub const CompositionExtParamDescriptor = resource_plans.CompositionExtParamDescriptor;
pub const CompositionInputPlan = resource_plans.CompositionInputPlan;
pub const CompositionFrontPlan = resource_plans.CompositionFrontPlan;
pub const RelationPlan = resource_plans.RelationPlan;
pub const FriFoldPlan = resource_plans.FriFoldPlan;
pub const QuotientCombinePlan = resource_plans.QuotientCombinePlan;
pub const FriRoundPlan = resource_plans.FriRoundPlan;
pub const FriTreePlan = resource_plans.FriTreePlan;
pub const FriFinalPlan = resource_plans.FriFinalPlan;

pub const QuotientCommitResult = struct {
    gpu_ms: f64,
    tree: Tree,
};

pub const QuotientFriCommitResult = struct {
    gpu_ms: f64,
    tree: Tree,
    fri: FriLineCascadeResult,
};

pub const FriFoldCommitResult = struct {
    stats: CommandEpochStats,
    tree: Tree,
};

pub const FriCircleFoldResult = struct {
    gpu_ms: f64,
    inverse_generated: bool,
};

pub const FriLineCascadeResult = struct {
    stats: CommandEpochStats,
    trees: []Tree,
    /// Bit 0: circle inverse grid generated; bit 1: line grid generated.
    inverse_generation_mask: u32,
};

pub const LdeCommitResult = struct {
    gpu_ms: f64,
    tree: Tree,
    work: LdeCommitWorkReceipt,
};

/// Counts written by the combined device epoch only after its command buffer
/// and complete Merkle parent chain succeed.
pub const LdeCommitWorkReceipt = struct {
    normalization_batch_count: u32,
    forward_skipped_layers: u32,
    merkle_compressions: u64,
};

pub const TraceGenerationStats = struct {
    gpu_ms: f64,
    copyback_columns: u32,
};

const session_ops = @import("runtime/session.zig");
const prepared_ops = @import("runtime/prepared_execution.zig");
const composition_ops = @import("runtime/composition_operations.zig");
const base_polynomial_ops = @import("runtime/base_polynomial_operations.zig");
const lookup_polynomial_ops = @import("runtime/lookup_polynomial_operations.zig");
const fri_cascade_ops = @import("runtime/fri_cascade_operations.zig");
const opening_ops = @import("runtime/opening_operations.zig");
const resident_ops = @import("runtime/resident_operations.zig");
const polynomial_ops = @import("runtime/polynomial_operations.zig");
const combined_commit_ops = @import("runtime/combined_commit_operations.zig");
const proof_of_work_ops = @import("runtime/proof_of_work.zig");

pub const Runtime = struct {
    handle: *anyopaque,

    pub const init = session_ops.init;
    pub const initFull = session_ops.initFull;
    pub const initFromAotBundle = session_ops.initFromAotBundle;
    pub const initFromAotAdmission = session_ops.initFromAotAdmission;
    pub const initFromMetallibDataOnDevice =
        session_ops.initFromMetallibDataOnDevice;
    pub const deinit = session_ops.deinit;
    pub const pipelineCacheStats = session_ops.pipelineCacheStats;
    pub const archiveStoreStats = session_ops.archiveStoreStats;
    pub const maxBufferLength = session_ops.maxBufferLength;
    pub const recommendedMaxWorkingSetSize = session_ops.recommendedMaxWorkingSetSize;
    pub const platformIdentityAlloc = session_ops.platformIdentityAlloc;
    pub const allocateResidentBuffer = session_ops.allocateResidentBuffer;
    pub const beginCommandEpoch = session_ops.beginCommandEpoch;
    pub const prepareArenaCopies = session_ops.prepareArenaCopies;
    pub const arenaCopyPrepared = session_ops.arenaCopyPrepared;
    pub const preparedStateTransfer = session_ops.preparedStateTransfer;
    pub const clearArenaRanges = session_ops.clearArenaRanges;
    pub const witnessFeedCounts = session_ops.witnessFeedCounts;
    pub const prepareWitnessFeed = session_ops.prepareWitnessFeed;
    pub const witnessFeedCountsPrepared = session_ops.witnessFeedCountsPrepared;
    pub const prepareWitnessFeedBatch = session_ops.prepareWitnessFeedBatch;
    pub const witnessFeedBatchCountsPrepared = session_ops.witnessFeedBatchCountsPrepared;
    pub const witnessFeedBatchClearPrepared = session_ops.witnessFeedBatchClearPrepared;
    pub const witnessFeedBatchIndexPrepared = session_ops.witnessFeedBatchIndexPrepared;
    pub const prepareCircleLde = prepared_ops.prepareCircleLde;
    pub const circleLdePrepared = prepared_ops.circleLdePrepared;
    pub const prepareCircleIfft = prepared_ops.prepareCircleIfft;
    pub const circleIfftPrepared = prepared_ops.circleIfftPrepared;
    pub const prepareFixedTable = prepared_ops.prepareFixedTable;
    pub const prepareFixedTableBatch = prepared_ops.prepareFixedTableBatch;
    pub const fixedTableBatchPrepared = prepared_ops.fixedTableBatchPrepared;
    pub const prepareMerkleParentChain = prepared_ops.prepareMerkleParentChain;
    pub const prepareMerkleLeaves = prepared_ops.prepareMerkleLeaves;
    pub const merkleLeavesPrepared = prepared_ops.merkleLeavesPrepared;
    pub const prepareResidentMerkle = prepared_ops.prepareResidentMerkle;
    pub const residentMerklePrepared = prepared_ops.residentMerklePrepared;
    pub const aliasCommitArena = prepared_ops.aliasCommitArena;
    pub const residentMerkleTreeFromCompletedArena = prepared_ops.residentMerkleTreeFromCompletedArena;
    pub const merkleParentChainPrepared = prepared_ops.merkleParentChainPrepared;
    pub const prepareEcOp = prepared_ops.prepareEcOp;
    pub const ecOpPrepared = prepared_ops.ecOpPrepared;
    pub const prepareCompact = prepared_ops.prepareCompact;
    pub const compactPrepared = prepared_ops.compactPrepared;
    pub const prepareEval = prepared_ops.prepareEval;
    pub const loadEvalLibrary = prepared_ops.loadEvalLibrary;
    pub const compileEvalLibrary = prepared_ops.compileEvalLibrary;
    pub const prepareEvalFromLibrary = prepared_ops.prepareEvalFromLibrary;
    pub const prepareWitnessFromLibrary = prepared_ops.prepareWitnessFromLibrary;
    pub const witnessPrepared = prepared_ops.witnessPrepared;
    pub const evalPrepared = prepared_ops.evalPrepared;
    pub const prepareEvalBatch = prepared_ops.prepareEvalBatch;
    pub const evalBatchPrepared = prepared_ops.evalBatchPrepared;
    pub const prepareBasePolynomialAot = base_polynomial_ops.prepareBasePolynomialAot;
    pub const prepareBasePolynomialFromLibrary = base_polynomial_ops.prepareBasePolynomialFromLibrary;
    pub const evaluateBasePolynomialBatch = base_polynomial_ops.evaluateBasePolynomialBatch;
    pub const prepareLookupPolynomialAot = lookup_polynomial_ops.prepareLookupPolynomialAot;
    pub const prepareLookupPolynomialFromLibrary = lookup_polynomial_ops.prepareLookupPolynomialFromLibrary;
    pub const evaluateLookupPolynomialBatch = lookup_polynomial_ops.evaluateLookupPolynomialBatch;
    pub const prepareCompositionFinalize = composition_ops.prepareCompositionFinalize;
    pub const prepareCompositionLde = composition_ops.prepareCompositionLde;
    pub const prepareCompositionLdeConfigured = composition_ops.prepareCompositionLdeConfigured;
    pub const compositionLdePrepared = composition_ops.compositionLdePrepared;
    pub const prepareCompositionFront = composition_ops.prepareCompositionFront;
    pub const prepareCompositionInputs = composition_ops.prepareCompositionInputs;
    pub const compositionFrontPrepared = composition_ops.compositionFrontPrepared;
    pub const compositionFinalizePrepared = composition_ops.compositionFinalizePrepared;
    pub const compositionPrepared = composition_ops.compositionPrepared;
    pub const prepareRelation = composition_ops.prepareRelation;
    pub const relationPrepared = composition_ops.relationPrepared;
    pub const foldFriCircle = opening_ops.foldFriCircle;
    pub const foldFriCircleWithReceipt = opening_ops.foldFriCircleWithReceipt;
    pub const foldFriLine = opening_ops.foldFriLine;
    pub const foldFriLineAndCommit = opening_ops.foldFriLineAndCommit;
    pub const foldFriCircleLineCascade = fri_cascade_ops.foldFriCircleLineCascade;
    pub const foldFriCircleLineCascadeWithReceipt = fri_cascade_ops.foldFriCircleLineCascadeWithReceipt;
    pub const foldFriLineCascade = fri_cascade_ops.foldFriLineCascade;
    pub const foldFriLineCascadeWithReceipt = fri_cascade_ops.foldFriLineCascadeWithReceipt;
    pub const prepareFriFold = opening_ops.prepareFriFold;
    pub const friFoldPrepared = opening_ops.friFoldPrepared;
    pub const prepareQuotientCombine = opening_ops.prepareQuotientCombine;
    pub const quotientCombinePrepared = opening_ops.quotientCombinePrepared;
    pub const accumulateQuotientCoefficientsResident = opening_ops.accumulateQuotientCoefficientsResident;
    pub const prepareFriRound = opening_ops.prepareFriRound;
    pub const friRoundPrepared = opening_ops.friRoundPrepared;
    pub const prepareFriTree = opening_ops.prepareFriTree;
    pub const friTreePrepared = opening_ops.friTreePrepared;
    pub const prepareFriFinal = opening_ops.prepareFriFinal;
    pub const friFinalPrepared = opening_ops.friFinalPrepared;
    pub const transcriptInit = opening_ops.transcriptInit;
    pub const transcriptMix = opening_ops.transcriptMix;
    pub const transcriptDrawSecure = opening_ops.transcriptDrawSecure;
    pub const transcriptDrawQueries = opening_ops.transcriptDrawQueries;
    pub const decommitNormalizeQueries = opening_ops.decommitNormalizeQueries;
    pub const decommitPrepareFriQueries = opening_ops.decommitPrepareFriQueries;
    pub const decommitPrepareTraceQueries = opening_ops.decommitPrepareTraceQueries;
    pub const decommitGatherTraceValues = opening_ops.decommitGatherTraceValues;
    pub const decommitGatherFriValues = opening_ops.decommitGatherFriValues;
    pub const decommitAssembleFri = opening_ops.decommitAssembleFri;
    pub const decommitFriRound = opening_ops.decommitFriRound;
    pub const decommitSparseParent = opening_ops.decommitSparseParent;
    pub const decommitSparseLeaves = opening_ops.decommitSparseLeaves;
    pub const decommitSparseLeafGroup = opening_ops.decommitSparseLeafGroup;
    pub const decommitTraceGroup = opening_ops.decommitTraceGroup;
    pub const decommitAssembleTrace = opening_ops.decommitAssembleTrace;
    pub const witnessInputGather = resident_ops.witnessInputGather;
    pub const quadraticRecurrenceTrace = resident_ops.quadraticRecurrenceTrace;
    pub const executionTableSplit = resident_ops.executionTableSplit;
    pub const memoryAddressBaseTrace = resident_ops.memoryAddressBaseTrace;
    pub const memoryValueBaseTrace = resident_ops.memoryValueBaseTrace;
    pub const memoryRc99Count = resident_ops.memoryRc99Count;
    pub const publicMemorySeed = resident_ops.publicMemorySeed;
    pub const leafAbsorb = resident_ops.leafAbsorb;
    pub const leafAbsorbCompact = resident_ops.leafAbsorbCompact;
    pub const parentSeeded = resident_ops.parentSeeded;
    pub const parentPlain = resident_ops.parentPlain;
    pub const qm31ToCoordinates = resident_ops.qm31ToCoordinates;
    pub const felt252Oracle = resident_ops.felt252Oracle;
    pub const commitColumns = resident_ops.commitColumns;
    pub const commitColumnsWithBacking = resident_ops.commitColumnsWithBacking;
    pub const computeQuotients = polynomial_ops.computeQuotients;
    pub const computeQuotientsWithReceipt = polynomial_ops.computeQuotientsWithReceipt;
    pub const computeQuotientsAndCommit = polynomial_ops.computeQuotientsAndCommit;
    pub const computeQuotientsAndCommitWithReceipt = polynomial_ops.computeQuotientsAndCommitWithReceipt;
    pub const computeQuotientsAndCommitFri = polynomial_ops.computeQuotientsAndCommitFri;
    pub const computeQuotientsAndCommitFriWithReceipt = polynomial_ops.computeQuotientsAndCommitFriWithReceipt;
    pub const evaluateCoefficientPlans = polynomial_ops.evaluateCoefficientPlans;
    pub const evaluateCoefficientPlansUnprofiled = polynomial_ops.evaluateCoefficientPlansUnprofiled;
    pub const evaluateCoefficientTreePlans = polynomial_ops.evaluateCoefficientTreePlans;
    pub const evaluateCoefficientTreePlansUnprofiled = polynomial_ops.evaluateCoefficientTreePlansUnprofiled;
    pub const transformCircle = polynomial_ops.transformCircle;
    pub const transformCircleResident = polynomial_ops.transformCircleResident;
    pub const transformCircleLde = polynomial_ops.transformCircleLde;
    pub const transformCircleLdeInto = polynomial_ops.transformCircleLdeInto;
    pub const evaluateRecurrenceComposition = polynomial_ops.evaluateRecurrenceComposition;
    pub const transformCircleLdeAndCommit = combined_commit_ops.transformCircleLdeAndCommit;
    pub const transformCircleLdeAndCommitPrepared = combined_commit_ops.transformCircleLdeAndCommitPrepared;
    pub const grindBlake2sProofOfWork = proof_of_work_ops.grindBlake2sProofOfWork;
};

/// Deferred compatibility hooks that deliberately bypass production admission.
pub const diagnostics = struct {
    pub const initFromMetallibUnchecked = session_ops.initFromMetallibUnchecked;
};

const resident_data_bindings = @import("runtime/resident_data.zig");
const resident_data = resident_data_bindings.ResidentData(MetalError, Runtime);

pub const ResidentBuffer = resident_data.ResidentBuffer;
pub const Tree = resident_data.Tree;

pub fn compositionLdeOptionsFromEnvironment() MetalError!CompositionLdeOptions {
    return resource_plans.compositionLdeOptionsFromEnvironment();
}

test {
    _ = @import("runtime/protocol_mode.zig");
}
