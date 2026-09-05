#ifndef STWO_ZIG_METAL_RUNTIME_OBJECT_MODEL_H
#define STWO_ZIG_METAL_RUNTIME_OBJECT_MODEL_H

@class StwoZigEvalLibraryKey;
@class StwoZigEvalPipelineKey;
@class StwoZigEvalArchiveKey;

@interface StwoZigMetalRuntime : NSObject
@property(nonatomic, strong) id<MTLDevice> device;
@property(nonatomic, strong) id<MTLCommandQueue> queue;
@property(nonatomic, strong) id<MTLComputePipelineState> quadraticRecurrenceTrace;
@property(nonatomic, strong) id<MTLComputePipelineState> quadraticRecurrenceIfftWide;
@property(nonatomic, strong) id<MTLComputePipelineState> leaves;
@property(nonatomic, strong) id<MTLComputePipelineState> poseidon2M31Leaves;
@property(nonatomic, strong) id<MTLComputePipelineState> poseidon2M31LeavesWide;
@property(nonatomic, strong) id<MTLComputePipelineState> proofOfWork;
@property(nonatomic, strong) id<MTLComputePipelineState> poseidon2ChannelPowSearch;
@property(nonatomic, strong) id<MTLComputePipelineState> parents;
@property(nonatomic, strong) id<MTLComputePipelineState> poseidon2M31Parents;
@property(nonatomic, strong) id<MTLComputePipelineState> quotients;
@property(nonatomic, strong) id<MTLComputePipelineState> rawQuotients;
@property(nonatomic, strong) id<MTLComputePipelineState> polynomialEval;
@property(nonatomic, strong) id<MTLComputePipelineState> polynomialBasis;
@property(nonatomic, strong) id<MTLComputePipelineState> sampledBarycentricDomain;
@property(nonatomic, strong) id<MTLComputePipelineState> sampledBarycentricScale;
@property(nonatomic, strong) id<MTLComputePipelineState> sampledBarycentricParts;
@property(nonatomic, strong) id<MTLComputePipelineState> sampledBarycentricInverseDirect;
@property(nonatomic, strong) id<MTLComputePipelineState> sampledBarycentricInverseTree;
@property(nonatomic, strong) id<MTLComputePipelineState> sampledBarycentricFinish;
@property(nonatomic, strong) id<MTLComputePipelineState> sampledBarycentricEvaluateMany;
@property(nonatomic, strong) id<MTLComputePipelineState> sampledBarycentricReduce;
@property(nonatomic, strong) id<MTLComputePipelineState> circleIfftFirst;
@property(nonatomic, strong) id<MTLComputePipelineState> circleIfftLayer;
@property(nonatomic, strong) id<MTLComputePipelineState> circleRfftLayer;
@property(nonatomic, strong) id<MTLComputePipelineState> circleRfftLast;
@property(nonatomic, strong) id<MTLComputePipelineState> circleRescale;
@property(nonatomic, strong) id<MTLComputePipelineState> circleExpand;
@property(nonatomic, strong) id<MTLComputePipelineState> circleIfftFused;
@property(nonatomic, strong) id<MTLComputePipelineState> circleIfftFusedWide;
@property(nonatomic, strong) id<MTLComputePipelineState> circleRfftFused;
@property(nonatomic, strong) id<MTLComputePipelineState> quotientNumerator;
@property(nonatomic, strong) id<MTLComputePipelineState> quotientFinalize;
@property(nonatomic, strong) id<MTLComputePipelineState> quotientPartialsRaw;
@property(nonatomic, strong) id<MTLComputePipelineState> quotientCombinePartialsRaw;
@property(nonatomic, strong) id<MTLComputePipelineState> quotientDomainPointsResident;
@property(nonatomic, strong) id<MTLBuffer> quotientDomainCache;
@property(nonatomic) uint32_t quotientDomainCacheRowCount;
@property(nonatomic) uint32_t quotientDomainCacheLogSize;
@property(nonatomic) uint32_t quotientDomainCacheInitialIndex;
@property(nonatomic) uint32_t quotientDomainCacheStepSize;
@property(nonatomic, strong) id<MTLBuffer> friCircleInverseCache;
@property(nonatomic) uint32_t friCircleInverseCacheCount;
@property(nonatomic) uint32_t friCircleInverseCacheInitialIndex;
@property(nonatomic) uint32_t friCircleInverseCacheStepSize;
@property(nonatomic, strong) id<MTLBuffer> friLineInverseCache;
@property(nonatomic) uint32_t friLineInverseCacheSourceCount;
@property(nonatomic) uint32_t friLineInverseCacheLayerCount;
@property(nonatomic) uint32_t friLineInverseCacheInitialIndex;
@property(nonatomic) uint32_t friLineInverseCacheStepSize;
@property(nonatomic, strong) id<MTLComputePipelineState> quotientDenominatorsResident;
@property(nonatomic, strong) id<MTLComputePipelineState> quotientCombineResident;
@property(nonatomic, strong) id<MTLComputePipelineState> quotientCoefficientsResident;
@property(nonatomic, strong) id<MTLComputePipelineState> friFoldCircle;
@property(nonatomic, strong) id<MTLComputePipelineState> friFoldLine;
@property(nonatomic, strong) id<MTLComputePipelineState> friFold3Resident;
@property(nonatomic, strong) id<MTLComputePipelineState> friFold2Resident;
@property(nonatomic, strong) id<MTLComputePipelineState> friPackedLeavesResident;
@property(nonatomic, strong) id<MTLComputePipelineState> poseidon2M31FriPackedLeavesResident;
@property(nonatomic, strong) id<MTLComputePipelineState> friFinalLineResident;
@property(nonatomic, strong) id<MTLComputePipelineState> transcriptInitResident;
@property(nonatomic, strong) id<MTLComputePipelineState> transcriptMixResident;
@property(nonatomic, strong) id<MTLComputePipelineState> transcriptDrawSecureResident;
@property(nonatomic, strong) id<MTLComputePipelineState> transcriptDrawQueriesResident;
@property(nonatomic, strong) id<MTLComputePipelineState> decommitNormalizeQueriesResident;
@property(nonatomic, strong) id<MTLComputePipelineState> decommitPrepareFriQueriesResident;
@property(nonatomic, strong) id<MTLComputePipelineState> decommitGatherFriValuesResident;
@property(nonatomic, strong) id<MTLComputePipelineState> decommitPrepareTraceQueriesResident;
@property(nonatomic, strong) id<MTLComputePipelineState> decommitGatherTraceValuesResident;
@property(nonatomic, strong) id<MTLComputePipelineState> decommitGatherTreeValuesResident;
@property(nonatomic, strong) id<MTLComputePipelineState> decommitGatherTreeValuesResidentWide;
@property(nonatomic, strong) id<MTLComputePipelineState> decommitAssembleFriResident;
@property(nonatomic, strong) id<MTLComputePipelineState> decommitSparseParentResident;
@property(nonatomic, strong) id<MTLComputePipelineState> decommitSparseLeavesResident;
@property(nonatomic, strong) id<MTLComputePipelineState> decommitSparseLeafGroupResident;
@property(nonatomic, strong) id<MTLComputePipelineState> decommitAssembleTraceResident;
@property(nonatomic, strong) id<MTLComputePipelineState> qm31ToCoordinates;
@property(nonatomic, strong) id<MTLComputePipelineState> witnessFeedCounts;
@property(nonatomic, strong) id<MTLComputePipelineState> witnessInputGatherResident;
@property(nonatomic, strong) id<MTLComputePipelineState> executionTableSplitResident;
@property(nonatomic, strong) id<MTLComputePipelineState> memoryAddressBaseTraceResident;
@property(nonatomic, strong) id<MTLComputePipelineState> memoryValueBaseTraceResident;
@property(nonatomic, strong) id<MTLComputePipelineState> memoryRc99CountResident;
@property(nonatomic, strong) id<MTLComputePipelineState> publicMemorySeedResident;
@property(nonatomic, strong) id<MTLComputePipelineState> leafAbsorbResident;
@property(nonatomic, strong) id<MTLComputePipelineState> leafAbsorbCompactResident;
@property(nonatomic, strong) id<MTLComputePipelineState> poseidon2M31LeafAbsorbResident;
@property(nonatomic, strong) id<MTLComputePipelineState> poseidon2M31LeafAbsorbCompactResident;
@property(nonatomic, strong) id<MTLComputePipelineState> poseidon2M31LeafStateDigestResidentV1;
@property(nonatomic, strong) id<MTLComputePipelineState> parentsPlainSparse;
@property(nonatomic, strong) id<MTLComputePipelineState> clearArenaSpans;
@property(nonatomic, strong) id<MTLComputePipelineState> circleExpandSparse;
@property(nonatomic, strong) id<MTLComputePipelineState> circleCopySparse;
@property(nonatomic, strong) id<MTLComputePipelineState> circleIfftFirstSparse;
@property(nonatomic, strong) id<MTLComputePipelineState> circleIfftLayerSparse;
@property(nonatomic, strong) id<MTLComputePipelineState> circleRescaleSparse;
@property(nonatomic, strong) id<MTLComputePipelineState> circleRfftLayerSparse;
@property(nonatomic, strong) id<MTLComputePipelineState> circleRfftRadix4Sparse;
@property(nonatomic, strong) id<MTLComputePipelineState> circleRfftLastSparse;
@property(nonatomic, strong) id<MTLComputePipelineState> circleRfftFusedSparse;
@property(nonatomic, strong) id<MTLComputePipelineState> circleRfftFusedSparseWide;
@property(nonatomic, strong) id<MTLComputePipelineState> circleRfftLayerSparseWide;
@property(nonatomic, strong) id<MTLComputePipelineState> circleRfftLastSparseWide;
@property(nonatomic, strong) id<MTLComputePipelineState> relationFused;
@property(nonatomic, strong) id<MTLComputePipelineState> relationBlockScan;
@property(nonatomic, strong) id<MTLComputePipelineState> relationScanBlocks;
@property(nonatomic, strong) id<MTLComputePipelineState> relationScanFinalize;
@property(nonatomic, strong) id<MTLComputePipelineState> fixedTableLookup;
@property(nonatomic, strong) id<MTLComputePipelineState> parentsSparse;
@property(nonatomic, strong) id<MTLComputePipelineState> parentTailSparse;
@property(nonatomic, strong) id<MTLComputePipelineState> poseidon2M31ParentsSparse;
@property(nonatomic, strong) id<MTLComputePipelineState> poseidon2M31ParentTailSparse;
@property(nonatomic, strong) id<MTLComputePipelineState> felt252Oracle;
@property(nonatomic, strong) id<MTLComputePipelineState> ecOpWitness;
@property(nonatomic, strong) id<MTLComputePipelineState> ecOpLookup;
@property(nonatomic, strong) id<MTLComputePipelineState> ecOpBaseFinalize;
@property(nonatomic, strong) id<MTLComputePipelineState> compactGather;
@property(nonatomic, strong) id<MTLComputePipelineState> compactRadixHistogram;
@property(nonatomic, strong) id<MTLComputePipelineState> compactRadixPrefix;
@property(nonatomic, strong) id<MTLComputePipelineState> compactRadixScatter;
@property(nonatomic, strong) id<MTLComputePipelineState> compactHeads;
@property(nonatomic, strong) id<MTLComputePipelineState> compactScanLocal;
@property(nonatomic, strong) id<MTLComputePipelineState> compactScanBlocks;
@property(nonatomic, strong) id<MTLComputePipelineState> compactScanAdd;
@property(nonatomic, strong) id<MTLComputePipelineState> compactClearOutputs;
@property(nonatomic, strong) id<MTLComputePipelineState> compactScatter;
@property(nonatomic, strong) id<MTLComputePipelineState> compactFinalize;
@property(nonatomic, strong) id<MTLComputePipelineState> compositionLift;
@property(nonatomic, strong) id<MTLComputePipelineState> compositionSplit;
@property(nonatomic, strong) id<MTLComputePipelineState> compositionExpand;
@property(nonatomic, strong) id<MTLComputePipelineState> compositionRandomPowers;
@property(nonatomic, strong) id<MTLComputePipelineState> compositionExtParams;
@property(nonatomic, strong) NSMutableDictionary<NSString *, id<MTLComputePipelineState>> *riscvPolynomialPipelines;
@property(nonatomic, strong) NSMutableDictionary<StwoZigEvalLibraryKey *, id> *evalLibraries;
@property(nonatomic, strong) NSMutableDictionary<StwoZigEvalPipelineKey *, id<MTLComputePipelineState>> *evalPipelines;
@property(nonatomic) uint64_t evalLibraryCacheHits;
@property(nonatomic) uint64_t evalLibraryCacheMisses;
@property(nonatomic) uint64_t evalPipelineCacheHits;
@property(nonatomic) uint64_t evalBinaryArchiveHits;
@property(nonatomic) uint64_t evalBinaryArchiveMisses;
@property(nonatomic) uint64_t evalDirectCompiles;
@property(nonatomic) uint64_t evalArchivePopulations;
@property(nonatomic) uint64_t evalArchiveSerializations;
@property(nonatomic) double evalPipelinePreparationSeconds;
@property(nonatomic) double evalLibraryPreparationSeconds;
@end

@interface StwoZigWitnessFeedPlan : NSObject
@property(nonatomic, strong) id<MTLBuffer> descriptors;
@property(nonatomic, strong) id<MTLBuffer> luts;
@property(nonatomic, strong) id<MTLBuffer> destinationOffsets;
@property(nonatomic, strong) id<MTLBuffer> sourceOffsets;
@property(nonatomic, strong) id<MTLBuffer> clearRanges;
@property(nonatomic) uint32_t descriptorCount;
@property(nonatomic) uint32_t clearRangeCount;
@property(nonatomic) uint32_t clearTotalWords;
@end

@implementation StwoZigWitnessFeedPlan
@end

@interface StwoZigWitnessFeedBatch : NSObject
@property(nonatomic, strong) NSArray<StwoZigWitnessFeedPlan *> *plans;
@property(nonatomic, strong) NSData *columnLengths;
@property(nonatomic, strong) id<MTLBuffer> clearSpans;
@property(nonatomic) uint32_t clearRangeCount;
@property(nonatomic) uint32_t clearTotalWords;
@end

@implementation StwoZigWitnessFeedBatch
@end

@interface StwoZigCircleLdePlan : NSObject
@property(nonatomic, strong) id<MTLBuffer> sourceOffsets;
@property(nonatomic, strong) id<MTLBuffer> destinationOffsets;
@property(nonatomic) uint32_t columnCount;
@property(nonatomic) uint32_t baseLogSize;
@property(nonatomic) uint32_t extendedLogSize;
@property(nonatomic) NSUInteger twiddleByteOffset;
@end

@implementation StwoZigCircleLdePlan
@end

/// Owns one command buffer for all direct shared-memory circle-LDE groups in a
/// commitment. Only operations whose coefficient and evaluation buffers are
/// both bound with `newBufferWithBytesNoCopy` enter it, so no deferred host
/// copy or extra private working set is hidden here.
@interface StwoZigCircleLdeBatch : NSObject
@property(nonatomic, strong) StwoZigMetalRuntime *runtime;
@property(nonatomic, strong) id<MTLCommandBuffer> command;
@property(nonatomic) NSUInteger encodedOperations;
@property(nonatomic) BOOL finished;
@end

@implementation StwoZigCircleLdeBatch
@end

@interface StwoZigCircleIfftPlan : NSObject
@property(nonatomic, strong) id<MTLBuffer> sourceOffsets;
@property(nonatomic, strong) id<MTLBuffer> destinationOffsets;
@property(nonatomic) uint32_t columnCount;
@property(nonatomic) uint32_t logSize;
@property(nonatomic) uint32_t scaleFactor;
@property(nonatomic) NSUInteger twiddleByteOffset;
@end

@implementation StwoZigCircleIfftPlan
@end

@interface StwoZigRelationPlan : NSObject
@property(nonatomic, strong) id<MTLBuffer> geometry;
@property(nonatomic, strong) id<MTLBuffer> sourceOffsets;
@property(nonatomic, strong) id<MTLBuffer> descriptors;
@property(nonatomic, strong) id<MTLBuffer> outputOffsets;
@property(nonatomic) uint32_t instanceCount;
@property(nonatomic) uint32_t totalBlocks;
@property(nonatomic) NSUInteger alphaByteOffset;
@property(nonatomic) NSUInteger zByteOffset;
@property(nonatomic) NSUInteger scratchByteOffset;
@end

@implementation StwoZigRelationPlan
@end

@interface StwoZigFixedTablePlan : NSObject
@property(nonatomic, strong) id<MTLBuffer> descriptors;
@property(nonatomic, strong) id<MTLBuffer> sourceOffsets;
@property(nonatomic, strong) id<MTLBuffer> multiplicityOffsets;
@property(nonatomic) uint32_t destinationOffset;
@property(nonatomic) uint32_t rowCount;
@property(nonatomic) uint32_t outputCount;
@end
@implementation StwoZigFixedTablePlan
@end

@interface StwoZigFixedTableBatch : NSObject
@property(nonatomic, strong) NSArray<StwoZigFixedTablePlan *> *plans;
@end
@implementation StwoZigFixedTableBatch
@end

@interface StwoZigMerkleParentChain : NSObject
@property(nonatomic, strong) NSData *childOffsets;
@property(nonatomic, strong) NSData *destinationOffsets;
@property(nonatomic, strong) NSData *parentCounts;
@property(nonatomic, strong) id<MTLBuffer> nodeSeed;
@property(nonatomic) uint32_t levelCount;
@property(nonatomic) uint32_t prefixBytes;
@property(nonatomic) uint32_t hashFamily;
@property(nonatomic) uint32_t bottomLevelCount;
@property(nonatomic) uint32_t bottomThreadgroupWidth;
@property(nonatomic) uint32_t bottomThreadgroupCount;
@property(nonatomic) NSUInteger bottomScratchBytes;
@property(nonatomic) uint32_t tailStart;
@property(nonatomic) uint32_t tailThreadgroupWidth;
@property(nonatomic) NSUInteger tailScratchBytes;
@end
@implementation StwoZigMerkleParentChain
@end

@interface StwoZigEcOpPlan : NSObject
@property(nonatomic, strong) id<MTLBuffer> executionOffsets;
@property(nonatomic, strong) id<MTLBuffer> traceOffsets;
@property(nonatomic, strong) id<MTLBuffer> partialOffsets;
@property(nonatomic, strong) id<MTLBuffer> multiplicityOffsets;
@property(nonatomic, strong) id<MTLBuffer> params;
@property(nonatomic, strong) id<MTLComputePipelineState> pipeline;
@property(nonatomic) uint32_t rowCount;
@property(nonatomic) NSUInteger threadgroupWidth;
@property(nonatomic) bool writeBase;
@end
@implementation StwoZigEcOpPlan
@end

@interface StwoZigCompactPlan : NSObject
@property(nonatomic, strong) id<MTLBuffer> sourceOffsets;
@property(nonatomic, strong) id<MTLBuffer> descriptors;
@property(nonatomic, strong) id<MTLBuffer> outputOffsets;
@property(nonatomic, strong) id<MTLBuffer> params;
@property(nonatomic) uint32_t sortRows;
@property(nonatomic) uint32_t totalRows;
@property(nonatomic) uint32_t consumerRows;
@property(nonatomic) uint32_t keyWords;
@property(nonatomic) uint32_t indicesA;
@property(nonatomic) uint32_t indicesB;
@end
@implementation StwoZigCompactPlan
@end

@interface StwoZigEvalPlan : NSObject
@property(nonatomic, strong) id<MTLComputePipelineState> pipeline;
@property(nonatomic, strong) id<MTLBuffer> arguments;
@property(nonatomic) uint32_t rowCount;
@end
@implementation StwoZigEvalPlan
@end

@interface StwoZigBasePolynomialPlan : NSObject
@property(nonatomic, strong) id<MTLComputePipelineState> pipeline;
@end
@implementation StwoZigBasePolynomialPlan
@end

@interface StwoZigLookupPolynomialPlan : NSObject
@property(nonatomic, strong) id<MTLComputePipelineState> pipeline;
@end
@implementation StwoZigLookupPolynomialPlan
@end

@interface StwoZigWitnessPlan : NSObject
@property(nonatomic, strong) id<MTLComputePipelineState> pipeline;
@property(nonatomic, strong) id<MTLBuffer> arguments;
@property(nonatomic) uint32_t rowCount;
@end
@implementation StwoZigWitnessPlan
@end

@interface StwoZigEvalBatch : NSObject
@property(nonatomic, strong) NSArray<StwoZigEvalPlan *> *plans;
@end
@implementation StwoZigEvalBatch
@end

@interface StwoZigEvalLibrary : NSObject
@property(nonatomic, strong) id<MTLLibrary> library;
@property(nonatomic, strong) id<MTLBinaryArchive> archive;
@property(nonatomic, strong) NSURL *archiveURL;
@property(nonatomic, strong) StwoZigEvalLibraryKey *cacheKey;
@property(nonatomic, strong) StwoZigEvalArchiveKey *archiveKey;
@property(nonatomic, strong) NSData *sourceBytes;
@property(nonatomic, weak) StwoZigMetalRuntime *runtimeOwner;
@property(nonatomic) uint64_t cacheByteCost;
@property(nonatomic) bool archiveLoaded;
@property(nonatomic) bool archiveDirty;
@end
@implementation StwoZigEvalLibrary
@end

@interface StwoZigCompositionFinalizePlan : NSObject
@property(nonatomic, strong) NSData *accumulatorOffsets;
@property(nonatomic, strong) NSData *accumulatorLogs;
@property(nonatomic, strong) id<MTLBuffer> coordinateOffsets;
@property(nonatomic, strong) id<MTLBuffer> outputOffsets;
@property(nonatomic) uint32_t accumulatorCount;
@property(nonatomic) NSUInteger inverseTwiddleByteOffset;
@property(nonatomic) uint32_t scaleFactor;
@end
@implementation StwoZigCompositionFinalizePlan
@end

@interface StwoZigCompositionLdePlan : NSObject
@property(nonatomic, strong) id<MTLBuffer> sourceOffsets;
@property(nonatomic, strong) id<MTLBuffer> sourceLogs;
@property(nonatomic, strong) id<MTLBuffer> destinationOffsets;
@property(nonatomic) uint32_t columnCount;
@property(nonatomic) uint32_t extendedLog;
@property(nonatomic) NSUInteger twiddleByteOffset;
@property(nonatomic) bool useRadix4;
@end
@implementation StwoZigCompositionLdePlan
@end

@interface StwoZigCompositionInputPlan : NSObject
@property(nonatomic, strong) id<MTLBuffer> descriptors;
@property(nonatomic) uint32_t descriptorCount;
@property(nonatomic) uint32_t randomOffset;
@property(nonatomic) uint32_t powersOffset;
@property(nonatomic) uint32_t powerCount;
@end
@implementation StwoZigCompositionInputPlan
@end

@interface StwoZigCompositionFrontPlan : NSObject
@property(nonatomic, strong) StwoZigCompositionInputPlan *inputs;
@property(nonatomic, strong) NSArray<StwoZigCompositionLdePlan *> *ldePlans;
@property(nonatomic, strong) NSArray<StwoZigEvalBatch *> *evalBatches;
@property(nonatomic) uint32_t accumulatorOffset;
@property(nonatomic) uint32_t accumulatorWords;
@end
@implementation StwoZigCompositionFrontPlan
@end

@interface StwoZigFriFoldPlan : NSObject
@property(nonatomic) NSUInteger sourceByteOffset;
@property(nonatomic) NSUInteger inverseByteOffset;
@property(nonatomic) NSUInteger alphaByteOffset;
@property(nonatomic) NSUInteger destinationByteOffset;
@property(nonatomic) uint32_t sourceCount;
@property(nonatomic) bool circle;
@end
@implementation StwoZigFriFoldPlan
@end

@interface StwoZigArenaCopyPlan : NSObject
@property(nonatomic, strong) NSData *ranges;
@property(nonatomic) uint32_t rangeCount;
@end
@implementation StwoZigArenaCopyPlan
@end

@interface StwoZigQuotientCombinePlan : NSObject
@property(nonatomic, strong) id<MTLBuffer> partialOffsets;
@property(nonatomic, strong) id<MTLBuffer> partialLogs;
@property(nonatomic) uint32_t sampleOffset;
@property(nonatomic) uint32_t linearOffset;
@property(nonatomic) uint32_t scratchOffset;
@property(nonatomic) uint32_t outputOffset;
@property(nonatomic) uint32_t rowCount;
@property(nonatomic) uint32_t logSize;
@property(nonatomic) uint32_t sampleCount;
@property(nonatomic) uint32_t initialIndex;
@property(nonatomic) uint32_t stepSize;
@end
@implementation StwoZigQuotientCombinePlan
@end

@interface StwoZigFriRoundPlan : NSObject
@property(nonatomic) uint32_t twiddleBase, twiddleOffset0, twiddleOffset1, twiddleOffset2;
@property(nonatomic) uint32_t inputBase, inputStride, alphaBase, outputBase, outputStride;
@property(nonatomic) uint32_t n, foldCount, firstCircle;
@end
@implementation StwoZigFriRoundPlan
@end

@interface StwoZigFriTreePlan : NSObject
@property(nonatomic, strong) NSData *layerOffsets;
@property(nonatomic, strong) id<MTLBuffer> leafSeed;
@property(nonatomic, strong) id<MTLBuffer> nodeSeed;
@property(nonatomic) uint32_t evaluationBase, coordinateStride, evaluationSize, logRowsPerLeaf, layerCount;
@property(nonatomic) uint32_t prefixBytes;
@property(nonatomic) uint32_t hashFamily;
@end
@implementation StwoZigFriTreePlan
@end

@interface StwoZigFriFinalPlan : NSObject
@property(nonatomic) uint32_t evaluationBase, coordinateStride, inverseX, coefficientBase, degreeError;
@end
@implementation StwoZigFriFinalPlan
@end

@interface StwoZigMerkleLeafPlan : NSObject
@property(nonatomic, strong) id<MTLBuffer> columnOffsets;
@property(nonatomic, strong) id<MTLBuffer> columnLogSizes;
@property(nonatomic, strong) id<MTLBuffer> leafSeed;
@property(nonatomic) uint32_t columnCount;
@property(nonatomic) uint32_t liftingLogSize;
@property(nonatomic) uint32_t destinationOffset;
@property(nonatomic) uint32_t prefixBytes;
@property(nonatomic) uint32_t hashFamily;
@end
@implementation StwoZigMerkleLeafPlan
@end

@interface StwoZigResidentMerklePlan : NSObject
@property(nonatomic, strong) id<MTLBuffer> columnOffsets;
@property(nonatomic, strong) id<MTLBuffer> columnLogSizes;
@property(nonatomic, strong) NSData *layerOffsets;
@property(nonatomic, strong) id<MTLBuffer> leafSeed;
@property(nonatomic, strong) id<MTLBuffer> nodeSeed;
@property(nonatomic, strong) NSData *stagedStateOffsets;
@property(nonatomic) uint32_t columnCount;
@property(nonatomic) uint32_t liftingLogSize;
@property(nonatomic) uint32_t layerCount;
@property(nonatomic) uint32_t prefixBytes;
@property(nonatomic) uint32_t hashFamily;
@property(nonatomic) uint32_t leafEncoding;
@end
@implementation StwoZigResidentMerklePlan
@end
@implementation StwoZigMetalRuntime
@end

@interface StwoZigMetalTree : NSObject
@property(nonatomic, strong) StwoZigMetalRuntime *runtimeOwner;
@property(nonatomic, strong) NSArray<id<MTLBuffer>> *layers;
@property(nonatomic, strong) NSData *layerWordOffsets;
@property(nonatomic, strong) NSData *layerWordLengths;
@property(nonatomic, strong) id<MTLBuffer> rootReadback;
@property(nonatomic, assign) uint32_t rootReadbackWordOffset;
@property(nonatomic, assign) uint32_t logSize;
@property(nonatomic, assign) double gpuMilliseconds;
@property(nonatomic, strong) id<MTLBuffer> residentColumns;
@property(nonatomic, assign) uintptr_t residentColumnsHostBegin;
@property(nonatomic, assign) NSUInteger residentColumnsWordCount;
// Proof-owned bindings from authenticated host column arenas to the exact
// Metal buffers that expose them. A tree may cover several skewed LDE arenas;
// keeping this map on the tree prevents cross-proof/global residency lookup.
@property(nonatomic, strong) NSArray<id<MTLBuffer>> *residentColumnBuffers;
@property(nonatomic, strong) NSData *residentColumnHostBegins;
@property(nonatomic, strong) NSData *residentColumnWordCounts;
@property(nonatomic, strong) NSData *residentColumnWordOffsets;
@property(nonatomic, assign) uint32_t residentColumnOffsetWordBytes;
@end
@implementation StwoZigMetalTree
@end

#endif
