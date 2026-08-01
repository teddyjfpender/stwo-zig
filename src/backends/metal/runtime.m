#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <CommonCrypto/CommonDigest.h>
#import <dispatch/dispatch.h>
#import "runtime_profile.m"
#import "runtime/compile_options.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "runtime/abi.h"

@class StwoZigEvalLibraryKey;
@class StwoZigEvalPipelineKey;
@class StwoZigEvalArchiveKey;

@interface StwoZigMetalRuntime : NSObject
@property(nonatomic, strong) id<MTLDevice> device;
@property(nonatomic, strong) id<MTLCommandQueue> queue;
@property(nonatomic, strong) id<MTLComputePipelineState> quadraticRecurrenceTrace;
@property(nonatomic, strong) id<MTLComputePipelineState> quadraticRecurrenceIfftWide;
@property(nonatomic, strong) id<MTLComputePipelineState> leaves;
@property(nonatomic, strong) id<MTLComputePipelineState> parents;
@property(nonatomic, strong) id<MTLComputePipelineState> quotients;
@property(nonatomic, strong) id<MTLComputePipelineState> rawQuotients;
@property(nonatomic, strong) id<MTLComputePipelineState> polynomialEval;
@property(nonatomic, strong) id<MTLComputePipelineState> polynomialBasis;
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
@end
@implementation StwoZigMerkleLeafPlan
@end

@interface StwoZigResidentMerklePlan : NSObject
@property(nonatomic, strong) id<MTLBuffer> columnOffsets;
@property(nonatomic, strong) id<MTLBuffer> columnLogSizes;
@property(nonatomic, strong) NSData *layerOffsets;
@property(nonatomic, strong) id<MTLBuffer> leafSeed;
@property(nonatomic, strong) id<MTLBuffer> nodeSeed;
@property(nonatomic) uint32_t columnCount;
@property(nonatomic) uint32_t liftingLogSize;
@property(nonatomic) uint32_t layerCount;
@property(nonatomic) uint32_t prefixBytes;
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
@end
@implementation StwoZigMetalTree
@end

typedef struct {
    __unsafe_unretained StwoZigMetalTree *tree;
    __unsafe_unretained id<MTLBuffer> buffer;
    size_t wordOffset;
    size_t availableWords;
} StwoZigResidentColumnBinding;

static bool stwo_zig_tree_resident_column(
    NSArray<StwoZigMetalTree *> *trees,
    const uint32_t *column,
    size_t column_words,
    StwoZigResidentColumnBinding *binding
) {
    if (column == NULL || binding == NULL) return false;
    uintptr_t address = (uintptr_t)column;
    for (StwoZigMetalTree *tree in trees) {
        NSArray<id<MTLBuffer>> *buffers = tree.residentColumnBuffers;
        const uintptr_t *begins = tree.residentColumnHostBegins.bytes;
        const size_t *counts = tree.residentColumnWordCounts.bytes;
        const uint32_t *offsets = tree.residentColumnWordOffsets.bytes;
        NSUInteger count = tree.residentColumnHostBegins.length / sizeof(uintptr_t);
        if (buffers.count == 1u && begins != NULL && counts != NULL && offsets != NULL &&
            tree.residentColumnHostBegins.length == count * sizeof(uintptr_t) &&
            tree.residentColumnWordCounts.length == count * sizeof(size_t) &&
            tree.residentColumnWordOffsets.length == count * sizeof(uint32_t)) {
            for (NSUInteger index = 0u; index < count; ++index) {
                uintptr_t begin = begins[index];
                size_t words = counts[index];
                if (address < begin || (address - begin) % sizeof(uint32_t) != 0u)
                    continue;
                size_t offset = (address - begin) / sizeof(uint32_t);
                if (offset > words || column_words > words - offset) continue;
                id<MTLBuffer> buffer = buffers[0];
                size_t device_offset = (size_t)offsets[index] + offset;
                if (buffer == nil || device_offset > buffer.length / sizeof(uint32_t) ||
                    column_words > buffer.length / sizeof(uint32_t) - device_offset)
                    continue;
                binding->tree = tree;
                binding->buffer = buffer;
                binding->wordOffset = device_offset;
                binding->availableWords = words - offset;
                return true;
            }
        }

        // Compatibility for trees built by older/specialized epochs while
        // their callers migrate to the multi-arena map.
        uintptr_t begin = tree.residentColumnsHostBegin;
        size_t words = tree.residentColumnsWordCount;
        if (tree.residentColumns == nil || address < begin ||
            (address - begin) % sizeof(uint32_t) != 0u)
            continue;
        size_t offset = (address - begin) / sizeof(uint32_t);
        if (offset <= words && column_words <= words - offset) {
            binding->tree = tree;
            binding->buffer = tree.residentColumns;
            binding->wordOffset = offset;
            binding->availableWords = words - offset;
            return true;
        }
    }
    return false;
}

static uint32_t tree_layer_word_offset(StwoZigMetalTree *tree, NSUInteger level) {
    if (tree.layerWordOffsets == nil) return 0u;
    return ((const uint32_t *)tree.layerWordOffsets.bytes)[level];
}

static uint32_t tree_layer_word_length(StwoZigMetalTree *tree, NSUInteger level) {
    if (tree.layerWordLengths == nil)
        return (uint32_t)(tree.layers[level].length / sizeof(uint32_t));
    return ((const uint32_t *)tree.layerWordLengths.bytes)[level];
}

@interface StwoZigCommandEpoch : NSObject
@property(nonatomic, strong) StwoZigMetalRuntime *runtime;
@property(nonatomic, strong) id<MTLBuffer> arena;
@property(nonatomic, strong) id<MTLCommandBuffer> command;
@property(nonatomic, strong) NSMutableArray *retainedPlans;
@property(nonatomic) StwoZigCommandEpochState state;
@property(nonatomic) uint64_t computeEncoders;
@property(nonatomic) uint64_t blitEncoders;
@property(nonatomic) uint64_t dispatches;
@end
@implementation StwoZigCommandEpoch
@end

static bool encode_composition_lde_counted(
    StwoZigMetalRuntime *runtime, id<MTLBuffer> arena,
    StwoZigCompositionLdePlan *plan, id<MTLCommandBuffer> command,
    uint64_t *compute_encoders, uint64_t *dispatches
);
static bool encode_merkle_parent_chain_prepared(
    StwoZigMetalRuntime *runtime, id<MTLBuffer> arena, StwoZigMerkleParentChain *plan,
    id<MTLCommandBuffer> command, uint64_t *compute_encoders, uint64_t *dispatches
);

static void write_error(char *destination, size_t length, NSString *message) {
    if (destination == NULL || length == 0) return;
    const char *utf8 = message.UTF8String ?: "Metal error";
    snprintf(destination, length, "%s", utf8);
}

static id<MTLComputePipelineState> make_pipeline(
    id<MTLDevice> device,
    id<MTLLibrary> library,
    NSString *name,
    char *error_message,
    size_t error_message_len
) {
    id<MTLFunction> function = [library newFunctionWithName:name];
    if (function == nil) {
        write_error(error_message, error_message_len,
                    [NSString stringWithFormat:@"Missing Metal function %@", name]);
        return nil;
    }
    NSError *error = nil;
    id<MTLComputePipelineState> pipeline =
        [device newComputePipelineStateWithFunction:function error:&error];
    if (pipeline == nil) {
        write_error(error_message, error_message_len,
                    error.localizedDescription ?: @"Failed to create Metal pipeline");
    }
    stwo_zig_metal_profile_name_pipeline(pipeline, name);
    return pipeline;
}

static id<MTLBuffer> alias_shared_buffer(id<MTLDevice> device, void *bytes, size_t length);

static StwoZigMetalRuntime *create_runtime_from_library(
    id<MTLDevice> device,
    id<MTLLibrary> library,
    bool include_deferred,
    char *error_message,
    size_t error_message_len
) {
    if (device == nil || library == nil) return nil;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = [StwoZigMetalRuntime new];
        runtime.device = device;
        runtime.queue = stwo_zig_metal_profile_queue([device newCommandQueue], device);
        runtime.riscvPolynomialPipelines = [NSMutableDictionary dictionaryWithCapacity:34u];
        runtime.evalLibraries = [NSMutableDictionary dictionary];
        runtime.evalPipelines = [NSMutableDictionary dictionary];
        runtime.quadraticRecurrenceTrace = make_pipeline(device, library, @"stwo_zig_quadratic_recurrence_trace",
                                                         error_message, error_message_len);
        runtime.quadraticRecurrenceIfftWide = make_pipeline(device, library, @"stwo_zig_quadratic_recurrence_ifft_fused_wide",
                                                            error_message, error_message_len);
        runtime.leaves = make_pipeline(device, library, @"stwo_zig_blake2s_leaves",
                                       error_message, error_message_len);
        runtime.parents = make_pipeline(device, library, @"stwo_zig_blake2s_parents",
                                        error_message, error_message_len);
        runtime.quotients = make_pipeline(device, library, @"stwo_zig_quotient_rows",
                                          error_message, error_message_len);
        runtime.rawQuotients = make_pipeline(device, library, @"stwo_zig_quotient_rows_raw",
                                             error_message, error_message_len);
        runtime.polynomialEval = make_pipeline(device, library, @"stwo_zig_eval_polynomials",
                                               error_message, error_message_len);
        runtime.polynomialBasis = make_pipeline(device, library, @"stwo_zig_eval_basis",
                                                error_message, error_message_len);
        runtime.circleIfftFirst = make_pipeline(device, library, @"stwo_zig_circle_ifft_first", error_message, error_message_len);
        runtime.circleIfftLayer = make_pipeline(device, library, @"stwo_zig_circle_ifft_layer", error_message, error_message_len);
        runtime.circleRfftLayer = make_pipeline(device, library, @"stwo_zig_circle_rfft_layer", error_message, error_message_len);
        runtime.circleRfftLast = make_pipeline(device, library, @"stwo_zig_circle_rfft_last", error_message, error_message_len);
        runtime.circleRescale = make_pipeline(device, library, @"stwo_zig_circle_rescale", error_message, error_message_len);
        runtime.circleExpand = make_pipeline(device, library, @"stwo_zig_circle_expand_coefficients", error_message, error_message_len);
        runtime.circleIfftFused = make_pipeline(device, library, @"stwo_zig_circle_ifft_fused_tail", error_message, error_message_len);
        runtime.circleIfftFusedWide = make_pipeline(device, library, @"stwo_zig_circle_ifft_fused_tail_wide", error_message, error_message_len);
        runtime.circleRfftFused = make_pipeline(device, library, @"stwo_zig_circle_rfft_fused_tail", error_message, error_message_len);
        runtime.quotientNumerator = make_pipeline(device, library, @"stwo_zig_quotient_numerator_raw", error_message, error_message_len);
        runtime.quotientFinalize = make_pipeline(device, library, @"stwo_zig_quotient_finalize", error_message, error_message_len);
        runtime.quotientDomainPointsResident = make_pipeline(device, library, @"stwo_zig_quotient_domain_points_resident", error_message, error_message_len);
        runtime.quotientDenominatorsResident = make_pipeline(device, library, @"stwo_zig_quotient_denominators_resident", error_message, error_message_len);
        runtime.quotientCombineResident = make_pipeline(device, library, @"stwo_zig_quotient_combine_resident", error_message, error_message_len);
        runtime.quotientCoefficientsResident = make_pipeline(device, library, @"stwo_zig_quotient_coefficients_resident", error_message, error_message_len);
        runtime.friFoldCircle = make_pipeline(device, library, @"stwo_zig_fri_fold_circle", error_message, error_message_len);
        runtime.friFoldLine = make_pipeline(device, library, @"stwo_zig_fri_fold_line", error_message, error_message_len);
        runtime.friFold3Resident = make_pipeline(device, library, @"stwo_zig_fri_fold3_resident", error_message, error_message_len);
        runtime.friFold2Resident = make_pipeline(device, library, @"stwo_zig_fri_fold2_resident", error_message, error_message_len);
        runtime.friPackedLeavesResident = make_pipeline(device, library, @"stwo_zig_fri_packed_leaves_resident", error_message, error_message_len);
        runtime.friFinalLineResident = make_pipeline(device, library, @"stwo_zig_fri_final_line_resident", error_message, error_message_len);
        runtime.transcriptInitResident = make_pipeline(device, library, @"stwo_zig_transcript_init_resident", error_message, error_message_len);
        runtime.transcriptMixResident = make_pipeline(device, library, @"stwo_zig_transcript_mix_resident", error_message, error_message_len);
        runtime.transcriptDrawSecureResident = make_pipeline(device, library, @"stwo_zig_transcript_draw_secure_resident", error_message, error_message_len);
        runtime.transcriptDrawQueriesResident = make_pipeline(device, library, @"stwo_zig_transcript_draw_queries_resident", error_message, error_message_len);
        runtime.decommitNormalizeQueriesResident = make_pipeline(device, library, @"stwo_zig_decommit_normalize_queries_resident", error_message, error_message_len);
        runtime.decommitPrepareFriQueriesResident = make_pipeline(device, library, @"stwo_zig_decommit_prepare_fri_queries_resident", error_message, error_message_len);
        runtime.decommitGatherFriValuesResident = make_pipeline(device, library, @"stwo_zig_decommit_gather_fri_values_resident", error_message, error_message_len);
        runtime.decommitPrepareTraceQueriesResident = make_pipeline(device, library, @"stwo_zig_decommit_prepare_trace_queries_resident", error_message, error_message_len);
        runtime.decommitGatherTraceValuesResident = make_pipeline(device, library, @"stwo_zig_decommit_gather_trace_values_resident", error_message, error_message_len);
        runtime.decommitAssembleFriResident = make_pipeline(device, library, @"stwo_zig_decommit_assemble_fri_resident", error_message, error_message_len);
        runtime.decommitSparseParentResident = make_pipeline(device, library, @"stwo_zig_decommit_sparse_parent_resident", error_message, error_message_len);
        runtime.decommitSparseLeavesResident = make_pipeline(device, library, @"stwo_zig_decommit_sparse_leaves_resident", error_message, error_message_len);
        runtime.decommitSparseLeafGroupResident = make_pipeline(device, library, @"stwo_zig_decommit_sparse_leaf_group_resident", error_message, error_message_len);
        runtime.decommitAssembleTraceResident = make_pipeline(device, library, @"stwo_zig_decommit_assemble_trace_resident", error_message, error_message_len);
        runtime.qm31ToCoordinates = make_pipeline(device, library, @"stwo_zig_qm31_to_coordinates", error_message, error_message_len);
        runtime.leafAbsorbResident = make_pipeline(device, library, @"stwo_zig_blake2s_leaf_absorb_resident", error_message, error_message_len);
        runtime.leafAbsorbCompactResident = make_pipeline(device, library, @"stwo_zig_blake2s_leaf_absorb_compact_resident", error_message, error_message_len);
        runtime.parentsPlainSparse = make_pipeline(device, library, @"stwo_zig_blake2s_parents_plain_sparse", error_message, error_message_len);
        runtime.clearArenaSpans = make_pipeline(device, library, @"stwo_zig_clear_arena_spans", error_message, error_message_len);
        runtime.circleExpandSparse = make_pipeline(device, library, @"stwo_zig_circle_expand_sparse", error_message, error_message_len);
        runtime.circleCopySparse = make_pipeline(device, library, @"stwo_zig_circle_copy_sparse", error_message, error_message_len);
        runtime.circleIfftFirstSparse = make_pipeline(device, library, @"stwo_zig_circle_ifft_first_sparse", error_message, error_message_len);
        runtime.circleIfftLayerSparse = make_pipeline(device, library, @"stwo_zig_circle_ifft_layer_sparse", error_message, error_message_len);
        runtime.circleRescaleSparse = make_pipeline(device, library, @"stwo_zig_circle_rescale_sparse", error_message, error_message_len);
        runtime.circleRfftLayerSparse = make_pipeline(device, library, @"stwo_zig_circle_rfft_layer_sparse", error_message, error_message_len);
        runtime.circleRfftRadix4Sparse = make_pipeline(device, library, @"stwo_zig_circle_rfft_radix4_sparse", error_message, error_message_len);
        runtime.circleRfftLastSparse = make_pipeline(device, library, @"stwo_zig_circle_rfft_last_sparse", error_message, error_message_len);
        runtime.circleRfftFusedSparse = make_pipeline(device, library, @"stwo_zig_circle_rfft_fused_tail_sparse", error_message, error_message_len);
        runtime.circleRfftFusedSparseWide = make_pipeline(device, library, @"stwo_zig_circle_rfft_fused_tail_sparse_wide", error_message, error_message_len);
        runtime.circleRfftLayerSparseWide = make_pipeline(device, library, @"stwo_zig_circle_rfft_layer_sparse_wide", error_message, error_message_len);
        runtime.circleRfftLastSparseWide = make_pipeline(device, library, @"stwo_zig_circle_rfft_last_sparse_wide", error_message, error_message_len);
        runtime.relationFused = make_pipeline(device, library, @"stwo_zig_relation_fused", error_message, error_message_len);
        runtime.relationBlockScan = make_pipeline(device, library, @"stwo_zig_relation_block_scan", error_message, error_message_len);
        runtime.relationScanBlocks = make_pipeline(device, library, @"stwo_zig_relation_scan_blocks", error_message, error_message_len);
        runtime.relationScanFinalize = make_pipeline(device, library, @"stwo_zig_relation_scan_finalize", error_message, error_message_len);
        runtime.parentsSparse = make_pipeline(device, library, @"stwo_zig_blake2s_parents_sparse", error_message, error_message_len);
        runtime.parentTailSparse = make_pipeline(device, library, @"stwo_zig_blake2s_parent_tail_sparse", error_message, error_message_len);
        runtime.compactGather = make_pipeline(device, library, @"stwo_zig_compact_gather", error_message, error_message_len);
        runtime.compactRadixHistogram = make_pipeline(device, library, @"stwo_zig_compact_radix_histogram", error_message, error_message_len);
        runtime.compactRadixPrefix = make_pipeline(device, library, @"stwo_zig_compact_radix_prefix", error_message, error_message_len);
        runtime.compactRadixScatter = make_pipeline(device, library, @"stwo_zig_compact_radix_scatter", error_message, error_message_len);
        runtime.compactHeads = make_pipeline(device, library, @"stwo_zig_compact_heads", error_message, error_message_len);
        runtime.compactScanLocal = make_pipeline(device, library, @"stwo_zig_compact_scan_local", error_message, error_message_len);
        runtime.compactScanBlocks = make_pipeline(device, library, @"stwo_zig_compact_scan_blocks", error_message, error_message_len);
        runtime.compactScanAdd = make_pipeline(device, library, @"stwo_zig_compact_scan_add", error_message, error_message_len);
        runtime.compactClearOutputs = make_pipeline(device, library, @"stwo_zig_compact_clear_outputs", error_message, error_message_len);
        runtime.compactScatter = make_pipeline(device, library, @"stwo_zig_compact_scatter", error_message, error_message_len);
        runtime.compactFinalize = make_pipeline(device, library, @"stwo_zig_compact_finalize", error_message, error_message_len);
        runtime.compositionLift = make_pipeline(device, library, @"stwo_zig_composition_lift_accumulate", error_message, error_message_len);
        runtime.compositionSplit = make_pipeline(device, library, @"stwo_zig_composition_split_coordinates", error_message, error_message_len);
        runtime.compositionExpand = make_pipeline(device, library, @"stwo_zig_composition_expand_sparse", error_message, error_message_len);
        runtime.compositionRandomPowers = make_pipeline(device, library, @"stwo_zig_composition_random_powers", error_message, error_message_len);
        runtime.compositionExtParams = make_pipeline(device, library, @"stwo_zig_composition_ext_params", error_message, error_message_len);

        // BEGIN GENERATED RISC-V POLYNOMIAL PIPELINES.
        // Keep this block in manifest order. Each content-addressed function
        // name is bound once so the runtime initializer remains auditable.
        NSString *riscvPolynomialName00 = @"stwo_zig_base_poly_7bce7473ee2f62288eceb8a3377d4634";
        runtime.riscvPolynomialPipelines[riscvPolynomialName00] = make_pipeline(
            device, library, riscvPolynomialName00, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName00] == nil) return NULL;
        NSString *riscvPolynomialName01 = @"stwo_zig_base_poly_c14a50f654a9c7e71379b41a108194ff";
        runtime.riscvPolynomialPipelines[riscvPolynomialName01] = make_pipeline(
            device, library, riscvPolynomialName01, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName01] == nil) return NULL;
        NSString *riscvPolynomialName02 = @"stwo_zig_base_poly_f3458c84073cbe0a1a0cc8d255a028f0";
        runtime.riscvPolynomialPipelines[riscvPolynomialName02] = make_pipeline(
            device, library, riscvPolynomialName02, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName02] == nil) return NULL;
        NSString *riscvPolynomialName03 = @"stwo_zig_base_poly_a2a6593402647f120c2a259a1710c6e3";
        runtime.riscvPolynomialPipelines[riscvPolynomialName03] = make_pipeline(
            device, library, riscvPolynomialName03, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName03] == nil) return NULL;
        NSString *riscvPolynomialName04 = @"stwo_zig_base_poly_875d2026fe2fc2b5e1c47b100b1b8f0d";
        runtime.riscvPolynomialPipelines[riscvPolynomialName04] = make_pipeline(
            device, library, riscvPolynomialName04, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName04] == nil) return NULL;
        NSString *riscvPolynomialName05 = @"stwo_zig_base_poly_d170513e9cfabf624e38dfa3d7d2f4ed";
        runtime.riscvPolynomialPipelines[riscvPolynomialName05] = make_pipeline(
            device, library, riscvPolynomialName05, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName05] == nil) return NULL;
        NSString *riscvPolynomialName06 = @"stwo_zig_base_poly_a74fd0125263cc1e887ee5d726ac99a0";
        runtime.riscvPolynomialPipelines[riscvPolynomialName06] = make_pipeline(
            device, library, riscvPolynomialName06, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName06] == nil) return NULL;
        NSString *riscvPolynomialName07 = @"stwo_zig_base_poly_3b018614b76f63e7a28e127029c18704";
        runtime.riscvPolynomialPipelines[riscvPolynomialName07] = make_pipeline(
            device, library, riscvPolynomialName07, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName07] == nil) return NULL;
        NSString *riscvPolynomialName08 = @"stwo_zig_base_poly_aa55ec34af78d3f2b74d4b3d06c708a8";
        runtime.riscvPolynomialPipelines[riscvPolynomialName08] = make_pipeline(
            device, library, riscvPolynomialName08, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName08] == nil) return NULL;
        NSString *riscvPolynomialName09 = @"stwo_zig_base_poly_0ade2040c246f9cad3919da46161d2fd";
        runtime.riscvPolynomialPipelines[riscvPolynomialName09] = make_pipeline(
            device, library, riscvPolynomialName09, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName09] == nil) return NULL;
        NSString *riscvPolynomialName10 = @"stwo_zig_base_poly_6301135c98c38c29971098b60b459397";
        runtime.riscvPolynomialPipelines[riscvPolynomialName10] = make_pipeline(
            device, library, riscvPolynomialName10, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName10] == nil) return NULL;
        NSString *riscvPolynomialName11 = @"stwo_zig_base_poly_95bca92bf8e5c8c0cd1438e06c6c8963";
        runtime.riscvPolynomialPipelines[riscvPolynomialName11] = make_pipeline(
            device, library, riscvPolynomialName11, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName11] == nil) return NULL;
        NSString *riscvPolynomialName12 = @"stwo_zig_base_poly_538cf123d369ae7e3fa5e0cfe6a0a976";
        runtime.riscvPolynomialPipelines[riscvPolynomialName12] = make_pipeline(
            device, library, riscvPolynomialName12, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName12] == nil) return NULL;
        NSString *riscvPolynomialName13 = @"stwo_zig_base_poly_2a07b91d7f51809a92cf5dccdf29c1b5";
        runtime.riscvPolynomialPipelines[riscvPolynomialName13] = make_pipeline(
            device, library, riscvPolynomialName13, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName13] == nil) return NULL;
        NSString *riscvPolynomialName14 = @"stwo_zig_base_poly_04a6d5f01089e9ee1136328c062b3055";
        runtime.riscvPolynomialPipelines[riscvPolynomialName14] = make_pipeline(
            device, library, riscvPolynomialName14, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName14] == nil) return NULL;
        NSString *riscvPolynomialName15 = @"stwo_zig_base_poly_7c3d009f184e1add15cea06850337ed9";
        runtime.riscvPolynomialPipelines[riscvPolynomialName15] = make_pipeline(
            device, library, riscvPolynomialName15, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName15] == nil) return NULL;
        NSString *riscvPolynomialName16 = @"stwo_zig_base_poly_ebe47c5c0304bddea66f3a2b7c9cd55c";
        runtime.riscvPolynomialPipelines[riscvPolynomialName16] = make_pipeline(
            device, library, riscvPolynomialName16, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName16] == nil) return NULL;
        NSString *riscvPolynomialName17 = @"stwo_zig_lookup_poly_f6f449b57d5a9c234b4276d588b695a2";
        runtime.riscvPolynomialPipelines[riscvPolynomialName17] = make_pipeline(
            device, library, riscvPolynomialName17, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName17] == nil) return NULL;
        NSString *riscvPolynomialName18 = @"stwo_zig_lookup_poly_50b304cc2ee4f2f9f39675717cf40382";
        runtime.riscvPolynomialPipelines[riscvPolynomialName18] = make_pipeline(
            device, library, riscvPolynomialName18, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName18] == nil) return NULL;
        NSString *riscvPolynomialName19 = @"stwo_zig_lookup_poly_075758e47d896ea9b9ed480adcc498d1";
        runtime.riscvPolynomialPipelines[riscvPolynomialName19] = make_pipeline(
            device, library, riscvPolynomialName19, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName19] == nil) return NULL;
        NSString *riscvPolynomialName20 = @"stwo_zig_lookup_poly_459147491178ba9a8fea95e70f7ba7de";
        runtime.riscvPolynomialPipelines[riscvPolynomialName20] = make_pipeline(
            device, library, riscvPolynomialName20, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName20] == nil) return NULL;
        NSString *riscvPolynomialName21 = @"stwo_zig_lookup_poly_223a80d6062ce49ec32568323089b631";
        runtime.riscvPolynomialPipelines[riscvPolynomialName21] = make_pipeline(
            device, library, riscvPolynomialName21, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName21] == nil) return NULL;
        NSString *riscvPolynomialName22 = @"stwo_zig_lookup_poly_e6f321d7e6a5216f0493a7d9dd1cce68";
        runtime.riscvPolynomialPipelines[riscvPolynomialName22] = make_pipeline(
            device, library, riscvPolynomialName22, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName22] == nil) return NULL;
        NSString *riscvPolynomialName23 = @"stwo_zig_lookup_poly_cc2c95d2bff4c999fee2f44e08222252";
        runtime.riscvPolynomialPipelines[riscvPolynomialName23] = make_pipeline(
            device, library, riscvPolynomialName23, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName23] == nil) return NULL;
        NSString *riscvPolynomialName24 = @"stwo_zig_lookup_poly_6417a7b6a721b820c56ded08d4ff45d4";
        runtime.riscvPolynomialPipelines[riscvPolynomialName24] = make_pipeline(
            device, library, riscvPolynomialName24, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName24] == nil) return NULL;
        NSString *riscvPolynomialName25 = @"stwo_zig_lookup_poly_b15f9ad4a9abfc83a7cdec6c46ee4ade";
        runtime.riscvPolynomialPipelines[riscvPolynomialName25] = make_pipeline(
            device, library, riscvPolynomialName25, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName25] == nil) return NULL;
        NSString *riscvPolynomialName26 = @"stwo_zig_lookup_poly_65a7491625ceb251a9d27754aba62fe9";
        runtime.riscvPolynomialPipelines[riscvPolynomialName26] = make_pipeline(
            device, library, riscvPolynomialName26, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName26] == nil) return NULL;
        NSString *riscvPolynomialName27 = @"stwo_zig_lookup_poly_4fae56a01407106338de7b5a0585b863";
        runtime.riscvPolynomialPipelines[riscvPolynomialName27] = make_pipeline(
            device, library, riscvPolynomialName27, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName27] == nil) return NULL;
        NSString *riscvPolynomialName28 = @"stwo_zig_lookup_poly_2a7765f5161c42b7e1e47eb4f38042a6";
        runtime.riscvPolynomialPipelines[riscvPolynomialName28] = make_pipeline(
            device, library, riscvPolynomialName28, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName28] == nil) return NULL;
        NSString *riscvPolynomialName29 = @"stwo_zig_lookup_poly_3d43f646d7e0de973374db1d7e9ffe16";
        runtime.riscvPolynomialPipelines[riscvPolynomialName29] = make_pipeline(
            device, library, riscvPolynomialName29, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName29] == nil) return NULL;
        NSString *riscvPolynomialName30 = @"stwo_zig_lookup_poly_58c75167f9212f9663711e80d150d46d";
        runtime.riscvPolynomialPipelines[riscvPolynomialName30] = make_pipeline(
            device, library, riscvPolynomialName30, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName30] == nil) return NULL;
        NSString *riscvPolynomialName31 = @"stwo_zig_lookup_poly_05d290ec9454d3ead43a08a8f547ed07";
        runtime.riscvPolynomialPipelines[riscvPolynomialName31] = make_pipeline(
            device, library, riscvPolynomialName31, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName31] == nil) return NULL;
        NSString *riscvPolynomialName32 = @"stwo_zig_lookup_poly_944959c865e0c8dee4d3972badf854b0";
        runtime.riscvPolynomialPipelines[riscvPolynomialName32] = make_pipeline(
            device, library, riscvPolynomialName32, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName32] == nil) return NULL;
        NSString *riscvPolynomialName33 = @"stwo_zig_lookup_poly_6036f462a378cec7d80f357b57bff1f4";
        runtime.riscvPolynomialPipelines[riscvPolynomialName33] = make_pipeline(
            device, library, riscvPolynomialName33, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName33] == nil) return NULL;
        // END GENERATED RISC-V POLYNOMIAL PIPELINES.

        if (runtime.queue == nil || runtime.quadraticRecurrenceTrace == nil ||
            runtime.quadraticRecurrenceIfftWide == nil ||
            runtime.leaves == nil || runtime.parents == nil ||
            runtime.quotients == nil || runtime.rawQuotients == nil || runtime.polynomialEval == nil ||
            runtime.polynomialBasis == nil || runtime.circleIfftFirst == nil || runtime.circleIfftLayer == nil ||
            runtime.circleRfftLayer == nil || runtime.circleRfftLast == nil || runtime.circleRescale == nil ||
            runtime.circleExpand == nil || runtime.circleIfftFused == nil || runtime.circleIfftFusedWide == nil ||
            runtime.circleRfftFused == nil ||
            runtime.quotientNumerator == nil || runtime.quotientFinalize == nil ||
            runtime.quotientDomainPointsResident == nil || runtime.quotientDenominatorsResident == nil ||
            runtime.quotientCombineResident == nil || runtime.quotientCoefficientsResident == nil ||
            runtime.friFoldCircle == nil || runtime.friFoldLine == nil || runtime.friFold3Resident == nil ||
            runtime.friFold2Resident == nil || runtime.friPackedLeavesResident == nil || runtime.friFinalLineResident == nil ||
            runtime.transcriptInitResident == nil || runtime.transcriptMixResident == nil ||
            runtime.transcriptDrawSecureResident == nil || runtime.transcriptDrawQueriesResident == nil ||
            runtime.decommitNormalizeQueriesResident == nil || runtime.decommitPrepareFriQueriesResident == nil ||
            runtime.decommitGatherFriValuesResident == nil || runtime.decommitPrepareTraceQueriesResident == nil ||
            runtime.decommitGatherTraceValuesResident == nil || runtime.qm31ToCoordinates == nil ||
            runtime.decommitAssembleFriResident == nil ||
            runtime.decommitSparseParentResident == nil || runtime.decommitAssembleTraceResident == nil ||
            runtime.decommitSparseLeavesResident == nil ||
            runtime.decommitSparseLeafGroupResident == nil || runtime.clearArenaSpans == nil ||
            runtime.leafAbsorbResident == nil || runtime.leafAbsorbCompactResident == nil ||
            runtime.parentsPlainSparse == nil ||
            runtime.circleExpandSparse == nil ||
            runtime.circleCopySparse == nil || runtime.circleIfftFirstSparse == nil ||
            runtime.circleIfftLayerSparse == nil || runtime.circleRescaleSparse == nil ||
            runtime.circleRfftLayerSparse == nil || runtime.circleRfftRadix4Sparse == nil ||
            runtime.circleRfftLastSparse == nil || runtime.circleRfftFusedSparse == nil ||
            runtime.circleRfftFusedSparseWide == nil ||
            runtime.circleRfftLayerSparseWide == nil || runtime.circleRfftLastSparseWide == nil) return NULL;
        if (runtime.relationFused == nil || runtime.relationBlockScan == nil ||
            runtime.relationScanBlocks == nil || runtime.relationScanFinalize == nil ||
            runtime.parentsSparse == nil || runtime.parentTailSparse == nil ||
            runtime.compactGather == nil || runtime.compactRadixHistogram == nil || runtime.compactRadixPrefix == nil ||
            runtime.compactRadixScatter == nil || runtime.compactHeads == nil || runtime.compactScanLocal == nil ||
            runtime.compactScanBlocks == nil || runtime.compactScanAdd == nil || runtime.compactClearOutputs == nil ||
            runtime.compactScatter == nil || runtime.compactFinalize == nil || runtime.compositionLift == nil ||
            runtime.compositionSplit == nil || runtime.compositionExpand == nil || runtime.compositionRandomPowers == nil ||
            runtime.compositionExtParams == nil) return NULL;
        if (include_deferred) {
            runtime.witnessFeedCounts = make_pipeline(device, library, @"stwo_zig_witness_feed_counts", error_message, error_message_len);
            runtime.witnessInputGatherResident = make_pipeline(device, library, @"stwo_zig_witness_input_gather_resident", error_message, error_message_len);
            runtime.executionTableSplitResident = make_pipeline(device, library, @"stwo_zig_execution_table_split_resident", error_message, error_message_len);
            runtime.memoryAddressBaseTraceResident = make_pipeline(device, library, @"stwo_zig_memory_address_base_trace_resident", error_message, error_message_len);
            runtime.memoryValueBaseTraceResident = make_pipeline(device, library, @"stwo_zig_memory_value_base_trace_resident", error_message, error_message_len);
            runtime.memoryRc99CountResident = make_pipeline(device, library, @"stwo_zig_memory_rc99_count_resident", error_message, error_message_len);
            runtime.publicMemorySeedResident = make_pipeline(device, library, @"stwo_zig_public_memory_seed_resident", error_message, error_message_len);
            runtime.fixedTableLookup = make_pipeline(device, library, @"stwo_zig_fixed_table_lookup_sparse", error_message, error_message_len);
            runtime.felt252Oracle = make_pipeline(device, library, @"stwo_zig_felt252_oracle", error_message, error_message_len);
            runtime.ecOpWitness = make_pipeline(device, library, @"stwo_zig_ec_op_witness", error_message, error_message_len);
            runtime.ecOpLookup = make_pipeline(device, library, @"stwo_zig_ec_op_lookup", error_message, error_message_len);
            runtime.ecOpBaseFinalize = make_pipeline(device, library, @"stwo_zig_ec_op_base_finalize", error_message, error_message_len);
            if (runtime.witnessFeedCounts == nil || runtime.witnessInputGatherResident == nil ||
                runtime.executionTableSplitResident == nil || runtime.memoryAddressBaseTraceResident == nil ||
                runtime.memoryValueBaseTraceResident == nil || runtime.memoryRc99CountResident == nil ||
                runtime.publicMemorySeedResident == nil || runtime.fixedTableLookup == nil ||
                runtime.felt252Oracle == nil || runtime.ecOpWitness == nil ||
                runtime.ecOpLookup == nil || runtime.ecOpBaseFinalize == nil) return NULL;
        }
        return runtime;
    }
}

static void bind_qm31_coordinate_kernel(
    id<MTLComputeCommandEncoder> encoder, id<MTLBuffer> source,
    id<MTLBuffer> coordinates, uint32_t value_count, id<MTLBuffer> leaves,
    id<MTLBuffer> leaf_seed, uint32_t prefix_bytes, uint32_t write_leaf
) {
    [encoder setBuffer:source offset:0u atIndex:0];
    [encoder setBuffer:coordinates offset:0u atIndex:1];
    [encoder setBytes:&value_count length:sizeof(value_count) atIndex:2];
    [encoder setBuffer:leaves offset:0u atIndex:3];
    [encoder setBuffer:leaf_seed offset:0u atIndex:4];
    [encoder setBytes:&prefix_bytes length:sizeof(prefix_bytes) atIndex:5];
    [encoder setBytes:&write_leaf length:sizeof(write_leaf) atIndex:6];
}

static void bind_fri_line_kernel(
    id<MTLComputeCommandEncoder> encoder, id<MTLBuffer> source,
    NSUInteger inverse_offset, id<MTLBuffer> inverse, id<MTLBuffer> alpha,
    NSUInteger alpha_offset, id<MTLBuffer> destination, uint32_t destination_count,
    id<MTLBuffer> coordinates, id<MTLBuffer> leaves, id<MTLBuffer> leaf_seed,
    uint32_t prefix_bytes, uint32_t prepare_next
) {
    [encoder setBuffer:source offset:0u atIndex:0];
    [encoder setBuffer:inverse offset:inverse_offset atIndex:1];
    [encoder setBuffer:alpha offset:alpha_offset atIndex:2];
    [encoder setBuffer:destination offset:0u atIndex:3];
    [encoder setBytes:&destination_count length:sizeof(destination_count) atIndex:4];
    [encoder setBuffer:coordinates offset:0u atIndex:5];
    [encoder setBuffer:leaves offset:0u atIndex:6];
    [encoder setBuffer:leaf_seed offset:0u atIndex:7];
    [encoder setBytes:&prefix_bytes length:sizeof(prefix_bytes) atIndex:8];
    [encoder setBytes:&prepare_next length:sizeof(prepare_next) atIndex:9];
}

static void encode_fri_inverse_domain(
    StwoZigMetalRuntime *runtime, id<MTLComputeCommandEncoder> encoder,
    id<MTLBuffer> destination, NSUInteger destination_offset,
    uint32_t value_count, uint32_t initial_index, uint32_t step_size,
    uint32_t mode
) {
    uint32_t log_size = 0u;
    for (uint32_t count = value_count; count > 1u; count >>= 1u) log_size += 1u;
    uint32_t destination_words = (uint32_t)(destination_offset / sizeof(uint32_t));
    [encoder setComputePipelineState:runtime.quotientDomainPointsResident];
    [encoder setBuffer:destination offset:0u atIndex:0];
    [encoder setBytes:&destination_words length:sizeof(destination_words) atIndex:1];
    [encoder setBytes:&value_count length:sizeof(value_count) atIndex:2];
    [encoder setBytes:&log_size length:sizeof(log_size) atIndex:3];
    [encoder setBytes:&initial_index length:sizeof(initial_index) atIndex:4];
    [encoder setBytes:&step_size length:sizeof(step_size) atIndex:5];
    [encoder setBytes:&mode length:sizeof(mode) atIndex:6];
    NSUInteger width = MIN(runtime.quotientDomainPointsResident.maxTotalThreadsPerThreadgroup,
                           runtime.quotientDomainPointsResident.threadExecutionWidth * 8u);
    [encoder dispatchThreads:MTLSizeMake(value_count, 1u, 1u)
         threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
}

#import "runtime/initialization.m"

// One translation unit keeps plan types and encoder helpers private to the stable C ABI.
#import "runtime/runtime_queries.m"
#import "runtime/fri_fold_commit.m"
#import "runtime/fri_plans.m"
#import "runtime/transcript_decommitment.m"
#import "runtime/witness_primitives.m"
#import "runtime/resource_plans.m"
#import "runtime/circle_plans.m"
#import "runtime/merkle_epochs.m"
#import "runtime/auxiliary_plans.m"
#import "runtime/cache_identity.m"
#import "runtime/archive_store.m"
#import "runtime/dynamic_evaluation.m"
#import "runtime/base_polynomial.m"
#import "runtime/lookup_polynomial.m"
#import "runtime/composition.m"
#import "runtime/composition_recurrence.m"
#import "runtime/prepared_auxiliary.m"
#import "runtime/circle_legacy.m"
#import "runtime/circle_commit_epoch.m"
#import "runtime/polynomial_evaluation.m"
#import "runtime/quotients.m"
#import "runtime/lifecycle_and_tree.m"

size_t stwo_zig_metal_runtime_identity(void *runtime_ptr, char *output, size_t output_len) {
    @autoreleasepool {
        if (runtime_ptr == NULL) return 0u;
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        NSData *encoded = [eval_runtime_identity(runtime.device).canonical
            dataUsingEncoding:NSUTF8StringEncoding];
        if (encoded.length == 0u) return 0u;
        if (output != NULL && output_len >= encoded.length)
            memcpy(output, encoded.bytes, encoded.length);
        return encoded.length;
    }
}
