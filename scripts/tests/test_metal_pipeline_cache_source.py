from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATHS = (
    ROOT / "src/backends/metal/runtime/cache_identity.m",
    ROOT / "src/backends/metal/runtime/archive_store.m",
    ROOT / "src/backends/metal/runtime/dynamic_evaluation.m",
    ROOT / "src/backends/metal/runtime/lifecycle_and_tree.m",
    ROOT / "src/backends/metal/runtime.m",
    ROOT / "src/backends/metal/runtime/runtime_queries.m",
    ROOT / "src/backends/metal/runtime/object_model.h",
    ROOT / "src/backends/metal/runtime/abi.h",
)
ZIG_SOURCE_PATH = ROOT / "src/backends/metal/runtime.zig"
ZIG_SESSION_PATH = ROOT / "src/backends/metal/runtime/session.zig"
ZIG_ABI_SOURCE_PATH = ROOT / "src/backends/metal/runtime/abi.zig"


def function_body(source: str, name: str, next_name: str) -> str:
    start = source.index(name)
    end = source.index(next_name, start)
    return source[start:end]


class MetalPipelineCacheSourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = "\n".join(path.read_text() for path in SOURCE_PATHS)
        cls.zig_source = ZIG_SOURCE_PATH.read_text() + ZIG_SESSION_PATH.read_text()
        cls.zig_abi_source = ZIG_ABI_SOURCE_PATH.read_text()

    def test_file_backed_libraries_use_canonical_runtime_cache(self):
        body = function_body(
            self.source,
            "void *stwo_zig_metal_eval_library_load(",
            "void *stwo_zig_metal_eval_library_compile(",
        )
        self.assertIn("stringByResolvingSymlinksInPath", body)
        self.assertIn("@synchronized(runtime)", body)
        self.assertIn("runtime.evalLibraries[cacheKey]", body)
        self.assertIn("result.cacheKey = cacheKey", body)

    def test_file_backed_metallib_cache_and_archive_are_content_addressed(self):
        body = function_body(
            self.source,
            "void *stwo_zig_metal_eval_library_load(",
            "void *stwo_zig_metal_eval_library_compile(",
        )
        self.assertIn("NSDataReadingMappedIfSafe", body)
        self.assertIn("eval_sha256_hex(libraryData.bytes, libraryData.length)", body)
        self.assertIn("StwoZigEvalLibraryKindMetallib", body)
        self.assertIn("result.archiveKey = eval_archive_key(cacheKey)", body)
        self.assertIn("eval_archive_store_prepare_library(runtime, result)", body)
        self.assertIn("eval_library_from_data(runtime.device, libraryData", body)
        self.assertNotIn("newLibraryWithURL", body)
        helper = function_body(
            self.source,
            "static NSString *eval_archive_path(",
            "static id<MTLBinaryArchive> eval_archive_new(",
        )
        self.assertIn("state.archives", helper)
        self.assertIn("stwo-zig-eval-cache-v2-%@.binarchive", helper)

    def test_archive_hit_is_probed_before_confirmed_miss_population(self):
        body = function_body(
            self.source,
            "static id<MTLComputePipelineState> resolve_eval_pipeline(",
            "void *stwo_zig_metal_eval_library_load(",
        )
        cache = body.index("runtime.evalPipelines[pipelineKey]")
        probe = body.index("MTLPipelineOptionFailOnBinaryArchiveMiss")
        direct_compile = body.index("newComputePipelineStateWithFunction", probe)
        populate = body.index("eval_archive_store_publish_pipeline", direct_compile)
        self.assertLess(cache, probe)
        self.assertLess(probe, direct_compile)
        self.assertLess(direct_compile, populate)
        self.assertEqual(self.source.count("addComputePipelineFunctionsWithDescriptor"), 1)

    def test_eval_and_witness_prepares_share_pipeline_resolver(self):
        witness = function_body(
            self.source,
            "void *stwo_zig_metal_witness_prepare_library(",
            "void stwo_zig_metal_witness_plan_destroy(",
        )
        evaluation = function_body(
            self.source,
            "void *stwo_zig_metal_eval_prepare_library(",
            "bool stwo_zig_metal_eval_library_serialize(",
        )
        self.assertIn("resolve_eval_pipeline(runtime, library, name", witness)
        self.assertIn("resolve_eval_pipeline(runtime, library, name", evaluation)
        self.assertNotIn("addComputePipelineFunctionsWithDescriptor", witness)
        self.assertNotIn("addComputePipelineFunctionsWithDescriptor", evaluation)

    def test_source_compiled_library_uses_content_keyed_runtime_cache_and_archive(self):
        body = function_body(
            self.source,
            "void *stwo_zig_metal_eval_library_compile(",
            "void stwo_zig_metal_eval_library_destroy(",
        )
        self.assertIn("eval_sha256_hex(source_bytes, source_len)", body)
        self.assertIn("StwoZigEvalLibraryKindSource", body)
        self.assertIn("eval_library_key(", body)
        self.assertIn("[cached.sourceBytes isEqualToData:sourceData]", body)
        self.assertIn("Metal source cache identity collision", body)
        key = body.index("eval_sha256_hex(source_bytes, source_len)")
        synchronized = body.index("@synchronized(runtime)", key)
        lookup = body.index("runtime.evalLibraries[cacheKey]", synchronized)
        hit = body.index("runtime.evalLibraryCacheHits += 1u", lookup)
        miss = body.index("runtime.evalLibraryCacheMisses += 1u", hit)
        compile_library = body.index("newLibraryWithSource", miss)
        insertion = body.index("cache_eval_library(runtime, result, cacheKey", compile_library)
        self.assertLess(key, synchronized)
        self.assertLess(synchronized, lookup)
        self.assertLess(lookup, hit)
        self.assertLess(hit, miss)
        self.assertLess(miss, compile_library)
        self.assertLess(compile_library, insertion)
        self.assertIn("result.cacheKey = cacheKey", body)
        self.assertIn("result.sourceBytes = sourceData", body)
        self.assertIn("result.archiveKey = eval_archive_key(cacheKey)", body)
        self.assertIn("eval_archive_store_prepare_library(runtime, result)", body)

    def test_source_identity_uses_full_sha256_not_fnv64(self):
        identity = function_body(
            self.source,
            "static NSString *eval_sha256_hex(",
            "static NSString *eval_length_prefixed(",
        )
        self.assertIn("CC_SHA256_Init", identity)
        self.assertIn("CC_SHA256_Update", identity)
        self.assertIn("CC_SHA256_Final", identity)
        self.assertIn("CC_SHA256_DIGEST_LENGTH * 2u", identity)
        self.assertNotIn("1099511628211", self.source)
        self.assertNotIn("14695981039346656037", self.source)

    def test_cache_keys_bind_typed_device_os_profile_and_content_identity(self):
        self.assertIn("@interface StwoZigEvalRuntimeIdentity : NSObject <NSCopying>", self.source)
        for field in (
            "registryID",
            "architectureName",
            "familySetSha256",
            "osVersion",
            "osBuild",
            "compileProfile",
        ):
            self.assertIn(field, self.source)
        self.assertIn("device.architecture.name", self.source)
        self.assertIn("supportsFamily:family", self.source)
        self.assertIn('system[@"ProductBuildVersion"]', self.source)
        self.assertIn("language=metal3.1;math=safe;minimum-macos=14.0", self.source)
        self.assertIn("@interface StwoZigEvalLibraryKey : NSObject <NSCopying>", self.source)
        self.assertIn("contentSha256", self.source)
        self.assertIn("contentBytes", self.source)
        self.assertIn("@interface StwoZigEvalPipelineKey : NSObject <NSCopying>", self.source)
        self.assertIn("functionName", self.source)
        self.assertIn('functionConstantIdentity = @"none"', self.source)
        self.assertIn('descriptorContract = @"compute-default-v1"', self.source)
        self.assertIn("@interface StwoZigEvalArchiveKey : NSObject <NSCopying>", self.source)
        self.assertIn('pipelineContract = @"compute-default-v1"', self.source)
        self.assertIn("2001, 2002, 3001, 3002, 3003, 5001, 5002", self.source)
        self.assertIn("NSMutableDictionary<StwoZigEvalLibraryKey *, id>", self.source)
        self.assertIn(
            "NSMutableDictionary<StwoZigEvalPipelineKey *, id<MTLComputePipelineState>>",
            self.source,
        )

    def test_pipeline_identity_and_invalidation_use_typed_library_keys(self):
        resolver = function_body(
            self.source,
            "static id<MTLComputePipelineState> resolve_eval_pipeline(",
            "static id<MTLLibrary> eval_library_from_data(",
        )
        self.assertIn("eval_pipeline_key(library.cacheKey, name)", resolver)
        self.assertIn("library.runtimeOwner != runtime", resolver)
        self.assertIn("library.library.device != runtime.device", resolver)
        invalidation = function_body(
            self.source,
            "static void invalidate_eval_library_pipelines(",
            "static void evict_eval_library(",
        )
        self.assertIn("[key.libraryKey isEqual:libraryKey]", invalidation)
        self.assertNotIn("hasPrefix", invalidation)

    def test_source_cache_returns_independently_retained_handles(self):
        compile_body = function_body(
            self.source,
            "void *stwo_zig_metal_eval_library_compile(",
            "void stwo_zig_metal_eval_library_destroy(",
        )
        destroy_body = function_body(
            self.source,
            "void stwo_zig_metal_eval_library_destroy(",
            "void *stwo_zig_metal_witness_prepare_library(",
        )
        self.assertIn("return (__bridge_retained void *)cached", compile_body)
        self.assertIn("return (__bridge_retained void *)result", compile_body)
        self.assertIn("cache_eval_library(runtime, result, cacheKey", compile_body)
        self.assertIn("CFRelease(library_ptr)", destroy_body)
        self.assertIn("@property(nonatomic, weak) StwoZigMetalRuntime *runtimeOwner", self.source)

    def test_archive_flush_is_store_owned_and_teardown_order_stays_stable(self):
        serialize = function_body(
            self.source,
            "static bool serialize_eval_archive(",
            "static id<MTLComputePipelineState> resolve_eval_pipeline(",
        )
        destroy = function_body(
            self.source,
            "void stwo_zig_metal_runtime_destroy(",
            "void *stwo_zig_metal_merkle_commit(",
        )
        self.assertIn("eval_archive_store_flush_library", serialize)
        self.assertIn("if (!library.archiveDirty) return true", self.source)
        self.assertIn("sortedArrayUsingSelector:@selector(compare:)", destroy)
        self.assertIn("if (!library.archiveDirty) continue", destroy)
        self.assertIn("serialize_eval_archive(library, &error, &didSerialize)", destroy)

    def test_cache_counters_increment_only_at_observed_events(self):
        load = function_body(
            self.source,
            "void *stwo_zig_metal_eval_library_load(",
            "void *stwo_zig_metal_eval_library_compile(",
        )
        resolve = function_body(
            self.source,
            "static id<MTLComputePipelineState> resolve_eval_pipeline(",
            "void *stwo_zig_metal_eval_library_load(",
        )
        serialize = function_body(
            self.source,
            "bool stwo_zig_metal_eval_library_serialize(",
            "void stwo_zig_metal_eval_destroy(",
        )
        self.assertIn("runtime.evalLibraryCacheHits += 1u", load)
        self.assertIn("runtime.evalLibraryCacheMisses += 1u", load)
        compile_library = function_body(
            self.source,
            "void *stwo_zig_metal_eval_library_compile(",
            "void stwo_zig_metal_eval_library_destroy(",
        )
        self.assertIn("runtime.evalLibraryCacheHits += 1u", compile_library)
        self.assertIn("runtime.evalLibraryCacheMisses += 1u", compile_library)
        for body in (load, compile_library):
            miss = body.index("runtime.evalLibraryCacheMisses += 1u")
            timed = body.index("@try", miss)
            finished = body.index("@finally", timed)
            accumulated = body.index("runtime.evalLibraryPreparationSeconds +=", finished)
            self.assertLess(miss, timed)
            self.assertLess(timed, finished)
            self.assertLess(finished, accumulated)
        self.assertIn("runtime.evalPipelineCacheHits += 1u", resolve)
        self.assertIn("if (pipeline != nil) runtime.evalBinaryArchiveHits += 1u", resolve)
        self.assertLess(
            resolve.index("newComputePipelineStateWithFunction", resolve.index("MTLPipelineOptionFailOnBinaryArchiveMiss")),
            resolve.index("runtime.evalBinaryArchiveMisses += 1u"),
        )
        self.assertIn("runtime.evalDirectCompiles += 1u", resolve)
        self.assertIn("@finally", resolve)
        self.assertIn("runtime.evalPipelinePreparationSeconds +=", resolve)
        publish = function_body(
            self.source,
            "static bool eval_archive_store_publish_pipeline(",
            "static bool eval_archive_store_flush_library(",
        )
        self.assertLess(
            publish.index("addComputePipelineFunctionsWithDescriptor"),
            publish.index("runtime.evalArchivePopulations += 1u"),
        )
        self.assertIn("runtime.evalArchiveSerializations += 1u", publish)

    def test_archive_store_is_owned_bounded_locked_and_atomically_published(self):
        for token in (
            "NSCachesDirectory",
            'STWO_ZIG_METAL_CACHE_DIR',
            '@"dev.stwo-zig"',
            '@"eval-archives-v3"',
            "STWO_ZIG_ARCHIVE_ENTRY_LIMIT",
            "STWO_ZIG_ARCHIVE_BYTE_LIMIT",
            "STWO_ZIG_ARCHIVE_PER_ENTRY_BYTE_LIMIT",
            "STWO_ZIG_ARCHIVE_QUARANTINE_ENTRY_LIMIT",
            "STWO_ZIG_ARCHIVE_QUARANTINE_BYTE_LIMIT",
            "O_NOFOLLOW",
            "flock(descriptor, LOCK_EX | LOCK_NB)",
            "STWO_ZIG_ARCHIVE_LOCK_TIMEOUT_SECONDS",
            "fsync(file)",
            "fsync(directory)",
            "rename(temporary.fileSystemRepresentation, target.fileSystemRepresentation)",
        ):
            self.assertIn(token, self.source)
        self.assertNotIn("serializeToURL:library.archiveURL", self.source)

    def test_archive_population_reloads_latest_and_never_fails_compiled_pso(self):
        resolve = function_body(
            self.source,
            "static id<MTLComputePipelineState> resolve_eval_pipeline(",
            "static id<MTLLibrary> eval_library_from_data(",
        )
        direct = resolve.index("newComputePipelineStateWithFunction")
        publish = resolve.index("eval_archive_store_publish_pipeline", direct)
        self.assertLess(direct, publish)
        self.assertIn("library.archive != nil", resolve)
        self.assertIn("(void)eval_archive_store_publish_pipeline", resolve)
        store = function_body(
            self.source,
            "static bool eval_archive_store_publish_pipeline(",
            "static bool eval_archive_store_flush_library(",
        )
        self.assertLess(store.index("eval_archive_new(runtime.device, path, true"),
                        store.index("addComputePipelineFunctionsWithDescriptor"))
        self.assertLess(store.index("addComputePipelineFunctionsWithDescriptor"),
                        store.index("eval_archive_atomic_serialize_locked"))

    def test_corrupt_archive_is_quarantined_and_rebuilt(self):
        prepare = function_body(
            self.source,
            "static void eval_archive_store_prepare_library(",
            "static bool eval_archive_atomic_serialize_locked(",
        )
        self.assertIn("state.diskRebuilds += 1u", prepare)
        self.assertIn("eval_archive_quarantine_locked", prepare)
        self.assertIn("eval_archive_new(runtime.device, path, false", prepare)
        self.assertIn("state.persistenceBypasses += 1u", prepare)

    def test_stats_abi_is_read_only_and_zero_initialized_in_zig(self):
        fields = (
            "library_cache_hits",
            "library_cache_misses",
            "pipeline_cache_hits",
            "binary_archive_hits",
            "binary_archive_misses",
            "direct_compiles",
            "archive_populations",
            "archive_serializations",
            "pipeline_preparation_seconds",
            "library_preparation_seconds",
            "library_cache_entries",
            "library_cache_bytes",
            "library_cache_peak_entries",
            "library_cache_peak_bytes",
            "library_cache_evictions",
            "library_cache_rejections",
            "pipeline_cache_entries",
            "pipeline_cache_bytes",
            "pipeline_cache_peak_entries",
            "pipeline_cache_peak_bytes",
            "pipeline_cache_evictions",
            "pipeline_cache_invalidations",
            "pipeline_cache_rejections",
            "library_cache_entry_limit",
            "library_cache_byte_limit",
            "pipeline_cache_entry_limit",
            "pipeline_cache_byte_limit",
        )
        for field in fields:
            self.assertIn(field, self.source)
            self.assertIn(field, self.zig_abi_source)
        self.assertIn("pub const PipelineCacheStats = extern struct", self.zig_abi_source)
        self.assertIn("return std.mem.zeroes(PipelineCacheStats)", self.zig_abi_source)
        self.assertIn("pub const PipelineCacheStats = abi.PipelineCacheStats", self.zig_source)
        self.assertIn("pub fn pipelineCacheStats(self: *const Runtime)", self.zig_source)
        self.assertIn('test "pipeline cache stats zero value"', self.zig_abi_source)

    def test_archive_store_stats_use_a_separate_versioned_sized_abi(self):
        fields = (
            "archive_disk_hits",
            "archive_disk_misses",
            "archive_disk_evictions",
            "archive_disk_rebuilds",
            "archive_disk_rejections",
            "archive_disk_quarantines",
            "archive_lock_acquisitions",
            "archive_lock_contentions",
            "archive_lock_timeouts",
            "archive_publication_successes",
            "archive_publication_failures",
            "archive_disk_entries",
            "archive_disk_bytes",
        )
        self.assertIn("StwoZigArchiveStoreStatsV1", self.source)
        self.assertIn("ArchiveStoreStatsV1", self.zig_abi_source)
        self.assertIn("stats_size != sizeof(*stats)", self.source)
        self.assertIn("_Static_assert(sizeof(StwoZigArchiveStoreStatsV1) == 200", self.source)
        for field in fields:
            self.assertIn(field, self.source)
            self.assertIn(field, self.zig_abi_source)


if __name__ == "__main__":
    unittest.main()
