//! Real supplemental seven-family recursive publication from live base proofs.
//! This retains immutable source admissions, not replay or PCS state. Durable
//! metadata is OPEN: original fresh leaves and global/source joins remain
//! mandatory before any whole-block cryptographic authority can be claimed.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Sources = @import("block_v5_cpu_recursive_sources_v1.zig");
const Parent = @import("../recursion/blake3_execution_parent_protocol.zig");
const Templates = @import("block_v5_recursive_template_callback_v1.zig");
const Providers = @import("block_v5_recursive_provider_store_v1.zig");
const Executions = @import("block_v5_recursive_execution_leaf_store_v1.zig");
const ProviderDefinition = @import("block_v5_recursive_provider_definition_v1.zig");
const ExecutionDefinition = @import("block_v5_recursive_execution_leaf_files_v1.zig");
const Base = @import("block_v5_cpu_bundle_store_v1.zig").ForCapacity(true);
const CallerPipeline = @import("block_v5_caller_recursive_pipeline_v1.zig");
const WordCache = @import("block_v5_word_expected_setup_cache_v1.zig");
const RamStage = @import("block_v5_ram_lanes_recursive_stage_v1.zig").ForBackend(Cpu);
const RangeStage = @import("block_v5_range16_recursive_stage_v1.zig").ForBackend(Cpu);
const ProgramStage = @import("block_v5_program_table_recursive_stage_v1.zig").ForBackend(Cpu);
const LookupStage = @import("block_v5_native_lookup_recursive_stage_v1.zig").ForBackend(Cpu);
const CallerArithmeticStage = @import("block_v5_caller_arithmetic_recursive_stage_v1.zig").ForBackend(Cpu);
const CallerFusedStage = @import("block_v5_caller_fused_recursive_stage_v1.zig").ForBackend(Cpu);
const NativeFusedStage = @import("block_v5_native_capacity_fused_recursive_stage_v1.zig").ForBackend(Cpu);
const Workers = @import("../recursion/blake3_native_parent_worker.zig");
const worker_fields = .{ "ram_worker", "range_worker", "program_worker", "lookup_worker", "caller_arithmetic_worker", "caller_fused_worker", "native_fused_worker" };
pub const WorkerFamily = enum { ram_lanes, range16, program_table, native_lookup, caller_arithmetic, caller_fused, native_capacity_fused };
pub const WorkerStatistics = struct {
    family: WorkerFamily,
    setup_hits: usize = 0,
    setup_misses: usize = 0,
    request_threads_started: u64 = 0,
    completed_requests: u64 = 0,
    retained_setup: bool = false,
    live_owned_bytes: usize = 0,
    peak_owned_bytes: usize = 0,
};
pub fn emptyWorkerStatistics() [worker_fields.len]WorkerStatistics {
    var result: [worker_fields.len]WorkerStatistics = undefined;
    inline for (0..worker_fields.len) |i| result[i] = .{ .family = @enumFromInt(i) };
    return result;
}

pub const Options = struct {
    sources: Sources.Limits = .{},
    providers: Providers.Limits = .{},
    executions: Executions.Limits = .{},
    transcript_capacity: u32 = 2,
    max_word_template_metadata_bytes: usize = 64 << 20,
    max_worker_bytes: usize = 8 << 30,
    worker_options: Workers.Options = .{ .worker_count = 1, .host_byte_limit = 8 << 30, .retained_scratch_limit = 0 },
    max_manifest_bytes: usize = 64 << 20,
    pub fn validate(self: Options) !void {
        try self.providers.validate();
        try self.executions.validate();
        _ = try @import("stwo_prover_engine").work_pool.WorkerBudget.init(self.worker_options.worker_count);
        if (self.max_worker_bytes == 0 or self.worker_options.host_byte_limit == 0 or
            self.worker_options.host_byte_limit > self.max_worker_bytes or
            self.worker_options.retained_scratch_limit > self.worker_options.host_byte_limit) return error.InvalidCpuRecursivePublicationOptions;
        if (self.transcript_capacity == 0 or self.max_word_template_metadata_bytes == 0 or self.sources.max_sources == 0 or self.sources.max_metadata_bytes == 0 or self.max_manifest_bytes == 0)
            return error.InvalidCpuRecursivePublicationOptions;
    }
};

fn WriterFor(comptime StoreModule: type, comptime D: type, comptime Prepared: type) type {
    return struct {
        pub const Module = StoreModule;
        pub const Binding = Templates.ForStore(StoreModule, Prepared, D.Protocol.Key, D.Bus.Wire, D.index);
        store: StoreModule.Store,
        binding: Binding,
        fn deinit(self: *@This()) void {
            self.store.deinit();
        }
    };
}
pub fn ProviderWriter(comptime family: Providers.Family) type {
    const D = ProviderDefinition.ForFamily(family);
    return WriterFor(Providers.ForFamily(family), D, D.Prepared);
}
pub fn ExecutionWriter(comptime family: Executions.Family) type {
    const D = ExecutionDefinition.ForFamily(family);
    return WriterFor(Executions.ForFamily(family), D, D.Admission.Prepared);
}

pub const Session = struct {
    a: std.mem.Allocator,
    sources: *Sources.Owner,
    base: *Base.Store,
    profile: Parent.Profile,
    options: Options,
    /// Borrowed only while joined family jobs are live.
    boundary: ?@import("block_v5_proof_boundary_v1.zig").Boundary = null,
    ranges: ?ProviderWriter(.range16) = null,
    lanes: ?ProviderWriter(.ram_lanes) = null,
    program: ?ProviderWriter(.program_table) = null,
    lookups: ?ProviderWriter(.native_lookup) = null,
    caller_arithmetic: ?ExecutionWriter(.caller_arithmetic) = null,
    caller_fused: ?ExecutionWriter(.caller_fused) = null,
    native_fused: ?ExecutionWriter(.native_capacity_fused) = null,
    /// Family callbacks are synchronous and ordered by their original stores.
    /// Entries contain only independent key/routing metadata, never captures.
    word_ram: ?WordCache.ForFamily(.ram_lanes, Cpu) = null,
    word_range: ?WordCache.ForFamily(.range16, Cpu) = null,
    ram_worker: ?RamStage.SetupCache = null,
    range_worker: ?RangeStage.SetupCache = null,
    program_worker: ?ProgramStage.SetupCache = null,
    lookup_worker: ?LookupStage.SetupCache = null,
    caller_arithmetic_worker: ?CallerArithmeticStage.SetupCache = null,
    caller_fused_worker: ?CallerFusedStage.SetupCache = null,
    native_fused_worker: ?NativeFusedStage.SetupCache = null,
    /// Set only after this session's exclusive manifest publication succeeds.
    /// The caller keeps the borrowed directory open through joined cleanup.
    open_manifest_dir: ?std.fs.Dir = null,

    /// Source/Prepared/Assembly/Base lifetimes must contain this session and
    /// every worker borrowing it. Callers use the exact same shared allocator.
    pub fn create(a: std.mem.Allocator, dir: std.fs.Dir, sources: *Sources.Owner, base: *Base.Store, profile: Parent.Profile, options: Options) !*Session {
        try options.validate();
        try sources.require();
        if (!std.meta.eql(profile.config(), sources.roster.pins.config) or
            a.ptr != sources.a.ptr or a.vtable != sources.a.vtable)
            return error.UntrustedCpuRecursivePublicationOwner;
        const self = try a.create(Session);
        self.* = .{ .a = a, .sources = sources, .base = base, .profile = profile, .options = options };
        errdefer self.deinit();
        self.word_ram = try WordCache.ForFamily(.ram_lanes, Cpu).init(a, options.max_word_template_metadata_bytes);
        self.word_range = try WordCache.ForFamily(.range16, Cpu).init(a, options.max_word_template_metadata_bytes);
        const worker_options = @import("block_v5_native_recursive_setup_cache_v1.zig").Options{ .profile = profile, .aggregate_host_byte_limit = options.max_worker_bytes, .worker_options = options.worker_options };
        inline for (worker_fields) |field| {
            const Cache = @typeInfo(@FieldType(Session, field)).optional.child;
            @field(self, field) = try Cache.init(a, worker_options);
        }
        self.ranges = try providerWriter(.range16, a, dir, sources, sources.ranges, options.providers);
        self.ranges.?.binding = .{ .store = &self.ranges.?.store };
        self.lanes = try providerWriter(.ram_lanes, a, dir, sources, sources.lanes, options.providers);
        self.lanes.?.binding = .{ .store = &self.lanes.?.store };
        self.program = try providerWriter(.program_table, a, dir, sources, @as([]const @import("block_v5_program_table_recursive_admission_v1.zig").Prepared, (&sources.program.?)[0..1]), options.providers);
        self.program.?.binding = .{ .store = &self.program.?.store };
        self.lookups = try providerWriter(.native_lookup, a, dir, sources, sources.lookups, options.providers);
        self.lookups.?.binding = .{ .store = &self.lookups.?.store };
        self.caller_arithmetic = try callerWriter(.caller_arithmetic, a, dir, sources, options.executions);
        self.caller_arithmetic.?.binding = .{ .store = &self.caller_arithmetic.?.store };
        self.caller_fused = try callerWriter(.caller_fused, a, dir, sources, options.executions);
        self.caller_fused.?.binding = .{ .store = &self.caller_fused.?.store };
        self.native_fused = try nativeWriter(a, dir, sources, options.executions);
        self.native_fused.?.binding = .{ .store = &self.native_fused.?.store };
        return self;
    }
    pub fn deinit(self: *Session) void {
        // All family callbacks join before destruction. Original request
        // coordinators/workers die before source/cache metadata or driver pool.
        inline for (worker_fields) |field| if (@field(self, field)) |*cache| cache.deinit();
        if (self.word_range) |*cache| cache.deinit();
        if (self.word_ram) |*cache| cache.deinit();
        if (self.native_fused) |*writer| writer.deinit();
        if (self.caller_fused) |*writer| writer.deinit();
        if (self.caller_arithmetic) |*writer| writer.deinit();
        if (self.lookups) |*writer| writer.deinit();
        if (self.program) |*writer| writer.deinit();
        if (self.lanes) |*writer| writer.deinit();
        if (self.ranges) |*writer| writer.deinit();
        self.a.destroy(self);
    }
    /// Called after all family/forest jobs join on an unsuccessful driver exit.
    /// Only successful writer-owned publications are eligible; pending paths
    /// and existing destinations rejected by exclusive publication survive.
    /// Cleanup needs no allocation, including when the initiating error is OOM.
    pub fn rollbackPublished(self: *Session) void {
        const Rollback = @import("block_v5_cpu_recursive_publication_rollback_v1.zig");
        inline for (.{ "ranges", "lanes", "program", "lookups", "caller_arithmetic", "caller_fused", "native_fused" }) |field| {
            if (@field(self, field)) |*writer| {
                const result = Rollback.rollbackWriter(@TypeOf(writer.*).Module, &writer.store);
                if (result.status != .complete)
                    std.debug.print("BLOCK_V5_RECURSIVE_ROLLBACK family={s} status={s} failed={d}\n", .{ field, @tagName(result.status), result.failed });
            }
        }
        if (self.open_manifest_dir) |dir| {
            dir.deleteFile("block-v5-recursive-open-leaves.pins") catch |err| switch (err) {
                error.FileNotFound => {},
                else => {
                    std.debug.print("BLOCK_V5_RECURSIVE_ROLLBACK manifest_error={s}\n", .{@errorName(err)});
                    return;
                },
            };
            self.open_manifest_dir = null;
        }
    }
    /// Observe only after all family requests have joined. Hits describe real
    /// setup acquisition; timing and whole-process memory are separate metrics.
    pub fn workerStatistics(self: *Session) [worker_fields.len]WorkerStatistics {
        var result = emptyWorkerStatistics();
        inline for (worker_fields, 0..) |field, i| if (@field(self, field)) |*cache| {
            const lane = cache.request_lane.snapshot();
            const owned = cache.budget.snapshot();
            result[i] = .{
                .family = @enumFromInt(i),
                .setup_hits = cache.stats.hits,
                .setup_misses = cache.stats.misses,
                .request_threads_started = lane.starts,
                .completed_requests = lane.completed,
                .retained_setup = cache.entry != null,
                .live_owned_bytes = owned.live_bytes,
                .peak_owned_bytes = owned.peak_live_bytes,
            };
        };
        return result;
    }
    /// Exact publication census only. This intentionally returns no verified
    /// or ClosedBlock token, and does not accept artifact-selected policies.
    pub fn requirePublished(self: *Session) !usize {
        var total: usize = 0;
        inline for (.{ "ranges", "lanes", "program", "lookups", "caller_arithmetic", "caller_fused", "native_fused" }) |field| {
            const store = &@field(self, field).?.store;
            const pins = try store.filePins(self.a);
            defer self.a.free(pins);
            total = try std.math.add(usize, total, pins.len);
        }
        return total;
    }
    /// Fixed-width OPEN transport inventory. Keys are recorded as proposals;
    /// final readers must rederive them from original base proofs and sources.
    /// No received inventory can choose source coverage or Expected policies.
    pub fn writeOpenManifest(self: *Session, dir: std.fs.Dir) ![32]u8 {
        const count = try self.requirePublished();
        const header_bytes = 76;
        const row_bytes = 80;
        const bytes = try std.math.add(usize, header_bytes, try std.math.mul(usize, count, row_bytes));
        if (bytes > self.options.max_manifest_bytes) return error.CpuRecursiveManifestResourceLimit;
        const raw = try self.a.alloc(u8, bytes);
        defer self.a.free(raw);
        @memcpy(raw[0..8], "B5RLOP01");
        std.mem.writeInt(u32, raw[8..12], std.math.cast(u32, count) orelse return error.Overflow, .little);
        @memcpy(raw[12..44], &self.sources.roster.pins.job_id);
        @memcpy(raw[44..76], &self.sources.roster.sealed.digest);
        var at: usize = header_bytes;
        inline for (.{ "ranges", "lanes", "program", "lookups", "caller_arithmetic", "caller_fused", "native_fused" }, 1..) |field, family| {
            const writer = &@field(self, field).?;
            const pins = try writer.store.filePins(self.a);
            defer self.a.free(pins);
            const policies = try writer.store.publishedPolicies(self.a);
            defer self.a.free(policies);
            for (pins, policies) |pin, policy| {
                const row = raw[at..][0..row_bytes];
                std.mem.writeInt(u32, row[0..4], @intCast(family), .little);
                std.mem.writeInt(u32, row[4..8], pin.index, .little);
                std.mem.writeInt(u64, row[8..16], pin.byte_len, .little);
                @memcpy(row[16..48], &pin.sha256);
                @memcpy(row[48..80], &policy.template.key_id);
                at += row_bytes;
            }
        }
        if (at != raw.len) return error.ChangedCpuRecursiveManifestCensus;
        const Files = @import("block_v5_artifact_files_v1.zig");
        try Files.publish(dir, "block-v5-recursive-open-leaves.pins", raw);
        self.open_manifest_dir = dir;
        return Files.hash(raw);
    }
    pub fn callerOptions(self: *Session, index: u32) !CallerPipeline.ForBackend(Cpu).Options {
        const pair = try self.sources.callers.?.get(index);
        return .{
            .arithmetic = .{ .profile = self.profile, .transcript_capacity = self.options.transcript_capacity, .on_template = self.caller_arithmetic.?.binding.callback(), .cache = &self.caller_arithmetic_worker.? },
            .fused = .{ .profile = self.profile, .transcript_capacity = self.options.transcript_capacity, .on_template = self.caller_fused.?.binding.callback(), .cache = &self.caller_fused_worker.? },
            .arithmetic_limits = pair.arithmetic.limits,
            .fused_limits = pair.fused.limits,
        };
    }
    pub fn callerSinks(self: *Session) CallerPipeline.Sinks {
        return .{ .arithmetic = self.caller_arithmetic.?.store.sink(), .fused = self.caller_fused.?.store.sink() };
    }
    pub fn fusedSink(self: *Session) @import("block_v5_native_capacity_fused_stage_v1.zig").Sink {
        return .{ .context = self, .put_fused = fused };
    }
    fn fused(raw: *anyopaque, index: u32, proof: *@import("block_v5_native_capacity_fused_proof_v1.zig").Proof) anyerror!void {
        const self: *Session = @ptrCast(@alignCast(raw));
        try @import("block_v5_proof_boundary_v1.zig").Boundary.require(self.boundary);
        const admitted = try self.sources.fusedFor(index);
        const Recursive = @import("block_v5_native_capacity_fused_recursive_stage_v1.zig").ForBackend(Cpu);
        try Recursive.publish(self.a, proof, admitted, .{ .profile = self.profile, .transcript_capacity = self.options.transcript_capacity, .on_template = self.native_fused.?.binding.callback(), .cache = &self.native_fused_worker.? }, self.native_fused.?.store.sink());
        try @import("block_v5_proof_boundary_v1.zig").Boundary.require(self.boundary);
        const sink = self.base.fusedSink();
        try sink.put_fused(sink.context, index, proof);
    }
    pub fn lanesSink(self: *Session) @import("block_v5_ram_lanes_stage_v1.zig").Sink {
        return .{ .context = self, .memory = memory, .range = range };
    }
    fn memory(raw: *anyopaque, index: u32, proof: *@import("block_v5_ram_lanes_proof_v1.zig").Proof) anyerror!void {
        const self: *Session = @ptrCast(@alignCast(raw));
        try @import("block_v5_proof_boundary_v1.zig").Boundary.require(self.boundary);
        if (index >= self.sources.lanes.len or self.sources.lanes[index].pin.index != index) return error.UnadmittedCpuRecursiveRamIndex;
        const Recursive = @import("block_v5_ram_lanes_recursive_stage_v1.zig").ForBackend(Cpu);
        try Recursive.publish(self.a, proof, &self.sources.lanes[index], .{ .profile = self.profile, .transcript_capacity = self.options.transcript_capacity, .on_template = self.lanes.?.binding.callback(), .expected_cache = &self.word_ram.?, .cache = &self.ram_worker.? }, self.lanes.?.store.sink());
        try @import("block_v5_proof_boundary_v1.zig").Boundary.require(self.boundary);
        const sink = self.base.ramLanesSink();
        try sink.memory(sink.context, index, proof);
    }
    fn range(raw: *anyopaque, index: u32, proof: *@import("block_v5_range16_proof_v1.zig").Proof) anyerror!void {
        const self: *Session = @ptrCast(@alignCast(raw));
        try @import("block_v5_proof_boundary_v1.zig").Boundary.require(self.boundary);
        if (index >= self.sources.ranges.len or self.sources.ranges[index].shard.index != index) return error.UnadmittedCpuRecursiveRangeIndex;
        const Recursive = @import("block_v5_range16_recursive_stage_v1.zig").ForBackend(Cpu);
        try Recursive.publish(self.a, proof, &self.sources.ranges[index], .{ .profile = self.profile, .transcript_capacity = self.options.transcript_capacity, .on_template = self.ranges.?.binding.callback(), .expected_cache = &self.word_range.?, .cache = &self.range_worker.? }, self.ranges.?.store.sink());
        try @import("block_v5_proof_boundary_v1.zig").Boundary.require(self.boundary);
        const sink = self.base.ramLanesSink();
        try sink.range(sink.context, index, proof);
    }
    pub fn publishProgram(self: *Session, proof: *@import("block_v5_program_table_proof_v1.zig").Proof) !void {
        try @import("block_v5_proof_boundary_v1.zig").Boundary.require(self.boundary);
        const Recursive = @import("block_v5_program_table_recursive_stage_v1.zig").ForBackend(Cpu);
        try Recursive.publish(self.a, proof, &self.sources.program.?, .{ .profile = self.profile, .transcript_capacity = self.options.transcript_capacity, .on_template = self.program.?.binding.callback(), .cache = &self.program_worker.? }, self.program.?.store.sink());
        try @import("block_v5_proof_boundary_v1.zig").Boundary.require(self.boundary);
        const sink = self.base.executionSink();
        try sink.table(sink.context, proof);
    }
    pub fn lookupSink(self: *Session) @import("block_v5_native_lookup_batch_v1.zig").Sink {
        return .{ .context = self, .accept = lookup };
    }
    fn lookup(raw: *anyopaque, index: u32, proof: *@import("block_v5_native_lookup_proof_v1.zig").Proof) anyerror!void {
        const self: *Session = @ptrCast(@alignCast(raw));
        try @import("block_v5_proof_boundary_v1.zig").Boundary.require(self.boundary);
        if (index >= self.sources.lookups.len or self.sources.lookups[index].index != index) return error.UnadmittedCpuRecursiveLookupIndex;
        const Recursive = @import("block_v5_native_lookup_recursive_stage_v1.zig").ForBackend(Cpu);
        try Recursive.publish(self.a, proof, &self.sources.lookups[index], .{ .profile = self.profile, .transcript_capacity = self.options.transcript_capacity, .on_template = self.lookups.?.binding.callback(), .cache = &self.lookup_worker.? }, self.lookups.?.store.sink());
        try @import("block_v5_proof_boundary_v1.zig").Boundary.require(self.boundary);
        const sink = self.base.providerSink();
        try sink.accept(sink.context, index, proof);
    }
};

fn providerWriter(comptime family: Providers.Family, a: std.mem.Allocator, dir: std.fs.Dir, owner: *Sources.Owner, prepared: []const ProviderDefinition.ForFamily(family).Prepared, limits: Providers.Limits) !ProviderWriter(family) {
    const M = Providers.ForFamily(family);
    const sources = try a.alloc(M.SourceAdmission, prepared.len);
    defer a.free(sources);
    for (sources, prepared) |*source, *admitted| source.* = .{ .prepared = admitted };
    return .{ .store = try M.Store.initWriterFromSources(a, dir, owner.roster, sources, limits), .binding = undefined };
}
fn callerWriter(comptime family: Executions.Family, a: std.mem.Allocator, dir: std.fs.Dir, owner: *Sources.Owner, limits: Executions.Limits) !ExecutionWriter(family) {
    const M = Executions.ForFamily(family);
    const sources = try a.alloc(M.SourceAdmission, owner.callers.?.entries.len);
    defer a.free(sources);
    for (sources, owner.callers.?.entries) |*source, entry| source.* = .{ .prepared = if (family == .caller_arithmetic) &entry.admissions.arithmetic else &entry.admissions.fused };
    return .{ .store = try M.Store.initWriterFromSources(a, dir, owner.roster, sources, limits), .binding = undefined };
}
fn nativeWriter(a: std.mem.Allocator, dir: std.fs.Dir, owner: *Sources.Owner, limits: Executions.Limits) !ExecutionWriter(.native_capacity_fused) {
    const M = Executions.ForFamily(.native_capacity_fused);
    const sources = try a.alloc(M.SourceAdmission, owner.fused.len);
    defer a.free(sources);
    for (sources, owner.fused) |*source, *admitted| source.* = .{ .prepared = admitted };
    return .{ .store = try M.Store.initWriterFromSourcesWithSelection(a, dir, owner.roster, sources, &owner.selection.?, limits), .binding = undefined };
}
