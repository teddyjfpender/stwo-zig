//! Durable original PAGE/RAM/range load adapter. Every decode uses the
//! receiver-supplied allocator and independent policies; files contain proposals.
//! Original Join freshly verifies all proofs. No VerifiedPage scalar is consumed.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const core = @import("stwo_core");
const JobModule = @import("block_v5_memory_source_page_job_v1.zig");
const Job = JobModule.ForBackend(Cpu).Job;
const Join = @import("block_v5_memory_source_page_join_owner_v1.zig");
const Page = @import("block_v5_memory_source_unified_page_proof_v1.zig");
const Codec = @import("block_v5_memory_source_unified_page_codec_v1.zig");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Inventory = @import("block_v5_memory_source_fold_inventory_owner_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
const Lane = @import("block_v5_ram_lanes_proof_v1.zig");
const Range = @import("block_v5_range16_proof_v1.zig");
const Transition = @import("block_v5_memory_source_page_transition_receiver_v1.zig");
const Bundle = @import("block_v5_cpu_bundle_store_v1.zig").ForCapacity(true);

pub const Loader = struct {
    /// All borrowed owners and immutable policies outlive the synchronous
    /// independent Join call. Reader metadata is admitted once under JobBudget;
    /// each returned proof belongs to its receiver-supplied bounded allocator.
    job: *const Job,
    reader: Bundle.Store,
    pending: ?Inventory.Owner = null,
    pending_index: ?u32 = null,
    pub fn init(job: *const Job, policies: []const Bundle.Policy, files: []const Bundle.FilePin, config: core.pcs.PcsConfig, limits: Bundle.Limits) !Loader {
        try job.requirePublished();
        if (!std.meta.eql(config, job.fold_plan.config) or policies.len != files.len) return error.UntrustedSourcePageLoaderPolicy;
        return .{ .job = job, .reader = try Bundle.Store.initReader(job.budget.allocator(), job.dir, policies, files, config, limits) };
    }
    pub fn deinit(self: *Loader) void {
        if (self.pending) |*inventory| inventory.deinit();
        self.reader.deinit();
        self.* = undefined;
    }
    pub fn requireReleased(self: *const Loader) !void {
        if (self.pending != null or self.pending_index != null) return error.SourcePageLoaderDescriptorLive;
    }
    pub fn pageLoader(self: *Loader) Join.Loader {
        return .{ .context = self, .raw = raw, .fold = fold, .fold_rows = foldRows, .release_fold_rows = releaseFoldRows, .memory = memory, .range = range };
    }
    pub fn transitionLoader(self: *Loader) Transition.Loader {
        return .{ .context = self, .native = takeBundle(.native), .fused = takeBundle(.native_fused), .caller = takeBundle(.caller), .caller_fused = takeBundle(.caller_fused), .program = program };
    }
    fn cast(context: *anyopaque) *Loader {
        return @ptrCast(@alignCast(context));
    }
    fn readArtifact(self: *Loader, a: std.mem.Allocator, comptime kind: Semantic.Kind, index: u32) ![]u8 {
        const context = &self.job.context.?;
        const records = if (kind == .raw) self.job.raws else self.job.folds;
        if (index >= records.len) return error.UnadmittedSourcePageLoaderIndex;
        const artifact = records[index].artifact orelse return error.IncompleteSourcePageJobPublication;
        const independent_identity = try Page.ForKind(kind).identity(context, records[index].pin, self.job.limits.proof);
        if (artifact.kind != kind or artifact.index != index or !std.meta.eql(artifact.source_seal, context.sealed.digest) or
            !std.meta.eql(artifact.premix_identity, independent_identity)) return error.UntrustedSourcePageLoaderPolicy;
        var path: [96]u8 = undefined;
        return Files.readPinned(a, self.job.dir, try JobModule.name(&path, kind, index, true), artifact.byte_len, artifact.sha256, self.job.limits.artifact.max_artifact_bytes);
    }
    fn raw(context: *anyopaque, a: std.mem.Allocator, index: u32) !JobModule.RawPage.Proof {
        const self = cast(context);
        const bytes = try self.readArtifact(a, .raw, index);
        defer a.free(bytes);
        return Codec.ForKind(.raw).decodeProposal(a, bytes, &self.job.context.?, self.job.raws[index].pin, &.{}, self.job.limits.proof, self.job.limits.artifact);
    }
    fn fold(context: *anyopaque, a: std.mem.Allocator, index: u32) !JobModule.FoldPage.Proof {
        const self = cast(context);
        if (self.pending_index == null or self.pending_index.? != index or self.pending == null) return error.UntrustedSourcePageLoaderInventory;
        const bytes = try self.readArtifact(a, .fold, index);
        defer a.free(bytes);
        return Codec.ForKind(.fold).decodeProposal(a, bytes, &self.job.context.?, self.job.folds[index].pin, self.pending.?.rows, self.job.limits.proof, self.job.limits.artifact);
    }
    fn foldRows(context: *anyopaque, a: std.mem.Allocator, index: u32, maximum: u32) ![]Semantic.FoldRow {
        const self = cast(context);
        if (self.pending != null or self.pending_index != null or index >= self.job.folds.len) return error.UntrustedSourcePageLoaderInventory;
        const record = self.job.folds[index];
        if (record.pin.page.count != maximum or maximum > 4096) return error.UntrustedSourcePageLoaderInventory;
        var path: [96]u8 = undefined;
        const inventory = try Inventory.load(a, self.job.dir, try JobModule.name(&path, .fold, index, false), record.pin, record.stored, self.job.limits.proof.fold);
        self.pending = inventory;
        self.pending_index = index;
        return inventory.rows;
    }
    fn releaseFoldRows(context: *anyopaque, a: std.mem.Allocator, rows: []const Semantic.FoldRow) void {
        const self = cast(context);
        if (self.pending) |*inventory| {
            inventory.requireRelease(a, rows);
            inventory.deinit();
        } else @panic("source PAGE descriptor release without owner");
        self.pending = null;
        self.pending_index = null;
    }
    fn takeBundle(comptime family: Bundle.Family) *const fn (*anyopaque, std.mem.Allocator, u32) anyerror!Bundle.ProofFor(family) {
        return struct {
            fn take(context: *anyopaque, a: std.mem.Allocator, index: u32) !Bundle.ProofFor(family) {
                const self = cast(context);
                return self.reader.takeWithAllocator(a, family, index);
            }
        }.take;
    }
    fn program(context: *anyopaque, a: std.mem.Allocator) !Bundle.ProofFor(.rom) {
        return takeBundle(.rom)(context, a, 0);
    }
    fn memory(context: *anyopaque, a: std.mem.Allocator, index: u32) !Lane.Proof {
        return takeBundle(.ram_lanes)(context, a, index);
    }
    fn range(context: *anyopaque, a: std.mem.Allocator, index: u32) !Range.Proof {
        return takeBundle(.range16)(context, a, index);
    }
};
