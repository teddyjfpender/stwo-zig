//! Receiver-owned setup cache for the RV64 GKR candidate route (block-to-inputs
//! plan, phase P1). Setup is a pure function of receiver-owned identity: the
//! running code, the pinned ELF and the request fields that shape program
//! authority, the native suite, the candidate rate and one component's
//! geometry rung. This module keeps every setup component resident across
//! blocks in one process and persists, per component, an authenticated
//! artifact that lets a later process skip both key commits.
//!
//! What an artifact holds (one file per component key):
//! - a verification-key (VK) section: the source key's suite identity, column
//!   heights and root, and the candidate fixed key's rate, identity, root,
//!   cell count and column heights. That is every value a receiver statement
//!   or transcript binds (`fixed_authority.zig`: fixed identity/root; truth
//!   statements: source root);
//! - a bulk section (prover only): the candidate tree's column descriptors,
//!   coefficients and retained Merkle layers, exactly as the sealed key holds
//!   them, plus each column's native sharing digest.
//!
//! Authority and integrity. The key of an artifact is derived from the
//! receiver's own identity, never from producer bytes. The header is
//! SHA-256-sealed, the VK section is SHA-256-bound in the header and the bulk
//! section is bound by a chunked parallel SHA-256 (`engine.chunked_sha256`),
//! so every byte that is used is checked once, in parallel. Any mismatch is a
//! hard error (fail closed), never a silent fallback. The verifier reads only
//! header + VK (a few KiB): the roots it trusts are exactly the values the
//! artifact's writer (a receiver running this code) derived. The prover's bulk
//! data cannot affect soundness: a wrong coefficient or node yields a
//! transcript an independent receiver does not reproduce. Hence the prover
//! skips the serial fixed-identity SHA-256 over every coefficient cell and the
//! native-sharing digest (both replaced by the authenticated stored values);
//! the only load-time hash is the parallel bulk digest. The trust boundary is
//! the cache directory itself: a party that can rewrite it consistently
//! (header, VK and digests) can equally replace the receiver binary, which is
//! why the code identity is the SHA-256 of the running executable.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Request = @import("../../rv64_ethereum_request.zig");
const R = @import("../services/roster.zig");
const SourceKeyModule = @import("../keccak/shared/key.zig");
const SourceKey = SourceKeyModule.Key;
const Suite = @import("../../word16_execution/pcs_suite.zig").Suite;
const Fixed = @import("../../word16_execution/fixed_setup.zig");
const Native = @import("../../word16_execution/fixed_native_cache.zig");
const M = core.fields.m31.M31;
const Coefficient = engine.poly.circle.CircleCoefficients;
const Tree = Fixed.Tree;
const Merkle = @FieldType(Tree, "commitment");
const Hash = @TypeOf(@as(Tree, undefined).root());

const MAGIC = "RV64SUC1";
const FORMAT_VERSION: u32 = 1;
const HEADER_BYTES: usize = 256;
const FLAG_BULK: u32 = 1;
const CHUNK_BYTES: usize = engine.chunked_sha256.default_chunk_bytes;
const MAX_VK_BYTES: u64 = 1 << 20;
const MAX_STRUCTURE_BYTES: u64 = 64 << 20;
const MAX_PAYLOAD_BYTES: u64 = 8 << 30;

pub const Mode = enum {
    /// Loads the bulk section (candidate trees for proving).
    prover,
    /// Loads only header + VK; restored candidate keys are root-only.
    verifier,
};

pub const Stats = struct {
    resident_hits: u64 = 0,
    disk_hits: u64 = 0,
    misses: u64 = 0,
    stores: u64 = 0,
    identity_only_sources: u64 = 0,
    load_ns: u64 = 0,
    load_bytes: u64 = 0,
    load_digest_ns: u64 = 0,
    store_ns: u64 = 0,
    store_bytes: u64 = 0,
    /// Wall time of component construction (load + build), summed over
    /// components, and the slowest one (the critical path when parallel).
    build_ns: u64 = 0,
    max_build_ns: u64 = 0,
    max_build_kind: []const u8 = "",
};

pub const Options = struct {
    mode: Mode,
    /// Absolute or cwd-relative directory; null keeps residency only.
    directory: ?[]const u8 = null,
    /// Hard limit for the resident candidate fixed keys (Fixed.Cache).
    fixed_setup_bytes: usize,
    /// Candidate-only CPU sources: interpolate, do not commit (no statement
    /// binds the CPU source root; see `SourceKey.identityOnly`).
    identity_only_cpu: bool = true,
    /// Concurrent component builds (independent pure functions); 1 = serial.
    max_build_threads: usize = 8,
    /// Producer-only scheduling: seal this component's candidate fixed tree
    /// before publishing it, overlapping other independent component builds.
    /// Fixed.Cache retains its single sealing lock and unchanged hard budget.
    eager_fixed: bool = false,
    unique_classes_first: bool = false,
    /// false: `persist` writes the VK-only artifact form (header + VK, flags 0,
    /// no structure/payload) that `.verifier` mode reads. Receiver-derived
    /// native VK tables (rv64_recursion/root_verify.zig, stream fold-v3) use it;
    /// the default keeps the prover's bulk artifacts byte for byte.
    store_bulk: bool = true,
};

const Resident = struct {
    /// Null while one thread builds it; waiters block on `Cache.built`.
    ptr: ?*anyopaque,
    type_name: []const u8,
    destroy: *const fn (std.mem.Allocator, *anyopaque) void,
    source: *const SourceKey,
    pending_store: bool,
};

pub const Cache = struct {
    allocator: std.mem.Allocator,
    mode: Mode,
    directory: ?[]u8,
    identity_only_cpu: bool,
    max_build_threads: usize,
    eager_fixed: bool = false,
    unique_classes_first: bool = false,
    store_bulk: bool = true,
    code_identity: [32]u8,
    /// Request-derived program identity; set per block by `bindRequest`.
    program_identity: ?[32]u8 = null,
    candidate: Fixed.CommitmentDescriptor,
    fixed: Fixed.Cache,
    resident: std.AutoArrayHashMapUnmanaged([32]u8, Resident) = .empty,
    stats: Stats = .{},
    /// Guards `resident` and `stats`; components build outside it.
    mutex: std.Thread.Mutex = .{},
    built: std.Thread.Condition = .{},

    pub fn init(a: std.mem.Allocator, candidate: Fixed.CommitmentDescriptor, options: Options) !Cache {
        try candidate.validate();
        if (options.eager_fixed and options.mode != .prover) return error.EagerFixedRequiresProver;
        const directory: ?[]u8 = if (options.directory) |d| try a.dupe(u8, d) else null;
        errdefer if (directory) |d| a.free(d);
        if (directory) |d| try std.fs.cwd().makePath(d);
        var fixed = try Fixed.Cache.init(a, options.fixed_setup_bytes);
        errdefer fixed.deinit();
        return .{ .allocator = a, .mode = options.mode, .directory = directory, .identity_only_cpu = options.identity_only_cpu, .max_build_threads = @max(1, options.max_build_threads), .eager_fixed = options.eager_fixed, .unique_classes_first = options.unique_classes_first, .store_bulk = options.store_bulk, .code_identity = try codeIdentity(a), .candidate = candidate, .fixed = fixed };
    }
    pub fn deinit(self: *Cache) void {
        for (self.resident.values()) |r| if (r.ptr) |ptr| r.destroy(self.allocator, ptr);
        self.resident.deinit(self.allocator);
        self.fixed.deinit();
        if (self.directory) |d| self.allocator.free(d);
        self.* = undefined;
    }
    /// Binds the receiver-pinned program fields of one block's request.
    pub fn bindRequest(self: *Cache, config: Request.Config) !void {
        self.program_identity = try programIdentity(self.allocator, config);
    }

    /// Resident component, else restored from its artifact, else built. The
    /// builder constructs `T` (which owns a `key: SourceKey`) and seals exactly
    /// one source key; the seam replaces that seal by a root-only key from the
    /// artifact or, for CPU components, an identity-only source.
    /// Thread-safe: concurrent callers for one key wait for a single build.
    pub fn obtain(self: *Cache, comptime T: type, kind: []const u8, params: anytype, program_bound: bool, builder: anytype) !*const T {
        const key = try self.componentKey(kind, params, program_bound);
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            while (self.resident.get(key)) |r| {
                if (!std.mem.eql(u8, r.type_name, @typeName(T))) return error.SetupCacheComponentTypeMismatch;
                if (r.ptr) |ptr| {
                    self.stats.resident_hits += 1;
                    return @ptrCast(@alignCast(ptr));
                }
                self.built.wait(&self.mutex);
            }
            try self.resident.put(self.allocator, key, .{ .ptr = null, .type_name = @typeName(T), .destroy = Destroy(T).run, .source = undefined, .pending_store = false });
        }
        var published = false;
        defer if (!published) {
            self.mutex.lock();
            _ = self.resident.orderedRemove(key);
            self.built.broadcast();
            self.mutex.unlock();
        };
        var local = Stats{};
        var build_timer = try std.time.Timer.start();
        var seam = Seam{ .mode = .commit };
        // Header + VK first (a few KiB): enough to arm the seam. The prover's
        // bulk candidate tree loads on a helper thread while the component
        // builds, and is adopted before this call returns.
        var restored: ?Artifact = null;
        defer if (restored) |*value| value.deinit(self.allocator);
        var bulk = BulkLoad{ .cache = self, .key = key };
        defer bulk.finish();
        if (self.directory != null) {
            var timer = try std.time.Timer.start();
            restored = try self.load(key, &local, false);
            local.load_ns += timer.read();
            if (restored != null and self.mode == .prover) bulk.thread = try std.Thread.spawn(.{ .stack_size = 16 << 20 }, BulkLoad.run, .{ &bulk, engine.work_pool.currentScopedPool() });
        }
        if (restored) |*artifact| {
            seam.mode = .{ .restore = .{ .suite_identity = artifact.vk.suite_identity, .root = artifact.vk.source_root, .logs = artifact.vk.source_logs } };
        } else if (self.identity_only_cpu and T == R.CpuSetup) seam.mode = .identity_only;
        const ptr = try self.allocator.create(T);
        errdefer self.allocator.destroy(ptr);
        SourceKeyModule.armSealSeam(.{ .ctx = &seam, .seal = Seam.seal });
        ptr.* = builder.build() catch |err| {
            SourceKeyModule.disarmSealSeam();
            return err;
        };
        SourceKeyModule.disarmSealSeam();
        errdefer ptr.deinit();
        if (seam.calls != 1) return error.SetupCacheUnexpectedSeal;
        if (restored) |*artifact| {
            // The source tag is the only route by which the root-only source
            // reaches a candidate key: adopt it before publishing the component.
            var source = artifact;
            if (bulk.thread != null) {
                bulk.join();
                inline for (@typeInfo(Stats).@"struct".fields) |f| if (comptime f.type == u64) {
                    @field(local, f.name) += @field(bulk.stats, f.name);
                };
                if (bulk.err) |err| return err;
                if (bulk.result) |*full| source = full else return error.SetupCacheArtifactRejected;
                if (!std.mem.eql(u8, &source.vk.identity, &artifact.vk.identity) or !std.mem.eql(u8, &source.vk.root, &artifact.vk.root) or !std.mem.eql(u8, &source.vk.source_root, &artifact.vk.source_root)) return error.SetupCacheArtifactRejected;
            }
            var tree_restored = try source.takeRestored(self.fixed.budgetAllocator());
            var lease = try self.fixed.adopt(&tree_restored);
            lease.deinit();
        }
        // Source authority is complete and immutable here, before publication.
        // Move the existing candidate seal earlier; FixedSet still performs
        // its normal source revalidation later. No key/profile/root changes.
        // Restored artifacts already adopted their candidate key above.
        if (self.eager_fixed and restored == null) {
            var candidate_lease = try self.fixed.acquireFromKey(&ptr.key, self.candidate);
            candidate_lease.deinit();
        }
        if (restored != null) local.disk_hits += 1 else local.misses += 1;
        if (seam.mode == .identity_only) local.identity_only_sources += 1;
        self.mutex.lock();
        defer self.mutex.unlock();
        const slot = self.resident.getPtr(key).?;
        slot.* = .{ .ptr = ptr, .type_name = @typeName(T), .destroy = Destroy(T).run, .source = &ptr.key, .pending_store = restored == null and self.directory != null };
        local.build_ns = build_timer.read();
        inline for (@typeInfo(Stats).@"struct".fields) |f| if (comptime f.type == u64 and !std.mem.eql(u8, f.name, "max_build_ns")) {
            @field(self.stats, f.name) += @field(local, f.name);
        };
        if (local.build_ns > self.stats.max_build_ns) {
            self.stats.max_build_ns = local.build_ns;
            self.stats.max_build_kind = kind;
        }
        published = true;
        self.built.broadcast();
        return ptr;
    }
    /// Runs `func(ctx, i)` for i in 0..count on up to `max_threads` threads,
    /// each bound to the caller's work pool. Returns the first error.
    pub fn parallel(count: usize, max_threads: usize, ctx: anytype, comptime func: fn (@TypeOf(ctx), usize) anyerror!void) !void {
        const Ctx = @TypeOf(ctx);
        const Shared = struct {
            ctx: Ctx,
            pool: ?*engine.work_pool.WorkPool,
            next: std.atomic.Value(usize) = .init(0),
            count: usize,
            failed: std.atomic.Value(bool) = .init(false),
            err: anyerror = error.Unexpected,
            err_mutex: std.Thread.Mutex = .{},
            fn work(shared: *@This()) void {
                var binding: ?engine.work_pool.ScopedPoolBinding = if (shared.pool) |pool| (engine.work_pool.ScopedPoolBinding.initIfNeeded(pool) catch null) else null;
                defer if (binding) |*b| b.deinit();
                while (!shared.failed.load(.acquire)) {
                    const i = shared.next.fetchAdd(1, .monotonic);
                    if (i >= shared.count) return;
                    func(shared.ctx, i) catch |e| {
                        shared.err_mutex.lock();
                        defer shared.err_mutex.unlock();
                        if (!shared.failed.load(.acquire)) shared.err = e;
                        shared.failed.store(true, .release);
                        return;
                    };
                }
            }
        };
        var shared = Shared{ .ctx = ctx, .pool = engine.work_pool.currentScopedPool(), .count = count };
        var threads: [16]std.Thread = undefined;
        var spawned: usize = 0;
        const target = @min(@min(count, max_threads), threads.len + 1);
        while (spawned + 1 < target) : (spawned += 1) {
            threads[spawned] = std.Thread.spawn(.{ .stack_size = 64 << 20 }, Shared.work, .{&shared}) catch break;
        }
        // The caller thread keeps its existing binding.
        while (!shared.failed.load(.acquire)) {
            const i = shared.next.fetchAdd(1, .monotonic);
            if (i >= count) break;
            func(ctx, i) catch |e| {
                shared.err_mutex.lock();
                if (!shared.failed.load(.acquire)) shared.err = e;
                shared.failed.store(true, .release);
                shared.err_mutex.unlock();
            };
        }
        for (threads[0..spawned]) |t| t.join();
        if (shared.failed.load(.acquire)) return shared.err;
    }

    /// Writes an artifact for every component built in this process whose
    /// candidate key now exists (after FixedSet.init). Never changes a key.
    pub fn persist(self: *Cache) !void {
        const dir_path = self.directory orelse return;
        var timer = try std.time.Timer.start();
        defer self.stats.store_ns += timer.read();
        for (self.resident.keys(), self.resident.values()) |key, *r| {
            if (!r.pending_store) continue;
            var lease = self.fixed.lookupSource(Fixed.SourceTag.of(r.source), self.candidate) orelse continue;
            defer lease.deinit();
            self.stats.store_bytes += try store(self.allocator, dir_path, key, self.code_identity, r.source, lease.key, self.store_bulk);
            self.stats.stores += 1;
            r.pending_store = false;
        }
    }

    pub fn componentKey(self: *const Cache, kind: []const u8, params: anytype, program_bound: bool) ![32]u8 {
        const encoded = try std.json.Stringify.valueAlloc(self.allocator, params, .{});
        defer self.allocator.free(encoded);
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64-gkr-setup-cache/component/v1\x00");
        h.update(&self.code_identity);
        writeU32(&h, FORMAT_VERSION);
        writeU32(&h, self.candidate.log_blowup);
        writeU32(&h, @intCast(kind.len));
        h.update(kind);
        writeU64(&h, encoded.len);
        h.update(encoded);
        if (program_bound) {
            h.update("program\x00");
            h.update(&(self.program_identity orelse return error.SetupCacheRequestUnbound));
        }
        return h.finalResult();
    }

    fn load(self: *Cache, key: [32]u8, stats: *Stats, bulk: bool) !?Artifact {
        var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const path = try artifactPath(&path_buffer, self.directory.?, key);
        const file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        defer file.close();
        return try Artifact.read(self.allocator, self.fixed.budgetAllocator(), file, key, self.code_identity, bulk, stats);
    }
};

/// One component's bulk artifact read on a helper thread.
const BulkLoad = struct {
    cache: *Cache,
    key: [32]u8,
    thread: ?std.Thread = null,
    joined: bool = false,
    result: ?Artifact = null,
    err: ?anyerror = null,
    stats: Stats = .{},
    fn run(self: *BulkLoad, pool: ?*engine.work_pool.WorkPool) void {
        var binding: ?engine.work_pool.ScopedPoolBinding = if (pool) |p| (engine.work_pool.ScopedPoolBinding.initIfNeeded(p) catch null) else null;
        defer if (binding) |*b| b.deinit();
        var timer = std.time.Timer.start() catch null;
        self.result = self.cache.load(self.key, &self.stats, true) catch |err| {
            self.err = err;
            return;
        };
        if (self.result == null) self.err = error.SetupCacheArtifactRejected;
        if (timer) |*t| self.stats.load_ns += t.read();
    }
    fn join(self: *BulkLoad) void {
        if (self.thread) |t| if (!self.joined) {
            t.join();
            self.joined = true;
        };
    }
    fn finish(self: *BulkLoad) void {
        self.join();
        if (self.result) |*r| r.deinit(self.cache.allocator);
    }
};

fn Destroy(comptime T: type) type {
    return struct {
        fn run(a: std.mem.Allocator, ptr: *anyopaque) void {
            const value: *T = @ptrCast(@alignCast(ptr));
            value.deinit();
            a.destroy(value);
        }
    };
}

const Seam = struct {
    mode: union(enum) {
        commit,
        identity_only,
        restore: struct { suite_identity: [32]u8, root: [32]u8, logs: []const u32 },
    },
    calls: usize = 0,
    fn seal(ctx: *anyopaque, a: std.mem.Allocator, columns: []const engine.pcs.ColumnEvaluation, suite: Suite, native: ?*const Native.Cache) anyerror!?SourceKey {
        const self: *Seam = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        if (self.calls != 1) return error.SetupCacheUnexpectedSeal;
        switch (self.mode) {
            .commit => return null,
            .identity_only => return try SourceKey.identityOnly(a, columns, suite, native),
            .restore => |r| {
                // Shape agreement with the columns this receiver just built.
                if (!std.mem.eql(u8, &r.suite_identity, &(try suite.identity()))) return error.SetupCacheArtifactRejected;
                const blowup = suite.config().fri_config.log_blowup_factor;
                if (r.logs.len != columns.len) return error.SetupCacheArtifactRejected;
                for (r.logs, columns) |log, column| if (log != column.log_size + blowup) return error.SetupCacheArtifactRejected;
                return try SourceKey.rootOnly(a, suite, r.root, r.logs);
            },
        }
    }
};

// ---------------------------------------------------------------------------
// Identities
// ---------------------------------------------------------------------------

/// SHA-256 of the running executable: any code or build change is a miss.
fn codeIdentity(a: std.mem.Allocator) ![32]u8 {
    const path = try std.fs.selfExePathAlloc(a);
    defer a.free(path);
    const bytes = try std.fs.cwd().readFileAlloc(a, path, 1 << 30);
    defer a.free(bytes);
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rv64-gkr-setup-cache/code/v1\x00");
    h.update(bytes);
    return h.finalResult();
}

/// Receiver-pinned request fields that shape program authority and setup.
/// Block-specific (input, expected output) and operational fields are excluded;
/// the ELF enters through its pinned SHA-256 (Image.init verifies the bytes).
fn programIdentity(a: std.mem.Allocator, c: Request.Config) ![32]u8 {
    const encoded = try std.json.Stringify.valueAlloc(a, .{
        .elf_sha256 = c.elf_sha256,
        .symbols = c.symbols,
        .terminal_pc = c.terminal_pc,
        .batch_steps = c.batch_steps,
        .max_steps = c.max_steps,
        .max_batches = c.max_batches,
        .omit_unused_arithmetic = c.omit_unused_arithmetic,
        .shared_main_arena = c.shared_main_arena,
        .control_policy = c.control_policy,
        .state_policy = c.state_policy,
        .diagnose_constraints = c.diagnose_constraints,
        .execution_profile = c.execution_profile,
        .authority_profile = Request.authorityProfile(c),
        .rom_profile = Request.romProfile(c),
    }, .{});
    defer a.free(encoded);
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rv64-gkr-setup-cache/program/v1\x00");
    h.update(encoded);
    return h.finalResult();
}

fn writeU32(h: *std.crypto.hash.sha2.Sha256, v: u32) void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .little);
    h.update(&b);
}
fn writeU64(h: *std.crypto.hash.sha2.Sha256, v: u64) void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, v, .little);
    h.update(&b);
}

fn artifactPath(buffer: []u8, directory: []const u8, key: [32]u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "{s}/{s}.rv64-setup", .{ directory, std.fmt.bytesToHex(key, .lower) });
}

// ---------------------------------------------------------------------------
// Artifact format
// ---------------------------------------------------------------------------
//
// header (256 bytes, little endian):
//   0  magic "RV64SUC1"          8  format u32            12 flags u32 (bit0 bulk)
//   16 component key [32]        48 code identity [32]
//   80 vk_len u64                88 structure_len u64     96 payload_len u64
//   104 vk SHA-256 [32]          136 bulk chunked SHA-256 [32]
//   168 chunk bytes u32          172..224 zero
//   224 SHA-256(header[0..224]) [32]
// VK: suite identity [32], source root [32], source column count u32, heights
//     u32[]; candidate log_blowup u32, identity [32], root [32], cells u64,
//     candidate column count u32, heights u32[].
// structure: column count u32; per column: height u32, coefficient log u32,
//     values_len u64, coefficient view u8, native digest [32]; layer count u32;
//     per layer: hash count u64.
// payload: per column its values then coefficients (u32 LE); then layers.

const Vk = struct {
    suite_identity: [32]u8,
    source_root: [32]u8,
    source_logs: []u32,
    log_blowup: u32,
    identity: [32]u8,
    root: [32]u8,
    cells: u64,
    candidate_logs: []u32,
    fn deinit(self: *Vk, a: std.mem.Allocator) void {
        a.free(self.source_logs);
        a.free(self.candidate_logs);
    }
    fn encode(self: Vk, a: std.mem.Allocator) ![]u8 {
        var out = std.ArrayList(u8).empty;
        errdefer out.deinit(a);
        try out.appendSlice(a, &self.suite_identity);
        try out.appendSlice(a, &self.source_root);
        try appendU32(&out, a, @intCast(self.source_logs.len));
        for (self.source_logs) |l| try appendU32(&out, a, l);
        try appendU32(&out, a, self.log_blowup);
        try out.appendSlice(a, &self.identity);
        try out.appendSlice(a, &self.root);
        try appendU64(&out, a, self.cells);
        try appendU32(&out, a, @intCast(self.candidate_logs.len));
        for (self.candidate_logs) |l| try appendU32(&out, a, l);
        return out.toOwnedSlice(a);
    }
    fn decode(a: std.mem.Allocator, bytes: []const u8) !Vk {
        var r = Reader{ .bytes = bytes };
        var vk: Vk = undefined;
        vk.suite_identity = (try r.take(32))[0..32].*;
        vk.source_root = (try r.take(32))[0..32].*;
        vk.source_logs = try r.u32s(a);
        errdefer a.free(vk.source_logs);
        vk.log_blowup = try r.u32v();
        vk.identity = (try r.take(32))[0..32].*;
        vk.root = (try r.take(32))[0..32].*;
        vk.cells = try r.u64v();
        vk.candidate_logs = try r.u32s(a);
        errdefer a.free(vk.candidate_logs);
        if (r.at != bytes.len) return error.SetupCacheArtifactRejected;
        return vk;
    }
};

const ColumnRecord = struct { height: u32, coefficient_log: u32, values_len: u64, view: bool, digest: [32]u8 };

fn appendU32(out: *std.ArrayList(u8), a: std.mem.Allocator, v: u32) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .little);
    try out.appendSlice(a, &b);
}
fn appendU64(out: *std.ArrayList(u8), a: std.mem.Allocator, v: u64) !void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, v, .little);
    try out.appendSlice(a, &b);
}

const Reader = struct {
    bytes: []const u8,
    at: usize = 0,
    fn take(self: *Reader, n: usize) ![]const u8 {
        if (n > self.bytes.len - self.at) return error.SetupCacheArtifactRejected;
        defer self.at += n;
        return self.bytes[self.at..][0..n];
    }
    fn u32v(self: *Reader) !u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .little);
    }
    fn u64v(self: *Reader) !u64 {
        return std.mem.readInt(u64, (try self.take(8))[0..8], .little);
    }
    fn u32s(self: *Reader, a: std.mem.Allocator) ![]u32 {
        const n = try self.u32v();
        if (n == 0 or n > 1 << 16) return error.SetupCacheArtifactRejected;
        const out = try a.alloc(u32, n);
        errdefer a.free(out);
        for (out) |*v| {
            v.* = try self.u32v();
            if (v.* > 30) return error.SetupCacheArtifactRejected;
        }
        return out;
    }
};

const Header = struct {
    flags: u32,
    key: [32]u8,
    code: [32]u8,
    vk_len: u64,
    structure_len: u64,
    payload_len: u64,
    vk_digest: [32]u8,
    bulk_digest: [32]u8,
    fn encode(self: Header) [HEADER_BYTES]u8 {
        var b: [HEADER_BYTES]u8 = @splat(0);
        @memcpy(b[0..8], MAGIC);
        std.mem.writeInt(u32, b[8..12], FORMAT_VERSION, .little);
        std.mem.writeInt(u32, b[12..16], self.flags, .little);
        @memcpy(b[16..48], &self.key);
        @memcpy(b[48..80], &self.code);
        std.mem.writeInt(u64, b[80..88], self.vk_len, .little);
        std.mem.writeInt(u64, b[88..96], self.structure_len, .little);
        std.mem.writeInt(u64, b[96..104], self.payload_len, .little);
        @memcpy(b[104..136], &self.vk_digest);
        @memcpy(b[136..168], &self.bulk_digest);
        std.mem.writeInt(u32, b[168..172], @intCast(CHUNK_BYTES), .little);
        var d: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(b[0..224], &d, .{});
        @memcpy(b[224..256], &d);
        return b;
    }
    fn decode(b: *const [HEADER_BYTES]u8) !Header {
        var d: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(b[0..224], &d, .{});
        if (!std.crypto.timing_safe.eql([32]u8, d, b[224..256].*)) return error.SetupCacheArtifactRejected;
        if (!std.mem.eql(u8, b[0..8], MAGIC) or std.mem.readInt(u32, b[8..12], .little) != FORMAT_VERSION or std.mem.readInt(u32, b[168..172], .little) != CHUNK_BYTES) return error.SetupCacheArtifactRejected;
        for (b[172..224]) |byte| if (byte != 0) return error.SetupCacheArtifactRejected;
        const h = Header{ .flags = std.mem.readInt(u32, b[12..16], .little), .key = b[16..48].*, .code = b[48..80].*, .vk_len = std.mem.readInt(u64, b[80..88], .little), .structure_len = std.mem.readInt(u64, b[88..96], .little), .payload_len = std.mem.readInt(u64, b[96..104], .little), .vk_digest = b[104..136].*, .bulk_digest = b[136..168].* };
        if (h.flags & ~FLAG_BULK != 0 or h.vk_len == 0 or h.vk_len > MAX_VK_BYTES or h.structure_len > MAX_STRUCTURE_BYTES or h.payload_len > MAX_PAYLOAD_BYTES) return error.SetupCacheArtifactRejected;
        return h;
    }
};

fn bulkDigest(a: std.mem.Allocator, key: [32]u8, slices: []const []const u8) ![32]u8 {
    var prefix: [64]u8 = @splat(0);
    const tag = "rv64-gkr-setup-cache/bulk/v1";
    @memcpy(prefix[0..tag.len], tag);
    @memcpy(prefix[32..64], &key);
    return engine.chunked_sha256.digest(a, &prefix, slices, CHUNK_BYTES);
}

const Artifact = struct {
    vk: Vk,
    /// Prover: restored candidate tree parts, owned by `tree_allocator`
    /// until `takeRestored` moves them into a tree.
    columns: ?[]engine.pcs.ColumnEvaluation = null,
    coefficients: ?[]Coefficient = null,
    coefficients_filled: usize = 0,
    layers: ?[][]Hash = null,
    digests: [][32]u8 = &.{},
    tree_allocator: std.mem.Allocator,

    fn deinit(self: *Artifact, a: std.mem.Allocator) void {
        const t = self.tree_allocator;
        if (self.columns) |columns| {
            for (columns) |c| if (c.values.len != 0) t.free(c.values);
            t.free(columns);
        }
        if (self.coefficients) |cs| {
            for (cs[0..self.coefficients_filled]) |*c| c.deinit(t);
            t.free(cs);
        }
        if (self.layers) |layers| Merkle.freeLayers(t, layers);
        a.free(self.digests);
        self.vk.deinit(a);
        self.* = undefined;
    }

    /// Moves the restored candidate key into Fixed.Cache adoption form.
    fn takeRestored(self: *Artifact, t: std.mem.Allocator) !Fixed.Cache.Restored {
        const pcs = suiteForIdentity(self.vk.suite_identity) orelse return error.SetupCacheArtifactRejected;
        const tree: Tree = if (self.columns) |columns| blk: {
            var built = Tree.initPrecommitted(columns, self.coefficients.?, null, null, Merkle.fromLayers(t, self.layers.?));
            built.compact_polynomials = true;
            self.columns = null;
            self.coefficients = null;
            self.layers = null;
            break :blk built;
        } else try SourceKeyModule.shapeTree(t, self.vk.root, self.vk.candidate_logs, null, null);
        return .{
            .descriptor = .{ .log_blowup = self.vk.log_blowup },
            .identity = self.vk.identity,
            .root = self.vk.root,
            .cells = self.vk.cells,
            .source = .{ .root = self.vk.source_root, .pcs = pcs, .columns = self.vk.source_logs.len },
            .tree = tree,
            .root_only = self.digests.len == 0,
            .column_digests = self.digests,
        };
    }

    fn read(a: std.mem.Allocator, t: std.mem.Allocator, file: std.fs.File, key: [32]u8, code: [32]u8, bulk: bool, stats: *Stats) !Artifact {
        var header_bytes: [HEADER_BYTES]u8 = undefined;
        if (try file.preadAll(&header_bytes, 0) != HEADER_BYTES) return error.SetupCacheArtifactRejected;
        const header = try Header.decode(&header_bytes);
        if (!std.mem.eql(u8, &header.key, &key) or !std.mem.eql(u8, &header.code, &code)) return error.SetupCacheArtifactRejected;
        const stat = try file.stat();
        const total = HEADER_BYTES + header.vk_len + header.structure_len + header.payload_len;
        if (stat.size != total or (header.flags & FLAG_BULK == 0 and (header.structure_len != 0 or header.payload_len != 0))) return error.SetupCacheArtifactRejected;
        if (bulk and header.flags & FLAG_BULK == 0) return error.SetupCacheArtifactRejected;
        const vk_bytes = try a.alloc(u8, header.vk_len);
        defer a.free(vk_bytes);
        if (try file.preadAll(vk_bytes, HEADER_BYTES) != vk_bytes.len) return error.SetupCacheArtifactRejected;
        var vk_digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(vk_bytes, &vk_digest, .{});
        if (!std.crypto.timing_safe.eql([32]u8, vk_digest, header.vk_digest)) return error.SetupCacheArtifactRejected;
        var out = Artifact{ .vk = try Vk.decode(a, vk_bytes), .tree_allocator = t };
        errdefer out.deinit(a);
        stats.load_bytes += HEADER_BYTES + header.vk_len;
        if (!bulk) return out;
        const vk = out.vk;
        const structure = try a.alloc(u8, header.structure_len);
        defer a.free(structure);
        const structure_at = HEADER_BYTES + header.vk_len;
        if (try file.preadAll(structure, structure_at) != structure.len) return error.SetupCacheArtifactRejected;
        var r = Reader{ .bytes = structure };
        const column_count = try r.u32v();
        if (column_count != vk.candidate_logs.len) return error.SetupCacheArtifactRejected;
        const records = try a.alloc(ColumnRecord, column_count);
        defer a.free(records);
        for (records, vk.candidate_logs) |*rec, height| {
            rec.* = .{ .height = try r.u32v(), .coefficient_log = try r.u32v(), .values_len = try r.u64v(), .view = (try r.take(1))[0] != 0, .digest = (try r.take(32))[0..32].* };
            if (rec.height != height or rec.coefficient_log > rec.height or rec.coefficient_log > 28 or (rec.values_len != 0 and rec.values_len != (@as(u64, 1) << @intCast(rec.height)))) return error.SetupCacheArtifactRejected;
        }
        const layer_count = try r.u32v();
        var max_height: u32 = 0;
        for (vk.candidate_logs) |h| max_height = @max(max_height, h);
        if (layer_count != max_height + 1) return error.SetupCacheArtifactRejected;
        const layer_lens = try a.alloc(u64, layer_count);
        defer a.free(layer_lens);
        var pruned: u32 = 0;
        for (layer_lens, 0..) |*len, i| {
            len.* = try r.u64v();
            if (len.* != 0 and len.* != (@as(u64, 1) << @intCast(i))) return error.SetupCacheArtifactRejected;
            if (len.* == 0) {
                if (i == 0) return error.SetupCacheArtifactRejected;
                pruned += 1;
            } else if (pruned != 0) return error.SetupCacheArtifactRejected;
        }
        if (r.at != structure.len) return error.SetupCacheArtifactRejected;
        var payload: u64 = 0;
        for (records) |rec| payload += (rec.values_len + (@as(u64, 1) << @intCast(rec.coefficient_log))) * @sizeOf(M);
        for (layer_lens) |len| payload += len * @sizeOf(Hash);
        if (payload != header.payload_len) return error.SetupCacheArtifactRejected;
        // Restored parts, read in file order: per column values then
        // coefficients, then the layers. `slices` mirrors file order.
        out.digests = try a.alloc([32]u8, column_count);
        for (out.digests, records) |*d, rec| d.* = rec.digest;
        const columns = try t.alloc(engine.pcs.ColumnEvaluation, column_count);
        for (columns, records) |*c, rec| c.* = .{ .log_size = rec.height, .values = &.{} };
        out.columns = columns;
        out.coefficients = try t.alloc(Coefficient, column_count);
        const slices = try a.alloc([]const u8, 1 + 2 * column_count + layer_count);
        defer a.free(slices);
        slices[0] = structure;
        var at: u64 = structure_at + header.structure_len;
        for (records, columns, 0..) |rec, *column, i| {
            if (rec.values_len != 0) {
                const values = try t.alloc(M, rec.values_len);
                column.values = values;
                try readAt(file, std.mem.sliceAsBytes(values), &at);
            }
            slices[1 + 2 * i] = std.mem.sliceAsBytes(column.values);
            const coeffs = try t.alloc(M, @as(usize, 1) << @intCast(rec.coefficient_log));
            out.coefficients.?[i] = Coefficient.initOwned(coeffs) catch {
                t.free(coeffs);
                return error.SetupCacheArtifactRejected;
            };
            out.coefficients_filled += 1;
            try readAt(file, std.mem.sliceAsBytes(coeffs), &at);
            if (rec.view) column.coefficient_values = coeffs;
            slices[2 + 2 * i] = std.mem.sliceAsBytes(coeffs);
        }
        const layers = try Merkle.allocateLayersPruned(t, max_height, pruned);
        out.layers = layers;
        for (layers, layer_lens, 0..) |layer, len, i| {
            if (layer.len != len) return error.SetupCacheArtifactRejected;
            const bytes = std.mem.sliceAsBytes(layer);
            try readAt(file, bytes, &at);
            slices[1 + 2 * column_count + i] = bytes;
        }
        if (at != total) return error.SetupCacheArtifactRejected;
        var timer = try std.time.Timer.start();
        const digest = try bulkDigest(a, key, slices);
        stats.load_digest_ns += timer.read();
        if (!std.crypto.timing_safe.eql([32]u8, digest, header.bulk_digest)) return error.SetupCacheArtifactRejected;
        if (!std.mem.eql(u8, std.mem.asBytes(&layers[0][0]), &vk.root)) return error.SetupCacheArtifactRejected;
        var cells: u64 = 0;
        for (out.coefficients.?) |c| cells += c.coeffs.len;
        if (cells != vk.cells) return error.SetupCacheArtifactRejected;
        stats.load_bytes += header.structure_len + header.payload_len;
        return out;
    }
};

fn readAt(file: std.fs.File, bytes: []u8, at: *u64) !void {
    if (try file.preadAll(bytes, at.*) != bytes.len) return error.SetupCacheArtifactRejected;
    at.* += bytes.len;
}

/// The PCS config of the admitted suite with this identity (validated set).
fn suiteForIdentity(id: [32]u8) ?core.pcs.PcsConfig {
    for ([_]Suite{ Suite.production(), Suite.experimentalFold4() }) |suite| {
        const known = suite.identity() catch continue;
        if (std.mem.eql(u8, &known, &id)) return suite.config();
    }
    return null;
}

fn store(a: std.mem.Allocator, directory: []const u8, key: [32]u8, code: [32]u8, source: *const SourceKey, fixed: *const Fixed.WideFixedKey, bulk: bool) !u64 {
    if (fixed.root_only) return 0;
    const tree = &fixed.tree;
    const source_logs = try a.alloc(u32, source.tree.columns.len);
    defer a.free(source_logs);
    for (source_logs, source.tree.columns) |*l, c| l.* = c.log_size;
    const candidate_logs = try a.alloc(u32, tree.columns.len);
    defer a.free(candidate_logs);
    for (candidate_logs, tree.columns) |*l, c| l.* = c.log_size;
    const vk = Vk{ .suite_identity = try source.suite.identity(), .source_root = source.root, .source_logs = source_logs, .log_blowup = fixed.descriptor.log_blowup, .identity = fixed.identity, .root = fixed.root, .cells = fixed.cells, .candidate_logs = candidate_logs };
    const vk_bytes = try vk.encode(a);
    defer a.free(vk_bytes);
    if (!bulk) return storeVkOnly(directory, key, code, vk_bytes);
    const coefficients = tree.coefficients orelse return error.MissingFixedSetupCoefficients;
    // Per-column native sharing digests, in parallel.
    const digests = try a.alloc([32]u8, coefficients.len);
    defer a.free(digests);
    parallelColumnDigests(coefficients, digests);
    var structure = std.ArrayList(u8).empty;
    defer structure.deinit(a);
    try appendU32(&structure, a, @intCast(tree.columns.len));
    for (tree.columns, coefficients, digests) |column, c, d| {
        try appendU32(&structure, a, column.log_size);
        try appendU32(&structure, a, c.log_size);
        try appendU64(&structure, a, column.values.len);
        try structure.append(a, @intFromBool(column.coefficient_values != null));
        try structure.appendSlice(a, &d);
    }
    const layers = tree.commitment.layers;
    try appendU32(&structure, a, @intCast(layers.len));
    for (layers) |layer| try appendU64(&structure, a, layer.len);
    const slices = try a.alloc([]const u8, 1 + 2 * coefficients.len + layers.len);
    defer a.free(slices);
    slices[0] = structure.items;
    var payload: u64 = 0;
    for (tree.columns, coefficients, 0..) |column, c, i| {
        slices[1 + 2 * i] = std.mem.sliceAsBytes(column.values);
        slices[2 + 2 * i] = std.mem.sliceAsBytes(c.coeffs);
        payload += slices[1 + 2 * i].len + slices[2 + 2 * i].len;
    }
    for (layers, 0..) |layer, i| {
        slices[1 + 2 * coefficients.len + i] = std.mem.sliceAsBytes(layer);
        payload += slices[1 + 2 * coefficients.len + i].len;
    }
    const header = (Header{ .flags = FLAG_BULK, .key = key, .code = code, .vk_len = vk_bytes.len, .structure_len = structure.items.len, .payload_len = payload, .vk_digest = blk: {
        var d: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(vk_bytes, &d, .{});
        break :blk d;
    }, .bulk_digest = try bulkDigest(a, key, slices) }).encode();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try artifactPath(&path_buffer, directory, key);
    var suffix: [8]u8 = undefined;
    std.crypto.random.bytes(&suffix);
    var tmp_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const tmp = try std.fmt.bufPrint(&tmp_buffer, "{s}.{s}.tmp", .{ path, std.fmt.bytesToHex(suffix, .lower) });
    {
        const file = try std.fs.cwd().createFile(tmp, .{ .exclusive = true, .mode = 0o600 });
        errdefer std.fs.cwd().deleteFile(tmp) catch {};
        defer file.close();
        try file.writeAll(&header);
        try file.writeAll(vk_bytes);
        for (slices) |slice| try file.writeAll(slice);
        try file.sync();
    }
    errdefer std.fs.cwd().deleteFile(tmp) catch {};
    try std.fs.cwd().rename(tmp, path);
    return HEADER_BYTES + vk_bytes.len + payload + structure.items.len;
}

/// VK-only artifact (flags 0): exactly what `Artifact.read(.., bulk = false)`
/// admits. Same header seal and atomic rename as the bulk form.
fn storeVkOnly(directory: []const u8, key: [32]u8, code: [32]u8, vk_bytes: []const u8) !u64 {
    var vk_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(vk_bytes, &vk_digest, .{});
    const header = (Header{ .flags = 0, .key = key, .code = code, .vk_len = vk_bytes.len, .structure_len = 0, .payload_len = 0, .vk_digest = vk_digest, .bulk_digest = @splat(0) }).encode();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try artifactPath(&path_buffer, directory, key);
    var suffix: [8]u8 = undefined;
    std.crypto.random.bytes(&suffix);
    var tmp_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const tmp = try std.fmt.bufPrint(&tmp_buffer, "{s}.{s}.tmp", .{ path, std.fmt.bytesToHex(suffix, .lower) });
    {
        const file = try std.fs.cwd().createFile(tmp, .{ .exclusive = true, .mode = 0o600 });
        errdefer std.fs.cwd().deleteFile(tmp) catch {};
        defer file.close();
        try file.writeAll(&header);
        try file.writeAll(vk_bytes);
    }
    errdefer std.fs.cwd().deleteFile(tmp) catch {};
    try std.fs.cwd().rename(tmp, path);
    return HEADER_BYTES + vk_bytes.len;
}

fn parallelColumnDigests(coefficients: []const Coefficient, out: [][32]u8) void {
    const Plan = struct {
        coefficients: []const Coefficient,
        out: [][32]u8,
        next: std.atomic.Value(usize) = .init(0),
        fn run(self: *@This()) void {
            while (true) {
                const i = self.next.fetchAdd(1, .monotonic);
                if (i >= self.out.len) return;
                self.out[i] = Native.columnDigest(self.coefficients[i]);
            }
        }
    };
    var plan = Plan{ .coefficients = coefficients, .out = out };
    if (engine.work_pool.getGlobalPool()) |pool| {
        var group: std.Thread.WaitGroup = .{};
        for (1..@min(pool.workerCount(), 16)) |_| pool.spawnWg(&group, Plan.run, .{&plan});
        plan.run();
        group.wait();
    } else plan.run();
}
