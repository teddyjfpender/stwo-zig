//! Bounded in-command CPU work that overlaps Cairo and circuit CUDA proving.
//! Both jobs retain exact captured bytes or canonical source products; neither
//! changes proof authority, request admission, or the scoring clock.
const std = @import("std");
const stwo = @import("stwo_cairo_cuda");
const cli = @import("cli.zig");
const canonical_paths = @import("canonical_paths.zig");

const Prefetched = stwo.executor.preprocessed_cache.Prefetched;
const Assets = stwo.integration.canonical_source.Assets;
const Prepared = stwo.integration.canonical_source.Prepared;
const CompileOptions = stwo.backend.runtime.execution_plan.CompileOptions;

/// An optional early read of the immutable coefficient artifact. The checked
/// loader still validates path, digest, column identities and values.
pub const FixedAssetJob = struct {
    allocator: std.mem.Allocator,
    path: []const u8,
    owned_path: ?[]u8 = null,
    thread: ?std.Thread = null,
    snapshot: ?Prefetched = null,
    failure: ?anyerror = null,

    pub fn start(self: *FixedAssetJob) !void {
        self.thread = try std.Thread.spawn(.{}, read, .{self});
    }

    /// The recursion CLI has no parsed Cairo request yet. Capture the same
    /// absolute path that canonical_paths later resolves for the proof.
    pub fn startFromEnvironment(self: *FixedAssetJob) !void {
        const path = try std.process.getEnvVarOwned(self.allocator, "STWO_CAIRO_CUDA_PREPROCESSED_COEFFICIENTS");
        errdefer self.allocator.free(path);
        if (!std.fs.path.isAbsolute(path)) return error.ArtifactPathNotAbsolute;
        self.path = path;
        try self.start();
        self.owned_path = path;
    }

    fn read(self: *FixedAssetJob) void {
        self.snapshot = Prefetched.read(self.allocator, self.path) catch |err| {
            self.failure = err;
            return;
        };
    }

    pub fn wait(self: *FixedAssetJob) !*const Prefetched {
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
        if (self.failure) |err| return err;
        if (self.snapshot) |*snapshot| return snapshot;
        return error.MissingPreprocessedPrefetch;
    }

    pub fn releaseSnapshot(self: *FixedAssetJob) void {
        if (self.thread) |thread| thread.join();
        self.thread = null;
        if (self.snapshot) |*snapshot| snapshot.deinit();
        self.snapshot = null;
    }

    pub fn deinit(self: *FixedAssetJob) void {
        self.releaseSnapshot();
        if (self.owned_path) |path| self.allocator.free(path);
        self.* = undefined;
    }
};

/// One canonical request of CPU source preparation ahead of CUDA proving.
/// It uses the same CPI admission and authenticated assets as the serial path.
pub const SourcePrepareJob = struct {
    allocator: std.mem.Allocator,
    request: cli.Prove,
    target: CompileOptions,
    assets: *const Assets,
    thread: ?std.Thread = null,
    prepared: ?Prepared = null,
    failure: ?anyerror = null,
    preparation_ns: u64 = 0,
    wait_ns: u64 = 0,
    wall: ?std.time.Timer = null,

    pub fn start(self: *SourcePrepareJob) !void {
        self.wall = try std.time.Timer.start();
        self.thread = try std.Thread.spawn(.{}, prepare, .{self});
    }

    fn prepare(self: *SourcePrepareJob) void {
        var timer = std.time.Timer.start() catch |err| {
            self.failure = err;
            return;
        };
        var paths = canonical_paths.Paths.init(
            self.allocator,
            self.request.input,
            self.request.circuit_registry,
        ) catch |err| {
            self.failure = err;
            return;
        };
        defer paths.deinit();
        self.prepared = stwo.integration.canonical_source.prepareWithAssets(
            self.allocator,
            paths.source,
            self.target,
            self.assets,
        ) catch |err| {
            self.failure = err;
            return;
        };
        self.preparation_ns = timer.read();
    }

    pub fn take(self: *SourcePrepareJob) !Prepared {
        var wait_timer = try std.time.Timer.start();
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
        if (self.failure) |err| return err;
        const prepared = self.prepared orelse return error.MissingPreparedCairoSource;
        self.prepared = null;
        self.wait_ns = wait_timer.read();
        std.debug.print("cairo-cuda source-lookahead prepare_ns={} wait_ns={} input={s}\n", .{
            self.preparation_ns, self.wait_ns, self.request.input,
        });
        return prepared;
    }

    pub fn elapsed(self: *SourcePrepareJob) u64 {
        return if (self.wall) |*timer| timer.read() else 0;
    }

    pub fn deinit(self: *SourcePrepareJob) void {
        if (self.thread) |thread| thread.join();
        if (self.prepared) |*prepared| prepared.deinit();
        self.* = undefined;
    }
};

pub fn sourceEligible(path: []const u8) bool {
    if (!std.mem.endsWith(u8, path, ".cpi")) return false;
    const stat = std.fs.cwd().statFile(path) catch return false;
    return stat.kind == .file and stat.size <= 64 << 20;
}
