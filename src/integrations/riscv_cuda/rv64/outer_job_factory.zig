//! OuterNodeJob request-layer adapter (M8 outer-job; runtime Stage A seam).
//! Outside rv64/jobs/ like outer_job_prestage.zig. One `Shared` per service
//! (resolved symbols), one `Prover` per DeviceWorker (its graph cache).
//!
//!   prove(node) = prestage (calling thread / host pool)
//!              -> OuterNodeJob submitted to the lane's worker
//!              -> completion (the worker's single event wait)
//!              -> assemble (calling thread) -> om31 prove.Produced
//!
//! The proof is the legacy controller's proof byte for byte
//! (vectors/reports/rv64-m8-20261106/outer-job/fixture-parity-01.json).
const std = @import("std");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const Prestage = @import("outer_job_prestage.zig");
const K = @import("jobs/outer_kernels.zig");
const Comp = @import("jobs/outer_composition.zig");
const NativePcs = @import("jobs/native_pcs.zig");
const Graphs = @import("jobs/outer_graph_cache.zig");
const Job = @import("jobs/outer_job.zig");
const Worker = @import("jobs/worker.zig");
const api = @import("jobs/api.zig");

pub const Shared = struct {
    kernels: K.Kernels,
    composition: Comp.Kernels,
    pcs: NativePcs.Symbols,
    wide: bool,
    graph_api: Graphs.Api,
    fs: std.DynLib,
    /// `base` = frozen base image, `addon` = libstwo-rv64-jobs.so, both owned by
    /// the caller (ops.Libraries); `fs_path` = libstwo-rv64-outer-fs-ops.so.
    pub fn init(base: *std.DynLib, addon: *std.DynLib, fs_path: []const u8) !Shared {
        var fs = try std.DynLib.open(fs_path);
        errdefer fs.close();
        const Version = *const fn () callconv(.c) u32;
        return .{
            .kernels = try K.Kernels.load(base, &fs),
            .composition = try Comp.Kernels.load(base, addon),
            .pcs = try NativePcs.Symbols.load(addon),
            .wide = if (base.lookup(Version, "stwo_rv64_pcs_request_version")) |version| version() >= 3 else false,
            .graph_api = try Graphs.Api.load(addon),
            .fs = fs,
        };
    }
    pub fn deinit(self: *Shared) void {
        self.fs.close();
        self.* = undefined;
    }
    pub fn whole(self: *const Shared) Job.Whole {
        return .{ .composition = &self.composition, .pcs = self.pcs, .wide = self.wide };
    }
};

pub const Report = struct {
    outcome: Graphs.Outcome = .direct,
    launches: u32 = 0,
    kernel_nodes: u64 = 0,
    prestage_ns: u64 = 0,
    job_ns: u64 = 0,
    assemble_ns: u64 = 0,
    receipt: api.Receipt = .{},
};

pub const Prover = struct {
    shared: *const Shared,
    worker: *Worker.Worker,
    graphs: Graphs.Cache,

    pub fn init(a: std.mem.Allocator, shared: *const Shared, worker: *Worker.Worker) Prover {
        return .{ .shared = shared, .worker = worker, .graphs = Graphs.Cache.init(a, shared.graph_api, Graphs.Policy.fromEnv()) };
    }
    pub fn deinit(self: *Prover) void {
        self.graphs.deinit();
    }

    const Done = struct {
        event: std.Thread.ResetEvent = .{},
        result: anyerror!void = {},
        receipt: api.Receipt = .{},
        fn done(raw: *anyopaque, c: api.Completion) void {
            const self: *Done = @ptrCast(@alignCast(raw));
            self.result = c.result;
            self.receipt = c.receipt;
            self.event.set();
        }
    };

    /// One node. Reentrant: concurrent callers (one per recursion lane) run
    /// their pre-stage and assembly on their own threads while the worker
    /// pipelines up to `max_outstanding` jobs, so node k+1's host preparation
    /// overlaps node k's GPU work. The graph cache is touched only by the
    /// worker thread (inside enqueue); every other shared table is locked.
    pub fn prove(self: *Prover, a: std.mem.Allocator, input: Prestage.Input, report: ?*Report) !Outer.prove.Produced {
        var timer = try std.time.Timer.start();
        const staged = try Prestage.prestage(a, input);
        defer staged.deinit();
        var r = Report{ .prestage_ns = timer.lap() };
        var job = try Job.OuterNodeJob.initWhole(staged, &self.shared.kernels, self.shared.whole());
        defer job.deinit();
        job.graphs = &self.graphs;
        var done = Done{};
        while (true) {
            self.worker.submit(job.job(), .{ .ctx = &done, .done = Done.done }) catch |err| switch (err) {
                // Mailbox occupied: the pipeline is full; back off briefly.
                error.WorkerBusy => {
                    std.Thread.sleep(50 * std.time.ns_per_us);
                    continue;
                },
                else => return err,
            };
            break;
        }
        done.event.wait();
        try done.result;
        r.job_ns = timer.lap();
        r.receipt = done.receipt;
        r.outcome = job.report.outcome;
        r.launches = job.report.launches;
        r.kernel_nodes = job.report.kernel_nodes;
        const produced = try Prestage.assemble(a, input.key, staged, &job);
        r.assemble_ns = timer.read();
        if (report) |out| out.* = r;
        return produced;
    }
};
