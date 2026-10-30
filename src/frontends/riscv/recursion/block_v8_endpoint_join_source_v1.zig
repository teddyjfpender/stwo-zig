//! Finite original verifier families admitted to the one-DAG endpoint root.
const std = @import("std");
const L = @import("block_v8_endpoint_recursive_adapter_v1.zig").For(.local_open);
const Mixed = @import("block_v8_endpoint_mixed_recursive_v1.zig");
const B = @import("block_v8_endpoint_bridge_recursive_v1.zig");
const C = @import("block_v8_compact_ram_recursive_v1.zig");
pub const Kind = enum { local, bridge, global, mixed };
pub fn Adapter(comptime kind: Kind) type {
    return switch (kind) {
        .local => L,
        .mixed => Mixed,
        .bridge => B,
        .global => C,
    };
}
pub const Value = L.Public.Values;
pub const RawWire = L.Public.Wire;
pub const Source = union(Kind) {
    local: *const L.Profile.Owned,
    bridge: *const B.Profile.Owned,
    global: *const C.Profile.Owned,
    mixed: *const Mixed.Profile.Owned,
    pub fn values(self: Source, a: std.mem.Allocator) !Value {
        return switch (self) {
            inline else => |p, k| blk: {
                const v = try Adapter(k).Public.reconstruct(a, p);
                break :blk .{ .allocator = v.allocator, .template = v.template, .statement = v.statement, .public = v.public, .roots_count = v.roots_count };
            },
        };
    }
    pub fn cold(self: Source, a: std.mem.Allocator) !Cold {
        return switch (self) {
            inline else => |p, k| blk: {
                var c = try Adapter(k).Fixed.Owned.derive(a, p, 4, .{});
                errdefer c.deinit();
                const wires = try a.alloc(RawWire, c.wires.len);
                for (wires, c.wires) |*w, v| w.* = convert(v);
                c.allocator.free(c.wires);
                break :blk .{ .allocator = c.allocator, .wire_allocator = a, .budget = c.budget, .fixed = c.fixed, .wires = wires, .context = c.context, .namespace = c.namespace };
            },
        };
    }
    pub fn prepare(self: Source, a: std.mem.Allocator, capture: Capture) !Live {
        return switch (self) {
            inline else => |p, k| blk: {
                if (std.meta.activeTag(capture) != k) return error.JoinCaptureFamilyMismatch;
                var v = try Adapter(k).Preparation.prepare(a, p, @field(capture, @tagName(k)), 4, .{});
                errdefer v.deinit();
                const wires = try a.alloc(RawWire, v.wires.len);
                for (wires, v.wires) |*w, want| w.* = convert(want);
                v.allocator.free(v.wires);
                v.values.deinit();
                break :blk .{ .allocator = a, .budget = v.budget, .recursive = v.recursive, .wires = wires };
            },
        };
    }
    pub fn seal(self: Source) [32]u8 {
        return switch (self) {
            inline else => |p| p.seal,
        };
    }
};
pub const Capture = union(Kind) { local: *const L.Original.VerifiedCapture, bridge: *const B.Original.VerifiedCapture, global: *const C.Original.VerifiedCapture, mixed: *const Mixed.Original.VerifiedCapture };
pub const Cold = struct {
    allocator: std.mem.Allocator,
    wire_allocator: std.mem.Allocator,
    budget: *@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
    fixed: @import("air/blake3_parent_row_storage.zig").FixedTuple(false),
    wires: []RawWire,
    context: @import("blake3_execution_parent_protocol.zig").Context,
    namespace: @import("air/block_v5_recursive_fixed_namespace_v1.zig").Plan,
    pub fn deinit(self: *Cold) void {
        inline for (0..@import("air/blake3_parent_row_storage.zig").Airs.len) |i| self.allocator.free(self.fixed[i]);
        self.wire_allocator.free(self.wires);
        self.namespace.deinit();
        self.budget.destroy();
        self.* = undefined;
    }
};
pub const Live = struct {
    allocator: std.mem.Allocator,
    budget: *@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
    recursive: @import("blake3_execution_parent_preparation.zig").Prepared,
    wires: []RawWire,
    pub fn deinit(v: *Live) void {
        v.recursive.deinit();
        v.allocator.free(v.wires);
        v.budget.destroy();
        v.* = undefined;
    }
};
fn convert(v: anytype) RawWire {
    return .{ .circuit = v.circuit, .wire = v.wire, .uses = v.uses, .source = @enumFromInt(@intFromEnum(v.source)), .coordinate = v.coordinate };
}
/// Receiver-selected metadata factories. No producer verifier-key field exists.
pub const Admission = union(Kind) {
    local: struct { statement: *const L.Statement.Owned, claims: L.Ledger.Claims },
    bridge: struct { statement: *const B.Statement.Owned, claims: B.Ledger.Claims },
    global: struct { statement: *const C.Statement.Owned, claims: C.Ledger.Claims },
    mixed: struct { statement: *const Mixed.Statement.Owned, claims: Mixed.Ledger.Claims },
    pub fn derive(v: Admission, a: std.mem.Allocator) !Source {
        return switch (v) {
            inline else => |input, k| @unionInit(Source, @tagName(k), try Adapter(k).Profile.Owned.derive(a, input.statement, input.claims, .{})),
        };
    }
};
pub fn deinitProfile(v: Source) void {
    switch (v) {
        inline else => |p| @constCast(p).deinit(),
    }
}

/// Jobs own independent preparation budgets, recorder TLS and serial local pools.
/// Results are transferred in original source order only after every job joins.
pub const Batch = struct {
    allocator: std.mem.Allocator,
    entries: []Live,
    pub fn deinit(v: *Batch) void {
        for (v.entries) |*entry| entry.deinit();
        v.allocator.free(v.entries);
        v.* = undefined;
    }
};
const PrepareJob = struct {
    allocator: std.mem.Allocator,
    source: Source,
    capture: Capture,
    result: ?Live = null,
    failure: ?anyerror = null,
    fn run(job: *PrepareJob) void {
        job.result = job.runOwned() catch |err| {
            job.failure = err;
            return;
        };
    }
    fn runOwned(job: *PrepareJob) !Live {
        const Engine = @import("stwo_prover_engine");
        var pool: Engine.work_pool.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{ .worker_count = 1, .backing_allocator = job.allocator });
        defer pool.deinit();
        var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        return job.source.prepare(job.allocator, job.capture);
    }
};
pub fn prepareBatch(a: std.mem.Allocator, sources: []const Source, captures: []const Capture, workers: u8) !Batch {
    if (sources.len != captures.len or workers == 0 or workers > 4) return error.InvalidEndpointJoinWorkers;
    const entries = try a.alloc(Live, sources.len);
    errdefer a.free(entries);
    var completed: usize = 0;
    errdefer for (entries[0..completed]) |*entry| entry.deinit();
    if (workers == 1) {
        for (sources, captures, 0..) |source, capture, i| {
            entries[i] = try source.prepare(a, capture);
            completed += 1;
        }
        return .{ .allocator = a, .entries = entries };
    }
    var first: usize = 0;
    while (first < sources.len) {
        const n = @min(@as(usize, workers), sources.len - first);
        var jobs: [4]PrepareJob = undefined;
        var threads: [4]std.Thread = undefined;
        var launched: usize = 0;
        for (0..n) |i| {
            jobs[i] = .{ .allocator = a, .source = sources[first + i], .capture = captures[first + i] };
            threads[i] = std.Thread.spawn(.{ .stack_size = @import("stwo_prover_engine").work_pool.WORKER_STACK_SIZE }, PrepareJob.run, .{&jobs[i]}) catch |err| {
                for (threads[0..launched]) |thread| thread.join();
                for (jobs[0..launched]) |*job| if (job.result) |*result| result.deinit();
                return err;
            };
            launched += 1;
        }
        for (threads[0..n]) |thread| thread.join();
        var failure: ?anyerror = null;
        for (jobs[0..n]) |job| if (job.failure) |err| {
            if (failure == null) failure = err;
        };
        if (failure) |err| {
            for (jobs[0..n]) |*job| if (job.result) |*result| result.deinit();
            return err;
        }
        for (jobs[0..n], 0..) |*job, i| {
            entries[first + i] = job.result.?;
            job.result = null;
            completed += 1;
        }
        first += n;
    }
    return .{ .allocator = a, .entries = entries };
}
