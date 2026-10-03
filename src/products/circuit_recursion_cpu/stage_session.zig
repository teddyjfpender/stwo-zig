//! Share the authenticated AIR, canonical circuit, and worker pool across
//! independent bounded fold stages in one process.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const circuit_cpu = @import("stwo_circuit_cpu_integration");
const wire = @import("stwo_circuit_recursion_wire");
const prover = @import("stwo_prover_engine");
const assets = @import("assets.zig");
const stage = @import("stage.zig");
const recursion = circuit_cpu.recursion;

pub const Session = struct {
    allocator: std.mem.Allocator,
    provers: *const circuit_cpu.prove.Provers,
    source: ?recursion.proof_source.Source,
    air: assets.Air,
    table: circuit.air_eval.component_table.Table,
    bundle: circuit_cpu.air.Bundle,
    topologies: recursion.canonical.Cache,
    device_canonical: ?recursion.CanonicalCircuit,
    canonical: *const recursion.CanonicalCircuit,
    pool: prover.work_pool.WorkPool,
    binding: prover.work_pool.ScopedPoolBinding,

    /// Initialize in place because the evaluator table borrows `air` and the
    /// binding borrows `pool`. A returned-by-value session would move them.
    pub fn initInPlace(
        self: *Session,
        allocator: std.mem.Allocator,
        registry: wire.registry.CircuitRegistry,
        provers: *const circuit_cpu.prove.Provers,
        source: ?recursion.proof_source.Source,
    ) !void {
        self.allocator = allocator;
        self.provers = provers;
        self.source = source;
        self.air = try assets.Air.init(allocator);
        errdefer self.air.deinit();
        self.table = try self.air.circuitTable(allocator);
        errdefer self.table.deinit();
        self.bundle = try assets.airBundle(allocator);
        errdefer self.bundle.deinit();
        self.topologies = recursion.canonical.Cache.init(allocator, .{});
        errdefer self.topologies.deinit();
        self.device_canonical = null;
        if (source != null) {
            self.device_canonical = try recursion.CanonicalCircuit.buildForDevice(allocator, &self.table, registry);
            self.canonical = &self.device_canonical.?;
        } else {
            self.canonical = try recursion.canonical.acquire(allocator, &self.topologies, &self.table, registry, recursion.fold.default_options);
        }
        errdefer if (self.device_canonical) |*item| item.deinit(allocator);
        try self.pool.initInPlace();
        errdefer self.pool.deinit();
        self.binding = try prover.work_pool.ScopedPoolBinding.init(&self.pool);
    }

    pub fn deinit(self: *Session) void {
        self.binding.deinit();
        self.pool.deinit();
        if (self.device_canonical) |*item| item.deinit(self.allocator);
        self.topologies.deinit();
        self.bundle.deinit();
        self.table.deinit();
        self.air.deinit();
        self.* = undefined;
    }

    pub fn run(self: *Session, inputs: []const stage.Input, terminal_root: bool) !stage.Files {
        if (inputs.len < 2 or inputs.len > 256) return error.InvalidFoldStageSize;
        var timer = try std.time.Timer.start();
        var packed_arena = std.heap.ArenaAllocator.init(self.allocator);
        defer packed_arena.deinit();
        var packed_safe = std.heap.ThreadSafeAllocator{ .child_allocator = packed_arena.allocator() };
        const fold: recursion.Fold = .{
            .canonical = self.canonical,
            .table = &self.table,
            .bundle = &self.bundle,
            .options = recursion.fold.default_options,
            .provers = self.provers,
            .source = self.source,
            .packed_allocator = packed_safe.allocator(),
        };
        return stage.run(self.allocator, &fold, inputs, 1, terminal_root, &timer, 0);
    }
};
