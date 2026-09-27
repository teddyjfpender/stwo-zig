//! Retains real production bodies without invoking a device or STARK.
const std = @import("std");
const core = @import("stwo_core");
const Backend = @import("backends/metal/commit_backend.zig").MetalCommitBackend;
const Replay = @import("frontends/riscv/prover/block_v5_ram_lanes_replay_v1.zig");
const Stage = @import("frontends/riscv/prover/block_v5_ram_lanes_stage_v1.zig");
const Seal = @import("frontends/riscv/prover/block_v5_source_seal_v1.zig");
const Planning = @import("frontends/riscv/prover/block_v5_ram_lanes_replay_plan_v1.zig");
const Production = Replay.ForBackend(Backend);
fn collect(a: std.mem.Allocator, sorted: Replay.SortedSource, total: u64, limits: Planning.Limits, config: core.pcs.PcsConfig, resources: Replay.Resources) anyerror!Production {
    return Production.collect(a, sorted, total, limits, config, resources);
}
fn prove(first: *const Stage.ForBackend(Backend), a: std.mem.Allocator, source: Stage.Source, sink: Stage.Sink, pins: Seal.Pins, entries: []const Seal.Entry, sealed: Seal.Sealed) anyerror!void {
    return first.prove(a, source, sink, pins, entries, sealed.digest, sealed);
}
fn open(production: *const Production, sorted: Replay.SortedSource) anyerror!Production.TraceLease {
    return production.openTraceSource(sorted);
}
export fn stwo_ram_lanes_metal_producer_body_gate() void {
    std.mem.doNotOptimizeAway(&collect);
    std.mem.doNotOptimizeAway(&prove);
    std.mem.doNotOptimizeAway(&open);
}
