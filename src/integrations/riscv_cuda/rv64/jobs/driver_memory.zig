//! One two-phase memory plan per GPU (rv64-m8-gpu-native.md §3.7).
//!
//! Regions in `gpu_native.RegionKind` order. Fixed at install; the only
//! request-path change is the phase boundary, which moves the arena's top
//! over the main_resident region once a GPU's last Stage 2 freed its MAIN
//! (stream-ordered on that GPU, see worker.installPlanArena / Batch phase_b):
//!
//!   phase A:  [ arena_A ............ | main_resident ]   Stage1/2, truths, early leaves
//!   phase B:  [ arena_B = arena_A + main_resident    ]   folds, root
//!
//! Device allocations at install: ONE block per GPU (arena_A + main_resident;
//! the worker owns it) and the request slab segments (2 parities). The class
//! cache is the worker's persistent pool plus whatever the factories' warm
//! built; graph_exec and reserve are accounting only. Nothing on the request
//! path allocates device memory (D1 asserts it on the host model).
const std = @import("std");
const G = @import("gpu_native.zig");

pub const granule: u64 = 64; // worker.Arena.granule

/// Defaults [default, carried from today's code; not tuned in this pass]:
/// reserve 1 GiB (worker CUDA/driver headroom), graph budget 256 MiB/worker
/// (outer_graph_cache default).
pub const default_reserve_words: u64 = (1 << 30) / 4;
pub const default_graph_exec_words: u64 = (256 << 20) / 4;

pub const Inputs = struct {
    device: u32,
    capacity_words: u64,
    class_cache_words: u64 = 0,
    graph_exec_words: u64 = default_graph_exec_words,
    /// MAIN of every segment placed on this GPU (class constants).
    main_resident_words: u64 = 0,
    /// Largest arena peak of a phase-A job on this GPU (class plans).
    phase_a_peak_words: u64 = 0,
    /// Largest arena peak of a phase-B job on this GPU.
    phase_b_peak_words: u64 = 0,
    /// One request slab segment (the plan holds two: pipelined parities).
    slab_words: u64,
    reserve_words: u64 = default_reserve_words,
    /// Cap the arena (0 = everything left). Tests and shared hosts.
    arena_cap_words: u64 = 0,
};

pub const Planned = struct {
    memory: G.MemoryPlan,
    phase_a_words: u64,
    phase_b_words: u64,
    slab_words: u64,
    pub fn mainResidentWords(self: Planned) u64 {
        return self.phase_b_words - self.phase_a_words;
    }
};

pub fn plan(in: Inputs) !Planned {
    const main = std.mem.alignForward(u64, in.main_resident_words, granule);
    const slab = std.mem.alignForward(u64, in.slab_words, granule);
    const fixed = in.class_cache_words + in.graph_exec_words + main + 2 * slab + in.reserve_words;
    if (fixed >= in.capacity_words) return error.GpuNativeMemoryPlanExceedsDevice;
    var arena = std.mem.alignBackward(u64, in.capacity_words - fixed, granule);
    if (in.arena_cap_words != 0) arena = @min(arena, std.mem.alignBackward(u64, in.arena_cap_words, granule));
    if (arena == 0) return error.GpuNativeMemoryPlanNoArena;
    if (in.phase_a_peak_words > arena) return error.GpuNativeMemoryPlanPhaseA;
    if (in.phase_b_peak_words > arena + main) return error.GpuNativeMemoryPlanPhaseB;
    var m = G.MemoryPlan{ .device = in.device, .capacity_words = in.capacity_words };
    m.set(.class_cache, in.class_cache_words);
    m.set(.graph_exec, in.graph_exec_words);
    m.set(.main_resident, main);
    m.set(.arena, arena);
    m.set(.truth, 0); // truth jobs are arena classes with measured peaks
    m.set(.exchange_slab, 2 * slab);
    m.set(.reserve, in.reserve_words);
    try m.validate();
    return .{ .memory = m, .phase_a_words = arena, .phase_b_words = arena + main, .slab_words = slab };
}

/// Sequential main_resident views per segment on one GPU (segment order).
pub fn mainViews(region_words: u64, segment_main_words: []const u64, out_offsets: []u64) !void {
    var at: u64 = 0;
    for (segment_main_words, out_offsets) |w, *o| {
        o.* = at;
        at += std.mem.alignForward(u64, w, granule);
        if (at > region_words) return error.GpuNativeMainResidentOverflow;
    }
}

const testing = std.testing;
const GiB: u64 = (1 << 30) / 4;

test "plan: 24628607-shaped dev0: a fold plus a staged leaf fits only in phase B" {
    // [M] sizes from the inventory: class cache ~3.1 GB, MAIN 4.15 GB on dev0,
    // fold/root peak 21.8 GB, leaf peak 18.2 GB; 32 GB card, 1 GiB reserve.
    const p = try plan(.{ .device = 0, .capacity_words = 32 * GiB, .class_cache_words = 31 * GiB / 10, .main_resident_words = 415 * GiB / 100, .phase_a_peak_words = 182 * GiB / 10, .phase_b_peak_words = 218 * GiB / 10, .slab_words = (24 << 20) / 4 });
    // fold peak 21.8 GB [M] + smallest staged leaf 3.1 GB [M] = 24.9 GB [D]:
    // above phase A (~23.4 GB [D]), inside phase B (~27.6 GB [D]).
    const pair = 218 * GiB / 10 + 31 * GiB / 10;
    try testing.expect(p.phase_a_words < pair);
    try testing.expect(p.phase_b_words >= pair);
    try testing.expectEqual(p.memory.get(.main_resident), p.mainResidentWords());
    try testing.expectEqual(p.memory.offset(.arena), p.memory.get(.class_cache) + p.memory.get(.graph_exec) + p.memory.get(.main_resident));
    try testing.expect(p.memory.total() <= p.memory.capacity_words);
}

test "plan: fails closed on each region" {
    try testing.expectError(error.GpuNativeMemoryPlanExceedsDevice, plan(.{ .device = 0, .capacity_words = GiB, .slab_words = 64 }));
    try testing.expectError(error.GpuNativeMemoryPlanPhaseA, plan(.{ .device = 0, .capacity_words = 8 * GiB, .phase_a_peak_words = 8 * GiB, .slab_words = 64 }));
    try testing.expectError(error.GpuNativeMemoryPlanPhaseB, plan(.{ .device = 0, .capacity_words = 8 * GiB, .main_resident_words = GiB, .phase_b_peak_words = 8 * GiB, .slab_words = 64 }));
    var offsets: [3]u64 = undefined;
    try mainViews(192, &.{ 64, 64, 64 }, &offsets);
    try testing.expectEqual(@as(u64, 128), offsets[2]);
    try testing.expectError(error.GpuNativeMainResidentOverflow, mainViews(190, &.{ 64, 64, 64 }, &offsets));
}
