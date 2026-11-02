//! Explicit frozen-family A/B for coefficient combination only. No FFT/PCS claim.
const std = @import("std");
const M = @import("stwo_core").fields.m31.M31;
const New = @import("pcs/quotients/combined_setup_family.zig");
const Old = @import("baseline");
const Pools = @import("work_pool.zig");
fn bench(comptime D: usize, workers: usize, mixed: bool) !void {
    const View = struct { coordinates: [D][]M };
    const N = New.ForCoordinates(D, View);
    const B = Old.ForCoordinates(D, View);
    const a = std.heap.page_allocator;
    const rows = 32768;
    const n_members = 64;
    var pool: Pools.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = 1024 * 1024 });
    defer pool.deinit();
    var binding = try Pools.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    // The explicit old-source module owns a separate TLS pool namespace.
    // Bind its own identically-sized pool so it cannot lazily use all cores.
    var old_pool: Old.Pools.WorkPool = undefined;
    try old_pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = 1024 * 1024 });
    defer old_pool.deinit();
    var old_binding = try Old.Pools.ScopedPoolBinding.init(&old_pool);
    defer old_binding.deinit();
    var sources: [n_members][]M = undefined;
    var old_members: [n_members]B.Member = undefined;
    var new_members: [n_members]N.Member = undefined;
    for (&sources, &old_members, &new_members, 0..) |*source, *om, *nm, i| {
        const len: usize = if (mixed and i % 11 == 0) rows / 2 else rows;
        source.* = try a.alloc(M, len);
        for (source.*, 0..) |*v, j| v.* = if (j % 17 == 0) M.one().neg() else M.fromCanonical(@intCast((i * 7919 + j * 977 + 3) % 1048573));
        var cs: [D]M = undefined;
        for (&cs, 0..) |*v, j| v.* = M.fromCanonical(@intCast((i * 631 + j * 1777 + 7) % 1048573));
        const view = if (mixed) i % 2 else i / (n_members / 2);
        om.* = .{ .source = source.*, .coefficients = cs, .view_index = view };
        nm.* = .{ .source = source.*, .coefficients = cs, .view_index = view };
    }
    defer for (sources) |s| a.free(s);
    var old_views: [2]View = undefined;
    var new_views: [2]View = undefined;
    for (&old_views, &new_views) |*ov, *nv| for (&ov.coordinates, &nv.coordinates) |*oc, *nc| {
        oc.* = try a.alloc(M, rows);
        nc.* = try a.alloc(M, rows);
    };
    defer for (old_views, new_views) |ov, nv| for (ov.coordinates, nv.coordinates) |oc, nc| {
        a.free(oc);
        a.free(nc);
    };
    // Exact coverage of the checked branch for this deterministic fixture.
    var grouped_cells: usize = 0;
    var all_cells: usize = 0;
    var start: usize = 0;
    while (start < rows) : (start += New.CHUNK_ROWS) {
        const end = @min(start + New.CHUNK_ROWS, rows);
        var at: usize = 0;
        while (at < n_members) {
            const member = new_members[at];
            var eligible = n_members - at >= 4;
            if (eligible) for (new_members[at..][0..4]) |candidate| {
                eligible = eligible and candidate.view_index == member.view_index and candidate.source.len >= end;
            };
            if (eligible) {
                grouped_cells += 4 * (end - start);
                all_cells += 4 * (end - start);
                at += 4;
            } else {
                if (member.source.len > start) all_cells += @min(end, member.source.len) - start;
                at += 1;
            }
        }
    }
    const w = std.fs.File.stdout().deprecatedWriter();
    for (0..6) |sample| {
        var timer = try std.time.Timer.start();
        var old_ns: u64 = undefined;
        var new_ns: u64 = undefined;
        if (sample % 2 == 0) {
            try B.combine(a, &old_views, &old_members);
            old_ns = timer.lap();
            try N.combine(a, &new_views, &new_members);
            new_ns = timer.read();
        } else {
            try N.combine(a, &new_views, &new_members);
            new_ns = timer.lap();
            try B.combine(a, &old_views, &old_members);
            old_ns = timer.read();
        }
        for (old_views, new_views) |ov, nv| for (ov.coordinates, nv.coordinates) |oc, nc| {
            for (oc, nc) |x, y| if (!x.eql(y)) return error.CombinationMismatch;
        };
        try w.print("{{\"coordinates\":{d},\"workers\":{d},\"mixed_views_partial\":{},\"sample\":{d},\"old_ns\":{d},\"dot4_ns\":{d},\"grouped_cells\":{d},\"all_cells\":{d},\"exact\":true}}\n", .{ D, workers, mixed, sample, old_ns, new_ns, grouped_cells, all_cells });
    }
}
pub fn main() !void {
    inline for (.{ 4, 8 }) |d| for ([_]usize{ 1, 8 }) |workers| {
        try bench(d, workers, false);
        try bench(d, workers, true);
    };
}
