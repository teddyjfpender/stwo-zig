//! Cold shape/mask accounting, not a model of simultaneous RSS or hash work.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const K = A.crypto.keccak;
const B = K.word16_bridge;
const G = @import("../../protocol.zig");
const Components = @import("../../../word16_execution/components.zig").Components;
const Case = @import("fixture.zig").Case;
const Q = G.Q;
pub const Totals = struct { native_source_cells: [3]u64 = @splat(0), component_oods_q_samples: u64 = 0 };
pub const Report = struct { scope: []const u8, shared: Totals, local_control_model: Totals, truth: Totals, native_permutation_rows: usize, control_permutation_rows: usize, physical_proofs_shared: u32 = 3, physical_proofs_control: u32 = 2, note: []const u8 };
fn addCells(out: *Totals, widths: [3]usize, log: u32) void {
    for (widths, 0..) |width, tree| out.native_source_cells[tree] += @as(u64, @intCast(width)) * (@as(u64, 1) << @intCast(log));
}
fn masks(a: std.mem.Allocator, c: core.air.components.Component) !u64 {
    var p = try c.maskPoints(a, .{ .x = Q.one(), .y = Q.zero() }, 16);
    defer p.deinit(a);
    var count: u64 = 0;
    for (p.items) |tree| for (tree) |column| {
        count += column.len;
    };
    return count;
}
pub fn measure(a: std.mem.Allocator, c: *const Case) !Report {
    var shared = Totals{};
    var channel = G.T.P.Channel{};
    const ch = G.Old.draw(&channel);
    const kc = K.equations.Challenges.draw(&channel);
    for (c.setups, c.bundle.cpus) |setup, encoded| {
        for (setup.materials.shapes()) |s| addCells(&shared, s.widths, s.log);
        addCells(&shared, .{ B.layout.FIXED, B.layout.MAIN, B.layout.INTERACTION }, setup.bridge_log);
        var cc = try Components.init(&setup.materials, encoded.request.base, ch, encoded.claims.base);
        const hh = try cc.verifiers(a);
        defer a.free(hh);
        for (hh) |h| shared.component_oods_q_samples += try masks(a, h);
        var bridge = B.component.Component{ .kind = .bridge, .log_size = setup.bridge_log, .rows = encoded.request.calls, .offsets = .{ setup.total(0), setup.total(1), setup.total(2) }, .claims = encoded.claims.bridge, .challenges = .{ .ram = ch.memory.ram, .owner = ch.cpu.owner, .io = kc.io, .range16 = ch.memory.range16, .range8 = ch.memory.range8 } };
        shared.component_oods_q_samples += try masks(a, bridge.asVerifierComponent());
    }
    var truth = Totals{};
    addCells(&truth, .{ K.layout.FIXED, K.layout.MAIN, K.layout.INTERACTION }, c.truth.log);
    addCells(&truth, .{ 7, 1, 4 }, 13);
    addCells(&truth, .{ 7, 1, 4 }, 10);
    var pp = K.component.Component{ .kind = .permutation, .log_size = c.truth.log, .calls = 2, .challenges = kc, .claim = Q.zero() };
    var chi = K.component.Component{ .kind = .chi, .log_size = 13, .challenges = kc, .claim = Q.zero() };
    var xor = K.component.Component{ .kind = .xor5, .log_size = 10, .challenges = kc, .claim = Q.zero() };
    truth.component_oods_q_samples = try masks(a, pp.asVerifierComponent()) + try masks(a, chi.asVerifierComponent()) + try masks(a, xor.asVerifierComponent());
    var control = shared;
    for (0..3) |i| {
        shared.native_source_cells[i] += truth.native_source_cells[i];
        control.native_source_cells[i] += 2 * truth.native_source_cells[i];
    }
    shared.component_oods_q_samples += truth.component_oods_q_samples;
    control.component_oods_q_samples += 2 * truth.component_oods_q_samples;
    return .{ .scope = "same four-instruction two-call fixture; measured component masks and native shape cells", .shared = shared, .local_control_model = control, .truth = truth, .native_permutation_rows = @as(usize, 1) << @intCast(c.truth.log), .control_permutation_rows = 2 * (@as(usize, 1) << @intCast(c.truth.log)), .note = "Only this fixture: two local one-call log5 providers become one two-call log5 provider. General native padding may differ; this is not a real-block throughput or simultaneous-memory model. OODS excludes composition/FRI/Merkle values; prefix hashing scales with native groups, not this mask count." };
}
