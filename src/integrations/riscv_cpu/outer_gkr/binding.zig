//! Binding columns of the outer LogUp-GKR (rv64-m5-outer-gkr.md section 5), CPU reference for the AIR hook
//! (canon-vk H2): per GKR-bound component, an eq column E and a weighted prefix column Pre, both OM31.
//!
//!   E[row]       = eq(z_row, row)                       z_row = last row_log coordinates of the GKR point
//!   v[row]       = sum_g rho_g sum_lane w_g(lane) (n_g[lane, row] + gamma d_g[lane, row]),  w_g(lane) = eq(z_lane_g, lane)
//!   Pre[0] = 0,  Pre[row + 1] = Pre[row] + E[row] v[row]
//!   boundary:    Pre[2^row_log] = sum_g rho_g (claim_n,g + gamma claim_d,g)      (claims = GKR terminal claims)
//!
//! Lane-major layout (index = lane * 2^row_log + row) is what makes z_row shared by every lane group of a component:
//! instance g reads the last n_g = row_log + lane_log_g coordinates of z, most significant first, so its row bits are
//! the last row_log coordinates whatever lane_log_g is. `boundaryHolds` is checked against the real artifact in tests.
const std = @import("std");
const core = @import("stwo_core");
const P = @import("profile.zig");
const S = @import("section.zig");
const O = core.fields.om31.OM31;
const M31 = core.fields.m31.M31;

/// eq(point, bits(index)) with bits most significant first (stwo MLE convention).
fn eqAt(point: []const O, index: usize) O {
    var acc = O.one();
    const n = point.len;
    for (point, 0..) |z, k| {
        const bit = (index >> @intCast(n - 1 - k)) & 1;
        acc = acc.mul(if (bit == 1) z else O.one().sub(z));
    }
    return acc;
}
/// All 2^n eq values (MSB-first indexing).
pub fn eqTable(a: std.mem.Allocator, point: []const O) ![]O {
    return eqTableFor(O, a, point);
}
pub fn eqTableFor(comptime F: type, a: std.mem.Allocator, point: []const F) ![]F {
    const out = try a.alloc(F, @as(usize, 1) << @intCast(point.len));
    out[0] = F.one();
    var size: usize = 1;
    for (point) |z| {
        // Extend MSB-first: new index = old * 2 + bit.
        var i = size;
        while (i > 0) {
            i -= 1;
            const v = out[i];
            out[2 * i + 1] = v.mul(z);
            out[2 * i] = v.sub(out[2 * i + 1]);
        }
        size *= 2;
    }
    return out;
}

pub const Challenges = struct { rho: [P.MAX_INSTANCES]O, gamma: O };
/// Drawn AFTER the GKR section (late binding), strict like every GKR draw.
pub fn drawChallenges(channel: *S.StrictChannel, n: usize) Challenges {
    var out: Challenges = .{ .rho = undefined, .gamma = channel.drawSecureFelt() };
    for (out.rho[0..n]) |*r| r.* = channel.drawSecureFelt();
    return out;
}

pub const Columns = struct {
    eq: []O,
    prefix: []O, // length 2^row_log + 1 (Pre[0] .. Pre[2^row_log])
    pub fn deinit(self: *Columns, a: std.mem.Allocator) void {
        a.free(self.eq);
        a.free(self.prefix);
    }
};
/// Prover side: E and Pre of one component from its fraction inputs (as the AIR would from MAIN).
pub fn columns(a: std.mem.Allocator, class: *const P.Class, component: P.Component, point: []const O, inputs: *const S.Inputs, ch: *const Challenges) !Columns {
    const r: u32 = class.row_logs[@intFromEnum(component)];
    const rows = @as(usize, 1) << @intCast(r);
    const z_row = point[point.len - r ..];
    const eq = try eqTable(a, z_row);
    errdefer a.free(eq);
    const v = try a.alloc(O, rows);
    defer a.free(v);
    @memset(v, O.zero());
    for (class.instances, 0..) |inst, g| {
        if (inst.component != component) continue;
        const n_g = inst.variables();
        const z_lane = point[point.len - n_g .. point.len - r];
        const w = try eqTable(a, z_lane);
        defer a.free(w);
        for (0..rows) |row| {
            var acc = O.zero();
            for (w, 0..) |wl, lane| {
                const idx = lane * rows + row;
                acc = acc.add(wl.mul(O.fromBase(inputs.numerators[g][idx]).add(ch.gamma.mul(inputs.denominators[g][idx]))));
            }
            v[row] = v[row].add(ch.rho[g].mul(acc));
        }
    }
    const prefix = try a.alloc(O, rows + 1);
    prefix[0] = O.zero();
    for (0..rows) |row| prefix[row + 1] = prefix[row].add(eq[row].mul(v[row]));
    return .{ .eq = eq, .prefix = prefix };
}
/// Verifier side: the boundary value the last prefix entry must equal, from the GKR terminal claims.
pub fn expectedBoundary(class: *const P.Class, component: P.Component, claims: anytype, ch: *const Challenges) O {
    var acc = O.zero();
    for (class.instances, 0..) |inst, g| {
        if (inst.component != component) continue;
        acc = acc.add(ch.rho[g].mul(claims[g][0].add(ch.gamma.mul(claims[g][1]))));
    }
    return acc;
}
pub fn boundaryHolds(cols: *const Columns, expected: O) bool {
    return cols.prefix[cols.prefix.len - 1].eql(expected);
}
/// The eq column satisfies E[row] = eqAt(z_row, row) (spot check helper for tests / AIR differential tests).
pub fn eqEntry(point: []const O, row_log: u32, row: usize) O {
    return eqAt(point[point.len - row_log ..], row);
}
