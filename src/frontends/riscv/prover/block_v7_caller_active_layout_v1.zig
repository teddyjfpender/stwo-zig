//! Independently derived finite caller layout. Zero signer calls omit ten
//! execution AIRs; zero Keccak calls omit its three exclusively owned AIRs.
//! Zero SHA calls omit all five SHA AIRs and their table projections. The
//! shared byte provider remains present for the Ethereum components.
//! This is a new commitment geometry, never a reinterpretation of old roots.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const P = @import("blake3_ethereum_sha_profile.zig");
const Protocol = @import("block_v5_precompile_protocol_v1.zig");
pub const TAG: u32 = 0x4237414c; // B7AL
pub const VERSION: u32 = 3;
pub const Layout = struct {
    active: [19]bool,
    original: [19][3]usize,
    placed: [19][3]usize,
    widths: [19][3]usize,
    logs: [19]u32,
    totals: [3]usize,
    original_totals: [3]usize,
    pub fn derive(statement: *const P.admission.Statement, steps: u32) !Layout {
        try Protocol.validateGeometry(statement, steps);
        if (statement.ethereum.localZeroCustody()) return error.UnqualifiedActiveCallerCustody;
        var out: Layout = .{ .active = undefined, .original = undefined, .placed = undefined, .widths = undefined, .logs = undefined, .totals = @splat(0), .original_totals = @splat(0) };
        for (P.descriptors(statement), 0..) |d, i| {
            out.active[i] = if (i >= 14) statement.sha.call_count != 0 else if (i < 3) statement.ethereum.counts.keccak_calls != 0 else statement.ethereum.counts.signer_calls != 0 or i == 12;
            out.original[i] = out.original_totals;
            out.placed[i] = out.totals;
            out.logs[i] = d.log_size;
            out.widths[i] = .{ d.preprocessed_columns, d.main_columns, d.interaction_columns };
            for (0..3) |tree| {
                out.original_totals[tree] = try std.math.add(usize, out.original_totals[tree], out.widths[i][tree]);
                if (out.active[i]) out.totals[tree] = try std.math.add(usize, out.totals[tree], out.widths[i][tree]);
            }
        }
        return out;
    }
    pub fn require(self: *const Layout, statement: *const P.admission.Statement, steps: u32) !void {
        if (!std.meta.eql(self.*, try derive(statement, steps))) return error.UntrustedActiveCallerLayout;
    }
    pub fn mix(self: *const Layout, ch: anytype) void {
        ch.mixU32s(&.{ TAG, VERSION, 19 });
        for (0..19) |i| {
            ch.mixU32s(&.{ @intCast(i), @intFromBool(self.active[i]), self.logs[i] });
            for (0..3) |tree| ch.mixU32s(&.{ @intCast(self.widths[i][tree]), @intCast(self.placed[i][tree]) });
        }
    }
    pub fn map(self: *const Layout, tree: usize, offset: usize, width: usize) !usize {
        if (tree >= 3) return error.InvalidActiveCallerTree;
        for (0..19) |i| {
            const start = self.original[i][tree];
            const end = try std.math.add(usize, offset, width);
            if (offset >= start and end <= start + self.widths[i][tree] and (width != 0 or offset < start + self.widths[i][tree])) {
                if (!self.active[i]) return error.OmittedActiveCallerDependency;
                return self.placed[i][tree] + offset - start;
            }
        }
        if (width == 0 and offset == self.original_totals[tree]) return self.totals[tree];
        return error.InvalidActiveCallerOffset;
    }
    pub fn columns(self: *const Layout, a: std.mem.Allocator, tree: usize, original: []const engine.pcs.ColumnEvaluation) ![]engine.pcs.ColumnEvaluation {
        if (tree >= 3 or original.len != self.original_totals[tree]) return error.InvalidActiveCallerColumns;
        const out = try a.alloc(engine.pcs.ColumnEvaluation, self.totals[tree]);
        errdefer a.free(out);
        for (0..19) |i| if (self.active[i]) {
            const source = original[self.original[i][tree]..][0..self.widths[i][tree]];
            for (source) |column| if (column.log_size != self.logs[i]) return error.InvalidActiveCallerColumns;
            @memcpy(out[self.placed[i][tree]..][0..source.len], source);
        };
        return out;
    }
    pub fn columnLogs(self: *const Layout, a: std.mem.Allocator, tree: usize) ![]u32 {
        if (tree >= 3) return error.InvalidActiveCallerTree;
        const out = try a.alloc(u32, self.totals[tree]);
        for (0..19) |i| if (self.active[i]) {
            @memset(out[self.placed[i][tree]..][0..self.widths[i][tree]], self.logs[i]);
        };
        return out;
    }
    pub fn requireClaims(self: *const Layout, statement: *const P.admission.Statement, claims: *const P.ExtensionClaim) !void {
        try claims.validate(statement);
        for (claims.componentClaims(), self.active) |claim, active| if (!active) {
            if (!claim.total.isZero()) return error.NonzeroOmittedCallerClaim;
            for (claim.detailed) |part| if (!part.isZero()) return error.NonzeroOmittedCallerClaim;
        };
    }
};
