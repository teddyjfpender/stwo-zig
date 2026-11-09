//! CLOSED R7-v2 direct-group source experiment. Every native verifier emitter,
//! frame and tree operation is shared with the R6 source stream. Only whole-DEEP
//! dots and the joint eight-role finalizer change. No root/runtime admission.
const std = @import("std");
const P = @import("../../rv64_recursion/om31_poseidon/common.zig");
const Base = @import("../native_group/source.zig");
const Dot = @import("scope.zig").Scope;
const Profile = @import("../op_profile.zig").Profile;
pub const Member = Base.Member;
pub const Stream = struct {
    inner: Base.Stream,
    pub fn init(a: std.mem.Allocator, trace_only: bool, first: u32, count: u32, profile: Profile, manifest: [36]u8) !Stream {
        return .{ .inner = try Base.Stream.init(a, trace_only, first, count, profile, manifest) };
    }
    pub fn deinit(self: *Stream) void {
        self.inner.deinit();
        self.* = undefined;
    }
    pub fn append(self: *Stream, member: Member) !void {
        // Borrowed native captures expire after append. No global hook remains
        // active between callbacks, including every failure path.
        var dot = Dot.begin(&self.inner.owner);
        defer dot.deinit();
        try self.inner.append(member);
    }
    pub fn expectedOutput(self: *const Stream) !@import("../native_omul/fold.zig").Digest {
        return self.inner.expectedOutput();
    }
    pub fn finish(self: *Stream) !P.PoseidonContext {
        var dot = Dot.begin(&self.inner.owner);
        defer dot.deinit();
        return self.inner.finishForNativeDot();
    }
};
/// Trace cells, not expanded evaluations, peak RAM or a speed prediction. These
/// widths are the actual OM31 eight-role physical roster, not QM31-field widths.
pub const Cost = struct {
    raw: [8]u64,
    rows: [8]usize,
    logs: [8]u32,
    fixed_cells: u64 = 0,
    main_cells: u64 = 0,
    interaction_cells: u64 = 0,
    total_cells: u64 = 0,
    dot_calls: usize,
    dot_terms: usize = 0,
    pub fn derive(owner: *const P.PoseidonContext) !Cost {
        const raw = try owner.rawCountsForNativeDot();
        var out = Cost{ .raw = raw, .rows = undefined, .logs = undefined, .dot_calls = owner.native_dot_calls.items.len };
        const L = @import("../layout.zig");
        const MR = @import("../native_omul/row.zig");
        const DR = @import("row.zig");
        const IR = @import("input_row.zig");
        for (owner.native_dot_calls.items) |call| out.dot_terms = try std.math.add(usize, out.dot_terms, call.terms.len);
        const fixed = [_]usize{ L.FACTS[0].fixed, L.FACTS[1].fixed, L.FACTS[2].fixed, L.FACTS[3].fixed, L.FACTS[4].fixed, MR.FIXED, DR.FIXED, IR.FIXED };
        const main = [_]usize{ L.FACTS[0].main, L.FACTS[1].main, L.FACTS[2].main, L.FACTS[3].main, L.FACTS[4].main, MR.MAIN, DR.MAIN, IR.MAIN };
        const inter = [_]usize{ L.FACTS[0].classic_interaction, L.FACTS[1].classic_interaction, L.FACTS[2].classic_interaction, L.FACTS[3].classic_interaction, L.FACTS[4].classic_interaction, MR.INTER, DR.INTER, IR.INTER };
        for (raw, &out.rows, &out.logs, fixed, main, inter, 0..) |n, *rows, *log, f, m, i, role| {
            rows.* = try std.math.ceilPowerOfTwo(usize, @max(if (role == 4) @as(usize, 65536) else 16, std.math.cast(usize, n) orelse return error.R7GroupGeometry));
            log.* = @intCast(std.math.log2_int(usize, rows.*));
            if (log.* > 26) return error.R7GroupGeometry;
            out.fixed_cells = try std.math.add(u64, out.fixed_cells, try std.math.mul(u64, rows.*, f));
            out.main_cells = try std.math.add(u64, out.main_cells, try std.math.mul(u64, rows.*, m));
            out.interaction_cells = try std.math.add(u64, out.interaction_cells, try std.math.mul(u64, rows.*, i));
        }
        out.total_cells = try std.math.add(u64, out.fixed_cells, try std.math.add(u64, out.main_cells, out.interaction_cells));
        return out;
    }
};
