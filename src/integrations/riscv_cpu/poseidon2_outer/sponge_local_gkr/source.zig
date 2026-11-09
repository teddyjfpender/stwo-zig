//! Construct each narrow MAIN witness once. Local facts are streamed from its
//! committed column-major cells; no row×query N/D matrix or replayed Keccak.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const K = A.crypto.keccak_sponge;
const S = K.serialized;
const R = @import("authority.zig");
const M = core.fields.m31.M31;
pub const Source = struct {
    allocator: std.mem.Allocator,
    geometry: R.Geometry,
    main: [8][]M,
    pub fn init(a: std.mem.Allocator, g: R.Geometry, calls: []const K.types.Call, words: []const K.types.State) !Source {
        const instances = try g.instances();
        if (calls.len != g.calls) return error.SpongeLocalSourceMismatch;
        var checked_perms: u32 = 0;
        var checked_words: usize = 0;
        for (calls) |call| {
            if (call.first_word != checked_words or call.first_perm != checked_perms or checked_words > words.len or call.words() > words.len - checked_words) return error.SpongeLocalSourceMismatch;
            try K.types.validateCall(call, words[checked_words..][0..call.words()]);
            checked_perms = try std.math.add(u32, checked_perms, call.permutations());
            checked_words += call.words();
            if (checked_perms > g.permutations) return error.SpongeLocalSourceMismatch;
        }
        if (checked_perms != g.permutations or checked_words != words.len) return error.SpongeLocalSourceMismatch;

        var out = Source{ .allocator = a, .geometry = g, .main = undefined };
        var allocated: usize = 0;
        errdefer for (out.main[0..allocated]) |v| a.free(v);
        for (instances, &out.main) |instance, *values| {
            values.* = try a.alloc(M, try std.math.mul(usize, try instance.rows(), R.mainWidth(instance.role)));
            @memset(values.*, M.zero());
            allocated += 1;
        }
        // Inactive word slots still satisfy their immutable address equations.
        const word_rows = try instances[3].rows();
        for (0..word_rows) |logical| {
            var m: [S.word.MAIN]M = @splat(M.zero());
            m[S.word.c.slot] = M.fromCanonical(@intCast(logical % 18));
            m[S.word.c.address] = M.fromCanonical(@intCast(8 * (logical % 18)));
            out.setRow(.word, logical, &m);
        }
        var permutation: u32 = 0;
        var word_cursor: usize = 0;
        for (calls, 0..) |call, i| {
            if (call.first_word != word_cursor or call.first_perm != permutation or call.words() > words.len - word_cursor) return error.SpongeLocalSourceMismatch;
            const local_words = words[word_cursor..][0..call.words()];
            try K.types.validateCall(call, local_words);
            const perms = try K.types.permutations(a, call, local_words);
            defer a.free(perms);
            const first = try std.math.add(u32, g.first_id, permutation);
            const descriptor = try S.descriptor.row(call, local_words, first);
            out.setRow(.descriptor, i, &descriptor);
            for (0..25) |lane| {
                const state = try S.state.row(call, first, perms[perms.len - 1][1], @intCast(lane));
                out.setRow(.state, 25 * i + lane, &state);
            }
            for (perms, 0..) |_, k| {
                // One original witness projection per permutation, shared by
                // every new row constructor; no47-fold reconstruction.
                const old = K.source.permRow(call, local_words, @intCast(k), perms);
                const p = @as(usize, permutation) + k;
                const header = S.header.row(&old);
                out.setRow(.header, p, &header);
                for (0..18) |slot| {
                    const word = try S.word.row(&old, first + @as(u32, @intCast(k)), @intCast(slot));
                    out.setRow(.word, 18 * p + slot, &word);
                }
                for (0..25) |lane| {
                    const value = try S.lane.row(&old, first + @as(u32, @intCast(k)), @intCast(lane));
                    out.setRow(.lane, 25 * p + lane, &value);
                }
            }
            permutation = try std.math.add(u32, permutation, call.permutations());
            word_cursor += call.words();
        }
        if (permutation != g.permutations or word_cursor != words.len) return error.SpongeLocalSourceMismatch;
        try out.countProviders();
        return out;
    }
    pub fn deinit(self: *Source) void {
        for (self.main) |v| self.allocator.free(v);
        self.* = undefined;
    }
    pub fn index(role: R.Role) usize {
        for (R.roles, 0..) |r, i| if (r == role) return i;
        unreachable;
    }
    pub fn setRow(self: *Source, comptime role: R.Role, logical: usize, m: *const [R.mainWidth(role)]M) void {
        const instance = (self.geometry.instances() catch unreachable)[index(role)];
        const rows = instance.rows() catch unreachable;
        const physical = A.witness.physical(logical, instance.row_log);
        for (m, 0..) |v, c| self.main[index(role)][c * rows + physical] = v;
    }
    pub fn row(self: *const Source, comptime role: R.Role, logical: usize) [R.mainWidth(role)]M {
        const instance = (self.geometry.instances() catch unreachable)[index(role)];
        const rows = instance.rows() catch unreachable;
        const physical = A.witness.physical(logical, instance.row_log);
        var m: [R.mainWidth(role)]M = undefined;
        for (&m, 0..) |*v, c| v.* = self.main[index(role)][c * rows + physical];
        return m;
    }
    pub fn validate(self: *const Source, g: R.Geometry) !void {
        if (!std.meta.eql(self.geometry, g)) return error.SpongeLocalSourceMismatch;
    }
    fn countProviders(self: *Source) !void {
        const Sink = struct {
            source: *Source,
            failure: ?anyerror = null,
            pub fn emit(s: *@This(), relation: usize, tuple: anytype, weight: M) void {
                if (s.failure != null or relation == K.equations.OWNER or relation == K.equations.RAM or relation == K.equations.IO or weight.isZero()) return;
                const role: R.Role = switch (relation) {
                    K.equations.RANGE16 => .u16,
                    K.equations.RANGE8 => .u8,
                    K.equations.AND => .and_,
                    else => unreachable,
                };
                var logical: usize = 0;
                if (comptime tuple.len == 3) {
                    if (tuple[0].v >= 256 or tuple[1].v >= 256 or tuple[2].v != (tuple[0].v & tuple[1].v)) {
                        s.failure = error.SpongeLocalNoncanonicalTable;
                        return;
                    }
                    logical = tuple[0].v + 256 * @as(usize, tuple[1].v);
                } else {
                    logical = tuple[0].v;
                    if ((role == .u8 and logical >= 256) or (role == .u16 and logical >= 65536)) {
                        s.failure = error.SpongeLocalNoncanonicalTable;
                        return;
                    }
                }
                const instance = (s.source.geometry.instances() catch unreachable)[index(role)];
                const physical = A.witness.physical(logical, instance.row_log);
                const values = s.source.main[index(role)];
                const sum = @as(u64, values[physical].v) + weight.v;
                if (sum >= core.fields.m31.Modulus) {
                    s.failure = error.SpongeLocalMultiplicityOverflow;
                    return;
                }
                values[physical] = M.fromCanonical(@intCast(sum));
            }
        };
        var sink = Sink{ .source = self };
        const instances = try self.geometry.instances();
        inline for (R.roles[0..5]) |role| for (0..try instances[index(role)].rows()) |logical| {
            const m = self.row(role, logical);
            emitRaw(role, M, &fixedRow(role, logical, instances[index(role)].row_log), &m, self.geometry.first_id, &sink);
        };
        if (sink.failure) |e| return e;
    }
};
pub fn fixedRow(comptime role: R.Role, logical: usize, log: u32) [R.fixedWidth(role)]M {
    if (role == .u16 or role == .u8) return .{M.fromCanonical(@intCast(logical))};
    if (role == .and_) return .{ M.fromCanonical(@intCast(logical % 256)), M.fromCanonical(@intCast(logical / 256)), M.fromCanonical(@intCast((logical % 256) & (logical / 256))) };
    if (role == .word) return .{ M.fromCanonical(@intCast(logical % 18)), M.fromCanonical(@intFromBool(logical % 18 == 0)), M.fromCanonical(@intFromBool(logical % 18 == 17)) };
    if (role == .lane) return .{ M.fromCanonical(@intCast(logical % 25)), M.fromCanonical(@intFromBool(logical % 25 < 17)), M.fromCanonical(@intFromBool(logical % 25 == 16)) };
    return .{ M.fromCanonical(@intCast(logical)), M.fromCanonical(@intFromBool(logical == 0)), M.fromCanonical(@intFromBool(logical + 1 == @as(usize, 1) << @intCast(log))) };
}
pub fn emitRaw(comptime role: R.Role, comptime F: type, f: *const [R.fixedWidth(role)]F, m: *const [R.mainWidth(role)]F, first_id: u32, sink: anytype) void {
    switch (role) {
        .descriptor => S.descriptor.emitRaw(F, m, sink),
        .state => S.state.emitRaw(F, m, sink),
        .header => S.header.emitRaw(F, f[0], m, A.evaluation.qFor(F, first_id), sink),
        .word => S.word.emitRaw(F, f, m, sink),
        .lane => S.lane.emitRaw(F, m, sink),
        .u16 => sink.emit(K.equations.RANGE16, f.*, m[0].neg()),
        .u8 => sink.emit(K.equations.RANGE8, f.*, m[0].neg()),
        .and_ => sink.emit(K.equations.AND, f.*, m[0].neg()),
    }
}
test "serialized sponge source builds canonical provider counts once" {
    const a = std.testing.allocator;
    var call = K.types.Call{ .pointer = 0x4000, .epoch = 1, .tick = 4, .packet = undefined, .state = undefined };
    const packet = [_]u64{ 0x8000, 0x9000, 0, K.types.Native.FINALIZE | K.types.Native.FRESH };
    for (&call.packet, packet) |*s, v| s.* = .{ .value = v, .epoch = 0, .tick = 0, .rights = 3 };
    for (&call.state) |*s| s.* = .{ .value = 0, .epoch = 0, .tick = 0, .rights = 3 };
    const g = R.Geometry{ .calls = 1, .permutations = 1, .first_id = 1 };
    var source = try Source.init(a, g, &.{call}, &.{});
    defer source.deinit();
    var counts: u64 = 0;
    for (source.main[Source.index(.u8)]) |v| counts += v.v;
    try std.testing.expect(counts > 0 and counts < core.fields.m31.Modulus);
    const lane = source.row(.lane, 16);
    try std.testing.expectEqual(@as(u32, 0x80), lane[S.lane.c.msg + 7].v);
    try std.testing.expectError(error.SpongeLocalSourceMismatch, source.validate(.{ .calls = 1, .permutations = 1, .first_id = 2 }));
}
