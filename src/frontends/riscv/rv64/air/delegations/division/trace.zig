//! One separately-sized service witness; no CPU journal, clocks or path cache.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const E = @import("../../evaluation.zig");
const D = @import("layout.zig");
const P = @import("provider.zig");
const rows = @import("../../rows.zig");
const rom = @import("../../program/provider.zig");
pub const Request = struct { opcode: E.O, a: u64, b: u64, result: u64 };
pub fn requestTuple(request: Request) !D.Tuple {
    _ = try D.opcodeIndex(request.opcode);
    var result: D.Tuple = undefined;
    result[0] = E.q(@intFromEnum(request.opcode));
    for ([_]u64{ request.a, request.b, request.result }, 0..) |value, w| for (0..8) |i| {
        result[1 + 8 * w + i] = E.q(@intCast((value >> @as(u6, @intCast(8 * i))) & 255));
    };
    return result;
}
pub fn fixedColumns(a: std.mem.Allocator, count: usize, log_size: u32) ![]M {
    if (log_size < 5 or log_size > 22 or count > @as(usize, 1) << @intCast(log_size)) return error.InvalidRv64DivisionShape;
    const n = @as(usize, 1) << @intCast(log_size);
    const data = try a.alloc(M, D.FIXED * n);
    @memset(data, M.zero());
    for (0..n) |i| {
        const row = rom.physical(i, log_size);
        data[row] = M.fromCanonical(@intCast(i));
        data[n + row] = M.fromCanonical(@intFromBool(i == 0));
        data[2 * n + row] = M.fromCanonical(@intFromBool(i + 1 == n));
    }
    return data;
}
pub const Trace = struct {
    allocator: std.mem.Allocator,
    count: usize,
    log_size: u32,
    fixed: []M,
    main: []M,
    owns_main: bool = true,
    /// Prover advice only; the bus polynomial authenticates these tuples against
    /// committed main rows. Survives optional source ownership transfer.
    request_metadata: []Request,
    interaction: []M = &.{},
    pub fn init(a: std.mem.Allocator, requests: []const Request) !Trace {
        return initWithLog(a, requests, @intCast(@max(5, std.math.log2_int_ceil(usize, @max(1, requests.len)))));
    }
    pub fn initWithLog(a: std.mem.Allocator, requests: []const Request, log: u32) !Trace {
        return initStorage(a, requests, log, null);
    }
    /// Caller owns the exact main buffer on both success and failure. All
    /// admission/allocation precedes writes; the canonical row filler is shared.
    pub fn initWithBorrowedMain(a: std.mem.Allocator, requests: []const Request, log: u32, main: []M) !Trace {
        return initStorage(a, requests, log, main);
    }
    fn initStorage(a: std.mem.Allocator, requests: []const Request, log: u32, borrowed: ?[]M) !Trace {
        if (log < 5 or log > 22 or requests.len > (@as(usize, 1) << @intCast(log))) return error.InvalidRv64DivisionShape;
        const n = @as(usize, 1) << @intCast(log);
        for (requests) |request| _ = try D.opcodeIndex(request.opcode);
        if (borrowed) |main| {
            const storage = @import("../main_storage.zig");
            const slices = [_]storage.Slice{.{ .values = main, .cells = D.MAIN * n }};
            try storage.validate(&slices);
            try storage.exclude(&slices, std.mem.sliceAsBytes(requests));
        }
        const fixed = try fixedColumns(a, requests.len, log);
        errdefer a.free(fixed);
        const request_metadata = try a.dupe(Request, requests);
        errdefer a.free(request_metadata);
        const main = borrowed orelse try a.alloc(M, D.MAIN * n);
        errdefer if (borrowed == null) a.free(main);
        @memset(main, M.zero());
        for (requests, 0..) |request, i| {
            var logical: rows.Main = @splat(M.zero());
            rows.putWord(&logical, .a, request.a);
            rows.putWord(&logical, .b, request.b);
            rows.putWord(&logical, .result, request.result);
            _ = try D.opcodeIndex(request.opcode);
            @import("../../witness_hints.zig").fill(&logical, request.opcode, 0);
            var encoded: [D.MAIN]M = undefined;
            try D.encode(&logical, request.opcode, &encoded);
            const row = rom.physical(i, log);
            for (encoded, 0..) |value, c| main[c * n + row] = value;
        }
        for (0..n) |i| main[D.COUNT * n + rom.physical(i, log)] = M.fromCanonical(@intCast(@min(i + 1, requests.len)));
        return .{ .allocator = a, .count = requests.len, .log_size = log, .fixed = fixed, .main = main, .owns_main = borrowed == null, .request_metadata = request_metadata };
    }
    /// Main is no longer read after commitment; narrow request metadata stays
    /// alive until interaction generation. Borrowed arena storage is not freed.
    pub fn releaseMain(self: *Trace) !void {
        if (self.main.len != D.MAIN * self.domainSize()) return error.InvalidRv64ArithmeticMainPhase;
        if (self.owns_main) self.allocator.free(self.main);
        self.main = &.{};
    }
    pub fn deinit(self: *Trace) void {
        self.allocator.free(self.fixed);
        if (self.owns_main) self.allocator.free(self.main);
        self.allocator.free(self.interaction);
        self.allocator.free(self.request_metadata);
        self.* = undefined;
    }
    pub fn domainSize(self: *const Trace) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn generateInteraction(self: *Trace, challenges: P.Challenges) !E.Q {
        if (self.interaction.len != 0 or self.request_metadata.len != self.count) return error.InvalidRv64DivisionPhase;
        const n = self.domainSize();
        const values = try self.allocator.alloc(M, D.INTERACTION * n);
        errdefer self.allocator.free(values);
        var sum = E.Q.zero();
        for (0..n) |i| {
            const row = rom.physical(i, self.log_size);
            const inverse = if (i < self.count) blk: {
                const entry = try requestTuple(self.request_metadata[i]);
                break :blk try challenges.denominator(&entry).inv();
            } else E.Q.zero();
            sum = sum.sub(inverse);
            for (inverse.toM31Array(), 0..) |part, c| values[c * n + row] = part;
            for (sum.toM31Array(), 0..) |part, c| values[(4 + c) * n + row] = part;
        }
        self.allocator.free(self.request_metadata);
        self.request_metadata = &.{};
        self.interaction = values;
        return sum;
    }
};
