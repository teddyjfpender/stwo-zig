//! Concrete unsigned-product witness recipe. Metadata may outlive owned main;
//! the shared polynomial authority authenticates every reconstructed fraction.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const E = @import("../../evaluation.zig");
const L = @import("layout.zig");
const P = @import("provider.zig");
const physical = @import("../../witness.zig").physical;
pub const Request = struct { opcode: E.O, a: u64, b: u64, result: u64 };
pub fn requestTuple(request: Request) !P.Tuple {
    _ = try L.opcodeIndex(request.opcode);
    var result: P.Tuple = undefined;
    result[0] = E.q(@intFromEnum(request.opcode));
    for ([_]u64{ request.a, request.b, request.result }, 0..) |word, w| for (0..8) |i| {
        result[1 + 8 * w + i] = E.q(@intCast((word >> @as(u6, @intCast(8 * i))) & 255));
    };
    return result;
}
pub fn row(request: Request) ![L.MAIN]M {
    const op = try L.opcodeIndex(request.opcode);
    var result: [L.MAIN]M = @splat(M.zero());
    result[L.SELECTORS + op] = M.one();
    const product: u128 = @as(u128, request.a) * request.b;
    for ([_]u64{ request.a, request.b, request.result }, 0..) |word, w| for (0..8) |i| {
        result[8 * w + i] = M.fromCanonical(@intCast((word >> @as(u6, @intCast(8 * i))) & 255));
    };
    for (0..16) |i| result[L.PRODUCT + i] = M.fromCanonical(@intCast((product >> @as(u7, @intCast(8 * i))) & 255));
    var carry: u32 = 0;
    for (0..15) |k| {
        var sum = carry;
        for (0..8) |i| if (k >= i and k - i < 8) {
            sum += result[L.A + i].v * result[L.B + k - i].v;
        };
        carry = sum >> 8;
        result[L.CARRY_LOW + k] = M.fromCanonical(carry & 255);
        result[L.CARRY_HIGH + k] = M.fromCanonical(carry >> 8);
    }
    result[L.SIGN_A] = M.fromCanonical(@intCast(request.a >> 63));
    result[L.SIGN_B] = M.fromCanonical(@intCast(request.b >> 63));
    result[L.SIGN_RESULT] = M.fromCanonical(@intCast((request.result >> 31) & 1));
    if (request.opcode == .MULH or request.opcode == .MULHSU or request.opcode == .MULHU) {
        var borrow: i32 = 0;
        for (0..8) |i| {
            var value: i32 = @intCast(result[L.PRODUCT + 8 + i].v);
            value -= borrow;
            if (request.opcode != .MULHU) value -= @as(i32, @intCast(result[L.SIGN_A].v * result[L.B + i].v));
            if (request.opcode == .MULH) value -= @as(i32, @intCast(result[L.SIGN_B].v * result[L.A + i].v));
            borrow = if (value < 0) @divTrunc(-value + 255, 256) else 0;
            result[L.BORROW + i] = M.fromCanonical(@intCast(borrow));
        }
    }
    return result;
}
pub fn fixedColumnsForLog(a: std.mem.Allocator, log: u32) ![]M {
    if (log < 5 or log > 22) return error.InvalidRv64MultiplicationShape;
    const n = @as(usize, 1) << @intCast(log);
    const data = try a.alloc(M, L.FIXED * n);
    @memset(data, M.zero());
    for (0..n) |i| {
        const r = physical(i, log);
        data[r] = M.fromCanonical(@intCast(i));
        data[n + r] = M.fromCanonical(@intFromBool(i == 0));
        data[2 * n + r] = M.fromCanonical(@intFromBool(i + 1 == n));
    }
    return data;
}
pub const Trace = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    count: u32,
    fixed: []M,
    main: []M,
    owns_main: bool = true,
    request_metadata: []Request,
    byte_counts: [256]u64,
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
        if (log < 5 or log > 22 or requests.len > (@as(usize, 1) << @intCast(log))) return error.InvalidRv64MultiplicationShape;
        const n = @as(usize, 1) << @intCast(log);
        for (requests) |request| _ = try L.opcodeIndex(request.opcode);
        if (borrowed) |main| {
            const storage = @import("../../crypto/main_storage.zig");
            const slices = [_]storage.Slice{.{ .values = main, .cells = L.MAIN * n }};
            try storage.validate(&slices);
            try storage.exclude(&slices, std.mem.sliceAsBytes(requests));
        }
        // BYTE padding is part of the global roster too. The joint caller must
        // additionally aggregate this mass with every other BYTE consumer.
        if (@as(u64, n) * L.BYTE_QUERIES >= core.fields.m31.Modulus) return error.InvalidRv64MultiplicationMass;
        const fixed = try fixedColumnsForLog(a, log);
        errdefer a.free(fixed);
        const main = borrowed orelse try a.alloc(M, L.MAIN * n);
        errdefer if (borrowed == null) a.free(main);
        const metadata = try a.dupe(Request, requests);
        errdefer a.free(metadata);
        @memset(main, M.zero());
        var counts: [256]u64 = @splat(0);
        counts[0] = L.BYTE_QUERIES * (n - requests.len);
        for (requests, 0..) |request, i| {
            const values = try row(request);
            for (values, 0..) |v, c| main[c * n + physical(i, log)] = v;
            for (try byteValuesNative(&values)) |value| counts[value] += 1;
        }
        for (0..n) |i| main[L.COUNT * n + physical(i, log)] = M.fromCanonical(@intCast(@min(i + 1, requests.len)));
        return .{ .allocator = a, .log_size = log, .count = @intCast(requests.len), .fixed = fixed, .main = main, .owns_main = borrowed == null, .request_metadata = metadata, .byte_counts = counts };
    }
    /// Main is no longer read after commitment; narrow request metadata stays
    /// alive until interaction generation. Borrowed arena storage is not freed.
    pub fn releaseMain(self: *Trace) !void {
        if (self.main.len != L.MAIN * self.domainSize()) return error.InvalidRv64ArithmeticMainPhase;
        if (self.owns_main) self.allocator.free(self.main);
        self.main = &.{};
    }
    pub fn deinit(self: *Trace) void {
        self.allocator.free(self.fixed);
        if (self.owns_main) self.allocator.free(self.main);
        self.allocator.free(self.request_metadata);
        self.allocator.free(self.interaction);
        self.* = undefined;
    }
    pub fn domainSize(self: *const Trace) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn generateInteraction(self: *Trace, challenges: P.Challenges, alpha: Q) !Q {
        if (self.interaction.len != 0 or self.request_metadata.len != self.count) return error.InvalidRv64MultiplicationPhase;
        const n = self.domainSize();
        const data = try self.allocator.alloc(M, L.INTERACTION * n);
        errdefer self.allocator.free(data);
        var inverses: [256]Q = undefined;
        for (&inverses, 0..) |*inverse, byte| inverse.* = try alpha.sub(E.q(@intCast(byte))).inv();
        var sum = Q.zero();
        // Typed inverses are batch-inverted with fixed scratch, rather than
        // performing one extension inversion for every multiplication request.
        var denominators: [512]Q = undefined;
        var prefixes: [512]Q = undefined;
        var first: usize = 0;
        while (first < n) : (first += @min(512, n - first)) {
            const count = @min(512, n - first);
            const active_count = @min(count, @as(usize, self.count) -| first);
            var product = Q.one();
            for (0..active_count) |i| {
                denominators[i] = challenges.denominator(&try requestTuple(self.request_metadata[first + i]));
                prefixes[i] = product;
                product = product.mul(denominators[i]);
            }
            var inverse = try product.inv();
            var i = active_count;
            while (i != 0) {
                i -= 1;
                const d = denominators[i];
                denominators[i] = inverse.mul(prefixes[i]);
                inverse = inverse.mul(d);
            }
            for (0..count) |local| {
                const logical = first + local;
                const r = physical(logical, self.log_size);
                const base = if (logical < self.count) try row(self.request_metadata[logical]) else [_]M{M.zero()} ** L.MAIN;
                const bytes = try byteValuesNative(&base);
                for (0..L.BYTE_QUERIES / 3) |group| {
                    for (bytes[group * 3 ..][0..3]) |byte| sum = sum.add(inverses[byte]);
                    store(data, n, r, 4 * group, sum);
                }
                if (local < active_count) sum = sum.sub(denominators[local]);
                store(data, n, r, L.INTERACTION - 4, sum);
            }
        }
        self.interaction = data;
        self.allocator.free(self.request_metadata);
        self.request_metadata = &.{};
        return sum;
    }
};
fn store(data: []M, n: usize, r: usize, c: usize, value: Q) void {
    for (value.toM31Array(), 0..) |part, i| data[(c + i) * n + r] = part;
}

/// Same affine values as provider.byteValues, evaluated without extension-field
/// arithmetic in native witness generation. Algebraic bounds remain in AIR.
pub fn byteValuesNative(main: *const [L.MAIN]M) ![L.BYTE_QUERIES]u8 {
    var values: [L.BYTE_QUERIES]u8 = undefined;
    for (0..40) |i| {
        if (main[i].v >= 256) return error.InvalidRv64MultiplicationByte;
        values[i] = @intCast(main[i].v);
    }
    for (0..15) |i| {
        const low = main[L.CARRY_LOW + i].v;
        const high = main[L.CARRY_HIGH + i].v;
        if (low >= 256 or high >= 8) return error.InvalidRv64MultiplicationByte;
        values[40 + 3 * i] = @intCast(low);
        values[41 + 3 * i] = @intCast(high);
        values[42 + 3 * i] = @intCast(32 * high);
    }
    for (0..8) |i| {
        if (main[L.BORROW + i].v >= 256) return error.InvalidRv64MultiplicationByte;
        values[85 + i] = @intCast(main[L.BORROW + i].v);
    }
    for ([_]usize{ L.A + 7, L.B + 7, L.RESULT + 3 }, [_]usize{ L.SIGN_A, L.SIGN_B, L.SIGN_RESULT }, 0..) |byte, sign, i| {
        const remainder = @as(i64, main[byte].v) - 128 * @as(i64, main[sign].v);
        if (remainder < 0 or remainder > 127) return error.InvalidRv64MultiplicationByte;
        values[93 + i] = @intCast(2 * remainder);
    }
    return values;
}
