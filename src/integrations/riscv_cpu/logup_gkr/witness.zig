//! Historical pre-LS32 range-query witness of the experimental LS family: 12 U16 lanes and
//! 4 U8 lanes per LS row, stored per lane in bit-reversed circle-domain order
//! (the same physical order as LS MAIN). Lane `j < 12` is `LOGICAL_U16[j]`,
//! lane `12 + j` is the historical `LOGICAL_U8[j]`. Current LS layouts may
//! have less debt; capture must refuse incompatible mappings.
const std = @import("std");

pub const LANES: usize = 16;
pub const HI_LANES: usize = 12;
pub const LO_LANES: usize = 4;
pub const LOG_LANES: u32 = 4;
pub const MAX_LOG: u32 = 24;

pub const Statement = struct {
    ls_log: u32,
    /// 0 means no tail instance.
    tail_log: u32 = 0,
    hi_log: u32 = 16,
    lo_log: u32 = 8,

    pub fn validate(self: Statement) !void {
        if (self.ls_log < 4 or self.ls_log > MAX_LOG) return error.InvalidGkrStatement;
        if (self.tail_log != 0 and (self.tail_log < 4 or self.tail_log > self.ls_log)) return error.InvalidGkrStatement;
        if (self.hi_log < 3 or self.hi_log > 16 or self.lo_log < 3 or self.lo_log > self.hi_log) return error.InvalidGkrStatement;
    }
    pub fn instanceCount(self: Statement) usize {
        return if (self.tail_log == 0) 1 else 2;
    }
    pub fn instanceLog(self: Statement, i: usize) u32 {
        return if (i == 0) self.ls_log else self.tail_log;
    }
    pub fn production(ls_log: u32, tail_log: u32) Statement {
        return .{ .ls_log = ls_log, .tail_log = tail_log };
    }
};

pub const Instance = struct {
    log: u32,
    lanes: [LANES][]u32,

    pub fn rows(self: *const Instance) usize {
        return @as(usize, 1) << @intCast(self.log);
    }
};

pub const Witness = struct {
    allocator: std.mem.Allocator,
    statement: Statement,
    instances: [2]Instance,
    count: usize,

    pub fn initZero(a: std.mem.Allocator, statement: Statement) !Witness {
        try statement.validate();
        var out = Witness{ .allocator = a, .statement = statement, .instances = undefined, .count = 0 };
        errdefer out.deinit();
        for (0..statement.instanceCount()) |i| {
            const log = statement.instanceLog(i);
            const n = @as(usize, 1) << @intCast(log);
            out.instances[i].log = log;
            var made: usize = 0;
            errdefer for (out.instances[i].lanes[0..made]) |l| a.free(l);
            for (&out.instances[i].lanes) |*lane| {
                lane.* = try a.alloc(u32, n);
                @memset(lane.*, 0);
                made += 1;
            }
            out.count += 1;
        }
        return out;
    }

    pub fn deinit(self: *Witness) void {
        for (self.instances[0..self.count]) |inst| for (inst.lanes) |lane| self.allocator.free(lane);
        self.count = 0;
    }

    pub fn slice(self: *const Witness) []const Instance {
        return self.instances[0..self.count];
    }

    pub fn clone(self: *const Witness) !Witness {
        var out = try initZero(self.allocator, self.statement);
        errdefer out.deinit();
        for (self.slice(), out.instances[0..out.count]) |src, *dst| {
            for (src.lanes, dst.lanes) |s, d| @memcpy(d, s);
        }
        return out;
    }

    /// Pseudo-random in-range witness (tests only).
    pub fn synthetic(a: std.mem.Allocator, statement: Statement, seed: u64) !Witness {
        var out = try initZero(a, statement);
        errdefer out.deinit();
        var prng = std.Random.DefaultPrng.init(seed);
        const r = prng.random();
        for (out.instances[0..out.count]) |*inst| {
            for (&inst.lanes, 0..) |*lane, j| {
                const bits: u5 = @intCast(if (j < HI_LANES) statement.hi_log else statement.lo_log);
                for (lane.*) |*v| v.* = r.int(u32) & ((@as(u32, 1) << bits) - 1);
            }
        }
        return out;
    }

    /// Table multiplicities. Values outside a table are not counted; the
    /// lookup then cannot balance, which is the honest-prover failure mode.
    pub fn multiplicities(self: *const Witness, a: std.mem.Allocator) !Multiplicities {
        const hi = try a.alloc(u32, @as(usize, 1) << @intCast(self.statement.hi_log));
        errdefer a.free(hi);
        const lo = try a.alloc(u32, @as(usize, 1) << @intCast(self.statement.lo_log));
        @memset(hi, 0);
        @memset(lo, 0);
        var out_of_range: u64 = 0;
        for (self.slice()) |inst| {
            for (inst.lanes, 0..) |lane, j| {
                const table = if (j < HI_LANES) hi else lo;
                for (lane) |v| {
                    if (v < table.len) table[v] += 1 else out_of_range += 1;
                }
            }
        }
        return .{ .hi = hi, .lo = lo, .out_of_range = out_of_range };
    }

    pub fn cells(self: *const Witness) u64 {
        var total: u64 = 0;
        for (self.slice()) |inst| total += LANES * inst.rows();
        return total;
    }
};

pub const Multiplicities = struct {
    hi: []u32,
    lo: []u32,
    out_of_range: u64,
    pub fn deinit(self: *Multiplicities, a: std.mem.Allocator) void {
        a.free(self.hi);
        a.free(self.lo);
    }
};

const MAGIC = "WGKRWIT1";

/// Little-endian: magic, 4 x u32 statement, then each instance's 16 lanes as u16.
pub fn write(w: *const Witness, file: std.fs.File) !void {
    var header: [8 + 16]u8 = undefined;
    @memcpy(header[0..8], MAGIC);
    std.mem.writeInt(u32, header[8..12], w.statement.ls_log, .little);
    std.mem.writeInt(u32, header[12..16], w.statement.tail_log, .little);
    std.mem.writeInt(u32, header[16..20], w.statement.hi_log, .little);
    std.mem.writeInt(u32, header[20..24], w.statement.lo_log, .little);
    var total: usize = header.len;
    for (w.slice()) |inst| total += 2 * LANES * inst.rows();
    const out = try w.allocator.alloc(u8, total);
    defer w.allocator.free(out);
    @memcpy(out[0..header.len], &header);
    var at: usize = header.len;
    for (w.slice()) |inst| for (inst.lanes) |lane| for (lane) |v| {
        if (v > 0xffff) return error.WitnessValueTooWide;
        std.mem.writeInt(u16, out[at..][0..2], @intCast(v), .little);
        at += 2;
    };
    std.debug.assert(at == total);
    try file.writeAll(out);
}

pub fn read(a: std.mem.Allocator, file: std.fs.File) !Witness {
    const size = try file.getEndPos();
    if (size < 24 or size > 1 << 30) return error.InvalidWitnessFile;
    const bytes = try a.alloc(u8, @intCast(size));
    defer a.free(bytes);
    if (try file.preadAll(bytes, 0) != bytes.len) return error.InvalidWitnessFile;
    if (!std.mem.eql(u8, bytes[0..8], MAGIC)) return error.InvalidWitnessFile;
    const statement = Statement{
        .ls_log = std.mem.readInt(u32, bytes[8..12], .little),
        .tail_log = std.mem.readInt(u32, bytes[12..16], .little),
        .hi_log = std.mem.readInt(u32, bytes[16..20], .little),
        .lo_log = std.mem.readInt(u32, bytes[20..24], .little),
    };
    var out = try Witness.initZero(a, statement);
    errdefer out.deinit();
    var expected: usize = 24;
    for (out.slice()) |inst| expected += 2 * LANES * inst.rows();
    if (expected != bytes.len) return error.InvalidWitnessFile;
    var at: usize = 24;
    for (out.instances[0..out.count]) |*inst| for (&inst.lanes) |*lane| for (lane.*) |*v| {
        v.* = std.mem.readInt(u16, bytes[at..][0..2], .little);
        at += 2;
    };
    return out;
}
