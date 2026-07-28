//! Authenticated Cairo witness bundle model consumed by CPU code generation.

const std = @import("std");

const magic = "STWZWIT\x00";
const bundle_version: u32 = 1;
const max_entries: u32 = 256;
const max_instructions: u32 = 1_000_000;

pub const Op = enum(u8) {
    input = 0,
    constant = 1,
    m31_add = 2,
    m31_sub = 3,
    m31_mul = 4,
    m31_neg = 5,
    u16_add = 6,
    u16_shl = 7,
    u16_shr = 8,
    u16_and = 9,
    u32_add = 10,
    u32_sub = 11,
    u32_mul = 12,
    u32_shl = 13,
    u32_shr = 14,
    u32_and = 15,
    u32_xor = 16,
    as_m31 = 17,
    trunc16 = 18,
    table_limb = 19,
    col_write = 20,
    mult_push = 21,
    lookup_word = 22,
    sub_word = 23,
    m31_inverse = 24,
    m31_eq = 25,
    deduce_arg = 26,
    deduce_call = 27,
};

pub const Inst = struct {
    op: Op,
    dst: u16,
    a: u32,
    b: u32,
    imm: u32,
};

pub const Program = struct {
    label: []const u8,
    insts: []const Inst,
    n_regs: u32,
    n_inputs: u32,
    n_cols: u32,
    n_mult_tables: u32,
    n_lookup_words: u32,
    n_sub_words: u32,

    pub fn semanticIdentity(self: Program) [32]u8 {
        var hash = std.crypto.hash.Blake3.init(.{});
        hash.update("stwo-cuda-witness-program-semantic-identity-v1\x00");
        hashLittle(&hash, u64, self.insts.len);
        for (self.insts) |inst| {
            hash.update(&.{ @intFromEnum(inst.op), 0 });
            hashLittle(&hash, u16, inst.dst);
            hashLittle(&hash, u32, inst.a);
            hashLittle(&hash, u32, inst.b);
            hashLittle(&hash, u32, inst.imm);
        }
        for ([_]u32{
            self.n_regs,
            self.n_inputs,
            self.n_cols,
            self.n_mult_tables,
            self.n_lookup_words,
            self.n_sub_words,
        }) |count| hashLittle(&hash, u32, count);
        var digest: [32]u8 = undefined;
        hash.final(&digest);
        return digest;
    }
};

pub const Bundle = struct {
    allocator: std.mem.Allocator,
    storage: []u8,
    programs: []Program,

    pub fn read(allocator: std.mem.Allocator, path: []const u8) !Bundle {
        const storage = try std.fs.cwd().readFileAlloc(
            allocator,
            path,
            64 * 1024 * 1024,
        );
        errdefer allocator.free(storage);
        var cursor = Cursor{ .bytes = storage };
        if (!std.mem.eql(u8, try cursor.take(magic.len), magic))
            return error.InvalidMagic;
        if (try cursor.int(u32) != bundle_version)
            return error.UnsupportedVersion;
        const count = try cursor.int(u32);
        if (count == 0 or count > max_entries) return error.InvalidCount;
        const programs = try allocator.alloc(Program, count);
        errdefer allocator.free(programs);
        var initialized: usize = 0;
        errdefer for (programs[0..initialized]) |program|
            allocator.free(program.insts);
        while (initialized < programs.len) : (initialized += 1) {
            const label_len = try cursor.int(u16);
            if (label_len == 0 or try cursor.int(u16) != 0)
                return error.InvalidEntry;
            const n_regs = try cursor.int(u32);
            const n_inputs = try cursor.int(u32);
            const n_cols = try cursor.int(u32);
            const n_mult_tables = try cursor.int(u32);
            const n_lookup_words = try cursor.int(u32);
            const n_sub_words = try cursor.int(u32);
            const instruction_count = try cursor.int(u32);
            _ = try cursor.int(u64);
            if (n_regs == 0 or n_cols == 0 or instruction_count == 0 or
                instruction_count > max_instructions)
                return error.InvalidEntry;
            const label = try cursor.take(label_len);
            const insts = try allocator.alloc(Inst, instruction_count);
            errdefer allocator.free(insts);
            for (insts) |*inst| {
                inst.* = .{
                    .op = std.meta.intToEnum(
                        Op,
                        try cursor.byte(),
                    ) catch return error.InvalidOpcode,
                    .dst = blk: {
                        if (try cursor.byte() != 0)
                            return error.InvalidPadding;
                        break :blk try cursor.int(u16);
                    },
                    .a = try cursor.int(u32),
                    .b = try cursor.int(u32),
                    .imm = try cursor.int(u32),
                };
            }
            programs[initialized] = .{
                .label = label,
                .insts = insts,
                .n_regs = n_regs,
                .n_inputs = n_inputs,
                .n_cols = n_cols,
                .n_mult_tables = n_mult_tables,
                .n_lookup_words = n_lookup_words,
                .n_sub_words = n_sub_words,
            };
        }
        if (cursor.offset != storage.len) return error.TrailingData;
        return .{
            .allocator = allocator,
            .storage = storage,
            .programs = programs,
        };
    }

    pub fn deinit(self: *Bundle) void {
        for (self.programs) |program| self.allocator.free(program.insts);
        self.allocator.free(self.programs);
        self.allocator.free(self.storage);
        self.* = undefined;
    }
};

const Cursor = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn take(self: *Cursor, count: usize) ![]const u8 {
        const end = std.math.add(usize, self.offset, count) catch
            return error.TruncatedBundle;
        if (end > self.bytes.len) return error.TruncatedBundle;
        defer self.offset = end;
        return self.bytes[self.offset..end];
    }

    fn byte(self: *Cursor) !u8 {
        return (try self.take(1))[0];
    }

    fn int(self: *Cursor, comptime T: type) !T {
        const bytes = try self.take(@sizeOf(T));
        const array: *const [@sizeOf(T)]u8 = @ptrCast(bytes.ptr);
        return std.mem.readInt(T, array, .little);
    }
};

fn hashLittle(
    hash: *std.crypto.hash.Blake3,
    comptime T: type,
    value: anytype,
) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
