//! Per-request multiplicities for immutable ROM/U16/U8 tables. Fixed storage is
//! borrowed from expected materials; exact request counts never enter that key.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const L = @import("layout.zig");
const Lookup = @import("lookup.zig");
const Rom = @import("rom.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
pub const Kind = enum { rom, range16, range8 };
pub const Source = struct {
    allocator: std.mem.Allocator,
    kind: Kind,
    log_size: u32,
    fixed: []const M,
    counts: []const u64,
    main: []M,
    interaction: []M = &.{},
    dictionary: []Q = &.{},
    claim: ?Q = null,
    pub fn initRom(a: std.mem.Allocator, program: *const Rom.Setup, counts_physical: []const u64) !Source {
        return init(a, .rom, program.log_size, program.fixed, counts_physical);
    }
    pub fn initRange16(a: std.mem.Allocator, fixed: []const M, counts: []const u64) !Source {
        return init(a, .range16, 16, fixed, counts);
    }
    pub fn initRange8(a: std.mem.Allocator, fixed: []const M, counts: []const u64) !Source {
        return init(a, .range8, 8, fixed, counts);
    }
    fn init(a: std.mem.Allocator, kind: Kind, log_size: u32, fixed: []const M, counts: []const u64) !Source {
        if (log_size < 5 or log_size > 22) return error.InvalidWord16TableGeometry;
        const n = @as(usize, 1) << @intCast(log_size);
        if (counts.len != n or fixed.len != (if (kind == .rom) @as(usize, 18) else 3) * n) return error.InvalidWord16TableShape;
        var total: u64 = 0;
        for (counts) |count| {
            total = std.math.add(u64, total, count) catch return error.Word16MassExceeded;
            if (total >= core.fields.m31.Modulus) return error.Word16MassExceeded;
        }
        if (kind == .rom) for (counts, 0..) |count, i| {
            if (count != 0 and fixed[i].isZero()) return error.InvalidWord16RomMultiplicity;
        };
        const main = try a.alloc(M, n);
        for (counts, 0..) |count, i| main[if (kind == .rom) i else L.physical(i, log_size)] = M.fromCanonical(@intCast(count));
        return .{ .allocator = a, .kind = kind, .log_size = log_size, .fixed = fixed, .counts = counts, .main = main };
    }
    pub fn size(self: *const Source) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn deinit(self: *Source) void {
        self.allocator.free(self.main);
        self.allocator.free(self.interaction);
        self.allocator.free(self.dictionary);
        self.* = undefined;
    }
    pub fn releaseMain(self: *Source) void {
        self.allocator.free(self.main);
        self.main = &.{};
    }
    pub fn columns(self: *const Source, a: std.mem.Allocator, tree: usize) ![]Column {
        const data = switch (tree) {
            0 => self.fixed,
            1 => self.main,
            2 => self.interaction,
            else => return error.InvalidWord16Tree,
        };
        const n = self.size();
        if (data.len == 0 or data.len % n != 0) return error.InvalidWord16TablePhase;
        const result = try a.alloc(Column, data.len / n);
        for (result, 0..) |*column, i| column.* = .{ .log_size = self.log_size, .values = data[i * n ..][0..n] };
        return result;
    }
    pub fn generate(self: *Source, challenges: Lookup.Challenges) !Q {
        if (self.interaction.len != 0 or self.dictionary.len != 0 or self.counts.len != self.size()) return error.InvalidWord16TablePhase;
        const n = self.size();
        const a = self.allocator;
        const output = try a.alloc(M, 8 * n);
        errdefer a.free(output);
        const dictionary = try a.alloc(Q, n);
        errdefer a.free(dictionary);
        const input = try a.alloc(Q, n);
        defer a.free(input);
        for (input, 0..) |*value, row| {
            const pos = L.physical(row, self.log_size);
            if (self.kind == .rom) {
                var denominator = challenges.rom.offset;
                for (challenges.rom.coefficients, 0..) |coefficient, column| denominator = denominator.sub(coefficient.mulM31(self.fixed[column * n + pos]));
                value.* = denominator;
            } else {
                const ch = if (self.kind == .range16) challenges.range16 else challenges.range8;
                value.* = ch.offset.sub(ch.coefficient.mulM31(self.fixed[pos]));
            }
        }
        try core.fields.batchInverseInPlace(Q, input, dictionary);
        var sum = Q.zero();
        for (0..n) |row| {
            const pos = L.physical(row, self.log_size);
            const count = self.counts[if (self.kind == .rom) pos else row];
            if (count >= core.fields.m31.Modulus) return error.Word16MassExceeded;
            sum = sum.sub(dictionary[row].mulM31(M.fromCanonical(@intCast(count))));
            store(output, n, pos, 0, dictionary[row]);
            store(output, n, pos, 4, sum);
        }
        for (sum.toM31Array(), 0..) |coordinate, i| {
            for (0..n) |row| output[(4 + i) * n + row] = output[(4 + i) * n + row].sub(coordinate);
        }
        self.interaction = output;
        self.dictionary = dictionary;
        self.claim = sum;
        return sum;
    }
};
fn store(values: []M, n: usize, row: usize, column: usize, value: Q) void {
    for (value.toM31Array(), 0..) |coordinate, i| values[(column + i) * n + row] = coordinate;
}
