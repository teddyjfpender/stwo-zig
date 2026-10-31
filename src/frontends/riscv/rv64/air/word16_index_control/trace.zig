//! One direct40-column projection from shared narrow native metadata.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const Base = @import("../word16_cpu/trace.zig");
const Old = @import("../word16_cpu/layout.zig");
const Lookup = @import("../word16_cpu/lookup.zig");
const Eq = @import("equations.zig");
const Authority = @import("authority.zig").Authority;
const Record = @import("../../retirement.zig").Retirement;
const M = core.fields.m31.M31;
const Q = E.Q;
pub const Source = struct {
    allocator: std.mem.Allocator,
    authority: *const Authority,
    base: Base.Source,
    public: Eq.Public,
    main: []M,
    pub fn init(a: std.mem.Allocator, authority: *const Authority, state: @import("../word16_cpu/public.zig").Public, log: u32, records: []const Record) !Source {
        var result = try initMetadata(a, authority, state, log, records);
        errdefer result.deinit();
        try result.fillMain();
        return result;
    }
    pub fn initMetadata(a: std.mem.Allocator, authority: *const Authority, state: @import("../word16_cpu/public.zig").Public, log: u32, records: []const Record) !Source {
        const public = try Eq.resolve(authority, state, log);
        const base = try Base.Source.initMetadata(a, authority.metadataView(), state, log, records);
        return .{ .allocator = a, .authority = authority, .base = base, .public = public, .main = &.{} };
    }
    pub fn fillMain(self: *Source) !void {
        if (self.main.len != 0 or self.base.rows_projected != 0) return error.InvalidIndexProjectionPhase;
        const n = self.base.size();
        const main = try self.allocator.alloc(M, Eq.MAIN * n);
        errdefer self.allocator.free(main);
        for (0..n) |i| {
            const native = self.base.projectDataRow(i);
            const row = self.project(i, &native);
            const pos = Old.physical(i, self.base.log_size);
            for (row, 0..) |value, c| main[c * n + pos] = value;
        }
        self.main = main;
    }

    pub fn deinit(self: *Source) void {
        self.releaseMain();
        self.base.deinit();
        self.* = undefined;
    }
    pub fn releaseMain(self: *Source) void {
        self.allocator.free(self.main);
        self.main = &.{};
    }
    fn project(self: *const Source, index: usize, native: *const [46]M) [Eq.MAIN]M {
        var row: [Eq.MAIN]M = undefined;
        @memcpy(row[2..], native[8..]);
        if (index < self.base.metadata.len) {
            const edge = self.authority.edges[self.base.metadata[index].rom_row];
            row[0] = M.fromCanonical(edge.id);
            row[1] = M.fromCanonical(edge.next_id);
        } else {
            row[0] = M.fromCanonical(self.public.final_id);
            row[1] = row[0];
        }
        return row;
    }
    pub fn rowValues(self: *const Source, index: usize) [Eq.MAIN]M {
        const native = self.base.dataValues(index);
        return self.project(index, &native);
    }
    pub fn generate(self: *Source, data: Lookup.Challenges, rom: Eq.RomChallenges, rom_dictionary: []const Q, range16: []const Q, range8: []const Q) !@import("../word16_cpu/public.zig").Claims {
        const padding = self.rowValues(self.base.size() - 1);
        const fields = Eq.tuple(M, &padding);
        var d = rom.offset;
        for (rom.coefficients, fields) |coefficient, value| d = d.sub(coefficient.mulM31(value));
        return @import("../word16_cpu/interaction.zig").generateWithRomCacheParallel(&self.base, data, range16, range8, .{ .inverses = rom_dictionary, .padding_inverse = try d.inv() }, @import("stwo_prover_engine").work_pool.currentScopedPool());
    }
};
