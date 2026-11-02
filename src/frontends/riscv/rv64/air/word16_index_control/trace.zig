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
const Projection = @import("../word16_cpu/native_projection.zig");
const work = @import("stwo_prover_engine").work_pool;
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
        return self.fillMainImpl(work.currentScopedPool(), null);
    }
    fn fillMainImpl(self: *Source, pool: ?*work.WorkPool, fail_after: ?usize) !void {
        try self.base.public.validate(self.base.log_size);
        if (self.main.len != 0 or self.base.rows_projected != 0 or self.base.metadata.len != self.base.public.steps or self.base.interaction.len != 0) return error.InvalidIndexProjectionPhase;
        if (pool) |active| if (active.stackSize() < Projection.MIN_STACK_BYTES) return error.InvalidNativeProjectionStack;
        const n = self.base.size();
        const main = try self.allocator.alloc(M, Eq.MAIN * n);
        errdefer self.allocator.free(main);
        const rows = NativeRows{ .source = self, .main = main };
        const kernel = Projection.Kernel{ .context = &rows, .rows = NativeRows.run };
        if (comptime @import("builtin").is_test) {
            if (fail_after) |after| {
                try Projection.testing.failSubmission(self.allocator, self.base.log_size, kernel, self.base.range16_counts, self.base.range8_counts, pool.?, after);
            } else try Projection.fill(self.allocator, self.base.log_size, kernel, self.base.range16_counts, self.base.range8_counts, pool);
        } else try Projection.fill(self.allocator, self.base.log_size, kernel, self.base.range16_counts, self.base.range8_counts, pool);
        self.main = main;
        self.base.rows_projected = n;
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

const NativeRows = struct {
    source: *const Source,
    main: []M,
    fn run(ctx: *const anyopaque, start: usize, end: usize, counts16: []u64, counts8: []u64) void {
        const self: *const NativeRows = @ptrCast(@alignCast(ctx));
        const log = self.source.base.log_size;
        const n = self.source.base.size();
        for (start..end) |position| {
            const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(position, log), log);
            const native = self.source.base.dataValues(logical);
            const row = self.source.project(logical, &native);
            for (row, 0..) |value, column| self.main[column * n + position] = value;
            for (0..3) |slot| {
                counts16[native[Old.main.gap16 + slot].v] += 1;
                counts8[native[Old.main.gap8 + slot].v] += 1;
            }
        }
    }
};
pub const testing = if (@import("builtin").is_test) struct {
    pub fn failProjectionSubmission(source: *Source, pool: *work.WorkPool, after: usize) !void {
        return source.fillMainImpl(pool, after);
    }
} else struct {};
