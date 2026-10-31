//! One direct index witness plus existing qualified truth/range/state sources.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const front = @import("stwo_riscv_frontend");
const air = front.rv64_air;
const I = air.word16_index_control;
const W = air.word16_cpu;
const B = air.word16_v1;
const A = B.alu_experiment;
const Tables = air.providers.tables;
const Mat = @import("materials.zig");
const M = core.fields.m31.M31;
const Q = air.evaluation.Q;
const Column = engine.pcs.ColumnEvaluation;
pub const Challenges = struct { data: W.lookup.Challenges, rom: I.equations.RomChallenges, map: I.equations.MapChallenges, and_: Tables.Challenges };
pub const Claims = struct {
    base: @import("../word16/cpu_sources.zig").Claims,
    alu: A.lookup.Claims,
    map: Q,
    known_map: Q,
    pub fn values(self: Claims) [16]Q {
        const old = self.base.values();
        var out: [16]Q = undefined;
        @memcpy(out[0..12], &old);
        out[12] = self.alu.range16;
        out[13] = self.alu.function;
        out[14] = self.map;
        out[15] = self.known_map;
        return out;
    }
    pub fn validate(self: Claims) !void {
        for (self.values()) |q| for (q.toM31Array()) |c| if (c.v >= core.fields.m31.Modulus) return error.NonCanonicalIndexClaim;
        try self.base.validateProfile(.local_binary, .alu_binary_v2, self.alu);
        if (!self.map.add(self.known_map).isZero()) return error.UnclosedIndexAddressClaims;
    }
};
pub fn mapFunction(ch: I.equations.MapChallenges) B.function_bus.Challenges {
    var result = B.function_bus.Challenges{ .offset = ch.offset, .coefficients = @splat(Q.zero()) };
    @memcpy(result.coefficients[0..5], &ch.coefficients);
    return result;
}
pub fn rosterFor(materials: *const Mat.Materials, pairs: []const Mat.Pair) !B.binary_component.ExpectedRoster {
    if (pairs.len > 32) return error.IndexAddressQueryLimit;
    var roster: B.binary_component.ExpectedRoster = @splat(@splat(M.zero()));
    for (pairs, 0..) |pair, row| {
        try materials.authority.validatePair(pair.id, pair.pc);
        roster[row][0] = M.fromCanonical(@intCast(pair.id));
        const pc = W.public.word(M, pair.pc);
        @memcpy(roster[row][1..5], &pc);
        roster[row][13] = M.one();
    }
    return roster;
}
pub const Source = struct {
    allocator: std.mem.Allocator,
    materials: *const Mat.Materials,
    cpu: I.trace.Source,
    rom: I.rom_trace.Source,
    range16: W.table_trace.Source,
    range8: W.table_trace.Source,
    alu: A.source.Source,
    binary: B.binary_source.Source,
    and_request: Tables.Request,
    merged: []u64,
    map_counts: []u64,
    map_roster: B.binary_component.ExpectedRoster,
    map_main: []M,
    map_interaction: []M = &.{},
    boundary: []M = &.{},
    claims: ?Claims = null,
    generation_started: bool = false,
    pub fn init(a: std.mem.Allocator, materials: *const Mat.Materials, state: W.public.Public, records: []const front.rv64.machine.Retirement, pairs: []const Mat.Pair) !Source {
        _ = try materials.validatePublic(state, pairs);
        const roster = try rosterFor(materials, pairs);
        var cpu = try I.trace.Source.initMetadata(a, &materials.authority, state, materials.geometry.cpu_log, records);
        errdefer cpu.deinit();
        const facts = try cpu.base.aluFacts(a);
        defer a.free(facts);
        const b_facts = try cpu.base.binaryFacts(a);
        defer a.free(b_facts);
        if (facts.len > @as(usize, 1) << @intCast(materials.geometry.alu_log) or b_facts.len > @as(usize, 1) << @intCast(materials.geometry.binary_log)) return error.IndexTruthCapacity;
        var alu = try A.source.Source.init(a, facts, materials.geometry.alu_log);
        errdefer alu.deinit();
        var binary = try B.binary_source.Source.init(a, b_facts, materials.geometry.binary_log);
        errdefer binary.deinit();
        try cpu.fillMain(); // sole CPU-wide writer:40 columns, never46.
        const merged = try a.dupe(u64, cpu.base.range16_counts);
        errdefer a.free(merged);
        for (merged, alu.range16_counts) |*count, addition| {
            count.* = std.math.add(u64, count.*, addition) catch return error.Word16MassExceeded;
            if (count.* >= core.fields.m31.Modulus) return error.Word16MassExceeded;
        }
        const map_counts = try a.alloc(u64, @as(usize, 1) << @intCast(materials.authority.log_size));
        errdefer a.free(map_counts);
        @memset(map_counts, 0);
        for (pairs) |pair| map_counts[W.layout.physical(materials.authority.first_rows[@intCast(pair.id)], materials.authority.log_size)] += 1;
        var rom = try I.rom_trace.Source.init(a, &materials.authority, cpu.base.rom_counts, map_counts);
        errdefer rom.deinit();
        var range16 = try W.table_trace.Source.initRange16(a, materials.range16_fixed, merged);
        errdefer range16.deinit();
        var range8 = try W.table_trace.Source.initRange8(a, materials.range8_fixed, cpu.base.range8_counts);
        errdefer range8.deinit();
        var and_request = try Tables.Request.init(a, &materials.and_table, binary.and_counts);
        errdefer and_request.deinit();
        const map_main = try B.binary_component.expectedMainValues(a, &roster);
        errdefer a.free(map_main);
        return .{ .allocator = a, .materials = materials, .cpu = cpu, .rom = rom, .range16 = range16, .range8 = range8, .alu = alu, .binary = binary, .and_request = and_request, .merged = merged, .map_counts = map_counts, .map_roster = roster, .map_main = map_main };
    }
    pub fn deinit(self: *Source) void {
        self.and_request.deinit();
        self.binary.deinit();
        self.alu.deinit();
        self.rom.deinit();
        self.range16.deinit();
        self.range8.deinit();
        self.cpu.deinit();
        for ([_][]M{ self.map_main, self.map_interaction, self.boundary }) |data| self.allocator.free(data);
        self.allocator.free(self.merged);
        self.allocator.free(self.map_counts);
        self.* = undefined;
    }
    pub fn releaseMain(self: *Source) void {
        self.cpu.releaseMain();
        self.rom.releaseMain();
        self.range16.releaseMain();
        self.range8.releaseMain();
        self.alu.releaseMain();
        self.binary.releaseMain();
        self.allocator.free(self.map_main);
        self.map_main = &.{};
    }
    /// All PCS columns are owned after the interaction commit. Keep only
    /// public parameters, physical claims and still-owned narrow metadata.
    pub fn releaseCommittedInteraction(self: *Source) void {
        std.debug.assert(self.claims != null);
        release(self.allocator, &self.cpu.base.interaction);
        release(self.allocator, &self.rom.interaction);
        release(self.allocator, &self.range16.interaction);
        release(self.allocator, &self.range8.interaction);
        release(self.allocator, &self.alu.interaction);
        release(self.allocator, &self.binary.interaction);
        release(self.allocator, &self.and_request.interaction);
        release(self.allocator, &self.boundary);
        release(self.allocator, &self.map_interaction);
    }
    pub fn columns(self: *const Source, a: std.mem.Allocator, tree: usize) ![]Column {
        if (tree == 0) return self.materials.fixedColumns(a);
        if (tree > 2 or (tree == 2 and self.claims == null)) return error.InvalidIndexSourcePhase;
        const shapes = self.materials.shapes();
        var count: usize = 0;
        for (shapes) |s| count += s.widths[tree];
        const out = try a.alloc(Column, count);
        errdefer a.free(out);
        for (shapes) |s| {
            const data: []const M = switch (s.role) {
                .cpu => if (tree == 1) self.cpu.main else self.cpu.base.interaction,
                .rom => if (tree == 1) self.rom.main else self.rom.interaction,
                .boundary => if (tree == 1) &.{} else self.boundary,
                .alu => if (tree == 1) self.alu.main else self.alu.interaction,
                .binary => if (tree == 1) self.binary.main else self.binary.interaction,
                .and_table => if (tree == 1) self.and_request.main else self.and_request.interaction,
                .range16 => if (tree == 1) self.range16.main else self.range16.interaction,
                .range8 => if (tree == 1) self.range8.main else self.range8.interaction,
                .map_queries => if (tree == 1) self.map_main else self.map_interaction,
            };
            try @import("../word16/cpu_materials.zig").fillColumns(out[s.offsets[tree]..][0..s.widths[tree]], data, s.log);
        }
        return out;
    }
    pub fn generate(self: *Source, ch: Challenges) !Claims {
        if (self.generation_started) return error.InvalidIndexSourcePhase;
        self.generation_started = true;
        const r16 = try self.range16.generate(ch.data);
        const r8 = try self.range8.generate(ch.data);
        const rom = try self.rom.generate(ch.rom, ch.map);
        const boundary = try W.boundary_trace.generate(self.allocator, self.materials.boundary_fixed, self.cpu.public.state, self.materials.geometry.cpu_log, ch.data.register);
        self.boundary = boundary.values;
        const cpu = try self.cpu.generate(ch.data, ch.rom, self.rom.dictionaries[0], self.range16.dictionary, self.range8.dictionary);
        const alu = try self.alu.generate(.{ .range16 = ch.data.range16, .function = ch.data.function }, self.range16.dictionary);
        const binary = try self.binary.generate(.{ .and_ = ch.and_, .function = ch.data.function });
        const and_ = try self.and_request.generateInteraction(ch.and_);
        const map = try self.generateKnownMap(mapFunction(ch.map));
        const claims = Claims{ .base = .{ .cpu = cpu, .rom = rom[0], .boundary = boundary.claim, .range16 = r16, .range8 = r8, .binary = binary, .and_table = and_ }, .alu = alu, .map = rom[1], .known_map = map };
        try claims.validate();
        self.claims = claims;
        return claims;
    }
    fn generateKnownMap(self: *Source, ch: B.function_bus.Challenges) !Q {
        const n = 32;
        const out = try self.allocator.alloc(M, 8 * n);
        errdefer self.allocator.free(out);
        var sum = Q.zero();
        for (self.map_roster, 0..) |row, logical| {
            var d = ch.offset;
            for (ch.coefficients, row[0..13]) |coefficient, value| d = d.sub(coefficient.mulM31(value));
            const inverse = try d.inv();
            sum = sum.add(inverse.mulM31(row[13]));
            const pos = W.layout.physical(logical, 5);
            for (inverse.toM31Array(), 0..) |value, c| out[c * n + pos] = value;
            for (sum.toM31Array(), 0..) |value, c| out[(4 + c) * n + pos] = value;
        }
        for (sum.toM31Array(), 0..) |value, c| for (0..n) |row| {
            out[(4 + c) * n + row] = out[(4 + c) * n + row].sub(value);
        };
        self.map_interaction = out;
        return sum;
    }
};

fn release(a: std.mem.Allocator, data: *[]M) void {
    a.free(data.*);
    data.* = &.{};
}
