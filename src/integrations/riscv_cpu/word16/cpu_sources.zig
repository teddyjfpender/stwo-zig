//! One concrete lifecycle for all local/delegated thin-CPU source columns.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const front = @import("stwo_riscv_frontend");
const air = front.rv64_air;
const W = air.word16_cpu;
const Binary = air.word16_v1;
const ALU = Binary.alu_experiment;
const Tables = air.providers.tables;
const Mat = @import("cpu_materials.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
pub const Claims = struct {
    cpu: W.public.Claims,
    rom: Q,
    boundary: Q,
    range16: Q,
    range8: Q,
    binary: Binary.binary_lookup.Claims,
    and_table: Q,
    pub fn values(self: Claims) [12]Q {
        return .{ self.cpu.register, self.cpu.function, self.cpu.rom, self.cpu.range16, self.cpu.range8, self.rom, self.boundary, self.range16, self.range8, self.binary.and_, self.binary.function, self.and_table };
    }
    pub fn validate(self: Claims, mode: Mat.Mode) !void {
        return self.validateProfile(mode, .binary_v1, .{ .range16 = Q.zero(), .function = Q.zero() });
    }
    pub fn validateProfile(self: Claims, mode: Mat.Mode, profile: W.profile.Profile, alu: ALU.lookup.Claims) !void {
        for (self.values()) |claim| for (claim.toM31Array()) |value| if (value.v >= core.fields.m31.Modulus) return error.NonCanonicalWord16Claim;
        for ([_]Q{ alu.range16, alu.function }) |claim| for (claim.toM31Array()) |value| if (value.v >= core.fields.m31.Modulus) return error.NonCanonicalWord16Claim;
        if (profile == .binary_v1 and (!alu.range16.isZero() or !alu.function.isZero())) return error.NonzeroOmittedThinCpuClaim;
        if (!self.cpu.register.add(self.boundary).isZero() or !self.cpu.rom.add(self.rom).isZero() or !self.cpu.range16.add(self.range16).add(alu.range16).isZero() or !self.cpu.range8.add(self.range8).isZero()) return error.UnclosedThinCpuLocalClaims;
        switch (mode) {
            .local_binary => if (!self.cpu.function.add(self.binary.function).add(alu.function).isZero() or !self.binary.and_.add(self.and_table).isZero()) return error.UnclosedThinCpuFunction,
            .open_function => if (!self.binary.and_.isZero() or !self.binary.function.isZero() or !self.and_table.isZero()) return error.NonzeroOmittedThinCpuClaim,
        }
    }
};
pub const Source = struct {
    allocator: std.mem.Allocator,
    materials: *const Mat.Materials,
    cpu: W.trace.Source,
    rom: W.table_trace.Source,
    range16: W.table_trace.Source,
    range8: W.table_trace.Source,
    boundary: []M = &.{},
    binary: ?Binary.binary_source.Source,
    and_request: ?Tables.Request,
    alu: ?ALU.source.Source = null,
    range16_merged: []u64 = &.{},
    claims: ?Claims = null,
    alu_claims: ?ALU.lookup.Claims = null,
    pub fn init(a: std.mem.Allocator, materials: *const Mat.Materials, public: W.public.Public, records: []const front.rv64.machine.Retirement) !Source {
        try public.validate(materials.geometry.cpu_log);
        if (materials.geometry.profile == .binary_v1 and materials.geometry.mode == .local_binary and public.steps > @as(u32, 1) << @intCast(materials.geometry.binary_log)) return error.ThinCpuBinaryCapacity;
        var cpu = try W.trace.Source.init(a, &materials.program, public, materials.geometry.cpu_log, records);
        errdefer cpu.deinit();
        var alu: ?ALU.source.Source = null;
        errdefer if (alu) |*value| value.deinit();
        var merged: []u64 = &.{};
        errdefer a.free(merged);
        if (materials.geometry.profile == .alu_binary_v2) {
            const narrow = try cpu.aluFacts(a);
            defer a.free(narrow);
            const facts = try a.alloc(ALU.source.Fact, narrow.len);
            defer a.free(facts);
            for (narrow, facts) |fact, *destination| destination.* = .{ .op = fact.op, .a = fact.a, .b = fact.b, .c = fact.c };
            alu = try ALU.source.Source.init(a, facts, materials.geometry.alu_log);
            merged = try a.dupe(u64, cpu.range16_counts);
            for (merged, alu.?.range16_counts) |*count, addition| {
                count.* = std.math.add(u64, count.*, addition) catch return error.Word16MassExceeded;
                if (count.* >= core.fields.m31.Modulus) return error.Word16MassExceeded;
            }
        }
        var rom = try W.table_trace.Source.initRom(a, &materials.program, cpu.rom_counts);
        errdefer rom.deinit();
        var range16 = try W.table_trace.Source.initRange16(a, materials.range16_fixed, if (merged.len != 0) merged else cpu.range16_counts);
        errdefer range16.deinit();
        var range8 = try W.table_trace.Source.initRange8(a, materials.range8_fixed, cpu.range8_counts);
        errdefer range8.deinit();
        var binary: ?Binary.binary_source.Source = null;
        errdefer if (binary) |*value| value.deinit();
        var and_request: ?Tables.Request = null;
        errdefer if (and_request) |*value| value.deinit();
        if (materials.geometry.mode == .local_binary) {
            const facts = try cpu.binaryFacts(a);
            defer a.free(facts);
            binary = try Binary.binary_source.Source.init(a, facts, materials.geometry.binary_log);
            and_request = try Tables.Request.init(a, &materials.and_table.?, binary.?.and_counts);
        }
        return .{ .allocator = a, .materials = materials, .cpu = cpu, .rom = rom, .range16 = range16, .range8 = range8, .binary = binary, .and_request = and_request, .alu = alu, .range16_merged = merged };
    }
    pub fn deinit(self: *Source) void {
        if (self.and_request) |*value| value.deinit();
        if (self.binary) |*value| value.deinit();
        if (self.alu) |*value| value.deinit();
        self.allocator.free(self.boundary);
        self.range8.deinit();
        self.range16.deinit();
        self.rom.deinit();
        self.cpu.deinit();
        self.allocator.free(self.range16_merged);
        self.* = undefined;
    }
    pub fn releaseMain(self: *Source) void {
        self.cpu.releaseMain();
        self.rom.releaseMain();
        self.range16.releaseMain();
        self.range8.releaseMain();
        if (self.binary) |*value| value.releaseMain();
        if (self.alu) |*value| value.releaseMain();
        // AND's tiny multiplicity column supplies its existing generator.
    }
    pub fn columns(self: *const Source, a: std.mem.Allocator, tree: usize) ![]Column {
        if (tree == 0) return self.materials.fixedColumns(a);
        if (tree > 2 or (tree == 2 and self.claims == null)) return error.InvalidThinCpuSourcePhase;
        const shapes = self.materials.shapes();
        var count: usize = 0;
        for (shapes.slice()) |shape| count += shape.widths[tree];
        const result = try a.alloc(Column, count);
        errdefer a.free(result);
        for (shapes.slice()) |shape| {
            const data: []const M = switch (shape.role) {
                .cpu => if (tree == 1) self.cpu.main else self.cpu.interaction,
                .rom => if (tree == 1) self.rom.main else self.rom.interaction,
                .boundary => if (tree == 1) &.{} else self.boundary,
                .range16 => if (tree == 1) self.range16.main else self.range16.interaction,
                .range8 => if (tree == 1) self.range8.main else self.range8.interaction,
                .binary => if (tree == 1) self.binary.?.main else self.binary.?.interaction,
                .alu => if (tree == 1) self.alu.?.main else self.alu.?.interaction,
                .and_table => if (tree == 1) self.and_request.?.main else self.and_request.?.interaction,
            };
            try Mat.fillColumns(result[shape.offsets[tree]..][0..shape.widths[tree]], data, shape.log);
        }
        return result;
    }
    pub fn generate(self: *Source, challenges: W.lookup.Challenges, and_challenges: Tables.Challenges) !Claims {
        if (self.claims != null or self.boundary.len != 0) return error.InvalidThinCpuSourcePhase;
        const range16 = try self.range16.generate(challenges);
        const range8 = try self.range8.generate(challenges);
        const rom = try self.rom.generate(challenges);
        const boundary = try W.boundary_trace.generate(self.allocator, self.materials.boundary_fixed, self.cpu.public, self.materials.geometry.cpu_log, challenges.register);
        self.boundary = boundary.values;
        const cpu = try self.cpu.generate(challenges, self.range16.dictionary, self.range8.dictionary);
        var binary = Binary.binary_lookup.Claims{ .and_ = Q.zero(), .function = Q.zero() };
        var and_table = Q.zero();
        if (self.binary) |*value| binary = try value.generate(.{ .and_ = and_challenges, .function = challenges.function });
        if (self.and_request) |*value| and_table = try value.generateInteraction(and_challenges);
        const alu = if (self.alu) |*value| try value.generate(.{ .range16 = challenges.range16, .function = challenges.function }, self.range16.dictionary) else ALU.lookup.Claims{ .range16 = Q.zero(), .function = Q.zero() };
        const claims = Claims{ .cpu = cpu, .rom = rom, .boundary = boundary.claim, .range16 = range16, .range8 = range8, .binary = binary, .and_table = and_table };
        try claims.validateProfile(self.materials.geometry.mode, self.materials.geometry.profile, alu);
        self.alu_claims = alu;
        self.claims = claims;
        return claims;
    }
};
