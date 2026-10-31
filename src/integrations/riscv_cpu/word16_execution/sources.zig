//! One joined ownership transaction. MAIN is sealed before challenges; narrow
//! advice survives until every physical provider has produced its interaction.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const W = A.word16_cpu;
const B = A.word16_v1;
const Mat = @import("setup.zig");
const P = @import("protocol.zig");
const CPU = @import("cpu_source.zig");
const ROM = @import("rom_source.zig");
const J = @import("jalr_source.zig");
pub const Prepared = @import("prepared.zig").Prepared;
const Memory = @import("memory/prepared.zig");
const AB = @import("arithmetic_bus.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
const Profile = @import("stwo_prover_api").stage_profile;
pub const Source = struct {
    allocator: std.mem.Allocator,
    materials: *const Mat.Materials,
    cpu: CPU.Source,
    rom: ROM.Source,
    alu: B.alu_experiment.source.Source,
    binary: B.binary_source.Source,
    shift: B.shift_word_packed_experiment.source.Source,
    jalr: J.Source,
    division: A.arithmetic.division.trace.Trace,
    multiplication: A.arithmetic.multiplication.trace.Trace,
    memory: Memory.Prepared,
    and_table: A.providers.tables.Request,
    shift_table: B.shift_word_packed_experiment.table.Request,
    range16: W.table_trace.Source,
    range8: W.table_trace.Source,
    counts16: []u64,
    counts8: []u64,
    boundary: []M = &.{},
    claims: ?P.Claims = null,
    pub fn init(a: std.mem.Allocator, materials: *const Mat.Materials, image: Memory.public.Image, public: A.word16_execution.types.Boundary, epoch: u16, tape: *const front.rv64.compact_tape.Tape) !Source {
        return initProfiled(a, materials, image, public, epoch, tape, null);
    }
    pub fn initProfiled(a: std.mem.Allocator, materials: *const Mat.Materials, image: Memory.public.Image, public: A.word16_execution.types.Boundary, epoch: u16, tape: *const front.rv64.compact_tape.Tape, recorder: ?*Profile.Recorder) !Source {
        var native_stage = try Profile.StageScope.begin(recorder, "source_native_advice", "Native CPU advice and family grouping");
        defer native_stage.end();
        var prepared = try Prepared.init(a, &materials.program, public, epoch, materials.geometry.cpu_log, tape, .{ .deduplicate_binary = false, .jalr_log = materials.geometry.jalr_log });
        defer prepared.deinit();
        native_stage.end();
        return fromPreparedProfiled(a, materials, image, &prepared, recorder);
    }
    /// Transfers CPU/JALR ownership on entry after identity/geometry checks.
    /// The caller always deinitializes Prepared to release remaining fact groups.
    /// On failure, transferred witnesses are destroyed here; never reconstructed.
    pub fn fromPrepared(a: std.mem.Allocator, materials: *const Mat.Materials, image: Memory.public.Image, prepared: *Prepared) !Source {
        return fromPreparedProfiled(a, materials, image, prepared, null);
    }
    pub fn fromPreparedProfiled(a: std.mem.Allocator, materials: *const Mat.Materials, image: Memory.public.Image, prepared: *Prepared, recorder: ?*Profile.Recorder) !Source {
        return fromPreparedInternal(a, materials, image, prepared, null, recorder);
    }
    /// Witness-only, consumes owned memory on success AND failure. Accepting
    /// global proofs requires the separate complete-manifest receiver.
    pub fn fromPreparedWithOwnedMemory(a: std.mem.Allocator, materials: *const Mat.Materials, prepared: *Prepared, owned_memory: Memory.Prepared) !Source {
        return fromPreparedWithOwnedMemoryProfiled(a, materials, prepared, owned_memory, null);
    }
    pub fn fromPreparedWithOwnedMemoryProfiled(a: std.mem.Allocator, materials: *const Mat.Materials, prepared: *Prepared, owned_memory: Memory.Prepared, recorder: ?*Profile.Recorder) !Source {
        return fromPreparedInternal(a, materials, null, prepared, owned_memory, recorder);
    }
    fn fromPreparedInternal(a: std.mem.Allocator, materials: *const Mat.Materials, image: ?Memory.public.Image, prepared: *Prepared, owned_memory: ?Memory.Prepared, recorder: ?*Profile.Recorder) !Source {
        var pending_memory = owned_memory;
        errdefer if (pending_memory) |*value| value.deinit();
        const g = materials.geometry;
        try g.validate();
        if (g.omit_empty_division and prepared.division.len != 0) return error.OmittedDivisionRequests;
        // A captured CPU materializes exactly once at the final Program owner;
        // projection failure preserves Prepared's narrow CPU/family advice.
        {
            var stage = try Profile.StageScope.begin(recorder, "source_cpu_materialize", "CPU materialization and final program binding");
            defer stage.end();
            try prepared.ensureCpuMain(&materials.program, g.cpu_log);
        }
        var cpu = try prepared.takeCpu(&materials.program, g.cpu_log);
        errdefer cpu.deinit();
        var jalr = blk: {
            var stage = try Profile.StageScope.begin(recorder, "source_jalr", "Adopt prepared JALR witness");
            defer stage.end();
            break :blk try prepared.takeJalr(g.jalr_log);
        };
        errdefer jalr.deinit();
        var alu = blk: {
            var stage = try Profile.StageScope.begin(recorder, "source_alu", "ALU witness");
            defer stage.end();
            break :blk try B.alu_experiment.source.Source.initWeighted(a, prepared.alu.facts, prepared.alu.weights, g.alu_log);
        };
        errdefer alu.deinit();
        var binary = blk: {
            var stage = try Profile.StageScope.begin(recorder, "source_binary", "BINARY witness");
            defer stage.end();
            break :blk try B.binary_source.Source.initWeighted(a, prepared.binary.facts, prepared.binary.weights, g.binary_log);
        };
        errdefer binary.deinit();
        var shift = blk: {
            var stage = try Profile.StageScope.begin(recorder, "source_shift", "SHIFT witness");
            defer stage.end();
            break :blk if (prepared.shift_weights.len != 0)
                try B.shift_word_packed_experiment.source.Source.initWeighted(a, prepared.shift, prepared.shift_weights, g.shift_log)
            else
                try B.shift_word_packed_experiment.source.Source.init(a, prepared.shift, g.shift_log);
        };
        errdefer shift.deinit();
        var division = blk: {
            var stage = try Profile.StageScope.begin(recorder, "source_division", "DIV witness");
            defer stage.end();
            break :blk try A.arithmetic.division.trace.Trace.initWithLog(a, prepared.division, g.division_log);
        };
        errdefer division.deinit();
        var multiplication = blk: {
            var stage = try Profile.StageScope.begin(recorder, "source_multiplication", "MUL witness");
            defer stage.end();
            break :blk try A.arithmetic.multiplication.trace.Trace.initWithLog(a, prepared.multiplication, g.multiplication_log);
        };
        errdefer multiplication.deinit();
        const epoch = cpu.epoch;
        var memory = blk: {
            var stage = try Profile.StageScope.begin(recorder, "source_memory", if (pending_memory != null) "Adopt prepared memory witnesses" else "Memory witness construction");
            defer stage.end();
            if (pending_memory) |value| {
                pending_memory = null;
                break :blk value;
            }
            break :blk try Memory.Prepared.initIndependentProfiled(a, image.?, cpu.memory.items, epoch, g.ls_log, g.initialLog(), g.terminalLog(), recorder);
        };
        errdefer memory.deinit();
        var rom = blk: {
            var stage = try Profile.StageScope.begin(recorder, "source_rom", "ROM multiplicities");
            defer stage.end();
            break :blk try ROM.Source.init(a, &materials.program, cpu.rom_counts);
        };
        errdefer rom.deinit();
        var count_stage = try Profile.StageScope.begin(recorder, "source_range_counts", "Merge all physical range histograms");
        defer count_stage.end();
        const c16 = try a.dupe(u64, cpu.counts16);
        errdefer a.free(c16);
        const c8 = try a.dupe(u64, cpu.counts8);
        errdefer a.free(c8);
        try addCounts(c16, alu.range16_counts);
        try addCounts(c16, shift.range16_counts);
        try addCounts(c16, memory.counts16);
        try addCounts(c8, &multiplication.byte_counts);
        try addCounts(c8, memory.counts8);
        count_stage.end();
        var range16 = blk: {
            var stage = try Profile.StageScope.begin(recorder, "source_range16", "U16 multiplicities");
            defer stage.end();
            break :blk try W.table_trace.Source.initRange16(a, materials.range16_fixed, c16);
        };
        errdefer range16.deinit();
        var range8 = blk: {
            var stage = try Profile.StageScope.begin(recorder, "source_range8", "U8 multiplicities");
            defer stage.end();
            break :blk try W.table_trace.Source.initRange8(a, materials.range8_fixed, c8);
        };
        errdefer range8.deinit();
        var and_table = blk: {
            var stage = try Profile.StageScope.begin(recorder, "source_and_table", "AND multiplicities");
            defer stage.end();
            break :blk try A.providers.tables.Request.init(a, &materials.and_table, binary.and_counts);
        };
        errdefer and_table.deinit();
        var shift_table = blk: {
            var stage = try Profile.StageScope.begin(recorder, "source_shift_table", "SHIFT table multiplicities");
            defer stage.end();
            break :blk try B.shift_word_packed_experiment.table.Request.init(a, &materials.shift_table, shift.shift_counts);
        };
        errdefer shift_table.deinit();
        {
            var stage = try Profile.StageScope.begin(recorder, "source_fact_retirement", "Retire temporary native family facts");
            defer stage.end();
            cpu.releaseFacts();
            prepared.releaseFacts();
        }
        return .{ .allocator = a, .materials = materials, .cpu = cpu, .rom = rom, .alu = alu, .binary = binary, .shift = shift, .jalr = jalr, .division = division, .multiplication = multiplication, .memory = memory, .and_table = and_table, .shift_table = shift_table, .range16 = range16, .range8 = range8, .counts16 = c16, .counts8 = c8 };
    }
    pub fn request(self: *const Source) P.Request {
        return .{ .cpu = self.cpu.public, .epoch = self.cpu.epoch, .division_requests = @intCast(self.division.count), .multiplication_requests = self.multiplication.count, .memory = self.memory.statement };
    }
    /// Success-only ownership handoff; failure leaves every source unchanged.
    pub fn takeMainForCommit(self: *Source) !@import("main_ownership.zig").Commit {
        return @import("main_ownership.zig").take(self);
    }
    pub fn releaseMain(self: *Source) !void {
        self.cpu.releaseMain();
        self.rom.releaseMain();
        self.alu.releaseMain();
        self.binary.releaseMain();
        self.shift.releaseMain();
        self.jalr.releaseMain();
        try self.division.releaseMain();
        try self.multiplication.releaseMain();
        self.memory.releaseMain();
        self.range16.releaseMain();
        self.range8.releaseMain();
        // Tiny table multiplicity columns supply their existing generators.
    }
    pub fn generate(self: *Source, ch: P.Draw) !P.Claims {
        return self.generateProfiled(ch, null);
    }
    pub fn generateProfiled(self: *Source, ch: P.Draw, recorder: ?*Profile.Recorder) !P.Claims {
        return self.generateInternal(ch, recorder, .closed);
    }
    pub const OpenGlobalRamClaims = struct { physical: P.Claims };
    pub fn generateOpenForGlobalRam(self: *Source, ch: P.Draw) !OpenGlobalRamClaims {
        return .{ .physical = try self.generateInternal(ch, null, .global_ram) };
    }
    pub const OpenKeccakClaims = struct { physical: P.Claims };
    /// Additional OWNER/range debt is accepted ONLY by the concrete joined K
    /// receiver. The old closed and RAM-only paths retain their exact checks.
    pub fn generateForKeccakJoin(self: *Source, ch: P.Draw) !OpenKeccakClaims {
        return .{ .physical = try self.generateInternal(ch, null, .keccak_join) };
    }
    const Closure = enum { closed, global_ram, keccak_join };
    fn generateInternal(self: *Source, ch: P.Draw, recorder: ?*Profile.Recorder, closure: Closure) !P.Claims {
        if (self.claims != null) return error.InvalidWord16ExecutionPhase;
        const old = P.legacy(ch.cpu);
        const r16 = block: {
            var stage = try Profile.StageScope.begin(recorder, "inter_r16_table", "U16 table interactions");
            defer stage.end();
            break :block try self.range16.generate(old);
        };
        const r8 = block: {
            var stage = try Profile.StageScope.begin(recorder, "inter_r8_table", "U8 table interactions");
            defer stage.end();
            break :block try self.range8.generate(old);
        };
        const rom = block: {
            var stage = try Profile.StageScope.begin(recorder, "inter_rom", "Immutable ROM interactions");
            defer stage.end();
            break :block try self.rom.generate(ch.cpu.rom);
        };
        const and_ = block: {
            var stage = try Profile.StageScope.begin(recorder, "inter_and_table", "AND table interactions");
            defer stage.end();
            break :block try self.and_table.generateInteraction(ch.and_);
        };
        const shifts = block: {
            var stage = try Profile.StageScope.begin(recorder, "inter_shift_table", "Packed SHIFT table interactions");
            defer stage.end();
            break :block try self.shift_table.generateInteraction(ch.shift_);
        };
        const boundary = block: {
            var stage = try Profile.StageScope.begin(recorder, "inter_register_boundary", "Public register boundary interactions");
            defer stage.end();
            break :block try W.boundary_trace.generate(self.allocator, self.materials.boundary_fixed, self.cpu.public, self.materials.geometry.cpu_log, old.register);
        };
        self.boundary = boundary.values;
        const cpu = block: {
            var stage = try Profile.StageScope.begin(recorder, "inter_cpu", "CPU register function ROM and range interactions");
            defer stage.end();
            break :block try self.cpu.generate(ch.cpu, .{ .rom = self.rom.dictionary, .range16 = self.range16.dictionary, .range8 = self.range8.dictionary });
        };
        const alu = block: {
            var stage = try Profile.StageScope.begin(recorder, "inter_alu", "ALU interactions");
            defer stage.end();
            break :block try self.alu.generate(.{ .function = old.function, .range16 = old.range16 }, self.range16.dictionary);
        };
        const binary = block: {
            var stage = try Profile.StageScope.begin(recorder, "inter_binary", "BINARY interactions");
            defer stage.end();
            break :block try self.binary.generate(.{ .function = old.function, .and_ = ch.and_ });
        };
        const shift = block: {
            var stage = try Profile.StageScope.begin(recorder, "inter_shift", "SHIFT interactions");
            defer stage.end();
            break :block try self.shift.generate(.{ .function = old.function, .range16 = old.range16, .shift = ch.shift_ }, self.shift_table.dictionary, self.range16.dictionary);
        };
        const jalr = block: {
            var stage = try Profile.StageScope.begin(recorder, "inter_jalr", "Composite JALR interactions");
            defer stage.end();
            break :block try self.jalr.generate(ch.cpu.function);
        };
        const division = if (self.materials.geometry.omit_empty_division) block: {
            try P.validateDivisionClass(self.materials.geometry, @intCast(self.division.count), Q.zero());
            break :block Q.zero();
        } else block: {
            var stage = try Profile.StageScope.begin(recorder, "inter_division", "DIV REM interactions");
            defer stage.end();
            break :block try self.division.generateInteraction(AB.division(ch.cpu.function));
        };
        const multiplication = block: {
            var stage = try Profile.StageScope.begin(recorder, "inter_multiplication", "MUL interactions");
            defer stage.end();
            break :block try A.arithmetic.multiplication.degree3_source.generateLegacy(&self.multiplication, AB.multiplication(ch.cpu.function), ch.cpu.range8.offset);
        };
        const memory = block: {
            var stage = try Profile.StageScope.begin(recorder, "inter_memory", "LS INIT TEARDOWN and selection interactions");
            defer stage.end();
            break :block try self.memory.generateProfiled(ch.memory, self.range16.dictionary, self.range8.dictionary, recorder);
        };
        const claims = P.Claims{ .cpu = cpu, .rom = rom, .regboundary = boundary.claim, .r16 = r16, .r8 = r8, .alu = alu, .binary = binary, .shift = shift, .jalr = jalr, .division = division, .multiplication = multiplication, .and_table = and_, .shift_table = shifts, .ls = memory[0], .initial = memory[1], .terminal = memory[2], .selectiontable = memory[3].selection };
        switch (closure) {
            .closed => try claims.validate(),
            .global_ram => try validateOpenForGlobalRam(claims),
            .keccak_join => try validateCanonicalClaims(claims),
        }
        self.claims = claims;
        return claims;
    }
    pub fn columns(self: *const Source, a: std.mem.Allocator, tree: usize) ![]Column {
        if (tree == 0) return self.materials.fixedColumns(a);
        if (tree > 2 or (tree == 2 and self.claims == null)) return error.InvalidWord16ExecutionPhase;
        const shapes = self.materials.shapes();
        var count: usize = 0;
        for (shapes) |s| count += s.widths[tree];
        const out = try a.alloc(Column, count);
        errdefer a.free(out);
        for (shapes) |s| {
            if (s.widths[tree] == 0) continue;
            const data: []const M = switch (s.role) {
                .cpu => if (tree == 1) self.cpu.main else self.cpu.interaction,
                .rom => if (tree == 1) self.rom.main else self.rom.interaction,
                .boundary => if (tree == 1) &.{} else self.boundary,
                .alu => if (tree == 1) self.alu.main else self.alu.interaction,
                .binary => if (tree == 1) self.binary.main else self.binary.interaction,
                .shift => if (tree == 1) self.shift.main else self.shift.interaction,
                .jalr => if (tree == 1) self.jalr.main else self.jalr.interaction,
                .division => if (tree == 1) self.division.main else self.division.interaction,
                .multiplication => if (tree == 1) self.multiplication.main else self.multiplication.interaction,
                .range16 => if (tree == 1) self.range16.main else self.range16.interaction,
                .range8 => if (tree == 1) self.range8.main else self.range8.interaction,
                .and_table => if (tree == 1) self.and_table.main else self.and_table.interaction,
                .shift_table => if (tree == 1) self.shift_table.main else self.shift_table.interaction,
                .ls => if (tree == 1) self.memory.ls.main else self.memory.ls.interaction,
                .initial => if (tree == 1) self.memory.initial.main else self.memory.initial.interaction,
                .terminal => if (tree == 1) self.memory.terminal.main else self.memory.terminal.interaction,
                .selection => if (tree == 1) self.memory.selection.main else self.memory.selection.interaction,
            };
            try @import("../word16/cpu_materials.zig").fillColumns(out[s.offsets[tree]..][0..s.widths[tree]], data, s.log);
        }
        return out;
    }
    /// Success-only transfer; all physical claims remain available separately.
    pub fn takeInteractionForCommit(self: *Source) !@import("interaction_ownership.zig").Commit {
        return @import("interaction_ownership.zig").take(self);
    }
    pub fn releaseCommittedInteraction(self: *Source) void {
        std.debug.assert(self.claims != null);
        inline for (.{ "cpu", "rom", "alu", "binary", "shift", "jalr", "division", "multiplication", "range16", "range8", "and_table", "shift_table" }) |name| release(self.allocator, &@field(self, name).interaction);
        inline for (.{ "ls", "initial", "terminal", "selection" }) |name| release(self.allocator, &@field(self.memory, name).interaction);
        release(self.allocator, &self.boundary);
    }
    pub fn deinit(self: *Source) void {
        self.range8.deinit();
        self.range16.deinit();
        self.allocator.free(self.counts16);
        self.allocator.free(self.counts8);
        self.shift_table.deinit();
        self.and_table.deinit();
        self.memory.deinit();
        self.multiplication.deinit();
        self.division.deinit();
        self.jalr.deinit();
        self.shift.deinit();
        self.binary.deinit();
        self.alu.deinit();
        self.rom.deinit();
        self.cpu.deinit();
        self.allocator.free(self.boundary);
        self.* = undefined;
    }
};
fn release(a: std.mem.Allocator, values: *[]M) void {
    a.free(values.*);
    values.* = &.{};
}
fn addCounts(out: []u64, input: []const u64) !void {
    if (out.len != input.len) return error.LookupCountShapeMismatch;
    for (out, input) |*o, v| {
        o.* = try std.math.add(u64, o.*, v);
        if (o.* >= core.fields.m31.Modulus) return error.Word16ExecutionMassExceeded;
    }
}

/// Canonical physical values only; this helper deliberately certifies no debt
/// closure. Accepting receivers must additionally enforce their complete roster.
pub fn validateCanonicalClaims(claims: P.Claims) !void {
    const values = claims.values();
    for (values) |q| for (q.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NoncanonicalExecutionClaim;
    for ([_]usize{ 23, 26, 28, 31 }) |index| if (!values[index].isZero()) return error.NonzeroOmittedMemoryClaim;
}
/// Existing RAM-only scope: all local debts must still close exactly.
pub fn validateOpenForGlobalRam(claims: P.Claims) !void {
    try validateCanonicalClaims(claims);
    const values = claims.values();
    var local = Q.zero();
    for (values, 0..) |q, index| if (index != 17 and index != 22 and index != 27) {
        local = local.add(q);
    };
    if (!local.isZero()) return error.UnclosedLocalExecutionRelations;
}
