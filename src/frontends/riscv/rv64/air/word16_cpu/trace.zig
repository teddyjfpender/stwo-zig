//! Native projection of existing RV64 retirements, not a second interpreter.
//! Only values/three predecessor clocks and immutable ROM row survive. A later
//! interaction phase can reconstruct its affine inputs after main adoption.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Record = @import("../../retirement.zig").Retirement;
const L = @import("layout.zig");
const P = @import("public.zig");
const Profile = @import("profile.zig");
const Rom = @import("rom.zig");
const Lookup = @import("lookup.zig");
const Operations = @import("../word16_v1/operations.zig");
const Binary = @import("../word16_v1/binary_source.zig");
pub const Metadata = struct { values: [4]u64, previous_clocks: [3]u32, rom_row: u32 };
comptime {
    std.debug.assert(@sizeOf(Metadata) == 48);
}
pub const Source = struct {
    allocator: std.mem.Allocator,
    program: *const Rom.Setup,
    public: P.Public,
    log_size: u32,
    metadata: []Metadata,
    main: []M,
    interaction: []M = &.{},
    rom_counts: []u64,
    range16_counts: []u64,
    range8_counts: []u64,
    pub fn init(a: std.mem.Allocator, program: *const Rom.Setup, public: P.Public, log_size: u32, records: []const Record) !Source {
        try public.validate(log_size);
        if (records.len != public.steps) return error.InvalidWord16CpuRecords;
        const metadata = try a.alloc(Metadata, records.len);
        errdefer a.free(metadata);
        const rom_counts = try a.alloc(u64, program.size());
        errdefer a.free(rom_counts);
        @memset(rom_counts, 0);
        var registers = public.initial_registers;
        var clocks: [32]u32 = @splat(0);
        var pc = public.initial_pc;
        // Validate narrow source before allocating any CPU wide matrix. Result
        // truth is proved by the family chips; this pass checks architecture
        // framing and register/clock continuity, without arithmetic replay.
        for (records, metadata, 0..) |record, *meta, index| {
            const word_index = try program.lookup(pc);
            const instruction = program.decoded[word_index];
            const operation = Operations.classify(instruction.opcode).?;
            const ids = Rom.effectiveIds(instruction, program.profile);
            const immediate: u64 = @bitCast(instruction.imm);
            const writes = @import("../../decode.zig").effects(instruction.opcode).writes_rd;
            const taken = operation.branch_predicate and record.branch_taken;
            const expected_next = if (taken) pc +% immediate else pc +% 4;
            if (record.clock != index + 1 or record.pc.toInt() != pc or record.next_pc.toInt() != expected_next or record.instruction != program.words[word_index] or record.opcode != instruction.opcode or record.rs1 != ids[0] or record.rs2 != ids[1] or record.rd != ids[2] or record.lhs.toInt() != registers[ids[0]] or record.rhs.toInt() != registers[ids[1]] or record.previous_rd.toInt() != (if (writes) registers[ids[2]] else 0) or record.writes_rd != (writes and ids[2] != 0) or record.immediate.toInt() != immediate or (record.branch_taken and !operation.branch_predicate) or record.memory != null or (operation.branch_predicate and record.result.toInt() != 0)) return error.InvalidWord16CpuRecords;
            const rom_row = try program.factIndex(word_index, taken);
            meta.* = .{ .values = .{ record.lhs.toInt(), if (operation.use_immediate) immediate else record.rhs.toInt(), if (operation.branch_predicate) @intFromBool(record.branch_taken) else record.result.toInt(), record.previous_rd.toInt() }, .previous_clocks = undefined, .rom_row = @intCast(rom_row) };
            for (ids, 0..) |id, slot| {
                meta.previous_clocks[slot] = if (id == 0) 0 else clocks[id];
                if (id != 0) clocks[id] = @intCast(4 * index + slot + 1);
            }
            if (writes and ids[2] != 0) registers[ids[2]] = record.result.toInt();
            pc = record.next_pc.toInt();
            rom_counts[L.physical(rom_row, program.log_size)] += 1;
        }
        if (pc != public.final_pc or !std.mem.eql(u64, &registers, &public.final_registers) or !std.mem.eql(u32, &clocks, &public.register_clocks)) return error.InvalidWord16CpuBoundary;
        const range16_counts = try a.alloc(u64, 65536);
        errdefer a.free(range16_counts);
        const range8_counts = try a.alloc(u64, 256);
        errdefer a.free(range8_counts);
        @memset(range16_counts, 0);
        @memset(range8_counts, 0);
        const n = @as(usize, 1) << @intCast(log_size);
        const main = try a.alloc(M, Profile.mainCount(program.profile) * n);
        errdefer a.free(main);
        var source = Source{ .allocator = a, .program = program, .public = public, .log_size = log_size, .metadata = metadata, .main = main, .rom_counts = rom_counts, .range16_counts = range16_counts, .range8_counts = range8_counts };
        for (0..n) |row| {
            const values = source.rowValues(row);
            const pos = L.physical(row, log_size);
            for (values[0..Profile.mainCount(program.profile)], 0..) |value, column| main[column * n + pos] = value;
            for (0..3) |slot| {
                range16_counts[values[L.main.gap16 + slot].v] += 1;
                range8_counts[values[L.main.gap8 + slot].v] += 1;
            }
        }
        return source;
    }
    pub fn size(self: *const Source) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn deinit(self: *Source) void {
        self.allocator.free(self.metadata);
        self.allocator.free(self.main);
        self.allocator.free(self.interaction);
        self.allocator.free(self.rom_counts);
        self.allocator.free(self.range16_counts);
        self.allocator.free(self.range8_counts);
        self.* = undefined;
    }
    pub fn releaseMain(self: *Source) void {
        self.allocator.free(self.main);
        self.main = &.{};
    }
    pub fn binaryFacts(self: *const Source, a: std.mem.Allocator) ![]Binary.Fact {
        var count: usize = 0;
        for (self.metadata) |meta| if (Operations.classify(self.program.rowInstruction(meta.rom_row).opcode).?.family == .binary) {
            count += 1;
        };
        const result = try a.alloc(Binary.Fact, count);
        var at: usize = 0;
        for (self.metadata) |meta| {
            const operation = Operations.classify(self.program.rowInstruction(meta.rom_row).opcode).?;
            if (operation.family != .binary) continue;
            result[at] = .{ .op = @enumFromInt(operation.op_id), .a = meta.values[0], .b = meta.values[1], .c = meta.values[2] };
            at += 1;
        }
        return result;
    }
    pub const AluFact = struct { op: Operations.Alu, a: u64, b: u64, c: u64 };
    pub fn aluFacts(self: *const Source, a: std.mem.Allocator) ![]AluFact {
        var count: usize = 0;
        for (self.metadata) |meta| if (Operations.classify(self.program.rowInstruction(meta.rom_row).opcode).?.family == .alu) {
            count += 1;
        };
        const result = try a.alloc(AluFact, count);
        var at: usize = 0;
        for (self.metadata) |meta| {
            const operation = Operations.classify(self.program.rowInstruction(meta.rom_row).opcode).?;
            if (operation.family != .alu) continue;
            result[at] = .{ .op = @enumFromInt(operation.op_id), .a = meta.values[0], .b = meta.values[1], .c = meta.values[2] };
            at += 1;
        }
        return result;
    }
    /// The SAME projection fills committed main and post-commit lookup inputs.
    /// Every PC/NEXT has4x16bits. Padding links unmasked to the final public PC.
    pub fn rowValues(self: *const Source, index: usize) [Profile.MAX_MAIN]M {
        std.debug.assert(index < self.size() and self.metadata.len == self.public.steps);
        var result: [Profile.MAX_MAIN]M = @splat(M.zero());
        if (index < self.metadata.len) {
            const meta = self.metadata[index];
            const pc = self.program.rowPc(meta.rom_row);
            const instruction = self.program.rowInstruction(meta.rom_row);
            const operation = Operations.classify(instruction.opcode).?;
            const pc_word = P.word(M, pc);
            const next_word = P.word(M, self.program.rowNext(meta.rom_row));
            @memcpy(result[L.main.pc..][0..4], &pc_word);
            @memcpy(result[L.main.next_pc..][0..4], &next_word);
            result[L.main.opcode] = M.fromCanonical(operation.busId());
            result[L.main.active] = M.one();
            if (self.program.profile == .alu_binary_v2) {
                result[Profile.immediate] = M.fromCanonical(@intFromBool(operation.use_immediate));
                result[Profile.branch] = M.fromCanonical(@intFromBool(operation.branch_predicate));
            }
            const ids = Rom.effectiveIds(instruction, self.program.profile);
            for (ids, 0..) |id, slot| {
                result[L.main.registers + slot] = M.fromCanonical(id);
                result[L.main.zero + slot] = M.fromCanonical(@intFromBool(id == 0));
                result[L.main.enabled + slot] = M.fromCanonical(@intFromBool(id != 0));
                result[L.main.previous_clock + slot] = M.fromCanonical(meta.previous_clocks[slot]);
            }
            const starts = [_]usize{ L.main.a, L.main.b, L.main.c, L.main.previous_rd };
            for (starts, meta.values) |start, value| {
                const limbs = P.word(M, value);
                @memcpy(result[start..][0..4], &limbs);
            }
        } else {
            const pc_word = P.word(M, self.public.final_pc);
            @memcpy(result[L.main.pc..][0..4], &pc_word);
            @memcpy(result[L.main.next_pc..][0..4], &pc_word);
            for (0..3) |slot| result[L.main.zero + slot] = M.one();
        }
        for (0..3) |slot| {
            const previous = result[L.main.previous_clock + slot].v;
            const now: u32 = @intCast(4 * index + slot + 1);
            std.debug.assert(previous < now);
            const gap = now - previous - 1;
            result[L.main.gap16 + slot] = M.fromCanonical(@as(u16, @truncate(gap)));
            result[L.main.gap8 + slot] = M.fromCanonical(gap >> 16);
        }
        return result;
    }
    pub fn generate(self: *Source, challenges: Lookup.Challenges, range16: []const Q, range8: []const Q) !P.Claims {
        return @import("interaction.zig").generate(self, challenges, range16, range8);
    }
};
