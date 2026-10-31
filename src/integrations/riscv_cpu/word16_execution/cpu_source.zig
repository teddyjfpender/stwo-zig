//! One pass over narrow captured advice; no interpreter or bulk Retirement copy.
//! The original matrix may be released after sealing. Owned56-byte metadata
//! retains exactly the register values/clocks, dynamic target and ROM row.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const front = @import("stwo_riscv_frontend");
const X = front.rv64_air.word16_execution;
const L = X.layout;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Program = @import("program.zig").Program;
const Tape = front.rv64.compact_tape.Tape;
const Projection = front.rv64_air.word16_cpu.native_projection;
pub const FunctionFact = struct { operation: u8, a: u64, b: u64, c: u64 };
pub const MemoryRecord = struct {
    opcode: front.rv64.decode.Opcode,
    a: u64,
    immediate: u64,
    b: u64,
    c: u64,
    epoch: u16,
    tick: u24,
    effect: front.rv64.machine.MemoryEffect,
};
pub const ServiceRecord = struct { pointer: u64, tag: u64, epoch: u16, tick: u24 };
pub const Metadata = struct { values: [5]u64, clocks: [3]u32, rom_row: u32 };
comptime {
    std.debug.assert(@sizeOf(Metadata) == 56);
}
pub const Source = struct {
    allocator: std.mem.Allocator,
    program: *const Program,
    public: X.types.Boundary,
    epoch: u16,
    log_size: u32,
    metadata: []Metadata,
    main: []M,
    interaction: []M = &.{},
    rom_counts: []u64,
    counts16: []u64,
    counts8: []u64,
    functions: std.ArrayList(FunctionFact) = .empty,
    memory: std.ArrayList(MemoryRecord) = .empty,
    services: std.ArrayList(ServiceRecord) = .empty,
    pub fn init(a: std.mem.Allocator, program: *const Program, public: X.types.Boundary, epoch: u16, log_size: u32, tape: *const Tape) !Source {
        _ = try X.types.inputs(public, epoch, log_size);
        if (tape.len != public.steps or tape.initial_pc != public.initial_pc) return error.InvalidExecutionAdvice;
        const metadata = try a.alloc(Metadata, public.steps);
        errdefer a.free(metadata);
        const rom_counts = try a.alloc(u64, program.size());
        errdefer a.free(rom_counts);
        const counts16 = try a.alloc(u64, 65536);
        errdefer a.free(counts16);
        const counts8 = try a.alloc(u64, 256);
        errdefer a.free(counts8);
        @memset(rom_counts, 0);
        @memset(counts16, 0);
        @memset(counts8, 0);
        var functions: std.ArrayList(FunctionFact) = .empty;
        errdefer functions.deinit(a);
        var memory: std.ArrayList(MemoryRecord) = .empty;
        errdefer memory.deinit(a);
        var services: std.ArrayList(ServiceRecord) = .empty;
        errdefer services.deinit(a);
        var registers = public.initial_registers;
        var clocks: [32]u32 = @splat(0);
        var pc = public.initial_pc;
        for (metadata, 0..) |*meta, index| {
            const word = try program.lookup(pc);
            const entry = program.entries[word];
            if (!entry.valid) return error.UnadmittedExecutionInstruction;
            const record = try tape.restore(index, .{ .raw = entry.raw, .instruction = entry.instruction }, .local);
            const effects = front.rv64.execution_profile.effects(.ethereum_services_v2, entry.instruction.opcode);
            const jump = entry.instruction.opcode == .JAL or entry.dynamic_next;
            if (record.clock != index + 1 or record.pc.toInt() != pc or record.instruction != entry.raw or record.opcode != entry.instruction.opcode or record.rs1 != entry.ids[0] or record.rs2 != entry.ids[1] or record.rd != entry.ids[2] or record.lhs.toInt() != registers[entry.ids[0]] or record.rhs.toInt() != registers[entry.ids[1]] or record.previous_rd.toInt() != (if (effects.writes_rd) registers[entry.ids[2]] else 0) or record.writes_rd != (effects.writes_rd and entry.ids[2] != 0) or record.immediate.toInt() != @as(u64, @bitCast(entry.instruction.imm))) return error.InvalidExecutionAdvice;
            if ((!entry.branch and record.branch_taken != jump) or (entry.branch and record.result.toInt() != 0)) return error.InvalidExecutionAdvice;
            const next = record.next_pc.toInt();
            if (next & 3 != 0 or (!entry.dynamic_next and next != entry.staticNext(entry.branch and record.branch_taken))) return error.InvalidExecutionAdvice;
            const c = if (entry.branch) @intFromBool(record.branch_taken) else record.result.toInt();
            const rom_row = try program.factIndex(word, entry.branch and record.branch_taken);
            meta.* = .{ .values = .{ record.lhs.toInt(), record.rhs.toInt(), c, record.previous_rd.toInt(), next }, .clocks = undefined, .rom_row = @intCast(rom_row) };
            for (entry.ids, 0..) |id, slot| {
                meta.clocks[slot] = if (id == 0) 0 else clocks[id];
                if (id != 0) clocks[id] = @intCast(4 * index + slot + 1);
            }
            rom_counts[L.physical(rom_row, program.log_size)] += 1;
            if (entry.function) {
                if (record.memory != null) return error.InvalidExecutionAdvice;
                try functions.append(a, .{ .operation = entry.operation, .a = if (entry.use_pc) pc else meta.values[0], .b = if (entry.use_immediate) entry.immediate else meta.values[1], .c = if (entry.dynamic_next) next else c });
            } else if (entry.instruction.opcode == .ECALL) {
                if (record.memory != null or c != 0) return error.InvalidExecutionAdvice;
                try services.append(a, .{ .pointer = meta.values[0], .tag = meta.values[1], .epoch = epoch, .tick = @intCast(4 * (index + 1)) });
            } else {
                const effect = record.memory orelse return error.MissingExecutionMemory;
                try memory.append(a, .{ .opcode = entry.instruction.opcode, .a = meta.values[0], .immediate = entry.immediate, .b = meta.values[1], .c = c, .epoch = epoch, .tick = @intCast(4 * (index + 1)), .effect = effect });
            }
            if (effects.writes_rd and entry.ids[2] != 0) registers[entry.ids[2]] = record.result.toInt();
            pc = next;
        }
        if (pc != public.final_pc or !std.mem.eql(u64, &registers, &public.final_registers) or !std.mem.eql(u32, &clocks, &public.register_clocks)) return error.InvalidExecutionBoundary;
        const n = @as(usize, 1) << @intCast(log_size);
        const main = try a.alloc(M, L.main.COUNT * n);
        errdefer a.free(main);
        var self = Source{ .allocator = a, .program = program, .public = public, .epoch = epoch, .log_size = log_size, .metadata = metadata, .main = main, .rom_counts = rom_counts, .counts16 = counts16, .counts8 = counts8, .functions = functions, .memory = memory, .services = services };
        // All validation and allocation precede disjoint physical writes.
        try Projection.fill(a, log_size, .{ .context = &self, .rows = fill }, counts16, counts8, engine.work_pool.currentScopedPool());
        return self;
    }
    fn fill(ctx: *const anyopaque, start: usize, end: usize, counts16: []u64, counts8: []u64) void {
        const self: *const Source = @ptrCast(@alignCast(ctx));
        const n = self.size();
        for (start..end) |physical| {
            const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(physical, self.log_size), self.log_size);
            const values = self.row(logical) catch unreachable; // prevalidated framing.
            for (values, 0..) |value, column| self.main[column * n + physical] = value;
            for (0..3) |slot| {
                counts16[values[L.main.gap16 + slot].v] += 1;
                counts8[values[L.main.gap8 + slot].v] += 1;
            }
        }
    }
    pub fn row(self: *const Source, logical: usize) !X.row.Main {
        if (self.metadata.len != self.public.steps) return error.InvalidExecutionSourcePhase;
        if (logical >= self.size()) return error.InvalidExecutionRow;
        if (logical >= self.metadata.len) return X.row.padding(@intCast(logical), self.public.final_pc);
        const meta = self.metadata[logical];
        const entry = self.program.entries[self.program.row_to_entry[meta.rom_row]];
        return X.row.active(entry, @intCast(logical), meta.values[4], .{ .a = meta.values[0], .b = meta.values[1], .c = meta.values[2], .previous_rd = meta.values[3] }, meta.clocks);
    }
    pub fn size(self: *const Source) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn releaseMain(self: *Source) void {
        self.allocator.free(self.main);
        self.main = &.{};
    }
    pub fn takeMainForCommit(self: *Source) ![]M {
        if (self.main.len == 0) return error.ExecutionMainUnavailable;
        const main = self.main;
        self.main = &.{};
        return main;
    }
    pub fn releaseFacts(self: *Source) void {
        self.functions.deinit(self.allocator);
        self.functions = .empty;
        self.memory.deinit(self.allocator);
        self.memory = .empty;
        self.services.deinit(self.allocator);
        self.services = .empty;
    }
    pub fn deinit(self: *Source) void {
        self.releaseMain();
        self.releaseFacts();
        self.allocator.free(self.interaction);
        self.allocator.free(self.metadata);
        self.allocator.free(self.rom_counts);
        self.allocator.free(self.counts16);
        self.allocator.free(self.counts8);
        self.* = undefined;
    }
    pub fn columns(self: *const Source, a: std.mem.Allocator, tree: u2) ![]engine.pcs.ColumnEvaluation {
        const data = switch (tree) {
            1 => self.main,
            2 => self.interaction,
            else => return error.InvalidExecutionTree,
        };
        if (data.len == 0) return error.InvalidExecutionSourcePhase;
        const result = try a.alloc(engine.pcs.ColumnEvaluation, data.len / self.size());
        for (result, 0..) |*c, i| c.* = .{ .log_size = self.log_size, .values = data[i * self.size() ..][0..self.size()] };
        return result;
    }
    pub fn generate(self: *Source, ch: X.types.Challenges, dictionaries: @import("cpu_interaction.zig").Dictionaries) !Q {
        return @import("cpu_interaction.zig").generate(self, ch, dictionaries, engine.work_pool.currentScopedPool());
    }
};
