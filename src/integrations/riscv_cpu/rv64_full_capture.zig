//! One execution journal for one complete software CSP request. No windowing,
//! trace replay, or AIR rows are constructed here. Initial state comes from an
//! independently loaded expected ELF/input image, never from retirement advice.
const std = @import("std");
const rv = @import("stwo_riscv_frontend").rv64;
pub const Cell = @import("rv64_full_statement.zig").Cell;
pub const Retirement = rv.machine.Retirement;
pub const MAX_STEPS: u32 = (1 << 22) - 1;
pub const Options = struct { expected_steps: ?u32 = null, max_retirements: u32 = MAX_STEPS };
const State = struct { cell: Cell, clock: u32 };

pub const Capture = struct {
    allocator: std.mem.Allocator,
    records: []Retirement,
    record_capacity: usize,
    program_words: []u32,
    program_addresses: []u64,
    program_base: u64,
    initial_pc: u64,
    final_pc: u64,
    initial_registers: [32]u64,
    final_registers: [32]u64,
    cells: []Cell,
    register_clocks: [32]u32,
    memory_clocks: []u32,
    opcodes: [65]bool,
    histogram: [65]u64,
    output: [32]u8,

    /// Borrowed view valid until this capture is deinitialized.
    pub fn statement(self: *const Capture) @import("rv64_full_statement.zig").Statement {
        return .{ .program = .{ .base = self.program_base, .words = self.program_words, .addresses = self.program_addresses }, .steps = @intCast(self.records.len), .initial_pc = self.initial_pc, .final_pc = self.final_pc, .initial_registers = self.initial_registers, .final_registers = self.final_registers, .cells = self.cells, .register_clocks = self.register_clocks, .memory_clocks = self.memory_clocks, .opcodes = self.opcodes };
    }

    /// Borrows all input bytes only for this call. Owns one bounded retirement
    /// allocation (exact if expected_steps is known); all other output is O(ROM
    /// words + touched cells). Publishes only after completion and digest checks.
    pub fn run(a: std.mem.Allocator, config: rv.csp_contract.Config, elf_bytes: []const u8, input: []const u8, options: Options) !Capture {
        const limit = @min(config.max_steps, options.max_retirements);
        if (limit == 0 or options.max_retirements > MAX_STEPS or config.expected_digest.len != 64) return error.InvalidRv64FullCaptureBudget;
        if (options.expected_steps) |expected| if (expected == 0 or expected > limit) return error.InvalidRv64FullCaptureBudget;
        const capacity: usize = options.expected_steps orelse @as(u32, @intCast(limit));
        const records = try a.alloc(Retirement, capacity);
        errdefer a.free(records);
        var expected_image = try rv.csp_contract.load(a, config, elf_bytes, input);
        defer expected_image.deinit();
        if (try expected_image.memory.load(config.symbols.halt_flag, 4) != 0 or try expected_image.memory.load(config.symbols.output_len, 4) != 0) return error.InvalidRv64FullInitialCompletion;
        const program = try captureProgram(a, &expected_image.memory);
        errdefer {
            a.free(program.words);
            a.free(program.addresses);
        }
        var loaded = try rv.csp_contract.load(a, config, elf_bytes, input);
        defer loaded.deinit();
        var session = try rv.Session.init(a, rv.machine.Cpu.init(loaded.info.entry, config.symbols.stack_top), &loaded.memory, .{ .max_retirements = limit });
        defer session.deinit();
        const initial_registers = session.cpu.regs;
        const initial_pc = session.cpu.pc;
        var states = std.AutoHashMap(u64, State).init(a);
        defer states.deinit();
        var register_clocks: [32]u32 = @splat(0);
        var opcodes: [65]bool = @splat(false);
        var histogram: [65]u64 = @splat(0);
        var count: usize = 0;
        var complete = false;
        while (count < capacity) {
            const record = try session.step();
            records[count] = record;
            if (record.clock != count + 1) return error.InvalidRv64FullJournalClock;
            const opcode: usize = @intFromEnum(record.opcode);
            opcodes[opcode] = true;
            histogram[opcode] += 1;
            const effects = rv.decode.effects(record.opcode);
            const tick: u32 = @intCast(4 * count);
            if (effects.reads_rs1 and record.rs1 != 0) register_clocks[record.rs1] = tick + 1;
            if (effects.reads_rs2 and record.rs2 != 0) register_clocks[record.rs2] = tick + 2;
            if (effects.writes_rd and record.rd != 0) register_clocks[record.rd] = tick + 3;
            if (record.memory) |event| {
                const address = event.address.toInt() & ~@as(u64, 7);
                const found = try states.getOrPut(address);
                if (!found.found_existing) {
                    // Whole-word custody requires all eight bytes mapped. Read
                    // loader backing directly for write-only initial regions.
                    try expected_image.memory.mappings.check(address, 8, .initialize);
                    const initial = expected_image.memory.backing.load(address, 8).value;
                    found.value_ptr.* = .{ .cell = .{ .address = address, .initial = initial, .final = initial, .readable = accessible(&expected_image.memory, address, false), .writable = accessible(&expected_image.memory, address, true) }, .clock = 0 };
                }
                if (found.value_ptr.cell.final != event.before_word.toInt()) return error.InvalidRv64FullJournalMemory;
                found.value_ptr.cell.final = event.after_word.toInt();
                found.value_ptr.clock = tick + 4;
                if (event.write and event.address.toInt() <= config.symbols.halt_flag + 3 and try rv.memory.endAddress(event.address.toInt(), event.width) >= config.symbols.halt_flag) {
                    const flag = try loaded.memory.load(config.symbols.halt_flag, 4);
                    if (flag > 1) return error.InvalidRv64FullCompletion;
                    complete = flag == 1;
                }
            }
            count += 1;
            if (complete) break;
        }
        if (!complete or (options.expected_steps != null and count != options.expected_steps.?)) return error.InvalidRv64FullCompletion;
        if (try loaded.memory.load(config.symbols.output_len, 4) != 32) return error.InvalidRv64FullOutputLength;
        var output: [32]u8 = undefined;
        for (&output, 0..) |*byte, i| byte.* = @intCast(try loaded.memory.load(config.symbols.output_data + i, 1));
        const digest = std.fmt.bytesToHex(output, .lower);
        if (!std.mem.eql(u8, &digest, config.expected_digest)) return error.Rv64FullOutputMismatch;
        const cells = try a.alloc(Cell, states.count());
        errdefer a.free(cells);
        const clocks = try a.alloc(u32, states.count());
        errdefer a.free(clocks);
        var iterator = states.valueIterator();
        var cursor: usize = 0;
        while (iterator.next()) |state| : (cursor += 1) {
            if (loaded.memory.backing.load(state.cell.address, 8).value != state.cell.final) return error.InvalidRv64FullFinalMemory;
            cells[cursor] = state.cell;
        }
        std.mem.sort(Cell, cells, {}, lessCell);
        for (cells, clocks) |cell, *clock| clock.* = states.get(cell.address).?.clock;
        return .{ .allocator = a, .records = records[0..count], .record_capacity = capacity, .program_words = program.words, .program_addresses = program.addresses, .program_base = program.addresses[0], .initial_pc = initial_pc, .final_pc = session.cpu.pc, .initial_registers = initial_registers, .final_registers = session.cpu.regs, .cells = cells, .register_clocks = register_clocks, .memory_clocks = clocks, .opcodes = opcodes, .histogram = histogram, .output = output };
    }
    pub fn deinit(self: *Capture) void {
        self.allocator.free(self.records.ptr[0..self.record_capacity]);
        self.allocator.free(self.program_words);
        self.allocator.free(self.program_addresses);
        self.allocator.free(self.cells);
        self.allocator.free(self.memory_clocks);
        self.* = undefined;
    }
};

const Program = struct { words: []u32, addresses: []u64 };
fn captureProgram(a: std.mem.Allocator, memory: *rv.memory.Memory) !Program {
    var count: usize = 0;
    for (memory.mappings.entries.items) |region| {
        if (!region.permissions.execute) continue;
        if (region.permissions.write or region.first & 3 != 0 or (region.last - region.first + 1) & 3 != 0) return error.InvalidRv64FullExecutable;
        count = std.math.add(usize, count, @intCast((region.last - region.first + 1) / 4)) catch return error.InvalidRv64FullExecutable;
    }
    if (count == 0 or count > 1 << 22) return error.InvalidRv64FullExecutable;
    const words = try a.alloc(u32, count);
    errdefer a.free(words);
    const addresses = try a.alloc(u64, count);
    errdefer a.free(addresses);
    var index: usize = 0;
    // Mappings are independently validated, disjoint and sorted by full u64 PC.
    for (memory.mappings.entries.items) |region| {
        if (!region.permissions.execute) continue;
        const size = (region.last - region.first + 1) / 4;
        for (0..@intCast(size)) |offset| {
            const pc = region.first + 4 * offset;
            addresses[index] = pc;
            words[index] = try memory.fetch(pc);
            index += 1;
        }
    }
    return .{ .words = words, .addresses = addresses };
}
fn accessible(memory: *rv.memory.Memory, address: u64, write: bool) bool {
    memory.mappings.check(address, 8, if (write) .write else .read) catch return false;
    return true;
}
fn lessCell(_: void, lhs: Cell, rhs: Cell) bool {
    return lhs.address < rhs.address;
}
