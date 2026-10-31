//! Durable physical full-execution witness. Native chains are checked in logical
//! order; each hint row is generated once in physical order using stack scratch.
//! No wide logical trace is allocated. Narrow relation metadata is retained only
//! until challenge-dependent interaction columns have been published.
//! Statement/program/plan are borrowed until deinit. All column/count buffers
//! belong to this owner; main publication precedes challenge-dependent columns.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64_air;
const execution = frontend.rv64;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const E = rv.evaluation;
const L = rv.layout;
const Frame = rv.full.frame;
const Full = rv.full.component;
const Tables = rv.providers.tables;
const ByteCpu = rv.range.cpu;
const TableCpu = rv.range.table_cpu;
const S = @import("rv64_full_statement.zig");
const work = engine.work_pool;
const service_journal = @import("rv64_service_journal.zig");
const Retirements = @import("rv64_retirements.zig").Source;
const MIN_PROJECTION_STACK = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024;
const MIN_ROWS_PER_WORKER = if (@import("builtin").is_test) 64 else 8192;
pub const MainCommit = @import("rv64_trace_main.zig").Commit;
pub const Trace = struct {
    allocator: std.mem.Allocator,
    statement: S.Statement,
    program: *const rv.program.setup.Setup,
    plan: *const rv.encoding.Plan,
    log_size: u32,
    main: []M,
    /// Original allocation: CPU matrix followed by a reserved provider tail.
    /// `main` is a borrowed prefix and must never be freed separately.
    main_backing: []M,
    borrowed_main: bool = false,
    interaction: []M = &.{},
    service_calls: []rv.crypto.keccak.bridge.trace.Call = &.{},
    secp: ?service_journal.SecpJournal = null,
    byte_counts: [256]u64 = @splat(0),
    and_counts: []u64,
    shift_counts: []u64,
    rom_counts: []u64,
    rom_indices: []u32,
    register_clocks: [32]u32 = @splat(0),
    memory_clocks: []u32,
    state_metadata: []StateRow,
    lookup_metadata: []u8,

    pub fn init(a: std.mem.Allocator, records: []const execution.machine.Retirement, statement: S.Statement, program: *const rv.program.setup.Setup, plan: *const rv.encoding.Plan) !Trace {
        return initWithPool(a, records, statement, program, plan, work.getGlobalPool());
    }
    /// The existing proof pool is borrowed only for the joined projection wave.
    pub fn initWithPool(a: std.mem.Allocator, records: []const execution.machine.Retirement, statement: S.Statement, program: *const rv.program.setup.Setup, plan: *const rv.encoding.Plan, pool: ?*work.WorkPool) !Trace {
        if (plan.execution_profile != .rv64im) return error.InvalidRv64ServiceConstructor;
        return initProfile(a, .{ .journal = records }, &.{}, 1, statement, program, plan, pool, &.{}, .{ 1, 1 }, null);
    }
    pub fn initWithServiceCalls(a: std.mem.Allocator, records: []const execution.machine.Retirement, calls: []const execution.services.Call, first_id: u32, statement: S.Statement, program: *const rv.program.setup.Setup, plan: *const rv.encoding.Plan) !Trace {
        if (plan.execution_profile != .keccak_service_v1) return error.InvalidRv64ServiceConstructor;
        return initProfile(a, .{ .journal = records }, calls, first_id, statement, program, plan, work.getGlobalPool(), &.{}, .{ 1, 1 }, null);
    }
    /// Borrows compact advice only until the joined projection completes.
    /// Wide columns are built once; no full retirement journal is materialized.
    pub fn initWithCompactTape(a: std.mem.Allocator, tape: *const execution.compact_tape.Tape, first_id: u32, statement: S.Statement, program: *const rv.program.setup.Setup, plan: *const rv.encoding.Plan) !Trace {
        if ((plan.execution_profile != .rv64im and plan.execution_profile != .keccak_service_v1) or tape.secp_calls.items.len != 0 or tape.execution_profile != plan.execution_profile or tape.initial_pc != statement.initial_pc) return error.InvalidRv64CompactProfile;
        return initProfile(a, .{ .compact = tape }, tape.service_calls.items, first_id, statement, program, plan, work.getGlobalPool(), &.{}, .{ 1, 1 }, null);
    }
    pub const CallBatch = struct { keccak: []const execution.services.Call = &.{}, secp: []const execution.ethereum_services.SecpCall = &.{}, first_keccak: u32 = 1, first_secp: [2]u32 = .{ 1, 1 } };
    pub const PrivateBoundary = @import("rv64_private_boundary.zig").Boundary;
    pub fn initWithEthereumCalls(a: std.mem.Allocator, records: []const execution.machine.Retirement, calls: CallBatch, statement: S.Statement, program: *const rv.program.setup.Setup, plan: *const rv.encoding.Plan) !Trace {
        if (plan.execution_profile != .ethereum_services_v1 and plan.execution_profile != .ethereum_services_v2) return error.InvalidRv64ServiceConstructor;
        return initProfile(a, .{ .journal = records }, calls.keccak, calls.first_keccak, statement, program, plan, work.getGlobalPool(), calls.secp, calls.first_secp, null);
    }
    pub fn initWithEthereumTape(a: std.mem.Allocator, tape: *const execution.compact_tape.Tape, first_keccak: u32, first_secp: [2]u32, statement: S.Statement, program: *const rv.program.setup.Setup, plan: *const rv.encoding.Plan) !Trace {
        if ((plan.execution_profile != .ethereum_services_v1 and plan.execution_profile != .ethereum_services_v2) or tape.execution_profile != plan.execution_profile or tape.initial_pc != statement.initial_pc) return error.InvalidRv64CompactProfile;
        return initProfile(a, .{ .compact = tape }, tape.service_calls.items, first_keccak, statement, program, plan, work.getGlobalPool(), tape.secp_calls.items, first_secp, null);
    }
    pub fn initWithPrivateBoundary(a: std.mem.Allocator, records: []const execution.machine.Retirement, calls: CallBatch, public: S.Statement, boundary: PrivateBoundary, program: *const rv.program.setup.Setup, plan: *const rv.encoding.Plan) !Trace {
        const native = try boundary.native(public);
        if (plan.execution_profile == .rv64im) {
            if (calls.keccak.len != 0 or calls.secp.len != 0) return error.InvalidRv64ServiceConstructor;
            return init(a, records, native, program, plan);
        }
        if (plan.execution_profile == .keccak_service_v1 and calls.secp.len != 0) return error.InvalidRv64ServiceConstructor;
        return if (plan.execution_profile == .keccak_service_v1) initWithServiceCalls(a, records, calls.keccak, calls.first_keccak, native, program, plan) else initWithEthereumCalls(a, records, calls, native, program, plan);
    }
    pub fn initWithPrivateTape(a: std.mem.Allocator, tape: *const execution.compact_tape.Tape, first_keccak: u32, first_secp: [2]u32, public: S.Statement, boundary: PrivateBoundary, program: *const rv.program.setup.Setup, plan: *const rv.encoding.Plan) !Trace {
        const native = try boundary.native(public);
        return if (plan.execution_profile == .keccak_service_v1 or plan.execution_profile == .rv64im) initWithCompactTape(a, tape, first_keccak, native, program, plan) else initWithEthereumTape(a, tape, first_keccak, first_secp, native, program, plan);
    }
    /// Writes the original physical CPU matrix directly into an outer owned
    /// arena. Metadata remains allocated independently and survives sealing.
    pub fn initWithPrivateTapeBorrowedMain(a: std.mem.Allocator, tape: *const execution.compact_tape.Tape, first_keccak: u32, first_secp: [2]u32, public: S.Statement, boundary: PrivateBoundary, program: *const rv.program.setup.Setup, plan: *const rv.encoding.Plan, main: []M) !Trace {
        if (tape.execution_profile != plan.execution_profile or tape.initial_pc != public.initial_pc or
            (plan.execution_profile == .rv64im and (tape.service_calls.items.len != 0 or tape.secp_calls.items.len != 0)) or
            (plan.execution_profile == .keccak_service_v1 and tape.secp_calls.items.len != 0)) return error.InvalidRv64CompactProfile;
        const native = try boundary.native(public);
        return initProfile(a, .{ .compact = tape }, tape.service_calls.items, first_keccak, native, program, plan, work.getGlobalPool(), tape.secp_calls.items, first_secp, main);
    }
    fn initProfile(a: std.mem.Allocator, records: Retirements, calls: []const execution.services.Call, first_id: u32, statement: S.Statement, program: *const rv.program.setup.Setup, plan: *const rv.encoding.Plan, pool: ?*work.WorkPool, secp_calls: []const execution.ethereum_services.SecpCall, first_secp: [2]u32, borrowed_main: ?[]M) !Trace {
        try statement.validateWithProfile(plan.execution_profile);
        if (borrowed_main) |main| try @import("rv64_trace_main_admission.zig").validate(main, records, calls, secp_calls, statement, program, plan);
        if (calls.len > records.len() or first_id == 0 or @as(u64, first_id) + calls.len > core.fields.m31.Modulus) return error.InvalidRv64ServiceCallSpan;
        const service_calls: []rv.crypto.keccak.bridge.trace.Call = if (plan.execution_profile != .rv64im) try a.alloc(rv.crypto.keccak.bridge.trace.Call, calls.len) else &.{};
        errdefer a.free(service_calls);
        if (calls.len + secp_calls.len > records.len()) return error.InvalidRv64ServiceCallSpan;
        var secp: ?service_journal.SecpJournal = if (plan.execution_profile == .ethereum_services_v1 or plan.execution_profile == .ethereum_services_v2) try service_journal.SecpJournal.init(a, secp_calls, first_secp, statement.steps, plan.execution_profile) else null;
        errdefer if (secp) |*journal| journal.deinit();
        if (records.len() != statement.steps or !plan.wide_clocks or !plan.byte_operations) return error.InvalidRv64FullTrace;
        for (statement.opcodes, plan.allowed_opcodes) |expected, actual| if (expected != actual) return error.InvalidRv64FullTracePlan;
        const log_size = statement.logSize();
        try (Frame.Public{ .steps = statement.steps, .initial_pc = statement.initial_pc, .final_pc = statement.final_pc }).validate(log_size);
        const size = @as(usize, 1) << @intCast(log_size);
        const main_cells = try std.math.mul(usize, plan.main_count + Frame.widthWithControl(plan.execution_profile, plan.control_policy), size);
        const provider_cells = try std.math.add(usize, try std.math.add(usize, program.domainSize(), 256), try std.math.add(usize, if (plan.byte_bitwise) Tables.Kind.byte_and.size() else 0, if (plan.support.shifts) Tables.Kind.byte_shift.size() else 0));
        if (borrowed_main) |values| if (values.len != main_cells) return error.InvalidRv64BorrowedMainShape;
        const main_backing: []M = if (borrowed_main == null) try a.alloc(M, try std.math.add(usize, main_cells, provider_cells)) else &.{};
        errdefer a.free(main_backing);
        const main = borrowed_main orelse main_backing[0..main_cells];
        const and_counts = try a.alloc(u64, if (plan.byte_bitwise) Tables.Kind.byte_and.size() else 0);
        errdefer a.free(and_counts);
        @memset(and_counts, 0);
        const shift_counts = try a.alloc(u64, if (plan.support.shifts) Tables.Kind.byte_shift.size() else 0);
        errdefer a.free(shift_counts);
        @memset(shift_counts, 0);
        const rom_counts = try a.alloc(u64, program.domainSize());
        errdefer a.free(rom_counts);
        @memset(rom_counts, 0);
        const memory_clocks = try a.alloc(u32, statement.cells.len);
        errdefer a.free(memory_clocks);
        @memset(memory_clocks, 0);
        const rom_indices = try a.alloc(u32, size);
        errdefer a.free(rom_indices);
        @memset(rom_indices, std.math.maxInt(u32));
        const state_metadata = try a.alloc(StateRow, records.len() + 1);
        errdefer a.free(state_metadata);
        const lookup_width = lookupWidth(plan);
        const lookup_metadata = try a.alloc(u8, try std.math.mul(usize, records.len() + 1, lookup_width));
        errdefer a.free(lookup_metadata);
        const memory_values = try a.alloc(u64, statement.cells.len);
        defer a.free(memory_values);
        for (memory_values, statement.cells) |*value, cell| value.* = cell.initial;
        var self = Trace{ .allocator = a, .statement = statement, .program = program, .plan = plan, .log_size = log_size, .main = main, .main_backing = main_backing, .borrowed_main = borrowed_main != null, .and_counts = and_counts, .shift_counts = shift_counts, .rom_counts = rom_counts, .rom_indices = rom_indices, .memory_clocks = memory_clocks, .state_metadata = state_metadata, .lookup_metadata = lookup_metadata, .service_calls = service_calls, .secp = secp };
        var registers = statement.initial_registers;
        var pc = statement.initial_pc;
        var physical: [L.MAIN]M = undefined;
        // Canonical padding is one constant physical row. Fill columns in
        // contiguous order, count that row with multiplicity, and overwrite
        // active positions below. This avoids rebuilding every padding row.
        const zero_row: rv.rows.Main = @splat(M.zero());
        for (physical[0..plan.main_count], 0..) |*value, c| value.* = plan.projectValue(&zero_row, c);
        state_metadata[records.len()] = StateRow.fromLogical(&zero_row);
        try self.countRow(&zero_row, physical[0..plan.main_count], @intCast(size - records.len()), lookup_metadata[records.len() * lookup_width ..][0..lookup_width]);
        if (size > records.len()) {
            for (physical[0..plan.main_count], 0..) |value, c| @memset(main[c * size ..][0..size], value);
            const zero_rom: rv.program.setup.Row = @splat(M.zero());
            var padding_storage: [Frame.WIDTH]M = undefined;
            const padding_advice = padding_storage[0..Frame.bodyWidth(plan.control_policy)];
            Frame.fillFromRowBaseWithControl(padding_advice, &zero_rom, statement.final_pc, false, plan.control_policy);
            for (padding_advice, 0..) |value, c| @memset(main[(plan.main_count + c) * size ..][0..size], value);
        }
        const decoded = program.decoded;
        var service_at: usize = 0;
        var secp_at: usize = 0;
        // The native clock/value chain is sequential. It creates only narrow
        // metadata and visits each retirement once, without generating hints.
        for (0..records.len()) |i| {
            if (records.pc(i) != pc) return error.InvalidRv64FullRetirement;
            const rom_index = try program.lookup(pc);
            self.rom_indices[i] = @intCast(rom_index);
            // lookup rejects invalid ROM rows before their decode advice is used.
            const entry = decoded[rom_index];
            const record = try records.record(i, entry.raw, entry.instruction);
            if (record.clock != i + 1 or record.pc.toInt() != pc) return error.InvalidRv64FullRetirement;
            if (entry.raw != record.instruction or record.opcode != entry.instruction.opcode or !plan.allowed_opcodes[@intFromEnum(record.opcode)]) return error.InvalidRv64FullRetirement;
            const instruction = entry.instruction;
            const effects = execution.execution_profile.effects(plan.execution_profile, instruction.opcode);
            var previous: [4]u32 = @splat(0);
            if (effects.reads_rs1 and record.lhs.toInt() != registers[instruction.rs1]) return error.InvalidRv64FullRegisterChain;
            if (effects.reads_rs2 and record.rhs.toInt() != registers[instruction.rs2]) return error.InvalidRv64FullRegisterChain;
            for ([_]u5{ instruction.rs1, instruction.rs2, instruction.rd }, 0..) |reg, slot| {
                if (!entry.enabled[slot]) continue;
                previous[slot] = self.register_clocks[reg];
                self.register_clocks[reg] = @intCast(4 * i + slot + 1);
            }
            if (entry.enabled[2]) {
                if (record.previous_rd.toInt() != registers[instruction.rd]) return error.InvalidRv64FullRegisterChain;
                registers[instruction.rd] = record.result.toInt();
            }
            var rights = execution.memory.Permissions{};
            if (record.memory) |event| {
                const index = try memoryIndex(statement.cells, event.address.toInt() & ~@as(u64, 7));
                if (event.before_word.toInt() != memory_values[index]) return error.InvalidRv64FullMemoryChain;
                memory_values[index] = event.after_word.toInt();
                previous[3] = memory_clocks[index];
                memory_clocks[index] = @intCast(4 * i + 4);
                rights = .{ .read = statement.cells[index].readable, .write = statement.cells[index].writable };
            } else if (entry.enabled[3]) return error.InvalidRv64FullMemoryChain;
            for (entry.enabled, previous, 0..) |enabled, before, slot| {
                if (enabled and (before >= 4 * i + slot + 1 or 4 * i + slot + 1 >= 1 << 24)) return error.InvalidRv64FullClock;
            }
            if (plan.execution_profile != .rv64im) {
                var flags: [3]bool = @splat(false);
                if (instruction.opcode == .ECALL) {
                    if (record.rhs.toInt() == execution.execution_profile.KECCAK_TAG) {
                        if (service_at == calls.len) return error.MissingRv64ServiceCall;
                        service_calls[service_at] = try service_journal.merge(try records.localCall(calls[service_at]), record, first_id, service_at, statement, memory_values, memory_clocks);
                        service_at += 1;
                        flags[0] = true;
                    } else if (self.secp) |*journal| {
                        if (secp_at == secp_calls.len) return error.MissingRv64ServiceCall;
                        const kind = try journal.mergeAt(try records.localSecpCall(secp_calls[secp_at]), record, statement, memory_values, memory_clocks);
                        secp_at += 1;
                        flags[1 + kind] = true;
                    } else return error.InvalidRv64ServiceTag;
                }
                const row = rv.witness.physical(i, log_size);
                main[(plan.main_count + Frame.keccakCount(plan.control_policy)) * size + row] = M.fromCanonical(@intCast(service_at));
                if (self.secp) |*journal| journal.writeAdvice(main, plan.main_count + Frame.serviceFlags(plan.control_policy), size, row, flags);
            }
            state_metadata[i] = StateRow.fromRetirement(record, previous, rights);
            pc = record.next_pc.toInt();
            self.rom_counts[rom_index] = try std.math.add(u64, self.rom_counts[rom_index], 1);
        }
        if (service_at != calls.len or secp_at != secp_calls.len) return error.InvalidRv64ServiceCallCensus;
        if (self.secp) |*journal| try journal.complete();
        if (plan.execution_profile != .rv64im) for (records.len()..size) |i| {
            const row = rv.witness.physical(i, log_size);
            main[(plan.main_count + Frame.keccakCount(plan.control_policy)) * size + row] = M.fromCanonical(@intCast(service_at));
            if (self.secp) |*journal| journal.writeAdvice(main, plan.main_count + Frame.serviceFlags(plan.control_policy), size, row, .{ false, false, false });
        };
        if (pc != statement.final_pc or !std.mem.eql(u64, &registers, &statement.final_registers) or !std.mem.eql(u32, &self.register_clocks, &statement.register_clocks) or !std.mem.eql(u32, memory_clocks, statement.memory_clocks)) return error.InvalidRv64FullFinalState;
        for (statement.cells, memory_values) |cell, value| if (cell.final != value) return error.InvalidRv64FullFinalState;
        const projection = ProjectionContext{ .records = records, .program = program, .plan = plan, .decoded = decoded, .state_metadata = state_metadata, .rom_indices = rom_indices, .columns = main, .lookup_metadata = lookup_metadata, .size = size, .log_size = log_size, .lookup_width = lookup_width };
        try projectPhysical(a, &projection, .{ .bytes = &self.byte_counts, .bitwise = and_counts, .shifts = shift_counts }, pool);
        return self;
    }
    fn countRow(self: *Trace, logical: *const rv.rows.Main, physical: []const M, multiplicity: u64, metadata: []u8) !void {
        return countProjectionRow(self.plan, .{ .bytes = &self.byte_counts, .bitwise = self.and_counts, .shifts = self.shift_counts }, logical, physical, multiplicity, metadata);
    }
    /// Narrow prover advice from the already validated journal metadata. The
    /// CPU bus AIR authenticates every cached tuple after source commitment.
    pub fn divisionRequests(self: *const Trace, a: std.mem.Allocator) ![]rv.arithmetic.division.cpu_bus.IndexedRequest {
        if (self.plan.arithmetic_policy == .inline_v4 or self.state_metadata.len != self.statement.steps + 1 or self.rom_indices.len < self.statement.steps) return error.InvalidRv64FullTracePhase;
        var count: usize = 0;
        for (self.program.rows, self.rom_counts[0..self.program.rows.len]) |row, multiplicity| {
            const op: execution.decode.Opcode = @enumFromInt(row[rv.program.setup.field.opcode].v);
            if (rv.operations.div(op)) count = try std.math.add(usize, count, @intCast(multiplicity));
        }
        if (count > self.statement.steps) return error.InvalidRv64FullRomCounts;
        const result = try a.alloc(rv.arithmetic.division.cpu_bus.IndexedRequest, count);
        errdefer a.free(result);
        var cursor: usize = 0;
        for (0..self.statement.steps) |i| {
            const index = self.rom_indices[i];
            if (index >= self.program.rows.len) return error.InvalidRv64FullRomCounts;
            const op: execution.decode.Opcode = @enumFromInt(self.program.rows[index][rv.program.setup.field.opcode].v);
            if (!rv.operations.div(op)) continue;
            if (cursor == result.len) return error.InvalidRv64FullRomCounts;
            const words = self.state_metadata[i].words;
            result[cursor] = .{ .row = @intCast(i), .request = .{ .opcode = op, .a = words[0], .b = words[1], .result = words[3] } };
            cursor += 1;
        }
        if (cursor != result.len) return error.InvalidRv64FullRomCounts;
        return result;
    }

    pub fn multiplicationRequests(self: *const Trace, a: std.mem.Allocator) ![]rv.arithmetic.multiplication.cpu_bus.IndexedRequest {
        if (self.plan.arithmetic_policy != .division_multiplication_services_v3 or self.state_metadata.len != self.statement.steps + 1 or self.rom_indices.len < self.statement.steps) return error.InvalidRv64FullTracePhase;
        var count: usize = 0;
        for (self.program.rows, self.rom_counts[0..self.program.rows.len]) |row, multiplicity| {
            const op: execution.decode.Opcode = @enumFromInt(row[rv.program.setup.field.opcode].v);
            if (rv.operations.mul(op)) count = try std.math.add(usize, count, @intCast(multiplicity));
        }
        if (count > self.statement.steps) return error.InvalidRv64FullRomCounts;
        const result = try a.alloc(rv.arithmetic.multiplication.cpu_bus.IndexedRequest, count);
        errdefer a.free(result);
        var cursor: usize = 0;
        for (0..self.statement.steps) |i| {
            const index = self.rom_indices[i];
            if (index >= self.program.rows.len) return error.InvalidRv64FullRomCounts;
            const op: execution.decode.Opcode = @enumFromInt(self.program.rows[index][rv.program.setup.field.opcode].v);
            if (!rv.operations.mul(op)) continue;
            if (cursor == result.len) return error.InvalidRv64FullRomCounts;
            const words = self.state_metadata[i].words;
            result[cursor] = .{ .row = @intCast(i), .request = .{ .opcode = op, .a = words[0], .b = words[1], .result = words[3] } };
            cursor += 1;
        }
        if (cursor != result.len) return error.InvalidRv64FullRomCounts;
        return result;
    }

    pub fn validateCommitAllocator(self: *const Trace, a: std.mem.Allocator) !void {
        if (!rv.memory.ownership.same(a, self.allocator)) return error.Rv64FullCommitAllocatorMismatch;
    }
    pub const takeMainForCommit = @import("rv64_trace_main.zig").take;
    /// After the main commitment is sealed, release only owned storage. An
    /// outer borrowed arena may already hold in-place retained coefficients.
    pub fn releaseMain(self: *Trace) !void {
        if (self.main.len != (self.plan.main_count + Frame.widthWithControl(self.plan.execution_profile, self.plan.control_policy)) * self.domainSize() or
            (self.borrowed_main and self.main_backing.len != 0) or
            (!self.borrowed_main and self.main_backing.len < self.main.len)) return error.InvalidRv64FullMainPhase;
        if (!self.borrowed_main) self.allocator.free(self.main_backing);
        self.main = &.{};
        self.main_backing = &.{};
    }

    /// Retire source evaluations only AFTER the PCS has sealed/copied them.
    /// The coordinator keeps the transcript-bound claims and authenticated PCS
    /// owner through proving; releasing this redundant buffer closes no debt.
    /// Idempotent so ordinary Trace teardown remains safe on every later error.
    pub fn releaseCommittedInteraction(self: *Trace) void {
        self.allocator.free(self.interaction);
        self.interaction = &.{};
    }

    pub fn deinit(self: *Trace) void {
        self.allocator.free(self.main_backing);
        self.allocator.free(self.service_calls);
        if (self.secp) |*journal| journal.deinit();
        self.allocator.free(self.interaction);
        self.allocator.free(self.and_counts);
        self.allocator.free(self.shift_counts);
        self.allocator.free(self.rom_counts);
        self.allocator.free(self.rom_indices);
        self.allocator.free(self.memory_clocks);
        self.allocator.free(self.state_metadata);
        self.allocator.free(self.lookup_metadata);
        self.* = undefined;
    }
    pub fn domainSize(self: *const Trace) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn byteStart(self: *const Trace) usize {
        return self.plan.stateInteractionCount() + 8;
    }
    pub fn andStart(self: *const Trace) usize {
        return self.byteStart() + ByteCpu.interactionCount(self.plan);
    }
    pub fn shiftStart(self: *const Trace) usize {
        return self.andStart() + TableCpu.interactionCount(self.plan, .byte_and);
    }
    pub fn interactionCount(self: *const Trace) usize {
        return self.shiftStart() + TableCpu.interactionCount(self.plan, .byte_shift);
    }
    pub fn columns(self: *const Trace, a: std.mem.Allocator, tree: u2) ![]engine.pcs.ColumnEvaluation {
        const storage = switch (tree) {
            1 => self.main,
            2 => self.interaction,
            else => return error.InvalidRv64FullTree,
        };
        const result = try a.alloc(engine.pcs.ColumnEvaluation, storage.len / self.domainSize());
        for (result, 0..) |*column, c| column.* = .{ .log_size = self.log_size, .values = storage[c * self.domainSize() ..][0..self.domainSize()] };
        return result;
    }

    /// Families write directly to final storage. Dictionary inverses are cached;
    /// state denominators use bounded 512-row batches (one inverse per 4096
    /// events). Failure leaves interaction unpublished and frees all scratch.
    pub fn generateInteraction(self: *Trace, challenges: Full.Challenges) !Full.Claims {
        return self.generateInteractionWithPool(challenges, work.getGlobalPool());
    }
    pub fn generateInteractionWithPool(self: *Trace, challenges: Full.Challenges, pool: ?*work.WorkPool) !Full.Claims {
        const metadata_rows = @as(usize, self.statement.steps) + 1;
        if (self.interaction.len != 0 or self.state_metadata.len != metadata_rows or
            self.lookup_metadata.len != metadata_rows * lookupWidth(self.plan) or self.rom_indices.len != self.domainSize()) return error.InvalidRv64FullTracePhase;
        const size = self.domainSize();
        const data = try self.allocator.alloc(M, try std.math.mul(usize, size, self.interactionCount()));
        errdefer self.allocator.free(data);
        @memset(data, M.zero());
        var byte_inverses: [256]Q = undefined;
        for (&byte_inverses, 0..) |*inverse, value| inverse.* = try challenges.bytes.sub(E.q(@intCast(value))).inv();
        const and_inverses = try tableInverses(self.allocator, .byte_and, self.and_counts, challenges.bitwise);
        defer self.allocator.free(and_inverses);
        const shift_inverses = try tableInverses(self.allocator, .byte_shift, self.shift_counts, challenges.shifts);
        defer self.allocator.free(shift_inverses);
        const rom_inverses = try self.allocator.alloc(Q, self.rom_counts.len);
        defer self.allocator.free(rom_inverses);
        for (rom_inverses, self.rom_counts, 0..) |*inverse, count, i| {
            inverse.* = Q.zero();
            if (count == 0) continue;
            if (i >= self.program.rows.len) return error.InvalidRv64FullRomCount;
            const compact_entry = rv.program.compact.fromRow(&self.program.rows[i]);
            const entry = rv.program.compact.expand(&compact_entry);
            inverse.* = try challenges.rom.denominator(&entry).inv();
        }
        const context = InteractionContext{ .program = self.program, .plan = self.plan, .steps = self.statement.steps, .log_size = self.log_size, .size = size, .state_metadata = self.state_metadata, .lookup_metadata = self.lookup_metadata, .rom_indices = self.rom_indices, .lookup_width = lookupWidth(self.plan), .data = data, .state_challenges = challenges.state, .bytes = &byte_inverses, .bitwise = and_inverses, .shifts = shift_inverses, .rom = rom_inverses, .byte_start = self.byteStart(), .and_start = self.andStart(), .shift_start = self.shiftStart() };
        try fillInteractions(self.allocator, &context, pool);
        const cyclic = rv.state_policy.isCyclic(self.plan.state_policy);
        const prefixes = [_]?usize{ if (cyclic) null else 32, self.plan.stateInteractionCount() + 4, self.andStart() - 4, if (self.plan.byte_bitwise) self.shiftStart() - 4 else null, if (self.plan.support.shifts) self.interactionCount() - 4 else null };
        var claims = scanPrefixes(data, size, self.log_size, prefixes);
        if (cyclic) claims.state = scanCyclicState(data, size, self.log_size);
        const expected_state = (try self.statement.expectedStateWithProfile(challenges.state, self.plan.execution_profile)).sub(try service_journal.ramContribution(self.service_calls, challenges.state)).sub(if (self.secp) |*journal| try journal.ramContribution(challenges.state) else Q.zero());
        if (!claims.state.eql(expected_state)) return error.InvalidRv64FullStateClosure;
        self.interaction = data;
        self.allocator.free(self.state_metadata);
        self.state_metadata = &.{};
        self.allocator.free(self.lookup_metadata);
        self.lookup_metadata = &.{};
        self.allocator.free(self.rom_indices);
        self.rom_indices = &.{};
        return claims;
    }

    /// Witness-only base-field arithmetic. The unchanged QM31 relation AIR
    /// authenticates these cached values against the committed physical trace.
    fn stateDenominators(row: *const StateRow, index: usize, slot: usize, fixed: *const rv.program.setup.Row, challenges: *const rv.relations.Challenges) [2]Q {
        var common = challenges.offset;
        if (slot == 3) {
            common = common.add(challenges.coefficients[0]);
            for (0..8) |i| addBase(&common, challenges.coefficients[1 + i], wordByte(row.words[6], i));
            addBase(&common, challenges.coefficients[18], M.fromCanonical(row.readable));
            addBase(&common, challenges.coefficients[19], M.fromCanonical(row.writable));
        } else {
            const source: usize = switch (slot) {
                0 => rv.program.setup.field.rs1,
                1 => rv.program.setup.field.rs2,
                else => rv.program.setup.field.rd,
            };
            addBase(&common, challenges.coefficients[1], fixed[source]);
            common = common.add(challenges.coefficients[18]).add(challenges.coefficients[19]);
        }
        const before_word: usize = switch (slot) {
            0 => 0,
            1 => 1,
            2 => 2,
            else => 4,
        };
        const after_word: usize = switch (slot) {
            0 => 0,
            1 => 1,
            2 => 3,
            else => 5,
        };
        var before = common;
        for (0..8) |i| addBase(&before, challenges.coefficients[10 + i], wordByte(row.words[before_word], i));
        var after = before;
        if (row.words[before_word] != row.words[after_word]) {
            after = common;
            for (0..8) |i| addBase(&after, challenges.coefficients[10 + i], wordByte(row.words[after_word], i));
        }
        addBase(&before, challenges.coefficients[9], M.fromCanonical(row.clocks[slot]));
        addBase(&after, challenges.coefficients[9], M.fromCanonical(@intCast(index * 4 + slot + 1)));
        return .{ before, after };
    }
};

const InteractionContext = struct {
    program: *const rv.program.setup.Setup,
    plan: *const rv.encoding.Plan,
    steps: u32,
    log_size: u32,
    size: usize,
    state_metadata: []const StateRow,
    lookup_metadata: []const u8,
    rom_indices: []const u32,
    lookup_width: usize,
    data: []M,
    state_challenges: rv.relations.Challenges,
    bytes: []const Q,
    bitwise: []const Q,
    shifts: []const Q,
    rom: []const Q,
    byte_start: usize,
    and_start: usize,
    shift_start: usize,
};
const InteractionJob = struct {
    context: *const InteractionContext,
    scratch: []Q,
    start: usize,
    end: usize,
    failure: ?anyerror = null,
    fn run(self: *InteractionJob) void {
        fillInteractionRange(self.context, self.scratch, self.start, self.end) catch |err| {
            self.failure = err;
        };
    }
};
fn fillInteractions(a: std.mem.Allocator, context: *const InteractionContext, pool: ?*work.WorkPool) !void {
    const workers = if (pool) |active| @min(active.workerCount(), @max(1, context.size / MIN_ROWS_PER_WORKER)) else 1;
    if (workers > 1 and pool.?.stackSize() < MIN_PROJECTION_STACK) return error.InvalidRv64InteractionStack;
    const scratch = try a.alloc(Q, workers * 8192);
    defer a.free(scratch);
    var jobs: [work.MAX_WORKERS]InteractionJob = undefined;
    const tiles = context.size / 32;
    for (jobs[0..workers], 0..) |*job, i| job.* = .{ .context = context, .scratch = scratch[i * 8192 ..][0..8192], .start = tiles * i / workers * 32, .end = tiles * (i + 1) / workers * 32 };
    if (workers == 1) return fillInteractionRange(context, jobs[0].scratch, 0, context.size);
    {
        var lease = try pool.?.acquire(try work.WorkerBudget.init(workers));
        defer lease.deinit();
        var wait_group = std.Thread.WaitGroup{};
        defer {
            wait_group.wait();
            lease.completeWave();
        }
        for (jobs[1..workers]) |*job| try lease.spawnWg(&wait_group, InteractionJob.run, .{job});
        jobs[0].run();
    }
    for (jobs[0..workers]) |job| if (job.failure) |err| return err;
}
fn fillInteractionRange(context: *const InteractionContext, scratch: []Q, start: usize, end: usize) !void {
    var chunk_start = start;
    while (chunk_start < end) : (chunk_start += 512) {
        const chunk_end = @min(end, chunk_start + 512);
        const inverses = scratch[0 .. (chunk_end - chunk_start) * 8];
        @memset(inverses, Q.one());
        for (chunk_start..chunk_end) |row| {
            const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(row, context.log_size), context.log_size);
            if (logical >= context.steps) continue;
            const fixed = &context.program.rows[context.rom_indices[logical]];
            for (0..4) |slot| {
                if (fixed[rv.program.setup.field.slots + slot].isZero()) continue;
                const pair = Trace.stateDenominators(&context.state_metadata[logical], logical, slot, fixed, &context.state_challenges);
                const offset = (row - chunk_start) * 8 + slot * 2;
                inverses[offset] = pair[0];
                inverses[offset + 1] = pair[1];
            }
        }
        try batchInvert(inverses, scratch[4096..][0..inverses.len]);
        for (chunk_start..chunk_end) |row| {
            const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(row, context.log_size), context.log_size);
            var state = Q.zero();
            var state_groups: [3]Q = @splat(Q.zero());
            var rom = Q.zero();
            if (logical < context.steps) {
                const rom_index = context.rom_indices[logical];
                for (0..4) |slot| {
                    if (context.program.rows[rom_index][rv.program.setup.field.slots + slot].isZero()) continue;
                    const offset = (row - chunk_start) * 8 + slot * 2;
                    const before = inverses[offset];
                    const after = inverses[offset + 1];
                    if (rv.state_policy.isCyclic(context.plan.state_policy)) {
                        state_groups[2 * slot / 3] = state_groups[2 * slot / 3].add(before);
                        state_groups[(2 * slot + 1) / 3] = state_groups[(2 * slot + 1) / 3].sub(after);
                    } else {
                        store(context.data, context.size, row, slot * 8, before);
                        store(context.data, context.size, row, slot * 8 + 4, after);
                    }
                    state = state.add(before).sub(after);
                }
                rom = context.rom[rom_index];
                store(context.data, context.size, row, context.plan.stateInteractionCount(), rom);
            }
            // Prefix slots temporarily hold row contributions. They remain
            // private and are overwritten by the joined logical prefix scan.
            if (rv.state_policy.isCyclic(context.plan.state_policy)) {
                for (state_groups, 0..) |contribution, group| store(context.data, context.size, row, group * 4, contribution);
            } else store(context.data, context.size, row, 32, state);
            store(context.data, context.size, row, context.plan.stateInteractionCount() + 4, rom);
            const source = @min(logical, context.steps);
            const lookup = context.lookup_metadata[source * context.lookup_width ..][0..context.lookup_width];
            var bytes = Q.zero();
            for (0..ByteCpu.batches(context.plan)) |batch| {
                const count = @min(3, context.plan.range_count - batch * 3);
                var inverse = context.bytes[lookup[batch * 3]];
                var contribution = inverse;
                for (1..count) |j| {
                    const cached = context.bytes[lookup[batch * 3 + j]];
                    inverse = inverse.mul(cached);
                    contribution = contribution.add(cached);
                }
                store(context.data, context.size, row, context.byte_start + batch * 4, inverse);
                bytes = bytes.add(contribution);
            }
            store(context.data, context.size, row, context.and_start - 4, bytes);
            var cursor = context.plan.range_count;
            for ([_]Tables.Kind{ .byte_and, .byte_shift }) |kind| {
                const count = TableCpu.requests(context.plan, kind);
                if (count == 0) continue;
                const dictionary = if (kind == .byte_and) context.bitwise else context.shifts;
                const column = if (kind == .byte_and) context.and_start else context.shift_start;
                var total = Q.zero();
                for (0..(count + 2) / 3) |batch| {
                    var inverse = try lookupInverse(dictionary, lookup, &cursor);
                    var contribution = inverse;
                    for (1..@min(3, count - batch * 3)) |_| {
                        const cached = try lookupInverse(dictionary, lookup, &cursor);
                        inverse = inverse.mul(cached);
                        contribution = contribution.add(cached);
                    }
                    store(context.data, context.size, row, column + batch * 4, inverse);
                    total = total.add(contribution);
                }
                store(context.data, context.size, row, column + TableCpu.interactionCount(context.plan, kind) - 4, total);
            }
        }
    }
}
fn lookupInverse(dictionary: []const Q, lookup: []const u8, cursor: *usize) !Q {
    const index = std.mem.readInt(u16, lookup[cursor.*..][0..2], .little);
    cursor.* += 2;
    if (index >= dictionary.len or dictionary[index].isZero()) return error.InvalidRv64FullLookupCount;
    return dictionary[index];
}
fn scanPrefixes(data: []M, size: usize, log_size: u32, columns: [5]?usize) Full.Claims {
    var sums: [5]Q = @splat(Q.zero());
    for (0..size) |logical| {
        const row = rv.witness.physical(logical, log_size);
        for (columns, 0..) |column, family| if (column) |offset| {
            const contribution = Q.fromM31(data[offset * size + row], data[(offset + 1) * size + row], data[(offset + 2) * size + row], data[(offset + 3) * size + row]);
            sums[family] = sums[family].add(contribution);
            store(data, size, row, offset, sums[family]);
        };
    }
    return .{ .state = sums[0], .rom = sums[1], .bytes = sums[2], .bitwise = sums[3], .shifts = sums[4] };
}

/// Three prefixes form one chain across both groups and rows. Row-parallel
/// construction wrote only local signed contributions; no wide temporary or
/// per-row extension inversion is needed for this joined scan.
fn scanCyclicState(data: []M, size: usize, log_size: u32) Q {
    var sum = Q.zero();
    for (0..size) |logical| {
        const row = rv.witness.physical(logical, log_size);
        for (0..3) |group| {
            const offset = 4 * group;
            const contribution = Q.fromM31(data[offset * size + row], data[(offset + 1) * size + row], data[(offset + 2) * size + row], data[(offset + 3) * size + row]);
            sum = sum.add(contribution);
            store(data, size, row, offset, sum);
        }
    }
    return sum;
}

const ProjectionCounts = struct { bytes: []u64, bitwise: []u64, shifts: []u64 };
const ProjectionContext = struct {
    records: Retirements,
    program: *const rv.program.setup.Setup,
    plan: *const rv.encoding.Plan,
    decoded: []const rv.program.setup.Decoded,
    state_metadata: []const StateRow,
    rom_indices: []const u32,
    columns: []M,
    lookup_metadata: []u8,
    size: usize,
    log_size: u32,
    lookup_width: usize,
};
const ProjectionJob = struct {
    context: *const ProjectionContext,
    counts: ProjectionCounts,
    start: usize,
    end: usize,
    failure: ?anyerror = null,
    fn run(self: *ProjectionJob) void {
        projectRange(self.context, self.counts, self.start, self.end) catch |err| {
            self.failure = err;
        };
    }
};
fn projectPhysical(a: std.mem.Allocator, context: *const ProjectionContext, counts: ProjectionCounts, pool: ?*work.WorkPool) !void {
    const workers = if (pool) |active| @min(active.workerCount(), @max(1, context.size / MIN_ROWS_PER_WORKER)) else 1;
    if (workers == 1) return projectRange(context, counts, 0, context.size);
    const active = pool.?;
    if (active.stackSize() < MIN_PROJECTION_STACK) return error.InvalidRv64ProjectionStack;
    // Each histogram has an unused cache-line gap. Workers allocate nothing and
    // never mutate the Trace owner or a neighbouring worker's counts.
    const stride = counts.bytes.len + counts.bitwise.len + counts.shifts.len + 16;
    const histograms = try a.alloc(u64, workers * stride);
    defer a.free(histograms);
    @memset(histograms, 0);
    var jobs: [work.MAX_WORKERS]ProjectionJob = undefined;
    const tiles = context.size / 32;
    for (jobs[0..workers], 0..) |*job, i| {
        const own = histograms[i * stride ..][0..stride];
        job.* = .{ .context = context, .counts = .{ .bytes = own[0..counts.bytes.len], .bitwise = own[counts.bytes.len..][0..counts.bitwise.len], .shifts = own[counts.bytes.len + counts.bitwise.len ..][0..counts.shifts.len] }, .start = tiles * i / workers * 32, .end = tiles * (i + 1) / workers * 32 };
    }
    {
        var lease = try active.acquire(try work.WorkerBudget.init(workers));
        defer lease.deinit();
        var wait_group = std.Thread.WaitGroup{};
        defer {
            wait_group.wait();
            lease.completeWave();
        }
        for (jobs[1..workers]) |*job| try lease.spawnWg(&wait_group, ProjectionJob.run, .{job});
        jobs[0].run();
    }
    // Every submitted helper has joined before either errors or buffers escape.
    for (jobs[0..workers]) |job| if (job.failure) |err| return err;
    for (jobs[0..workers]) |job| {
        for (counts.bytes, job.counts.bytes) |*value, extra| value.* = try std.math.add(u64, value.*, extra);
        for (counts.bitwise, job.counts.bitwise) |*value, extra| value.* = try std.math.add(u64, value.*, extra);
        for (counts.shifts, job.counts.shifts) |*value, extra| value.* = try std.math.add(u64, value.*, extra);
    }
}
fn projectRange(context: *const ProjectionContext, counts: ProjectionCounts, start: usize, end: usize) !void {
    var physical_storage: [L.MAIN]M = undefined;
    const physical = physical_storage[0..context.plan.main_count];
    for (start..end) |row| {
        const i = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(row, context.log_size), context.log_size);
        if (i >= context.records.len()) continue;
        const rom_index = context.rom_indices[i];
        const entry = context.decoded[rom_index];
        const record = try context.records.record(i, entry.raw, entry.instruction);
        const metadata = context.state_metadata[i];
        const rights = execution.memory.Permissions{ .read = metadata.readable != 0, .write = metadata.writable != 0 };
        var logical = try rv.witness.fromRetirementValuesWithMultiplicationService(record, context.decoded[rom_index].instruction, rights, context.plan.arithmetic_policy == .division_multiplication_services_v3);
        rv.arithmetic.division.cpu.canonicalizeAdvice(&logical, record.opcode, context.plan.arithmetic_policy);
        for (context.decoded[rom_index].enabled, metadata.clocks, 0..) |enabled, before, slot| {
            if (!enabled) continue;
            logical[L.previousClock(slot)] = M.fromCanonical(before);
            logical[L.gap(slot)] = M.fromCanonical(@as(u32, @intCast(4 * i + slot + 1)) - before - 1);
        }
        for (physical, 0..) |*value, c| {
            value.* = context.plan.projectValue(&logical, c);
            context.columns[c * context.size + row] = value.*;
        }
        var advice_storage: [Frame.WIDTH]M = undefined;
        const advice = advice_storage[0..Frame.bodyWidth(context.plan.control_policy)];
        Frame.fillFromRowBaseWithControl(advice, &context.program.rows[rom_index], record.next_pc.toInt(), true, context.plan.control_policy);
        for (advice, 0..) |value, c| context.columns[(context.plan.main_count + c) * context.size + row] = value;
        try countProjectionRow(context.plan, counts, &logical, physical, 1, context.lookup_metadata[i * context.lookup_width ..][0..context.lookup_width]);
    }
}
fn countProjectionRow(plan: *const rv.encoding.Plan, counts: ProjectionCounts, logical: *const rv.rows.Main, physical: []const M, multiplicity: u64, metadata: []u8) !void {
    var cursor: usize = 0;
    for (plan.range_sources[0..plan.range_count]) |source| {
        const byte = physical[source].v;
        if (byte >= 256) return error.InvalidByteRangeWitness;
        metadata[cursor] = @intCast(byte);
        cursor += 1;
        counts.bytes[byte] = try std.math.add(u64, counts.bytes[byte], multiplicity);
    }
    if (plan.byte_bitwise) for (0..8) |i| {
        const tuple: Tables.Tuple = .{ logical[L.byte(.a, i)].v, logical[L.byte(.rhs, i)].v, physical[plan.and_start + i].v, 0, 0, 0 };
        const index = try Tables.Kind.byte_and.rowIndex(tuple);
        std.mem.writeInt(u16, metadata[cursor..][0..2], @intCast(index), .little);
        cursor += 2;
        counts.bitwise[index] = try std.math.add(u64, counts.bitwise[index], multiplicity);
    };
    if (plan.support.shifts) for (0..9) |i| {
        const start = plan.shift_outputs + 4 * i;
        const tuple: Tables.Tuple = .{ if (i == 8) 255 else logical[L.byte(.a, i)].v, physical[plan.shift_amount].v, physical[start].v, physical[start + 1].v, physical[start + 2].v, physical[start + 3].v };
        const index = try Tables.Kind.byte_shift.rowIndex(tuple);
        std.mem.writeInt(u16, metadata[cursor..][0..2], @intCast(index), .little);
        cursor += 2;
        counts.shifts[index] = try std.math.add(u64, counts.shifts[index], multiplicity);
    };
    std.debug.assert(cursor == metadata.len);
}

/// Active-only metadata retained from construction, followed by one shared
/// padding record. No logical AIR row, execution receipt or authority is stored.
const StateRow = struct {
    words: [7]u64,
    clocks: [4]u32,
    readable: u8,
    writable: u8,
    fn fromRetirement(record: execution.machine.Retirement, previous: [4]u32, rights: execution.memory.Permissions) StateRow {
        const event = record.memory;
        return .{ .words = .{ record.lhs.toInt(), record.rhs.toInt(), record.previous_rd.toInt(), record.result.toInt(), if (event) |e| e.before_word.toInt() else 0, if (event) |e| e.after_word.toInt() else 0, if (event) |e| e.address.toInt() & ~@as(u64, 7) else 0 }, .clocks = previous, .readable = @intFromBool(event != null and rights.read), .writable = @intFromBool(event != null and rights.write) };
    }
    fn fromLogical(logical: *const rv.rows.Main) StateRow {
        var row: StateRow = undefined;
        for ([_]L.Word{ .a, .b, .previous_rd, .result, .memory_before, .memory_after, .address }, 0..) |word, i| row.words[i] = rv.rows.getWord(logical, word);
        row.words[6] &= ~@as(u64, 7);
        for (0..4) |slot| row.clocks[slot] = logical[L.previousClock(slot)].v;
        row.readable = @intCast(logical[L.readable].v);
        row.writable = @intCast(logical[L.writable].v);
        return row;
    }
};
fn wordByte(value: u64, index: usize) M {
    return M.fromCanonical(@intCast((value >> @as(u6, @intCast(index * 8))) & 255));
}
fn lookupWidth(plan: *const rv.encoding.Plan) usize {
    return plan.range_count + 2 * (TableCpu.requests(plan, .byte_and) + TableCpu.requests(plan, .byte_shift));
}
fn addBase(result: *Q, coefficient: Q, value: M) void {
    if (!value.isZero()) result.* = result.add(coefficient.mulM31(value));
}
fn batchInvert(values: []Q, prefixes: []Q) !void {
    std.debug.assert(values.len == prefixes.len);
    var product = Q.one();
    for (values, prefixes) |value, *prefix| {
        prefix.* = product;
        product = product.mul(value);
    }
    var inverse = try product.inv();
    var i = values.len;
    while (i != 0) {
        i -= 1;
        const value = values[i];
        values[i] = inverse.mul(prefixes[i]);
        inverse = inverse.mul(value);
    }
}
fn tableInverses(a: std.mem.Allocator, kind: Tables.Kind, counts: []const u64, challenges: Tables.Challenges) ![]Q {
    const result = try a.alloc(Q, counts.len);
    errdefer a.free(result);
    for (result, counts, 0..) |*inverse, count, i| {
        inverse.* = Q.zero();
        if (count == 0) continue;
        const base = kind.tupleAt(i);
        var tuple: [6]Q = undefined;
        for (base, 0..) |value, c| tuple[c] = E.q(value);
        inverse.* = try challenges.denominator(tuple[0..kind.arity()]).inv();
    }
    return result;
}
fn store(data: []M, size: usize, row: usize, column: usize, value: Q) void {
    for (value.toM31Array(), 0..) |coordinate, i| data[(column + i) * size + row] = coordinate;
}
fn memoryIndex(cells: []const S.Cell, address: u64) !usize {
    return S.cellIndex(cells, address);
}
