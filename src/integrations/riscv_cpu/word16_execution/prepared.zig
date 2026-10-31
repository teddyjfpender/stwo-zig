//! One CPU witness and one native family routing/grouping pass, before setup.
//! Program is borrowed. After moving it into Setup, callers MUST transfer via
//! Sources.fromPrepared, which validates identity and rebinds CPU.program to
//! the final stable Setup address before any row/interaction access.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const B = A.word16_v1;
const CPU = @import("cpu_source.zig");
const Program = @import("program.zig").Program;
const J = @import("jalr_source.zig");
const Coverage = @import("coverage.zig");
const G = @import("geometry.zig");
pub const Binary = @import("binary_dedup.zig");
pub const Options = struct {
    deduplicate_binary: bool = true,
    /// Legacy wrapper keeps its caller-declared padded JALR geometry.
    jalr_log: ?u32 = null,
};
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    program_identity: [32]u8,
    cpu: ?CPU.Source,
    jalr: ?J.Source,
    alu: B.alu_experiment.source.WeightedFacts,
    binary: Binary.WeightedFacts,
    shift: []B.operations.ShiftFact,
    division: []A.arithmetic.division.trace.Request,
    multiplication: []A.arithmetic.multiplication.trace.Request,
    raw_counts: Coverage.Counts,
    unique_memory_words: u32,
    pub fn init(a: std.mem.Allocator, program: *const Program, public: A.word16_execution.types.Boundary, epoch: u16, cpu_log: u32, tape: *const front.rv64.compact_tape.Tape, options: Options) !Prepared {
        var result = try capture(a, program, public, epoch, cpu_log, tape, options);
        errdefer result.deinit();
        try result.ensureCpuMain(program, cpu_log);
        return result;
    }
    /// Explicit service witness route. Old constructors remain fail-closed;
    /// acceptance belongs only to the complete Keccak service coordinator.
    pub fn initForKeccak(a: std.mem.Allocator, program: *const Program, public: A.word16_execution.types.Boundary, epoch: u16, cpu_log: u32, tape: *const front.rv64.compact_tape.Tape, options: Options) !Prepared {
        var result = try captureForKeccak(a, program, public, epoch, cpu_log, tape, options);
        errdefer result.deinit();
        try result.ensureCpuMain(program, cpu_log);
        return result;
    }
    /// Geometry/grouping ready without CPU MAIN. JALR retains its existing
    /// independently sized witness; this does not claim all providers narrow.
    pub fn capture(a: std.mem.Allocator, program: *const Program, public: A.word16_execution.types.Boundary, epoch: u16, cpu_log: u32, tape: *const front.rv64.compact_tape.Tape, options: Options) !Prepared {
        return captureInternal(a, program, public, epoch, cpu_log, tape, options, false);
    }
    pub fn captureForKeccak(a: std.mem.Allocator, program: *const Program, public: A.word16_execution.types.Boundary, epoch: u16, cpu_log: u32, tape: *const front.rv64.compact_tape.Tape, options: Options) !Prepared {
        return captureInternal(a, program, public, epoch, cpu_log, tape, options, true);
    }
    fn captureInternal(a: std.mem.Allocator, program: *const Program, public: A.word16_execution.types.Boundary, epoch: u16, cpu_log: u32, tape: *const front.rv64.compact_tape.Tape, options: Options, allow_keccak: bool) !Prepared {
        var cpu = try CPU.Source.capture(a, program, public, epoch, cpu_log, tape);
        errdefer cpu.deinit();
        if (!allow_keccak and cpu.services.items.len != 0) return error.UnqualifiedWord16ServiceOwners;
        for (cpu.services.items) |call| if (call.tag != 0x10001) return error.UnqualifiedWord16ServiceOwners;
        var af: std.ArrayList(B.operations.AluFact) = .empty;
        defer af.deinit(a);
        var bf: std.ArrayList(Binary.Fact) = .empty;
        defer bf.deinit(a);
        var sf: std.ArrayList(B.operations.ShiftFact) = .empty;
        defer sf.deinit(a);
        var jf: std.ArrayList(J.Fact) = .empty;
        defer jf.deinit(a);
        var df: std.ArrayList(A.arithmetic.division.trace.Request) = .empty;
        defer df.deinit(a);
        var mf: std.ArrayList(A.arithmetic.multiplication.trace.Request) = .empty;
        defer mf.deinit(a);
        for (cpu.functions.items) |f| switch (f.operation) {
            0...9 => try af.append(a, .{ .op = @enumFromInt(f.operation), .a = f.a, .b = f.b, .c = f.c }),
            10 => try jf.append(a, .{ .a = f.a, .b = f.b, .c = f.c }),
            16...18 => try bf.append(a, .{ .op = @enumFromInt(f.operation - 16), .a = f.a, .b = f.b, .c = f.c }),
            32...37 => try sf.append(a, .{ .op = @enumFromInt(f.operation - 32), .a = f.a, .b = f.b, .c = f.c }),
            49...52, 57 => try mf.append(a, .{ .opcode = @enumFromInt(f.operation), .a = f.a, .b = f.b, .result = f.c }),
            53...56, 58...61 => try df.append(a, .{ .opcode = @enumFromInt(f.operation), .a = f.a, .b = f.b, .result = f.c }),
            else => return error.UnroutedWord16Function,
        };
        const jalr_log = options.jalr_log orelse try Coverage.minimalLog(@intCast(jf.items.len));
        var jalr = try J.Source.init(a, jf.items, jalr_log);
        errdefer jalr.deinit();
        const extra_alu = try jalr.aluFacts(a);
        defer a.free(extra_alu);
        try af.appendSlice(a, extra_alu);
        const extra_binary = try jalr.binaryFacts(a);
        defer a.free(extra_binary);
        try bf.appendSlice(a, extra_binary);
        var alu = try B.alu_experiment.source.deduplicate(a, af.items);
        errdefer alu.deinit();
        var binary = try Binary.collect(a, bf.items, options.deduplicate_binary);
        errdefer binary.deinit();
        var words: std.AutoHashMapUnmanaged(u64, void) = .empty;
        defer words.deinit(a);
        for (cpu.memory.items) |record| try words.put(a, record.effect.address.toInt() & ~@as(u64, 7), {});
        const shift = try sf.toOwnedSlice(a);
        errdefer a.free(shift);
        const division = try df.toOwnedSlice(a);
        errdefer a.free(division);
        const multiplication = try mf.toOwnedSlice(a);
        return .{ .allocator = a, .program_identity = program.identity, .cpu = cpu, .jalr = jalr, .alu = alu, .binary = binary, .shift = shift, .division = division, .multiplication = multiplication, .raw_counts = .{ .alu = @intCast(af.items.len), .binary = @intCast(bf.items.len), .shift = @intCast(shift.len), .jalr = @intCast(jf.items.len), .division = @intCast(division.len), .multiplication = @intCast(multiplication.len), .memory = @intCast(cpu.memory.items.len), .service = @intCast(cpu.services.items.len) }, .unique_memory_words = @intCast(words.count()) };
    }
    pub fn geometry(self: *const Prepared) !G.Geometry {
        const cpu = self.cpu orelse return error.PreparedExecutionConsumed;
        return .{ .cpu_log = cpu.log_size, .alu_log = try Coverage.minimalLog(@intCast(self.alu.facts.len)), .binary_log = try Coverage.minimalLog(@intCast(self.binary.facts.len)), .shift_log = try Coverage.minimalLog(@intCast(self.shift.len)), .jalr_log = (self.jalr orelse return error.PreparedExecutionConsumed).log_size, .division_log = try Coverage.minimalLog(@intCast(self.division.len)), .multiplication_log = try Coverage.minimalLog(@intCast(self.multiplication.len)), .ls_log = try Coverage.minimalPrefixLog(self.raw_counts.memory), .boundary_log = try Coverage.minimalPrefixLog(self.unique_memory_words) };
    }
    /// Validate/rebind before projection. A projection failure leaves the CPU
    /// and grouped facts here for retry; no ownership moves on this barrier.
    pub fn ensureCpuMain(self: *Prepared, program: *const Program, expected_cpu_log: u32) !void {
        if (!std.mem.eql(u8, &self.program_identity, &program.identity)) return error.PreparedProgramMismatch;
        const cpu = if (self.cpu) |*value| value else return error.PreparedExecutionConsumed;
        if (cpu.log_size != expected_cpu_log) return error.PreparedGeometryMismatch;
        cpu.program = program;
        if (cpu.main_projection_closed) {
            if (cpu.main.len == 0) return error.ExecutionMainUnavailable;
        } else try cpu.materializeMain();
    }
    pub fn takeCpu(self: *Prepared, program: *const Program, expected_cpu_log: u32) !CPU.Source {
        if (!std.mem.eql(u8, &self.program_identity, &program.identity)) return error.PreparedProgramMismatch;
        var cpu = self.cpu orelse return error.PreparedExecutionConsumed;
        if (cpu.log_size != expected_cpu_log) return error.PreparedGeometryMismatch;
        cpu.program = program;
        self.cpu = null;
        return cpu;
    }
    pub fn takeJalr(self: *Prepared, expected_log: u32) !J.Source {
        const value = self.jalr orelse return error.PreparedExecutionConsumed;
        if (value.log_size != expected_log) return error.PreparedGeometryMismatch;
        self.jalr = null;
        return value;
    }
    /// Providers have copied their narrow metadata; discard temporary grouping
    /// arrays immediately, while retaining census fields for telemetry.
    pub fn releaseFacts(self: *Prepared) void {
        self.allocator.free(self.alu.facts);
        self.allocator.free(self.alu.weights);
        self.alu.facts = &.{};
        self.alu.weights = &.{};
        self.allocator.free(self.binary.facts);
        self.allocator.free(self.binary.weights);
        self.binary.facts = &.{};
        self.binary.weights = &.{};
        self.allocator.free(self.shift);
        self.allocator.free(self.division);
        self.allocator.free(self.multiplication);
        self.shift = &.{};
        self.division = &.{};
        self.multiplication = &.{};
    }
    pub fn deinit(self: *Prepared) void {
        if (self.cpu) |*value| value.deinit();
        if (self.jalr) |*value| value.deinit();
        self.alu.deinit();
        self.binary.deinit();
        self.allocator.free(self.shift);
        self.allocator.free(self.division);
        self.allocator.free(self.multiplication);
        self.* = undefined;
    }
};
