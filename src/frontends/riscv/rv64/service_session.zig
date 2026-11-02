//! Explicit RV64 service execution profile. Host results are witness generation,
//! not proof authority; ordinary Session retains its trapping ECALL semantics.
const std = @import("std");
const Base = @import("session.zig");
const machine = @import("machine.zig");
const memory = @import("memory.zig");
const Keccak = std.crypto.core.keccak.KeccakF(1600);
const profile = @import("execution_profile.zig");
pub const PROFILE = "rv64im-keccak-service-v1";
pub const KECCAK_TAG = profile.KECCAK_TAG;
pub const State = [25]u64;
pub const Call = struct {
    call_id: u64,
    /// One-based retirement clock, identical to ordinary Retirement.clock.
    clock: u64,
    pc: u64,
    pointer: u64,
    before: State,
    after: State,
    pub fn retirement(self: Call) machine.Retirement {
        const Word = @import("word.zig").Word;
        return .{ .clock = self.clock, .pc = Word.fromInt(self.pc), .next_pc = Word.fromInt(self.pc +% 4), .immediate = Word.fromInt(0), .instruction = 0x00000073, .opcode = .ECALL, .rs1 = profile.POINTER_REGISTER, .rs2 = profile.TAG_REGISTER, .lhs = Word.fromInt(self.pointer), .rhs = Word.fromInt(KECCAK_TAG), .rd = 0, .previous_rd = Word.fromInt(0), .result = Word.fromInt(0), .writes_rd = false, .branch_taken = false, .memory = null };
    }
};
pub const Error = Base.Error || error{ UnsupportedService, ServiceCounterOverflow };
pub const Session = struct {
    base: Base.Session,
    calls: u64 = 0,

    pub fn init(a: std.mem.Allocator, cpu: machine.Cpu, mem: *memory.Memory, options: Base.Options) Error!Session {
        return .{ .base = try Base.Session.init(a, cpu, mem, options) };
    }
    pub fn deinit(self: *Session) void {
        self.base.deinit();
        self.* = undefined;
    }
    /// A normal retirement never copies a permutation-sized event union.
    /// `call` is initialized only when null is returned for a service retirement.
    pub fn step(self: *Session, call: *Call) Error!?machine.Retirement {
        const row = self.base.step() catch |err| {
            if (err != error.EnvironmentCall) return err;
            call.* = try self.keccak();
            return null;
        };
        return row;
    }
    fn keccak(self: *Session) Error!Call {
        const cpu = &self.base.cpu;
        const mem = self.base.memory;
        if (cpu.read(profile.TAG_REGISTER) != KECCAK_TAG) return error.UnsupportedService;
        if (self.calls == std.math.maxInt(u64)) return error.ServiceCounterOverflow;
        const pointer = cpu.read(profile.POINTER_REGISTER);
        if (pointer & 7 != 0) return error.MisalignedAddress;
        _ = try memory.endAddress(pointer, 200);
        try mem.mappings.check(pointer, 200, .read);
        var before: State = undefined;
        for (&before, 0..) |*word, i| word.* = try mem.load(pointer + 8 * i, 8);
        var permutation = Keccak{ .st = before };
        permutation.permute();
        const after = permutation.st;
        // All fallible reservation happens before any RAM/CPU/event publication.
        try mem.storeWords(pointer, &after);
        const result = Call{ .call_id = self.calls + 1, .clock = cpu.retired + 1, .pc = cpu.pc, .pointer = pointer, .before = before, .after = after };
        cpu.pc +%= 4;
        cpu.retired += 1; // Base.step rejected a saturated budget before ECALL.
        self.calls += 1;
        return result;
    }
};
