//! Separately versioned Ethereum services. Outputs are native witness data;
//! acceptance requires the corresponding CPU/RAM/arithmetic proof relations.
const std = @import("std");
const Base = @import("../session.zig");
const K = @import("../service_session.zig");
const machine = @import("../machine.zig");
const memory = @import("../memory.zig");
const profile = @import("../execution_profile.zig");
pub const secp256k1 = @import("secp256k1.zig");
pub const PROFILE = "rv64im-ethereum-services-v1";
pub const PROFILE_WORDS = "rv64im-ethereum-services-v2";
pub const SecpCall = struct {
    kind: secp256k1.Kind,
    packet_format: profile.SecpPacketFormat = .big_endian_bytes_v1,
    /// One-based counter within this typed service family; never guest-visible.
    call_id: u64,
    clock: u64,
    pc: u64,
    pointer: u64,
    /// Native64-bit memory words. Coordinate byte order follows packet_format;
    /// ADD has24 words, DOUBLE12, unused trailing words are zero.
    before: [24]u64,
    after: [24]u64,
    pub fn wordCount(self: SecpCall) usize {
        return if (self.kind == .add) 24 else 12;
    }
    pub fn tag(self: SecpCall) u64 {
        return switch (self.packet_format) {
            .big_endian_bytes_v1 => if (self.kind == .add) profile.SECP_ADD_TAG else profile.SECP_DOUBLE_TAG,
            .little_endian_words_v2 => if (self.kind == .add) profile.SECP_ADD_WORD_TAG else profile.SECP_DOUBLE_WORD_TAG,
        };
    }
    pub fn retirement(self: SecpCall) machine.Retirement {
        const Word = @import("../word.zig").Word;
        return .{ .clock = self.clock, .pc = Word.fromInt(self.pc), .next_pc = Word.fromInt(self.pc +% 4), .immediate = Word.fromInt(0), .instruction = 0x73, .opcode = .ECALL, .rs1 = profile.POINTER_REGISTER, .rs2 = profile.TAG_REGISTER, .lhs = Word.fromInt(self.pointer), .rhs = Word.fromInt(self.tag()), .rd = 0, .previous_rd = Word.fromInt(0), .result = Word.fromInt(0), .writes_rd = false, .branch_taken = false, .memory = null };
    }
};
pub const Event = union(enum) {
    keccak: K.Call,
    secp: SecpCall,
    pub fn retirement(self: Event) machine.Retirement {
        return switch (self) {
            .keccak => |call| call.retirement(),
            .secp => |call| call.retirement(),
        };
    }
};
pub const Error = K.Error || error{InvalidProjectiveInputCount};
pub const Session = struct {
    keccak: K.Session,
    execution_profile: profile.Profile = .ethereum_services_v1,
    add_calls: u64 = 0,
    double_calls: u64 = 0,
    pub fn init(a: std.mem.Allocator, cpu: machine.Cpu, mem: *memory.Memory, options: Base.Options) Error!Session {
        return initWithProfile(a, cpu, mem, options, .ethereum_services_v1);
    }
    pub fn initWithProfile(a: std.mem.Allocator, cpu: machine.Cpu, mem: *memory.Memory, options: Base.Options, execution_profile: profile.Profile) Error!Session {
        if (execution_profile != .ethereum_services_v1 and execution_profile != .ethereum_services_v2) return error.UnsupportedService;
        return .{ .keccak = try K.Session.init(a, cpu, mem, options), .execution_profile = execution_profile };
    }
    pub fn deinit(self: *Session) void {
        self.keccak.deinit();
        self.* = undefined;
    }
    /// Ordinary rows never initialize/copy the event union.
    pub fn step(self: *Session, event: *Event) Error!?machine.Retirement {
        var call: K.Call = undefined;
        const row = self.keccak.step(&call) catch |err| {
            if (err != error.UnsupportedService) return err;
            event.* = .{ .secp = try self.projective() };
            return null;
        };
        if (row == null) event.* = .{ .keccak = call };
        return row;
    }
    fn projective(self: *Session) Error!SecpCall {
        const cpu = &self.keccak.base.cpu;
        const mem = self.keccak.base.memory;
        const format: profile.SecpPacketFormat = if (self.execution_profile == .ethereum_services_v1) .big_endian_bytes_v1 else .little_endian_words_v2;
        const tag = cpu.read(profile.TAG_REGISTER);
        const kind: secp256k1.Kind = if (format == .big_endian_bytes_v1) switch (tag) {
            profile.SECP_ADD_TAG => .add,
            profile.SECP_DOUBLE_TAG => .double,
            else => return error.UnsupportedService,
        } else switch (tag) {
            profile.SECP_ADD_WORD_TAG => .add,
            profile.SECP_DOUBLE_WORD_TAG => .double,
            else => return error.UnsupportedService,
        };
        const count = if (kind == .add) &self.add_calls else &self.double_calls;
        if (count.* == std.math.maxInt(u64)) return error.ServiceCounterOverflow;
        const pointer = cpu.read(profile.POINTER_REGISTER);
        if (pointer & 31 != 0) return error.MisalignedAddress;
        const words: usize = if (kind == .add) 24 else 12;
        _ = try memory.endAddress(pointer, words * 8);
        try mem.mappings.check(pointer, words * 8, .read);
        var before: [24]u64 = @splat(0);
        var bytes: [192]u8 = @splat(0);
        for (before[0..words], 0..) |*word, i| {
            word.* = try mem.load(pointer + 8 * i, 8);
            std.mem.writeInt(u64, bytes[8 * i ..][0..8], word.*, .little);
        }
        var coordinates: [6]u256 = undefined;
        const program = secp256k1.get(kind);
        for (coordinates[0..program.inputs], 0..) |*value, i| value.* = if (format == .big_endian_bytes_v1) std.mem.readInt(u256, bytes[32 * i ..][0..32], .big) else std.mem.readInt(u256, bytes[32 * i ..][0..32], .little);
        const values = try secp256k1.execute(program, coordinates[0..program.inputs]);
        for (program.outputs, 0..) |wire, i| {
            if (format == .big_endian_bytes_v1) std.mem.writeInt(u256, bytes[32 * i ..][0..32], values[wire], .big) else std.mem.writeInt(u256, bytes[32 * i ..][0..32], values[wire], .little);
        }
        var after = before;
        for (after[0..12], 0..) |*word, i| word.* = std.mem.readInt(u64, bytes[8 * i ..][0..8], .little);
        // Only the left XYZ is overwritten; RHS is read-only. Reservation and
        // publication are atomic across pages, before CPU/counter/event changes.
        try mem.storeWords(pointer, after[0..12]);
        const result = SecpCall{ .kind = kind, .packet_format = format, .call_id = count.* + 1, .clock = cpu.retired + 1, .pc = cpu.pc, .pointer = pointer, .before = before, .after = after };
        cpu.pc +%= 4;
        cpu.retired += 1;
        count.* += 1;
        return result;
    }
};
