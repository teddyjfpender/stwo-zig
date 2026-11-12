//! Separately versioned Ethereum services. Outputs are native witness data;
//! acceptance requires the corresponding CPU/RAM/arithmetic proof relations.
const std = @import("std");
const call_abi = @import("../services/call_abi.zig");
const Base = @import("../session.zig");
const K = @import("../service_session.zig");
const machine = @import("../machine.zig");
const memory = @import("../memory.zig");
const profile = @import("../execution_profile.zig");
pub const secp256k1 = @import("stwo_riscv_precompiles").primitives.secp256k1;
pub const PROFILE = "rv64im-ethereum-services-v1";
pub const PROFILE_WORDS = "rv64im-ethereum-services-v2";
pub const PROFILE_V3 = "rv64im-ethereum-services-v3";
pub const sha256 = @import("stwo_riscv_precompiles").primitives.sha256;
pub const arith256 = @import("stwo_riscv_precompiles").primitives.arith256;
pub const curves = @import("../services/curve_packets.zig");
pub const bulk_memory = @import("../services/bulk_packets.zig");
pub const keccak_sponge = @import("../services/sponge_packets.zig");
pub const SecpCall = call_abi.SecpCall;
pub const Sha256Call = call_abi.Sha256Call;
pub const Arith256ModCall = call_abi.Arith256ModCall;
pub const CurveCall = call_abi.CurveCall;
pub const Event = call_abi.Event;
pub const Error = K.Error || keccak_sponge.Error || error{ InvalidProjectiveInputCount, BulkMemoryLength, BulkMemoryOverlap, CurveServiceDomain };
pub const Session = struct {
    keccak: K.Session,
    execution_profile: profile.Profile = .ethereum_services_v1,
    add_calls: u64 = 0,
    double_calls: u64 = 0,
    sha256_calls: u64 = 0,
    arith256_mod_calls: u64 = 0,
    bulk_calls: u64 = 0,
    sponge_calls: u64 = 0,
    /// Admitted v3 curve/field calls per op (curves.index order).
    curve_calls: [curves.COUNT]u64 = @splat(0),
    allocator: std.mem.Allocator = undefined,
    /// Destination words before the latest bulk call (Event.bulk.dst_before).
    bulk_before: std.ArrayList(u64) = .empty,
    pub fn init(a: std.mem.Allocator, cpu: machine.Cpu, mem: *memory.Memory, options: Base.Options) Error!Session {
        return initWithProfile(a, cpu, mem, options, .ethereum_services_v1);
    }
    pub fn initWithProfile(a: std.mem.Allocator, cpu: machine.Cpu, mem: *memory.Memory, options: Base.Options, execution_profile: profile.Profile) Error!Session {
        if (execution_profile != .ethereum_services_v1 and execution_profile != .ethereum_services_v2 and !profile.isV3(execution_profile)) return error.UnsupportedService;
        // The ISA follows the profile; a caller cannot widen a pre-Zbb profile.
        var opts = options;
        if (opts.isa != .rv64im and opts.isa != profile.isaOf(execution_profile)) return error.UnsupportedService;
        opts.isa = profile.isaOf(execution_profile);
        return .{ .keccak = try K.Session.init(a, cpu, mem, opts), .execution_profile = execution_profile, .allocator = a };
    }
    pub fn deinit(self: *Session) void {
        self.bulk_before.deinit(self.allocator);
        self.keccak.deinit();
        self.* = undefined;
    }
    /// Ordinary rows never initialize/copy the event union.
    pub fn step(self: *Session, event: *Event) Error!?machine.Retirement {
        var call: K.Call = undefined;
        const row = self.keccak.step(&call) catch |err| {
            if (err != error.UnsupportedService) return err;
            // v3-only tags are dispatched before secp; v2 never sees them.
            const tag = self.keccak.base.cpu.read(profile.TAG_REGISTER);
            if (profile.isV3(self.execution_profile)) if (bulk_memory.kindOf(tag)) |kind| {
                event.* = .{ .bulk = try self.bulk(kind) };
                return null;
            };
            if (profile.isV3(self.execution_profile) and tag == profile.KECCAK_SPONGE_TAG) {
                event.* = .{ .sponge = try self.sponge() };
                return null;
            }
            if (profile.admitsV3(self.execution_profile, tag)) if (curves.opOfTag(tag)) |op| {
                event.* = .{ .curve = try self.curve(op) };
                return null;
            };
            if (profile.admitsV3(self.execution_profile, tag)) {
                event.* = if (tag == profile.ARITH256_MOD_TAG) .{ .arith256_mod = try self.mulAddMod() } else if (tag == profile.SHA256_COMPRESS_TAG) .{ .sha256 = try self.compress() } else unreachable;
                return null;
            }
            event.* = .{ .secp = try self.projective() };
            return null;
        };
        if (row == null) event.* = .{ .keccak = call };
        return row;
    }
    /// Admitted Keccak-256 sponge; every check precedes the state store.
    fn sponge(self: *Session) Error!keccak_sponge.Event {
        const cpu = &self.keccak.base.cpu;
        if (self.sponge_calls == std.math.maxInt(u64)) return error.ServiceCounterOverflow;
        const pointer = cpu.read(profile.POINTER_REGISTER);
        const done = try keccak_sponge.execute(self.allocator, self.keccak.base.memory, pointer);
        const call = keccak_sponge.Call{ .clock = cpu.retired + 1, .pc = cpu.pc, .pointer = pointer };
        cpu.pc +%= 4;
        cpu.retired += 1;
        self.sponge_calls += 1;
        return .{ .call = call, .packet = done.packet, .state_before = done.state_before };
    }
    /// Admitted memcpy/memset/memcmp; every check precedes the atomic write.
    fn bulk(self: *Session, kind: bulk_memory.Kind) Error!bulk_memory.Event {
        const cpu = &self.keccak.base.cpu;
        if (self.bulk_calls == std.math.maxInt(u64)) return error.ServiceCounterOverflow;
        const pointer = cpu.read(profile.POINTER_REGISTER);
        const packet = try bulk_memory.executeRecording(self.allocator, self.keccak.base.memory, kind, pointer, &self.bulk_before);
        const call = bulk_memory.BulkCall{ .clock = cpu.retired + 1, .pc = cpu.pc, .pointer = pointer, .tag = bulk_memory.tagOf(kind) };
        cpu.pc +%= 4;
        cpu.retired += 1;
        self.bulk_calls += 1;
        return .{ .call = call, .packet = packet, .dst_before = self.bulk_before.items };
    }
    /// All checks precede the atomic state write; a trap changes nothing.
    fn compress(self: *Session) Error!Sha256Call {
        const cpu = &self.keccak.base.cpu;
        const mem = self.keccak.base.memory;
        if (self.sha256_calls == std.math.maxInt(u64)) return error.ServiceCounterOverflow;
        const pointer = cpu.read(profile.POINTER_REGISTER);
        // The Word16 bridge binds 32-byte coordinates; the admitted packet is
        // therefore 32-byte aligned (the candidate ABI only required 8).
        if (pointer & 31 != 0) return error.MisalignedAddress;
        _ = try memory.endAddress(pointer, 8 * Sha256Call.WORDS);
        try mem.mappings.check(pointer, 8 * Sha256Call.WORDS, .read);
        var before: [12]u64 = undefined;
        for (&before, 0..) |*word, i| word.* = try mem.load(pointer + 8 * i, 8);
        var after = before;
        after[0..4].* = sha256.compressPacket(before);
        try mem.storeWords(pointer, after[0..Sha256Call.WRITTEN]);
        const result = Sha256Call{ .call_id = self.sha256_calls + 1, .clock = cpu.retired + 1, .pc = cpu.pc, .pointer = pointer, .before = before, .after = after };
        cpu.pc +%= 4;
        cpu.retired += 1;
        self.sha256_calls += 1;
        return result;
    }
    /// All checks precede the atomic r write; a trap changes nothing.
    fn mulAddMod(self: *Session) Error!Arith256ModCall {
        const cpu = &self.keccak.base.cpu;
        const mem = self.keccak.base.memory;
        const W = Arith256ModCall.WORDS;
        if (self.arith256_mod_calls == std.math.maxInt(u64)) return error.ServiceCounterOverflow;
        const pointer = cpu.read(profile.POINTER_REGISTER);
        // The Word16 bridge binds 32-byte coordinates (candidate ABI: 8).
        if (pointer & 31 != 0) return error.MisalignedAddress;
        _ = try memory.endAddress(pointer, 8 * W);
        try mem.mappings.check(pointer, 8 * W, .read);
        try mem.mappings.check(pointer + 8 * Arith256ModCall.FIRST_WRITTEN, 8 * (W - Arith256ModCall.FIRST_WRITTEN), .write);
        var before: [W]u64 = undefined;
        for (&before, 0..) |*word, i| word.* = try mem.load(pointer + 8 * i, 8);
        var after = before;
        after[Arith256ModCall.FIRST_WRITTEN..].* = arith256.mulAddModPacket(before);
        try mem.storeWords(pointer + 8 * Arith256ModCall.FIRST_WRITTEN, after[Arith256ModCall.FIRST_WRITTEN..]);
        const result = Arith256ModCall{ .call_id = self.arith256_mod_calls + 1, .clock = cpu.retired + 1, .pc = cpu.pc, .pointer = pointer, .before = before, .after = after };
        cpu.pc +%= 4;
        cpu.retired += 1;
        self.arith256_mod_calls += 1;
        return result;
    }
    /// All checks precede the atomic write of the leading words; a trap
    /// (alignment, rights, CurveServiceDomain) changes nothing.
    fn curve(self: *Session, op: curves.Op) Error!CurveCall {
        const cpu = &self.keccak.base.cpu;
        const mem = self.keccak.base.memory;
        const count = &self.curve_calls[curves.index(op)];
        if (count.* == std.math.maxInt(u64)) return error.ServiceCounterOverflow;
        const pointer = cpu.read(profile.POINTER_REGISTER);
        const n = curves.words(op);
        // The Word16 bridge binds 32-byte coordinates (candidate ABI: 8-byte
        // aligned pointer packets; the admitted packet is inline).
        if (pointer & 31 != 0) return error.MisalignedAddress;
        _ = try memory.endAddress(pointer, 8 * n);
        try mem.mappings.check(pointer, 8 * n, .read);
        try mem.mappings.check(pointer, 8 * curves.writtenWords(op), .write);
        var before: [curves.MAX_WORDS]u64 = @splat(0);
        for (before[0..n], 0..) |*word, i| word.* = try mem.load(pointer + 8 * i, 8);
        const after = try curves.execute(op, before[0..n]);
        try mem.storeWords(pointer, after[0..curves.writtenWords(op)]);
        const result = CurveCall{ .op = op, .call_id = count.* + 1, .clock = cpu.retired + 1, .pc = cpu.pc, .pointer = pointer, .before = before, .after = after };
        cpu.pc +%= 4;
        cpu.retired += 1;
        count.* += 1;
        return result;
    }
    fn projective(self: *Session) Error!SecpCall {
        const cpu = &self.keccak.base.cpu;
        const mem = self.keccak.base.memory;
        const format: profile.SecpPacketFormat = if (profile.secpWords(self.execution_profile)) .little_endian_words_v2 else .big_endian_bytes_v1;
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
