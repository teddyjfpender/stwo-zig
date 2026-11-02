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
pub const PROFILE_V3 = "rv64im-ethereum-services-v3";
pub const sha256 = @import("sha256.zig");
pub const arith256 = @import("arith256.zig");
pub const curves = @import("curves.zig");
pub const bulk_memory = @import("bulk_memory.zig");
pub const keccak_sponge = @import("keccak_sponge.zig");
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
/// One admitted v3 SHA-256 compression (tag 0x0003_0010). The packet is 12
/// little-endian u64 words at a 32-byte aligned pointer: state H0..H7 as LE
/// u32 pairs (H0 in the low half of word 0), then the 64-byte block in stream
/// order. Only words 0..4 change.
pub const Sha256Call = struct {
    /// One-based counter within this family; never guest-visible.
    call_id: u64,
    clock: u64,
    pc: u64,
    pointer: u64,
    before: [12]u64,
    after: [12]u64,
    pub const WORDS = 12;
    pub const WRITTEN = 4;
    pub fn tag(_: Sha256Call) u64 {
        return profile.SHA256_COMPRESS_TAG;
    }
    pub fn retirement(self: Sha256Call) machine.Retirement {
        const Word = @import("../word.zig").Word;
        return .{ .clock = self.clock, .pc = Word.fromInt(self.pc), .next_pc = Word.fromInt(self.pc +% 4), .immediate = Word.fromInt(0), .instruction = 0x73, .opcode = .ECALL, .rs1 = profile.POINTER_REGISTER, .rs2 = profile.TAG_REGISTER, .lhs = Word.fromInt(self.pointer), .rhs = Word.fromInt(self.tag()), .rd = 0, .previous_rd = Word.fromInt(0), .result = Word.fromInt(0), .writes_rd = false, .branch_taken = false, .memory = null };
    }
};
/// One admitted v3 arith256_mod call (tag 0x0003_0021). The packet is 20
/// little-endian u64 words at a 32-byte aligned pointer: a, b, c, m, r as four
/// LE limbs each. Only words 16..20 (r) change: r = (a*b + c) mod m, 0 if m = 0.
pub const Arith256ModCall = struct {
    /// One-based counter within this family; never guest-visible.
    call_id: u64,
    clock: u64,
    pc: u64,
    pointer: u64,
    before: [20]u64,
    after: [20]u64,
    pub const WORDS = 20;
    /// First written word; words FIRST_WRITTEN..WORDS hold r.
    pub const FIRST_WRITTEN = 16;
    pub fn tag(_: Arith256ModCall) u64 {
        return profile.ARITH256_MOD_TAG;
    }
    pub fn retirement(self: Arith256ModCall) machine.Retirement {
        const Word = @import("../word.zig").Word;
        return .{ .clock = self.clock, .pc = Word.fromInt(self.pc), .next_pc = Word.fromInt(self.pc +% 4), .immediate = Word.fromInt(0), .instruction = 0x73, .opcode = .ECALL, .rs1 = profile.POINTER_REGISTER, .rs2 = profile.TAG_REGISTER, .lhs = Word.fromInt(self.pointer), .rhs = Word.fromInt(self.tag()), .rd = 0, .previous_rd = Word.fromInt(0), .result = Word.fromInt(0), .writes_rd = false, .branch_taken = false, .memory = null };
    }
};
/// One admitted v3 curve/field call (curves.zig). The packet is
/// `curves.words(op)` little-endian u64 words at a 32-byte aligned pointer;
/// only the leading `curves.writtenWords(op)` words may change.
pub const CurveCall = struct {
    op: curves.Op,
    /// One-based counter within this op; never guest-visible.
    call_id: u64,
    clock: u64,
    pc: u64,
    pointer: u64,
    /// Words beyond wordCount() are zero.
    before: [curves.MAX_WORDS]u64,
    after: [curves.MAX_WORDS]u64,
    pub fn wordCount(self: CurveCall) usize {
        return curves.words(self.op);
    }
    pub fn writtenWords(self: CurveCall) usize {
        return curves.writtenWords(self.op);
    }
    pub fn tag(self: CurveCall) u64 {
        return curves.tag(self.op);
    }
    pub fn retirement(self: CurveCall) machine.Retirement {
        const Word = @import("../word.zig").Word;
        return .{ .clock = self.clock, .pc = Word.fromInt(self.pc), .next_pc = Word.fromInt(self.pc +% 4), .immediate = Word.fromInt(0), .instruction = 0x73, .opcode = .ECALL, .rs1 = profile.POINTER_REGISTER, .rs2 = profile.TAG_REGISTER, .lhs = Word.fromInt(self.pointer), .rhs = Word.fromInt(self.tag()), .rd = 0, .previous_rd = Word.fromInt(0), .result = Word.fromInt(0), .writes_rd = false, .branch_taken = false, .memory = null };
    }
};
pub const Event = union(enum) {
    keccak: K.Call,
    secp: SecpCall,
    sha256: Sha256Call,
    arith256_mod: Arith256ModCall,
    bulk: bulk_memory.Event,
    sponge: keccak_sponge.Event,
    curve: CurveCall,
    pub fn retirement(self: Event) machine.Retirement {
        return switch (self) {
            .sponge => |e| e.call.retirement(),
            .bulk => |e| e.call.retirement(),
            .keccak => |call| call.retirement(),
            .secp => |call| call.retirement(),
            .sha256 => |call| call.retirement(),
            .arith256_mod => |call| call.retirement(),
            .curve => |call| call.retirement(),
        };
    }
};
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
        if (execution_profile != .ethereum_services_v1 and execution_profile != .ethereum_services_v2 and execution_profile != .ethereum_services_v3) return error.UnsupportedService;
        return .{ .keccak = try K.Session.init(a, cpu, mem, options), .execution_profile = execution_profile, .allocator = a };
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
            if (self.execution_profile == .ethereum_services_v3) if (bulk_memory.kindOf(tag)) |kind| {
                event.* = .{ .bulk = try self.bulk(kind) };
                return null;
            };
            if (self.execution_profile == .ethereum_services_v3 and tag == profile.KECCAK_SPONGE_TAG) {
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
