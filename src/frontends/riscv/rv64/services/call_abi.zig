//! Canonical captured service calls; session admission and dispatch stay with the executor.
const K = @import("../service_session.zig");
const machine = @import("../machine.zig");
const profile = @import("../execution_profile.zig");
pub const secp256k1 = @import("stwo_riscv_precompiles").primitives.secp256k1;
pub const curves = @import("curve_packets.zig");
pub const bulk_memory = @import("bulk_packets.zig");
pub const keccak_sponge = @import("sponge_packets.zig");
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

/// Independent mathematical references, separate from optimized witnesses.
pub const reference_crypto = @import("reference_crypto.zig");
