//! Admitted Keccak-256 sponge call metadata, challenges, claims and bounds.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../../evaluation.zig");
const R = @import("../../memory/closed_ram/mod.zig");
const Owner = @import("../../memory/load_store_v2/types.zig");
const Scalar = @import("../../providers/scalar_range.zig");
const Tables = @import("../../providers/tables.zig");
const KE = @import("../keccak/equations.zig");
pub const Native = @import("../../../ethereum_services/keccak_sponge.zig");
pub const Q = E.Q;
pub const State = R.types.State;
pub const Packet = Native.Packet;

pub const TAG: u64 = Native.TAG;
/// OWNER19 slot-0 value of the call -> first-permutation token. CPU OWNER
/// tuples carry a decoded opcode (< 256) in slot 0, bulk tokens 0x424D000x.
pub const TOKEN: u32 = 0x4B53_0001;
/// IO11 direction of the call -> first-permutation state link. The Keccak-f
/// truth only produces directions 0 (input) and 1 (output).
pub const LINK: u32 = 2;
pub const LANES = 25;
pub const RATE_LANES = 17;
pub const RATE = 136;
/// Message words one permutation row can read: slot 0 (word 17k, first row
/// only, else the previous row's slot 17) and slots 1..17.
pub const SLOTS = 18;

/// One admitted call: RAM predecessors of the packet and state words; the
/// message word predecessors are `words[first_word..][0..packet().words()]`.
pub const Call = struct {
    pointer: u64,
    epoch: u16,
    tick: u24,
    packet: [4]State,
    state: [25]State,
    first_word: u32 = 0,
    first_perm: u32 = 0,
    pub fn p(self: Call) Packet {
        return .{ .state = self.packet[0].value, .input = self.packet[1].value, .len = self.packet[2].value, .flags = self.packet[3].value };
    }
    pub fn permutations(self: Call) u32 {
        return @intCast(self.p().permutations());
    }
    pub fn words(self: Call) u32 {
        return @intCast(self.p().words());
    }
};

pub const Challenges = struct {
    ram: R.types.RamChallenges,
    owner: Owner.OwnerChallenges,
    io: KE.Io,
    and_: Tables.Challenges,
    range16: Scalar.Challenges,
    range8: Scalar.Challenges,
};
pub const RELATIONS = 6;
pub const Claims = struct {
    ram: Q,
    owner: Q,
    io: Q,
    and_: Q,
    range16: Q,
    range8: Q,
    pub fn zero() @This() {
        return .{ .ram = Q.zero(), .owner = Q.zero(), .io = Q.zero(), .and_ = Q.zero(), .range16 = Q.zero(), .range8 = Q.zero() };
    }
    pub fn values(self: @This()) [RELATIONS]Q {
        return .{ self.ram, self.owner, self.io, self.and_, self.range16, self.range8 };
    }
    pub fn fromValues(v: [RELATIONS]Q) @This() {
        return .{ .ram = v[0], .owner = v[1], .io = v[2], .and_ = v[3], .range16 = v[4], .range8 = v[5] };
    }
    pub fn add(self: @This(), other: @This()) @This() {
        var out = self.values();
        for (&out, other.values()) |*x, y| x.* = x.add(y);
        return fromValues(out);
    }
};

/// `rows` active rows must leave at least one inactive row (wrap guard), and
/// every unconditional lookup mass of the component stays below p.
pub fn validateGeometry(kind: @import("layout.zig").Kind, rows: u64, log: u32) !usize {
    if (log < 5 or log > 22) return error.InvalidKeccakSpongeGeometry;
    const n = @as(usize, 1) << @intCast(log);
    if (rows >= n) return error.InvalidKeccakSpongeGeometry;
    const L = @import("layout.zig");
    const lookups: u64 = L.range16Count(kind) + L.range8Count(kind) + L.andCount(kind);
    if (lookups * n >= core.fields.m31.Modulus) return error.KeccakSpongeMassBound;
    return n;
}

fn before(state: State, call: Call) !void {
    if (state.epoch > call.epoch or (state.epoch == call.epoch and state.tick >= call.tick)) return error.InvalidKeccakSpongePredecessor;
}
/// Native admission of one call against its RAM predecessors (the executor's
/// ABI rules); every bridge row is built only from admitted calls.
pub fn validateCall(call: Call, words: []const State) !void {
    // The tick stride (4, or 1 under the wide-clock CPU) is the producing CPU's
    // encoding; collectors check it against the CPU log (word16_execution.layout.ramStride).
    if (call.epoch == 0 or call.tick == 0) return error.InvalidKeccakSpongeClock;
    const p = call.p();
    Native.validatePacket(call.pointer, p) catch return error.InvalidKeccakSpongePacket;
    if (words.len != p.words()) return error.InvalidKeccakSpongeWords;
    for (call.packet) |s| {
        if (s.rights & 1 == 0) return error.InvalidKeccakSpongePredecessor;
        try before(s, call);
    }
    for (call.state) |s| {
        if (s.rights != 3) return error.InvalidKeccakSpongePredecessor;
        try before(s, call);
    }
    for (words) |s| {
        if (s.rights & 1 == 0) return error.InvalidKeccakSpongePredecessor;
        try before(s, call);
    }
}

/// Every permutation input/output of one call, computed natively from the
/// predecessor values. Witness only: the Keccak-f truth re-derives outputs.
pub fn permutations(a: std.mem.Allocator, call: Call, words: []const State) ![][2][25]u64 {
    const values = try a.alloc(u64, words.len);
    defer a.free(values);
    for (values, words) |*v, s| v.* = s.value;
    const out = try a.alloc([2][25]u64, call.permutations());
    errdefer a.free(out);
    var state: [25]u64 = undefined;
    for (&state, call.state) |*v, s| v.* = s.value;
    Native.run(call.p(), &state, values, out);
    return out;
}
