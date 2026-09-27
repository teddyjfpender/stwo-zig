//! Versioned packed-word block buses, appended after the frozen universal47
//! prefix. Every address/value is two16-bit limbs; clocks/ordinals use four.
//! A separately verified range16 provider authenticates each non-Boolean limb.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const elements = @import("../air/relation_challenges.zig");
const universal_module = @import("../recursion/air/universal_challenges.zig");
const wide = @import("../air/block/memory_transition.zig");
// Version4 additionally packs trusted ordinals and derives global boundary
// selectors from pinned geometry:12 fixed,27 main,68 interaction,degree4.
pub const VERSION = 4;
pub const TAG: u32 = 0x4235574d; // B5WM
pub const TRANSITION_ARITY = 11;
pub const LINK_ARITY = 13;
pub const INITIAL_ARITY = 5;
pub const ENDPOINT_ARITY = 9;
pub const RANGE_ARITY = 1;
pub const Challenges = struct {
    transition: elements.RelationElements(TRANSITION_ARITY),
    link: elements.RelationElements(LINK_ARITY),
    initial: elements.RelationElements(INITIAL_ARITY),
    endpoint: elements.RelationElements(ENDPOINT_ARITY),
    range16: elements.RelationElements(RANGE_ARITY),
    universal_prefix: universal_module.UniversalRelations,
    pub fn draw(a: std.mem.Allocator, sealed: anytype) !Challenges {
        var channel = sealed.sharedChannel();
        return drawFromChannel(a, &channel);
    }
    pub fn drawFromChannel(a: std.mem.Allocator, channel: anytype) !Challenges {
        return drawWith(a, channel, LiveDraw);
    }
    /// One protocol ordering for live challenges and value-free setup emitters.
    /// A fixed emitter records consumption only and has Output=void.
    pub fn drawWith(a: std.mem.Allocator, channel: anytype, comptime Sink: type) !Sink.Output {
        const prefix = try Sink.universal(a, channel);
        channel.mixU32s(&.{ TAG, VERSION, TRANSITION_ARITY, LINK_ARITY, INITIAL_ARITY, ENDPOINT_ARITY, RANGE_ARITY });
        return Sink.extra(a, channel, prefix);
    }
};
const LiveDraw = struct {
    pub const Output = Challenges;
    pub fn universal(a: std.mem.Allocator, channel: anytype) !universal_module.UniversalRelations {
        return universal_module.UniversalRelations.draw(a, channel);
    }
    pub fn extra(a: std.mem.Allocator, channel: anytype, prefix: universal_module.UniversalRelations) !Challenges {
        const draws = try channel.drawSecureFelts(a, 10);
        defer a.free(draws);
        return .{ .transition = .init(draws[0], draws[1]), .link = .init(draws[2], draws[3]), .initial = .init(draws[4], draws[5]), .endpoint = .init(draws[6], draws[7]), .range16 = .init(draws[8], draws[9]), .universal_prefix = prefix };
    }
};

pub fn abiId() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-v5/word-memory-relations/v4\x00");
    hash.update(&universal_module.registryOrderDigest());
    hash.update("radix=65536;range16=0..65535;space-bit;address-u32-byte-units;clock-u64;ordinal-u64;value-u32\x00");
    hash.update("transition=space,addressLE16x2,clockLE16x4,beforeLE16x2,afterLE16x2;link=ordinalLE16x4,space,addressLE16x2,clockLE16x4,afterLE16x2\x00");
    hash.update("initial=space,addressLE16x2,beforeLE16x2;endpoint=space,addressLE16x2,clockLE16x4,afterLE16x2;range16=scalar\x00");
    hash.update("universal47-prefix;B5WM-v4;transition,link,initial,endpoint,range16:z-alpha;alpha-powers-minus-z\x00");
    hash.update("fixed12=active,first,last,domain-last,ordinalLE16x4,previous-ordinalLE16x4;global-first=claim-first-row-zero*first;global-last=claim-end-total*last\x00");
    hash.update("sorted-main27;direct46;range17=current10,key-gap3,clock-gap4;prior=shifted-current-or-public;endpoint=interior-plus-constant-public-fractions;degree4;interaction68\x00");
    hash.update("mask:fixed=current;word-main=current-all,previous=key[2..5),clock[5..9),after[25..27);range-main=current-only;interaction=current-and-previous\x00");
    return hash.finalResult();
}
pub fn transitionTuple(value: wide.Transition) [TRANSITION_ARITY]M {
    var out: [TRANSITION_ARITY]M = undefined;
    out[0] = M.fromCanonical(value.space);
    put(out[1..3], value.address);
    put(out[3..7], value.clock);
    put(out[7..9], value.before);
    put(out[9..11], value.after);
    return out;
}
pub fn initialTuple(value: wide.Transition) [INITIAL_ARITY]M {
    const full = transitionTuple(value);
    return full[0..3].* ++ full[7..9].*;
}
pub fn endpointTuple(value: wide.Transition) [ENDPOINT_ARITY]M {
    const full = transitionTuple(value);
    return full[0..7].* ++ full[9..11].*;
}
pub fn linkTuple(ordinal: u64, value: wide.Transition) [LINK_ARITY]M {
    var out: [LINK_ARITY]M = undefined;
    put(out[0..4], ordinal);
    const end = endpointTuple(value);
    @memcpy(out[4..13], &end);
    return out;
}
/// The existing same-root execution integer AIR authenticates every byte.
/// This linear projection proves an exact equivalent packed tuple with no
/// extra witness and no reduction/truncation of a u64 clock.
pub fn fromByteTransition(comptime S: type, bytes: [21]S) [TRANSITION_ARITY]S {
    return @import("block_v5_native_fused_algebra_v1.zig").Algebra(S).packedTransition(bytes);
}

pub fn readLimbs(limbs: []const M) !u64 {
    if (limbs.len > 4) return error.InvalidV5WordTuple;
    var result: u64 = 0;
    for (limbs, 0..) |limb, i| {
        const value = limb.toU32();
        if (value >= 1 << 16) return error.InvalidV5WordLimb;
        result |= @as(u64, value) << @intCast(16 * i);
    }
    return result;
}
fn put(out: []M, value: anytype) void {
    var rest: u64 = value;
    for (out) |*limb| {
        limb.* = M.fromCanonical(@intCast(rest & 65535));
        rest >>= 16;
    }
}
