//! Row-lane challenge lifting. Every lane uses the same sealed challenge;
//! only witness/evaluation values differ across the lanes.
const core = @import("stwo_core");
const P = core.fields.packed_qm31.PackedQM31;
const protocol = @import("block_v5_word_memory_protocol_v1.zig");
const elements = @import("../air/relation_challenges.zig");
fn Relation(comptime arity: usize) type {
    return struct {
        z: P,
        powers: [arity]P,
        fn init(source: elements.RelationElements(arity)) @This() {
            var powers: [arity]P = undefined;
            for (&powers, source.alpha_powers) |*out, value| out.* = P.splat(value);
            return .{ .z = P.splat(source.z), .powers = powers };
        }
        pub fn combineSecure(self: @This(), values: [arity]P) P {
            return elements.combineGeneric(P, self.z, self.powers, values);
        }
    };
}
pub const Challenges = struct {
    transition: Relation(protocol.TRANSITION_ARITY),
    link: Relation(protocol.LINK_ARITY),
    initial: Relation(protocol.INITIAL_ARITY),
    endpoint: Relation(protocol.ENDPOINT_ARITY),
    range16: Relation(protocol.RANGE_ARITY),
    pub fn init(source: *const protocol.Challenges) Challenges {
        return .{ .transition = .init(source.transition), .link = .init(source.link), .initial = .init(source.initial), .endpoint = .init(source.endpoint), .range16 = .init(source.range16) };
    }
};
