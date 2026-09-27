//! Shared typed page-binding kernel; schemas fix exact original source
//! inventory and grammar. No host/source descriptor grants proof authority.
const std = @import("std");
const core = @import("stwo_core");
const Base = @import("block_v5_source_seal_v1.zig");
const Universal = @import("../recursion/air/universal_challenges.zig");

pub fn ForSchema(comptime Schema: type) type {
    return struct {
        //! B5SP binds page arithmetic to the original prechallenge source main tree.
        //! Uses exact recursion_wire(6) grammar with a NEW post-source-root challenge.
        const suite = core.proof_suites.Blake3;
        const First = Schema.Protocol;
        const Source = Schema.Source;
        pub const TAG: u32 = Schema.PAGE_TAG;
        pub const VERSION: u32 = Schema.PAGE_VERSION;
        pub const CIRCUIT_BASE: u32 = Schema.CIRCUIT_BASE;
        pub fn abiId() [32]u8 {
            return Schema.pageAbiId();
        }

        /// After source commitments, before arithmetic commitments and wire draws.
        pub const SourceEpoch = struct { source: Source.Challenges, channel: suite.Channel };
        pub fn sourceEpoch(a: std.mem.Allocator, admitted: *const Source.Admitted, plan: First.Plan, entries: []const First.Pin, sealed: First.Sealed, expected: [32]u8, base: Base.Sealed, limits: First.Limits) !SourceEpoch {
            try sealed.require(admitted, plan, entries, expected, limits);
            if (!std.meta.eql(base.digest, admitted.sealed_digest)) return error.UntrustedSourceFirstSeal;
            var channel = base.sharedChannel();
            const source = try First.drawFromChannel(a, &channel, sealed);
            return .{ .source = source, .channel = channel };
        }
        /// Physical arithmetic fixed/main roots, including ALL requesting operand and
        /// output witness cells. These are candidates until a genuine proof verifies.
        pub const ArithmeticPin = struct {
            page_index: u32,
            source_pin_id: [32]u8,
            graph_roster_id: [32]u8,
            roots: [2][32]u8,
        };
        pub const Challenges = struct { source: Source.Challenges, arithmetic: Universal.UniversalRelations, channel: suite.Channel };
        /// `expected_arithmetic` must be independently derived from the actual page
        /// arithmetic admission and root roster, never selected from received bytes.
        /// Both source and arithmetic main rosters precede the same wire draw.
        pub fn draw(a: std.mem.Allocator, admitted: *const Source.Admitted, plan: First.Plan, entries: []const First.Pin, sealed: First.Sealed, expected: [32]u8, base: Base.Sealed, expected_arithmetic: []const ArithmeticPin, received_arithmetic: []const ArithmeticPin, limits: First.Limits) !Challenges {
            var epoch = try sourceEpoch(a, admitted, plan, entries, sealed, expected, base, limits);
            if (expected_arithmetic.len != plan.pages or !std.meta.eql(expected_arithmetic.len, received_arithmetic.len)) return error.InvalidMemorySourceArithmeticRoster;
            epoch.channel.mixRoot(abiId());
            epoch.channel.mixU32s(&.{ TAG, VERSION, 0x41524954, plan.pages, 6, CIRCUIT_BASE });
            for (expected_arithmetic, received_arithmetic, entries, 0..) |pin, received, source_pin, i| {
                if (!std.meta.eql(pin, received) or pin.page_index != i or !std.meta.eql(pin.source_pin_id, try source_pin.identity(plan)) or std.mem.allEqual(u8, &pin.graph_roster_id, 0)) return error.InvalidMemorySourceArithmeticRoster;
                epoch.channel.mixU32s(&.{pin.page_index});
                epoch.channel.mixRoot(pin.source_pin_id);
                epoch.channel.mixRoot(pin.graph_roster_id);
                for (pin.roots) |root| {
                    if (std.mem.allEqual(u8, &root, 0)) return error.InvalidMemorySourceArithmeticRoster;
                    epoch.channel.mixRoot(root);
                }
            }
            const q = try epoch.channel.drawSecureFelts(a, 2);
            defer a.free(q);
            var arithmetic = epoch.source.word.universal_prefix;
            const domain = @import("../air/lang/relation.zig").Domain.recursion_wire;
            arithmetic.elements[@intFromEnum(domain)] = .init(6, q[0], q[1]);
            try arithmetic.validate();
            return .{ .source = epoch.source, .arithmetic = arithmetic, .channel = epoch.channel };
        }
        pub fn circuitId(global_chunk: u64) !u32 {
            const id = try std.math.add(u64, CIRCUIT_BASE, global_chunk);
            if (id >= core.fields.m31.Modulus) return error.InvalidMemorySourceCircuitId;
            return @intCast(id);
        }
    };
}
