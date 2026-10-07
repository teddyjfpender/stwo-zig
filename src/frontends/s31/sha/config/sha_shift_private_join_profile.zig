//! Public layout and component roster for one private 80-byte Bitcoin header.
//! The header, three message schedules, and compression states are absent
//! from this statement. Gate closure belongs to the enclosing circuit proof.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const caller = @import("../air/sha_caller_stream_air.zig");
const caller_bus = @import("../air/sha_caller_stream_bus.zig");
const schedule = @import("../air/sha_schedule_direct_air.zig");
const schedule_bus = @import("../air/sha_schedule_direct_word_logup.zig");
const round = @import("../air/sha_round_shift_air.zig");
const round_bus = @import("../air/sha_round_shift_word_logup.zig");
const feed = @import("../air/sha_feed_direct_air.zig");
const feed_bus = @import("../air/sha_feed_direct_word_logup.zig");
const word_bus = @import("../air/sha_direct_word_bus.zig");

pub const call_count: usize = 3;
pub const word_claim_count: usize = 1 + call_count * 3;
pub const component_count: usize = 2 + call_count * 6;
pub const format_version: u32 = 1;

pub const PublicStatement = caller.Statement;
pub const Claims = struct {
    gate: core.fields.qm31.QM31,
    word: [word_claim_count]core.fields.qm31.QM31,

    pub fn wordClosure(self: Claims) core.fields.qm31.QM31 {
        var total = core.fields.qm31.QM31.zero();
        for (self.word) |claim| total = total.add(claim);
        return total;
    }
    pub fn validate(self: Claims) !void {
        if (!self.wordClosure().isZero()) return error.UnclosedShaWordBus;
    }
};

pub const Prefix = struct { fixed: usize = 0, main: usize = 0, interaction: usize = 0 };
pub const Layout = struct {
    caller_fixed: usize,
    caller_bus_fixed: usize,
    caller_main: usize,
    caller_bus_interaction: usize,
    schedule_fixed: [call_count]usize,
    round_fixed: [call_count]usize,
    feed_fixed: [call_count]usize,
    schedule_main: [call_count]usize,
    round_main: [call_count]usize,
    feed_main: [call_count]usize,
    schedule_interaction: [call_count]usize,
    round_interaction: [call_count]usize,
    feed_interaction: [call_count]usize,
    total_fixed: usize,
    total_main: usize,
    total_interaction: usize,

    /// All offsets are absolute within the three shared PCS commitment trees.
    /// A circuit may prepend its own columns and use the returned offsets.
    pub fn init(prefix: Prefix) Layout {
        var f = prefix.fixed;
        var m = prefix.main;
        var i = prefix.interaction;
        var out: Layout = undefined;
        out.caller_fixed = f;
        f += caller.fixed_width;
        out.caller_main = m;
        m += caller.main_width;
        out.caller_bus_fixed = f;
        f += caller_bus.fixed_width;
        out.caller_bus_interaction = i;
        i += caller_bus.interaction_width;
        for (0..call_count) |call| {
            out.schedule_fixed[call] = f;
            f += schedule.fixed_width;
            out.round_fixed[call] = f;
            f += round.fixed_width;
            out.feed_fixed[call] = f;
            f += feed.fixed_width;
            out.schedule_main[call] = m;
            m += schedule.main_width;
            out.round_main[call] = m;
            m += round.main_width;
            out.feed_main[call] = m;
            m += feed.main_width;
            out.schedule_interaction[call] = i;
            i += schedule_bus.interaction_width;
            out.round_interaction[call] = i;
            i += round_bus.interaction_width;
            out.feed_interaction[call] = i;
            i += feed_bus.interaction_width;
        }
        out.total_fixed = f;
        out.total_main = m;
        out.total_interaction = i;
        return out;
    }
};

pub const Components = struct {
    caller_component: caller.Component,
    caller_bus_component: caller_bus.Component,
    schedule_components: [call_count]schedule.Component,
    round_components: [call_count]round.Component,
    feed_components: [call_count]feed.Component,
    schedule_bus_components: [call_count]schedule_bus.Component,
    round_bus_components: [call_count]round_bus.Component,
    feed_bus_components: [call_count]feed_bus.Component,

    pub fn init(statement: PublicStatement, claims: Claims, gate_elements: word_bus.Elements, word_elements: word_bus.Elements, layout: Layout) Components {
        const empty_round = round.Statement{ .initial = @splat(0), .final = @splat(0), .schedule = @splat(0) };
        var result: Components = undefined;
        result.caller_component = .{
            .statement = statement,
            .fixed_offset = layout.caller_fixed,
            .main_offset = layout.caller_main,
        };
        result.caller_bus_component = .{
            .config = statement.config,
            .fixed_offset = layout.caller_bus_fixed,
            .main_offset = layout.caller_main,
            .interaction_offset = layout.caller_bus_interaction,
            .gate_elements = gate_elements,
            .word_elements = word_elements,
            .gate_claimed_sum = claims.gate,
            .word_claimed_sum = claims.word[0],
        };
        for (0..call_count) |call| {
            const id = statement.config.first_call_id + @as(u32, @intCast(call));
            result.schedule_components[call] = .{
                .fixed_offset = layout.schedule_fixed[call],
                .main_offset = layout.schedule_main[call],
                .boundary_mode = .private_input,
            };
            result.round_components[call] = .{
                .statement = empty_round,
                .fixed_offset = layout.round_fixed[call],
                .main_offset = layout.round_main[call],
            };
            result.feed_components[call] = .{
                .private_mode = true,
                .fixed_offset = layout.feed_fixed[call],
                .main_offset = layout.feed_main[call],
            };
            result.schedule_bus_components[call] = .{
                .call_id = id,
                .elements = word_elements,
                .claimed_sum = claims.word[1 + 3 * call],
                .fixed_offset = layout.schedule_fixed[call],
                .main_offset = layout.schedule_main[call],
                .interaction_offset = layout.schedule_interaction[call],
            };
            result.round_bus_components[call] = .{
                .call_id = id,
                .elements = word_elements,
                .claimed_sum = claims.word[2 + 3 * call],
                .fixed_offset = layout.round_fixed[call],
                .main_offset = layout.round_main[call],
                .interaction_offset = layout.round_interaction[call],
            };
            result.feed_bus_components[call] = .{
                .call_id = id,
                .elements = word_elements,
                .claimed_sum = claims.word[3 + 3 * call],
                .fixed_offset = layout.feed_fixed[call],
                .main_offset = layout.feed_main[call],
                .interaction_offset = layout.feed_interaction[call],
            };
        }
        return result;
    }

    pub fn proverHandles(self: *const Components) [component_count]prover.air.component_prover.ComponentProver {
        var handles: [component_count]prover.air.component_prover.ComponentProver = undefined;
        handles[0] = self.caller_component.asProverComponent();
        handles[1] = self.caller_bus_component.asProverComponent();
        for (0..call_count) |call| {
            const at = 2 + 6 * call;
            handles[at] = self.schedule_components[call].asProverComponent();
            handles[at + 1] = self.round_components[call].asProverComponent();
            handles[at + 2] = self.feed_components[call].asProverComponent();
            handles[at + 3] = self.schedule_bus_components[call].asProverComponent();
            handles[at + 4] = self.round_bus_components[call].asProverComponent();
            handles[at + 5] = self.feed_bus_components[call].asProverComponent();
        }
        return handles;
    }
    pub fn verifierHandles(self: *const Components) [component_count]core.air.components.Component {
        var handles: [component_count]core.air.components.Component = undefined;
        handles[0] = self.caller_component.asVerifierComponent();
        handles[1] = self.caller_bus_component.asVerifierComponent();
        for (0..call_count) |call| {
            const at = 2 + 6 * call;
            handles[at] = self.schedule_components[call].asVerifierComponent();
            handles[at + 1] = self.round_components[call].asVerifierComponent();
            handles[at + 2] = self.feed_components[call].asVerifierComponent();
            handles[at + 3] = self.schedule_bus_components[call].asVerifierComponent();
            handles[at + 4] = self.round_bus_components[call].asVerifierComponent();
            handles[at + 5] = self.feed_bus_components[call].asVerifierComponent();
        }
        return handles;
    }
};

pub fn semanticDigest() [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(@embedFile("sha_shift_private_join_profile.zig"));
    hasher.update(@embedFile("../air/sha_caller_stream_air.zig"));
    hasher.update(@embedFile("../air/sha_caller_stream_equations.zig"));
    hasher.update(@embedFile("../air/sha_caller_stream_bus.zig"));
    hasher.update(@embedFile("../air/sha_schedule_direct_air.zig"));
    hasher.update(@embedFile("../air/sha_schedule_direct_equations.zig"));
    hasher.update(@embedFile("../air/sha_schedule_direct_word_logup.zig"));
    hasher.update(@embedFile("../air/sha_round_shift_air.zig"));
    hasher.update(@embedFile("../air/sha_round_shift_word_logup.zig"));
    hasher.update(@embedFile("../air/sha_feed_direct_air.zig"));
    hasher.update(@embedFile("../air/sha_feed_direct_equations.zig"));
    hasher.update(@embedFile("../air/sha_feed_direct_word_logup.zig"));
    hasher.update(@embedFile("../air/sha_direct_word_bus.zig"));
    hasher.update(@embedFile("../air/sha_round_shift_word_bus.zig"));
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

test "private SHA join layout preserves all shared column offsets and three call namespaces" {
    const layout = Layout.init(.{});
    try std.testing.expectEqual(@as(usize, 79), layout.total_fixed);
    try std.testing.expectEqual(@as(usize, 500), layout.total_main);
    try std.testing.expectEqual(@as(usize, 112), layout.total_interaction);
    const with_prefix = Layout.init(.{ .fixed = 17, .main = 23, .interaction = 29 });
    try std.testing.expectEqual(layout.total_fixed + 17, with_prefix.total_fixed);
    try std.testing.expectEqual(layout.total_main + 23, with_prefix.total_main);
    try std.testing.expectEqual(layout.total_interaction + 29, with_prefix.total_interaction);
    try std.testing.expectEqual(layout.caller_bus_fixed + 17, with_prefix.caller_bus_fixed);
    try std.testing.expectEqual(layout.round_main[2] + 23, with_prefix.round_main[2]);
}
