//! Value-free roster for a private three-call SHA256d witness.
//! The fused trace shares a word bus with the caller and three feed chips.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const caller = @import("../air/sha_caller_stream_air.zig");
const caller_bus = @import("../air/sha_caller_stream_bus.zig");
const fused = @import("../air/sha_fused_air.zig");
const fused_bus = @import("../air/sha_fused_word_logup.zig");
const feed = @import("../air/sha_feed_direct_air.zig");
const feed_bus = @import("../air/sha_feed_direct_word_logup.zig");
const word_bus = @import("../air/sha_direct_word_bus.zig");

pub const call_count: usize = 3;
pub const word_claim_count: usize = 2 + call_count;
pub const component_count: usize = 4 + 2 * call_count;
pub const PublicStatement = caller.Statement;
pub const Claims = struct {
    gate: core.fields.qm31.QM31,
    word: [word_claim_count]core.fields.qm31.QM31,
    pub fn validate(self: Claims) !void {
        var sum = core.fields.qm31.QM31.zero();
        for (self.word) |claim| sum = sum.add(claim);
        if (!sum.isZero()) return error.UnclosedShaWordBus;
    }
};
pub const Prefix = struct { fixed: usize = 0, main: usize = 0, interaction: usize = 0 };
pub const Layout = struct {
    caller_fixed: usize,
    caller_bus_fixed: usize,
    fused_fixed: usize,
    feed_fixed: [call_count]usize,
    caller_main: usize,
    fused_main: usize,
    feed_main: [call_count]usize,
    caller_bus_interaction: usize,
    fused_interaction: usize,
    feed_interaction: [call_count]usize,
    total_fixed: usize,
    total_main: usize,
    total_interaction: usize,
    pub fn init(prefix: Prefix) Layout {
        var f = prefix.fixed;
        var m = prefix.main;
        var i = prefix.interaction;
        var out: Layout = undefined;
        out.caller_fixed = f;
        f += caller.fixed_width;
        out.caller_bus_fixed = f;
        f += caller_bus.fixed_width;
        out.fused_fixed = f;
        f += fused.fixed_width;
        out.caller_main = m;
        m += caller.main_width;
        out.fused_main = m;
        m += fused.main_width;
        out.caller_bus_interaction = i;
        i += caller_bus.interaction_width;
        out.fused_interaction = i;
        i += fused_bus.interaction_width;
        for (0..call_count) |call| {
            out.feed_fixed[call] = f;
            f += feed.fixed_width;
            out.feed_main[call] = m;
            m += feed.main_width;
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
    fused_component: fused.Component,
    fused_bus_component: fused_bus.Component,
    feed_components: [call_count]feed.Component,
    feed_bus_components: [call_count]feed_bus.Component,
    pub fn init(statement: PublicStatement, claims: Claims, gate_elements: word_bus.Elements, word_elements: word_bus.Elements, layout: Layout) Components {
        var result: Components = undefined;
        result.caller_component = .{ .statement = statement, .fixed_offset = layout.caller_fixed, .main_offset = layout.caller_main };
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
        result.fused_component = .{ .fixed_offset = layout.fused_fixed, .main_offset = layout.fused_main };
        result.fused_bus_component = .{
            .elements = word_elements,
            .claimed_sum = claims.word[1],
            .fixed_offset = layout.fused_fixed,
            .main_offset = layout.fused_main,
            .interaction_offset = layout.fused_interaction,
        };
        for (0..call_count) |call| {
            result.feed_components[call] = .{
                .private_mode = true,
                .fixed_offset = layout.feed_fixed[call],
                .main_offset = layout.feed_main[call],
            };
            result.feed_bus_components[call] = .{
                .call_id = statement.config.first_call_id + @as(u32, @intCast(call)),
                .elements = word_elements,
                .claimed_sum = claims.word[2 + call],
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
        handles[2] = self.fused_component.asProverComponent();
        handles[3] = self.fused_bus_component.asProverComponent();
        for (0..call_count) |call| {
            handles[4 + 2 * call] = self.feed_components[call].asProverComponent();
            handles[5 + 2 * call] = self.feed_bus_components[call].asProverComponent();
        }
        return handles;
    }
    pub fn verifierHandles(self: *const Components) [component_count]core.air.components.Component {
        var handles: [component_count]core.air.components.Component = undefined;
        handles[0] = self.caller_component.asVerifierComponent();
        handles[1] = self.caller_bus_component.asVerifierComponent();
        handles[2] = self.fused_component.asVerifierComponent();
        handles[3] = self.fused_bus_component.asVerifierComponent();
        for (0..call_count) |call| {
            handles[4 + 2 * call] = self.feed_components[call].asVerifierComponent();
            handles[5 + 2 * call] = self.feed_bus_components[call].asVerifierComponent();
        }
        return handles;
    }
};

pub fn semanticDigest() [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    inline for (.{ "sha_fused_private_join_profile.zig", "../air/sha_caller_stream_air.zig", "../air/sha_caller_stream_equations.zig", "../air/sha_caller_stream_bus.zig", "../air/sha_fused_air.zig", "../air/sha_fused_word_bus.zig", "../air/sha_fused_word_logup.zig", "../air/sha_schedule_direct_equations.zig", "../air/sha_feed_direct_air.zig", "../air/sha_feed_direct_equations.zig", "../air/sha_feed_direct_word_logup.zig", "../air/sha_direct_word_bus.zig" }) |path| hasher.update(@embedFile(path));
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

test "fused private layout is compact and prefix-stable" {
    const a = Layout.init(.{});
    try std.testing.expectEqual(@as(usize, 51), a.total_fixed);
    try std.testing.expectEqual(@as(usize, 270), a.total_main);
    try std.testing.expectEqual(@as(usize, 64), a.total_interaction);
    const b = Layout.init(.{ .fixed = 7, .main = 13, .interaction = 17 });
    try std.testing.expectEqual(a.fused_fixed + 7, b.fused_fixed);
    try std.testing.expectEqual(a.fused_main + 13, b.fused_main);
    try std.testing.expectEqual(a.fused_interaction + 17, b.fused_interaction);
}
