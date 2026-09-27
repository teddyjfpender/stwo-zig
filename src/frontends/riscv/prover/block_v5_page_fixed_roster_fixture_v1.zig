//! Original nominal component/byte-layout oracle, never an admitted recursive
//! owner, capture, proof or receiver token. No private verifier is executed.
const std = @import("std");
const core = @import("stwo_core");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Components = @import("block_v5_memory_source_unified_page_components_v1.zig");
const Protocol = @import("block_v5_memory_source_unified_page_protocol_v1.zig");
const Layout = @import("../recursion/air/block_v5_memory_source_page_fixed_layout_v1.zig");
const Transcript = @import("../recursion/block_v5_memory_source_page_recursive_fixed_transcript_v1.zig");
const Static = @import("../recursion/air/block_v5_static_component_compiler_v1.zig");
const ArithmeticAirs = @import("../recursion/air/arithmetic_fusion_fixed_columns_v1.zig").Airs;
const Deep = @import("../recursion/air/pcs_deep_circuit.zig");
const Fri = @import("../recursion/air/fri_verifier_circuit.zig");
pub fn ForKind(comptime kind: Semantic.Kind) type {
    const Original = if (kind == .raw) @import("block_v5_memory_source_page_raw_recursive_parity_test_v1.zig").Fixture else @import("block_v5_memory_source_page_recursive_test_v1.zig").Fixture;
    const C = Components.ForKind(kind);
    const Equation = @import("../recursion/air/block_v5_memory_source_page_shape_composition_v1.zig").ForKind(kind);
    const CoreCompiler = Static.ForAirs(C.CoreAirs);
    const ArithmeticCompiler = Static.ForAirs(ArithmeticAirs);
    return struct {
        const Self = @This();
        original: Original,
        cores: *CoreCompiler,
        arithmetic: *ArithmeticCompiler,
        profile: *@import("block_v5_native_fixed_pcs_test_v1.zig").PageView,
        composition: Equation.Compiled,
        deep: Deep.Circuit,
        fri: Fri.Circuit,
        layout: Layout.Layout,
        transcript: @import("../recursion/air/blake3_transcript_plan.zig").Plan,
        pub fn init(a: std.mem.Allocator) !Self {
            var original = try Original.init(a);
            errdefer original.deinit();
            const cores = try CoreCompiler.init(a, original.core_setup, original.frame.geometry.core_logs, @as([C.CoreAirs.len][0]core.fields.m31.M31, @splat(.{})));
            errdefer cores.deinit();
            const arithmetic = try ArithmeticCompiler.init(a, original.arithmetic_setup, original.frame.geometry.arithmetic_logs, Components.ARITHMETIC_PARAMETERS);
            errdefer arithmetic.deinit();
            var logs: [9][]const u32 = undefined;
            for (&logs, original.frame.logs) |*out, columns| out.* = columns;
            var composition = try Equation.compileView(a, @splat(17), original.graph.identity, &original.fixed.plan, .{ .cores = cores, .arithmetic = arithmetic }, .{ .geometry = original.frame.geometry, .constraint_count = original.frame.constraint_count, .constraint_log = original.frame.constraint_log, .split = original.frame.split }, logs, .{});
            errdefer composition.deinit();
            const profile = try @import("block_v5_native_fixed_pcs_test_v1.zig").PageView.init(a, original.owner.composition.?);
            errdefer profile.deinit();
            var deep = try Deep.build(a, profile.deepProfile());
            errdefer deep.deinit();
            var fri = try Fri.build(a, profile.friProfile());
            errdefer fri.deinit();
            var layout = try deriveLayout(kind, a, &original);
            errdefer layout.deinit();
            var transcript = try Transcript.ForKind(kind).recordForLayout(a, &layout, profile, 1, .{});
            errdefer transcript.deinit();
            return .{ .original = original, .cores = cores, .arithmetic = arithmetic, .profile = profile, .composition = composition, .deep = deep, .fri = fri, .layout = layout, .transcript = transcript };
        }
        pub fn deinit(self: *Self) void {
            self.transcript.deinit();
            self.layout.deinit();
            self.fri.deinit();
            self.deep.deinit();
            self.profile.deinit();
            self.composition.deinit();
            self.arithmetic.deinit();
            self.cores.deinit();
            self.original.deinit();
        }
    };
}
fn epoch(a: std.mem.Allocator) !Protocol.SourceEpoch {
    // Fully initialized public framing proposal only; no authenticated epoch
    // or independently admitted production policy is constructed by this test.
    var channel = core.channel.blake3.Channel{};
    channel.mixRoot(@splat(14));
    const word = try @import("block_v5_word_memory_protocol_v1.zig").Challenges.drawFromChannel(a, &channel);
    const values = try channel.drawSecureFelts(a, 24);
    defer a.free(values);
    return .{ .seal_digest = @splat(14), .after_draw_digest = channel.digestBytes(), .challenges = .{
        .source = .{ .word = word, .bytes = .init(values[0], values[1]), .input = .init(values[2], values[3]), .insertion = .init(values[4], values[5]), .before = .init(values[6], values[7]), .after = .init(values[8], values[9]), .route = .init(values[10], values[11]), .roots = .init(values[12], values[13]), .ordering = .init(values[14], values[15]), .sha_chain = .init(values[16], values[17]) },
        .route = .init(values[18], values[19]),
        .indexed = .init(values[20], values[21]),
        .hash = .init(values[22], values[23]),
    } };
}
fn deriveLayout(comptime kind: Semantic.Kind, a: std.mem.Allocator, original: anytype) !Layout.Layout {
    const admitted = try @import("block_v5_memory_source_page_raw_recursive_parity_test_v1.zig").emptyAdmission();
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 1) };
    const public_epoch = try epoch(a);
    if (kind == .raw) {
        const Raw = @import("block_v5_memory_source_packed_sha_replay_v1.zig");
        const RawSchema = @import("block_v5_memory_source_batch_raw_schema_v1.zig");
        const plan = try RawSchema.Protocol.init(&admitted.source, config, .{ .page_row_log = 1 });
        const page = try plan.page(0);
        const geometry = try @import("block_v5_memory_source_packed_sha_columns_v1.zig").Geometry.fromPage(&admitted.source, page, .{});
        const roots: [6][32]u8 = .{ @splat(13), @splat(14), @splat(15), @splat(16), @splat(17), @splat(18) };
        const pin = Raw.Pin{ .raw = .{ .plan_id = plan.identity, .page = page, .roots = roots[0..2].*, .config = config }, .geometry = geometry, .roots = roots };
        try pin.require(&admitted.source, plan, .{ .first = .{ .page_row_log = 1 } });
        return Layout.deriveForMetadata(kind, a, plan, pin, public_epoch, original.frame.semantic.premix_identity, original.graph, original.frame.semantic.claims, .{});
    } else {
        const plan = try Protocol.FoldPlan.init(&admitted, .{ .empty = 1, .roots = 1 }, config, .{ .page_row_log = 1 });
        const root = admitted.source.pins.expected_final_rw_root;
        const operations = [_]@import("block_v5_memory_source_batch_fold_v1.zig").Operation{
            .{ .ordinal = 0, .kind = .empty, .coordinate = .{ .height = 30, .index = 0 }, .value = .{ .before = root, .after = root } },
            .{ .ordinal = 1, .kind = .root, .coordinate = .{ .height = 30, .index = 0 }, .value = .{ .before = root, .after = root } },
        };
        const geometry = try @import("block_v5_memory_source_packed_blake_columns_v1.zig").Geometry.fromOperations(&operations, 100, .{});
        const pin = Protocol.FoldPin{ .page = try plan.page(0), .plan_id = plan.identity, .inventory_id = @splat(19), .geometry = geometry, .roots = .{ @splat(13), @splat(14), @splat(15), @splat(16), @splat(17), @splat(18) } };
        try pin.require(&admitted, plan, .{ .page_row_log = 1 });
        return Layout.deriveForMetadata(kind, a, plan, pin, public_epoch, original.frame.semantic.premix_identity, original.graph, original.frame.semantic.claims, .{});
    }
}
