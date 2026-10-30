//! Original ROM/lookup/caller arithmetic fixed rosters from independent policy.
//! No proof, verified capture, private claim or channel execution is accepted.
const std = @import("std");
const core = @import("stwo_core");
const Native = @import("block_v6_provider_recursive_fixed_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Sink = @import("air/blake3_fixed_operation_recorder_v1.zig");
const Schema = @import("air/blake3_pcs_operation_schema_v1.zig");
const Plan = @import("air/blake3_transcript_plan.zig").Plan;
const Sources = @import("air/block_v5_recursive_parent_fixed_sources_v1.zig");
const Pcs = @import("block_v5_native_recursive_fixed_pcs_v1.zig");
const Original = @import("block_v5_recursive_parent_fixed_roster_v1.zig");
const Assembly = @import("block_v5_recursive_parent_fixed_assembly_v1.zig");
const Namespace = @import("air/block_v5_recursive_fixed_namespace_v1.zig");
const Storage = @import("air/blake3_parent_row_storage.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
pub const Limits = struct { max_bytes: usize = 2 << 30, native: Native.Limits = .{}, transcript: Sink.Limits = .{} };
pub fn PublicBus(comptime family: Native.Family) type {
    return switch (family) {
        .program_table => @import("block_v5_program_table_recursive_public_bus_v1.zig"),
        .native_lookup => @import("block_v5_native_lookup_recursive_public_bus_v1.zig"),
        .caller_arithmetic => @import("block_v5_caller_arithmetic_recursive_public_bus_v1.zig"),
    };
}
fn Prefix(comptime family: Native.Family) type {
    return switch (family) {
        .program_table => @import("air/block_v5_program_table_transcript_v1.zig"),
        .native_lookup => @import("air/block_v5_native_lookup_transcript_v1.zig"),
        .caller_arithmetic => @import("air/block_v5_caller_arithmetic_transcript_v1.zig"),
    };
}
pub fn ForFamily(comptime family: Native.Family) type {
    const A = Native.Admission(family);
    const N = Native.ForFamily(family).Owned;
    const Bus = PublicBus(family);
    const Profile = struct {
        pub const commitment_trees = 4;
        native: *const N,
        admitted: *const A.Prepared,
        limits: Native.Limits,
        columns: [4][]const u32,
        widths: []const u32,
        config: core.pcs.PcsConfig,
        lifting_log: u32,
        seal: [32]u8,
        fn init(native: *const N, admitted: *const A.Prepared, limits: Native.Limits) !@This() {
            if (native.shape.columns.len != 4) return error.InvalidProviderFixedShape;
            return .{ .native = native, .admitted = admitted, .limits = limits, .columns = native.shape.columns[0..4].*, .widths = native.shape.widths, .config = admitted.config, .lifting_log = native.shape.lifting_log, .seal = identity(native) };
        }
        fn identity(native: *const N) [32]u8 {
            var channel = core.channel.blake3.Channel{};
            channel.mixU32s(&.{ 0x42365046, 1, @intFromEnum(family) });
            channel.mixRoot(native.template_id);
            channel.mixRoot(native.shape.deepProfile().identityDigest());
            channel.mixRoot(native.shape.friProfile().identityDigest());
            return channel.digestBytes();
        }
        pub fn validate(self: *const @This()) !void {
            try self.native.validateAgainst(self.admitted, self.limits);
            if (!std.meta.eql(self.seal, identity(self.native)) or !std.meta.eql(self.config, self.admitted.config) or !std.mem.eql(u32, self.widths, self.native.shape.widths) or self.lifting_log != self.native.shape.lifting_log) return error.UntrustedProviderFixedShape;
            for (self.columns, self.native.shape.columns) |got, want| if (!std.mem.eql(u32, got, want)) return error.UntrustedProviderFixedShape;
        }
        pub fn deepProfile(self: *const @This()) @import("air/pcs_deep_circuit.zig").Profile {
            return self.native.shape.deepProfile();
        }
        pub fn friProfile(self: *const @This()) @import("air/fri_verifier_circuit.zig").Profile {
            return self.native.shape.friProfile();
        }
    };
    return struct {
        pub const Owned = struct {
            allocator: std.mem.Allocator,
            budget: *Budget,
            fixed: Storage.FixedTuple(false),
            wires: []Bus.Wire,
            context: Base.Context,
            namespace: Namespace.Plan,
            retry_capacity: u32,
            profile: Base.Profile,
            pub const fixed_setup_only = true;
            pub const complete_family_setup = true;
            pub const whole_family_live_parity_qualified = false;
            pub const complete_block_authority = false;
            pub fn derive(backing: std.mem.Allocator, admitted: *const A.Prepared, capacity: u32, profile: Base.Profile, limits: Limits) !@This() {
                if (capacity == 0 or limits.max_bytes == 0 or !std.meta.eql(admitted.config, profile.config())) return error.ProviderFixedRosterPolicy;
                try admitted.validate(admitted.template_id);
                const budget = try Budget.createRetainingParent(backing, limits.max_bytes);
                errdefer budget.destroy();
                const a = budget.allocator();
                const native = try N.derive(a, admitted, limits.native);
                defer native.deinit();
                var transcript = try transcriptFor(a, admitted, native, capacity, limits.transcript);
                defer transcript.deinit();
                var shape = try Profile.init(native, admitted, limits.native);
                const pcs = try Pcs.ForCommitments(4).Owned.compile(a, &shape, &native.deep_graph, &native.fri_graph, &transcript);
                defer pcs.deinit();
                const sources = if (family == .caller_arithmetic)
                    try Sources.Owned.compileCallerArithmetic(a, &shape, &native.composition, &native.deep_graph, &native.fri_graph, &transcript)
                else
                    try Sources.Owned.compileNativeProvider(a, &shape, &native.composition, &native.deep_graph, &native.fri_graph, &transcript);
                defer sources.deinit();
                const selectors = try Assembly.selectorsForGraphs(a, &native.deep_graph, &native.fri_graph);
                const fixed = try Original.compileOriginalRoster(a, sources, null, pcs.openings, pcs.ports, &transcript, &pcs.paths, &native.arithmetic, selectors, &native.deep_graph);
                errdefer inline for (0..Storage.Airs.len) |i| a.free(fixed[i]);
                const wires = if (family == .caller_arithmetic) blk: {
                    const claims = try A.Profile.ExtensionClaim.zeroForStatement(&admitted.statement);
                    var count: usize = 0;
                    for (claims.componentClaims()) |view| count += view.detailed.len + @intFromBool(view.has_batch_frame);
                    break :blk try Bus.collectFixedSchedule(a, &transcript, &native.composition, @intCast(admitted.config.fri_config.n_queries), count);
                } else if (family == .program_table)
                    try Bus.collectFixedSchedule(a, &transcript, &native.composition, .{
                        if (admitted.logs[0].len == 0) 0 else @intCast(admitted.config.fri_config.n_queries),
                        if (admitted.logs[1].len == 0) 0 else @intCast(admitted.config.fri_config.n_queries),
                    })
                else
                    try Bus.collectFixedSchedule(a, &transcript, &native.composition, @intCast(admitted.config.fri_config.n_queries));
                errdefer a.free(wires);
                var namespace = try Namespace.prepareForArithmetic(a, fixed, 1, .{ .plan = &native.arithmetic.plan, .reference = native.arithmetic.reference, .kind = .segment_leaf });
                errdefer namespace.deinit();
                try namespace.requireIndependentMainPort();
                const context = Base.Context{ .child_key_id = admitted.template_id, .child_config = admitted.config, .graph_ids = .{ native.composition.circuit.identity_digest, native.deep_graph.graph().identity_digest, native.fri_graph.graph().identity_digest }, .transcript_plan_id = transcript.id };
                _ = try Base.contextIdentity(context);
                _ = try Bus.scheduleDigest(wires);
                try admitted.validate(admitted.template_id);
                return .{ .allocator = a, .budget = budget, .fixed = fixed, .wires = wires, .context = context, .namespace = namespace, .retry_capacity = capacity, .profile = profile };
            }
            pub fn validateLive(self: *const @This(), live: *Bus.Prepared) !void {
                try live.recursive.rows.partitionHashRows();
                if (!std.meta.eql(self.context, live.recursive.context) or self.wires.len != live.wires.len) return error.UntrustedProviderFixedRoster;
                for (self.wires, live.wires) |got, want| if (!std.meta.eql(got, want)) return error.UntrustedProviderFixedRoster;
                inline for (0..Storage.Airs.len) |i| {
                    if (self.fixed[i].len != live.recursive.rows.fixed[i].len) return error.UntrustedProviderFixedRoster;
                    for (self.fixed[i], live.recursive.rows.fixed[i]) |got, want| if (!std.meta.eql(got, want)) return error.UntrustedProviderFixedRoster;
                }
                try self.namespace.validateLive(&live.recursive.rows);
            }
            pub fn deinit(self: *@This()) void {
                const a = self.allocator;
                const budget = self.budget;
                self.namespace.deinit();
                a.free(self.wires);
                inline for (0..Storage.Airs.len) |i| a.free(self.fixed[i]);
                self.* = undefined;
                budget.destroy();
            }
        };
        pub fn transcriptFor(a: std.mem.Allocator, admitted: *const A.Prepared, native: *const N, capacity: u32, limits: Sink.Limits) !Plan {
            if (capacity == 0 or limits.max_operations == 0 or limits.max_routed_words == 0) return error.InvalidBlake3Transcript;
            try admitted.validate(admitted.template_id);
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const temp = arena.allocator();
            var recorder = Sink.Recorder{ .a = temp, .limits = limits };
            try Prefix(family).prefixFixed(temp, &recorder, admitted);
            try recorder.suffix(.{ .commitment = .{ .slot = 2, .source = try @import("air/blake3_root_sources.zig").caller(2) } });
            var suffix: std.ArrayList(Schema.Operation) = .empty;
            try Schema.appendPcsSuffix(temp, &suffix, admitted.config, native.shape.deepProfile(), native.shape.friProfile(), 4);
            for (suffix.items) |operation| try recorder.suffix(operation);
            try recorder.check();
            return Plan.initCompact(a, .{ .namespace = 1_000_000, .attempt_capacity = capacity }, recorder.operations.items);
        }
    };
}
test "provider full original fixed roster codegen" {
    inline for (comptime std.meta.tags(Native.Family)) |family| {
        std.mem.doNotOptimizeAway(&ForFamily(family).Owned.derive);
        std.mem.doNotOptimizeAway(&ForFamily(family).Owned.validateLive);
    }
}
