//! Exact original arithmetic + selected control + one shared memory bridge.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Geometry = @import("block_v7_keccak_batch_geometry_v1.zig");
const Source = @import("block_v7_keccak_batch_source_v1.zig");
const Claims = @import("block_v7_keccak_batch_claims_v1.zig").Claims;
const K = @import("../air/guest_precompile/keccakf_component.zig");
const Trace = @import("../air/guest_precompile/keccakf_trace.zig");
const T = @import("../air/guest_precompile/keccakf_table_component.zig");
const Tables = @import("../air/guest_precompile/keccakf_tables.zig");
const Control = @import("block_v7_keccak_window_control_v1.zig").For(true);
const Memory = @import("block_v7_keccak_window_memory_v1.zig");
const Lookup = @import("block_v7_keccak_window_lookup_v1.zig");
const Adapter = @import("block_v5_caller_fused_component_v1.zig");
const Joint = @import("block_v6_caller_joint_components_v1.zig");
pub fn Owner(comptime proving: bool) type {
    return struct {
        allocator: std.mem.Allocator,
        keccak: K.KeccakShardComponent,
        tables: [2]T.KeccakTableComponent,
        controls: []Control.Component,
        memory: [Memory.SLOT_COUNT]Adapter.Memory,
        lookup: Lookup.Owned,
        lookup_components: []Lookup.Component,
        joint: *Joint.Owner(proving),
        const Self = @This();
        const Handle = if (proving) engine.air.component_prover.ComponentProver else core.air.components.Component;
        pub fn init(a: std.mem.Allocator, pin: Source.Pin, geometry: *const Geometry.Owned, drawn: *const Source.Drawn, claims: *const Claims) !*Self {
            try claims.validate(pin);
            const self = try a.create(Self);
            errdefer a.destroy(self);
            self.allocator = a;
            self.keccak = try K.KeccakShardComponent.initForRecipe(claims.keccak, .{ .preprocessed_offset = 0, .main_offset = 0, .interaction_offset = 0 }, &drawn.relations.ethereum.keccak, Trace.maximum_log_size, true);
            inline for (.{ Tables.Kind.chi, Tables.Kind.xor5 }, 0..) |kind, i| {
                const fixed = K.preprocessed_column_count + i * T.preprocessed_column_count;
                var tuple: [Tables.arity]usize = undefined;
                for (&tuple, 0..) |*v, j| v.* = fixed + 1 + j;
                self.tables[i] = try T.KeccakTableComponent.initVerifier(kind, .{ .is_first_col_idx = fixed, .tuple_col_indices = tuple, .main_col_offset = K.main_column_count + 2 + i, .interaction_col_offset = K.interaction_column_count + i * T.interaction_column_count }, &drawn.relations.ethereum.keccak, if (i == 0) claims.chi else claims.xor5);
            }
            self.controls = try a.alloc(Control.Component, pin.windows.len);
            errdefer a.free(self.controls);
            for (self.controls, claims.controls, 0..) |*component, sums, i| component.* = try Control.Component.init(.{ .relations = &drawn.relations.ethereum.keccak, .sums = sums }, pin.geometry.log_size, .{ @intCast(Geometry.FIXED_PREFIX + i), Trace.Layout.caller, @intCast(Geometry.ARITHMETIC_PREFIX + i * 12) });
            self.lookup = try Lookup.Owned.init(a, pin.geometry.log_size, 0, 0, 1);
            errdefer self.lookup.deinit();
            self.lookup_components = try self.lookup.components(a, geometry.logs[0], geometry.logs[1], geometry.logs[4], Geometry.MEMORY_COLUMNS, claims.tables, &drawn.relations);
            errdefer a.free(self.lookup_components);
            for (&self.memory, claims.memory, 0..) |*component, claim, i| component.* = try (Adapter.Memory{ .composition_split = 2, .inner = .{
                .family = .base_alu_imm,
                .slot = i + 1,
                .external_source = .{ .kind = .keccak, .slot = i + 1, .log_size = pin.geometry.log_size, .fixed_offset = 0, .main_offset = 0, .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 1 }, .x0_local_custody_version = 1 },
                .log_size = pin.geometry.log_size,
                .base_clock = 0,
                .fixed_clock_offset = geometry.clockOffset(),
                .fixed_logs = geometry.logs[0],
                .main_logs = geometry.logs[1],
                .witness_logs = geometry.logs[2],
                .interaction_logs = geometry.logs[4],
                .root_owner = i == 0,
                .main_offset = 0,
                .witness_offset = i * @import("block_execution_integer_bridge_v2.zig").COLUMN_COUNT,
                .interaction_offset = i * Memory.INTERACTION_COUNT,
                .shared_keccak_state_offset = Trace.Layout.state,
                .transition_claim = claim.transition_sum,
                .transition_count = claim.active_count,
                .range_claims = claim.range_claims,
                .challenges = &drawn.epoch.bytes,
                .v5_universal = .{ .claim = claim.universal_sum, .elements = drawn.epoch.word.universal_prefix.get(.memory_access) },
                .v5_packed = .{ .elements = &drawn.epoch.word },
                .register_custody_mode = 1,
            } }).init();
            const left = try a.alloc(Handle, 3 + self.controls.len);
            defer a.free(left);
            left[0] = handle(&self.keccak);
            for (&self.tables, 0..) |*component, i| left[i + 1] = handle(component);
            for (self.controls, 0..) |*component, i| left[i + 3] = handle(component);
            const right = try a.alloc(Handle, self.memory.len + self.lookup_components.len);
            defer a.free(right);
            for (&self.memory, 0..) |*component, i| right[i] = handle(component);
            for (self.lookup_components, 0..) |*component, i| right[self.memory.len + i] = handle(component);
            // Both physical interaction inventories are memory-first; no rotation.
            self.joint = try Joint.Owner(proving).create(a, left, right, .{ geometry.logs[0], geometry.logs[1], geometry.logs[2], geometry.logs[3], geometry.logs[4] }, 0);
            return self;
        }
        fn handle(component: anytype) Handle {
            return if (proving) component.asProverComponent() else component.asVerifierComponent();
        }
        pub fn deinit(self: *Self) void {
            self.joint.destroy();
            self.allocator.free(self.lookup_components);
            self.lookup.deinit();
            self.allocator.free(self.controls);
            self.allocator.destroy(self);
        }
    };
}
