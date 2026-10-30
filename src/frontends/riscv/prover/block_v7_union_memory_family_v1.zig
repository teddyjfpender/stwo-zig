//! Joint-memory original equations/physical claims for one heterogeneous STARK.
//! Prepared contexts are OPEN. Only the enclosing independently keyed STARK
//! authenticates them; the original global algebra remains mandatory afterward.
pub fn ForMode(comptime window: bool) type {
    return struct {
        const std = @import("std");
        const core = @import("stwo_core");
        const Engine = @import("stwo_prover_engine");
        const Budget = Engine.host_budget_allocator.SharedHostBudget;
        const Source = if (window) @import("block_v7_window_memory_joint_v1.zig") else @import("block_v7_memory_joint_proof_v1.zig");
        const Policy = @import("block_v7_execution_policy_v1.zig").Policy;
        const Epoch = @import("block_v7_execution_epoch_v1.zig");
        const Layout = if (window) @import("block_v7_window_memory_joint_layout_v1.zig") else @import("block_v7_memory_joint_layout_v1.zig");
        const Protocol = if (window) @import("block_v7_window_memory_joint_protocol_v1.zig") else @import("block_v7_memory_joint_protocol_v1.zig");
        const Air = if (window) @import("block_v7_window_memory_joint_air_v1.zig") else @import("block_v7_memory_joint_air_v1.zig");
        const Matrix = @import("block_v7_memory_trace_v1.zig");
        const Ram = if (window) @import("block_v7_window_ram_component_v1.zig") else @import("block_v7_ram_component_v1.zig");
        const Geometry = @import("block_v5_ram_lanes_protocol_v1.zig");
        const Q = core.fields.qm31.QM31;
        const Column = Engine.pcs.ColumnEvaluation;
        pub const Claims = Air.Claims;
        pub const Input = struct {
            policy: Policy,
            epoch: Epoch.Epoch,
            entries: []const Epoch.Entry,
            roots: [2][32]u8,
            interval_log: u32,
            claims: Claims,
        };
        pub const Context = struct {
            allocator: std.mem.Allocator,
            lease: ?*Budget,
            arena: std.heap.ArenaAllocator,
            row_arena: ?std.heap.ArenaAllocator = null,
            policy: Policy,
            pin: Epoch.Entry,
            roots: [2][32]u8,
            interval_log: u32,
            layout: Layout.Layout,
            claims: Claims,
            logs: [3][]u32,
            fixed_columns: []Column,
            interaction: []Column,
            provers: []Engine.air.component_prover.ComponentProver,
            verifiers: []core.air.components.Component,
            /// Only after the union has committed fixed and interaction columns.
            /// Component equations/claims/layout live in the independent main arena.
            pub fn releaseTransientRows(self: *Context) !void {
                if (self.row_arena) |*rows| rows.deinit() else return error.InvalidV7JointPhase;
                self.row_arena = null;
                self.interaction = &.{};
                self.fixed_columns = &.{};
            }
            pub fn recordAfterChallenges(self: *const Context, ch: anytype) !void {
                try Protocol.recordAfterChallenges(ch, self.pin, &self.layout, self.claims);
            }
            pub fn deinit(self: *Context) void {
                const a = self.allocator;
                const lease = self.lease;
                if (self.row_arena) |*rows| rows.deinit();
                self.arena.deinit();
                a.destroy(self);
                if (lease) |budget| budget.destroy();
            }
        };
        fn begin(a: std.mem.Allocator, lease: ?*Budget) !*Context {
            const self = try a.create(Context);
            self.allocator = a;
            self.lease = lease;
            self.arena = std.heap.ArenaAllocator.init(a);
            self.row_arena = null;
            return self;
        }
        fn finish(self: *Context, input: Input, layout: Layout.Layout, drawn: Epoch.Drawn, fixed: []Column, interaction: []Column, quotient: @import("block_v7_ram_quotient_policy_v1.zig").Policy, request_cap: usize) !void {
            const a = self.arena.allocator();
            const pin = try Protocol.entry(input.policy, &layout, input.roots);
            try Protocol.requireEpoch(input.policy, input.epoch, input.entries, pin);
            // All physical fields must have the original canonical framing, even when
            // verifier construction receives an untrusted public claim proposal.
            var ch = drawn.channel;
            try Protocol.recordAfterChallenges(&ch, pin, &layout, input.claims);
            const owner = try Source.airOwner(a, &layout, input.claims, drawn, input.policy);
            try owner.configureRamQuotient(quotient, request_cap);
            self.provers = owner.provers;
            self.verifiers = owner.verifiers;
            self.policy = input.policy;
            self.pin = pin;
            self.roots = input.roots;
            self.interval_log = input.interval_log;
            self.layout = layout;
            self.claims = input.claims;
            self.fixed_columns = fixed;
            self.interaction = interaction;
            for (&self.logs, 0..) |*logs, tree| logs.* = try layout.logs(a, tree);
        }
        /// Uses the ORIGINAL Stage allocator and keeps its allocation authority leased.
        /// Stage and its committed witness must remain alive until the union proof has
        /// adopted/finished those original trees. This does not consume or re-prove it.
        pub fn prepare(comptime Backend: type, stage: *const Source.For(Backend).Stage, epoch: Epoch.Epoch, entries: []const Epoch.Entry) !*Context {
            if ((stage.policy.window != null) != window) return error.InvalidV7MemoryPolicyMode;
            if (stage.consumed or !stage.owns_scheme or !stage.witness_live) return error.InvalidV7JointPhase;
            try Protocol.requireEpoch(stage.policy, epoch, entries, try stage.entry());
            const lease = stage.budget.retain();
            const self = begin(stage.allocator, lease) catch |err| {
                lease.destroy();
                return err;
            };
            errdefer self.deinit();
            const a = self.arena.allocator();
            self.row_arena = std.heap.ArenaAllocator.init(stage.allocator);
            const rows = self.row_arena.?.allocator();
            const drawn = try epoch.draw(a);
            const ram = try a.alloc(Air.RamClaim, stage.witness.ram.len);
            const generated = try a.alloc(Matrix.Generated(Ram.PLANES), ram.len);
            for (ram, generated, stage.witness.ram) |*claim, *g, item| {
                g.* = try Matrix.interactions(Ram.PLANES, rows, item.matrix, Source.RamContext{ .spec = try Source.ramSpec(item.geometry, drawn, stage.policy) }, stage.limits.memory.max_matrix_bytes);
                claim.* = .{ .geometry = item.geometry, .sums = g.sums };
            }
            const interval = try Source.providerInteractions(.interval, rows, stage.witness.interval, drawn.memory, stage.limits.memory.max_matrix_bytes);
            const range16 = try Source.providerInteractions(.range16, rows, stage.witness.range16, drawn.memory, stage.limits.memory.max_matrix_bytes);
            const terminal = if (window) {} else try Source.providerInteractions(.terminal, rows, stage.witness.terminal, drawn.memory, stage.limits.memory.max_matrix_bytes);
            const claims: Claims = .{ .ram = ram, .interval = interval.sums, .range16 = range16.sums, .terminal = if (window) {} else terminal.sums };
            const columns = try a.alloc(Column, stage.layout.columns[2]);
            for (generated, stage.layout.parts[0..ram.len]) |g, part| @memcpy(columns[part.offset[2]..][0..part.width[2]], g.matrix.columns);
            inline for (.{ &interval, &range16 }, 0..) |g, i| {
                const part = stage.layout.parts[ram.len + i];
                @memcpy(columns[part.offset[2]..][0..part.width[2]], g.matrix.columns);
            }
            if (!window) {
                const part = stage.layout.parts[ram.len + 2];
                @memcpy(columns[part.offset[2]..][0..part.width[2]], terminal.matrix.columns);
            }
            try finish(self, .{ .policy = stage.policy, .epoch = epoch, .entries = entries, .roots = stage.roots, .interval_log = stage.witness.interval.log, .claims = claims }, stage.layout, drawn, try Source.witnessColumns(a, &stage.witness, &stage.layout, 0), columns, stage.limits.ram_quotient, stage.limits.max_live_bytes);
            return self;
        }
        /// Same independent shape/fixed-root admission as the original memory verifier.
        /// No proof or producer-owned geometry is used as verification authority.
        pub fn verifier(comptime Backend: type, a: std.mem.Allocator, input: Input, limits: Source.Limits) !*Context {
            try input.policy.validate();
            if (input.claims.ram.len == 0 or input.claims.ram.len > limits.memory.max_shards) return error.V7JointResourceLimit;
            const self = try begin(a, null);
            errdefer self.deinit();
            const temp = self.arena.allocator();
            const geometries = try temp.alloc(Geometry.Claim, input.claims.ram.len);
            for (geometries, input.claims.ram) |*g, claim| g.* = claim.geometry;
            try Source.For(Backend).requireFixedRoot(a, input.policy, geometries, input.interval_log, input.roots[0], limits);
            const layout = try Layout.Layout.init(temp, geometries, input.interval_log, limits.layout);
            var owned_input = input;
            owned_input.claims.ram = try temp.dupe(Air.RamClaim, input.claims.ram);
            try finish(self, owned_input, layout, try input.epoch.draw(temp), try Source.fixedColumns(temp, input.policy, geometries, &layout, limits.memory), &.{}, .whole_domain, limits.max_live_bytes);
            return self;
        }
    };
}
