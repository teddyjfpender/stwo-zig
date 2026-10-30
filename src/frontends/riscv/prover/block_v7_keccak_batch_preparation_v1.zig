//! Original shared-Keccak interaction and AIR preparation, with no proof.
//! The Stage must outlive this owner. Every generated column, claim and drawn
//! challenge is owned here; the same object feeds standalone and union proofs.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Q = core.fields.qm31.QM31;
const Suite = core.proof_suites.Blake3;
const Column = engine.pcs.ColumnEvaluation;
const E = @import("block_v7_execution_epoch_v1.zig");
const Source = @import("block_v7_keccak_batch_source_v1.zig");
const Native = @import("block_v7_native_source_v1.zig");
const Geometry = @import("block_v7_keccak_batch_geometry_v1.zig");
const Air = @import("block_v7_keccak_batch_air_v1.zig");
const Memory = @import("block_v7_keccak_window_memory_v1.zig");
const Lookup = @import("block_v7_keccak_window_lookup_v1.zig");
const Control = @import("block_v7_keccak_window_control_v1.zig").For(true);
const Trace = @import("block_v7_memory_trace_v1.zig");
const K = @import("../air/guest_precompile/keccakf_component.zig");
const KI = @import("../air/guest_precompile/keccakf_interaction.zig");
const TI = @import("../air/guest_precompile/keccakf_table_interaction.zig");
const Claims = @import("block_v7_keccak_batch_claims_v1.zig").Claims;
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Self = @This();
        pub const Stage = @import("block_v7_keccak_batch_stage_v1.zig").For(Backend);
        allocator: std.mem.Allocator,
        arena: std.heap.ArenaAllocator,
        drawn: Source.Drawn,
        entry: E.Entry,
        claims: Claims,
        channel: Suite.Channel,
        arithmetic_columns: []Column,
        relation_columns: []Column,
        owner: *Air.Owner(true),
        keccak: KI.Result,
        chi: TI.Result,
        xor5: TI.Result,
        table_interactions: Lookup.Generated,
        memory_interactions: Memory.Generated,
        /// The independently admitted original Stage and its raw/PCS storage
        /// remain external; this owner never assumes their allocator/custody.
        stage: *const Stage,
        pub fn init(a: std.mem.Allocator, stage: *Stage, natives: []const Native.Pin, epoch: E.Epoch, entries: []const E.Entry, pool: *engine.work_pool.WorkPool) !*Self {
            const pin = stage.pin;
            const entry = try pin.require(a, natives, epoch, entries, stage.limits.owners);
            if (!stage.owns_scheme or stage.scheme.trees.items.len != 3) return error.InvalidKeccakBatchPhase;
            const roots = pin.roots ++ .{pin.access_root};
            for (stage.scheme.trees.items, roots) |tree, root| if (!std.meta.eql(tree.commitment.root(), root)) return error.UntrustedKeccakBatchRoots;
            const self = try a.create(Self);
            errdefer a.destroy(self);
            self.allocator = a;
            self.stage = stage;
            self.entry = entry;
            self.arena = std.heap.ArenaAllocator.init(a);
            errdefer self.arena.deinit();
            const temp = self.arena.allocator();
            self.drawn = try Source.draw(a, epoch, entry);
            const relations = &self.drawn.relations;
            self.keccak = try KI.generate(a, &stage.shard, &relations.ethereum.keccak, pool);
            errdefer self.keccak.deinit(a);
            self.chi = try TI.generate(a, .chi, &stage.counters, &relations.ethereum.keccak, pool);
            errdefer self.chi.deinit(a);
            self.xor5 = try TI.generate(a, .xor5, &stage.counters, &relations.ethereum.keccak, pool);
            errdefer self.xor5.deinit(a);
            const controls = try temp.alloc([3]Q, pin.windows.len);
            self.arithmetic_columns = try temp.alloc(Column, stage.geometry.logs[3].len);
            var at: usize = 0;
            inline for (.{ self.keccak.columns, self.chi.columns, self.xor5.columns }, .{ pin.geometry.log_size, @import("../air/guest_precompile/keccakf_tables.zig").logSize(.chi), @import("../air/guest_precompile/keccakf_tables.zig").logSize(.xor5) }) |columns, log| for (columns) |values| {
                self.arithmetic_columns[at] = .{ .log_size = log, .values = values };
                at += 1;
            };
            // Reuse one narrow input copy across windows. Only their distinct
            // cyclic prefix columns are retained; arithmetic rows are shared.
            var matrix = try Trace.Matrix.init(a, pin.geometry.log_size, Control.MAIN_COUNT + 1, stage.limits.memory.max_interaction_bytes);
            defer matrix.deinit();
            for (0..Control.MAIN_COUNT) |c| @memcpy(@constCast(matrix.columns[c].values), stage.shard.mainColumn(@import("../air/guest_precompile/keccakf_trace.zig").Layout.caller + c));
            for (controls, 0..) |*sums, i| {
                @memcpy(@constCast(matrix.columns[Control.MAIN_COUNT].values), stage.fixed[Geometry.FIXED_PREFIX + i].values);
                const generated = try Trace.interactions(3, temp, matrix, Control{ .relations = &relations.ethereum.keccak, .sums = @splat(Q.zero()) }, stage.limits.memory.max_interaction_bytes);
                sums.* = generated.sums;
                @memcpy(self.arithmetic_columns[at..][0..12], generated.matrix.columns);
                at += 12;
            }
            var lookup = try Lookup.Owned.init(a, pin.geometry.log_size, 0, 0, 1);
            defer lookup.deinit();
            self.table_interactions = try lookup.generate(a, stage.fixed, stage.main, relations, stage.limits.memory.max_interaction_bytes);
            errdefer self.table_interactions.deinit();
            self.memory_interactions = try stage.memory.generate(a, &self.drawn.epoch.word, stage.snapshots, stage.limits.memory);
            errdefer self.memory_interactions.deinit();
            self.relation_columns = try temp.alloc(Column, stage.geometry.logs[4].len);
            @memcpy(self.relation_columns[0..self.memory_interactions.matrix.columns.len], self.memory_interactions.matrix.columns);
            @memcpy(self.relation_columns[self.memory_interactions.matrix.columns.len..], self.table_interactions.matrix.columns);
            self.claims = .{ .keccak = try K.Claim.canonical(&stage.shard, self.keccak.claims), .chi = self.chi.claim, .xor5 = self.xor5.claim, .controls = controls, .tables = self.table_interactions.claims, .memory = self.memory_interactions.claims };
            _ = try self.claims.open(pin, lookup.slots);
            self.channel = self.drawn.channel;
            try self.claims.record(pin, entry, &self.channel);
            self.owner = try Air.Owner(true).init(a, pin, &stage.geometry, &self.drawn, &self.claims);
            return self;
        }
        pub fn cloneClaims(self: *const Self, a: std.mem.Allocator) !Claims {
            var out = self.claims;
            out.controls = try a.dupe([3]Q, self.claims.controls);
            return out;
        }
        pub fn deinit(self: *Self) void {
            self.owner.deinit();
            self.memory_interactions.deinit();
            self.table_interactions.deinit();
            self.xor5.deinit(self.allocator);
            self.chi.deinit(self.allocator);
            self.keccak.deinit(self.allocator);
            self.arena.deinit();
            self.allocator.destroy(self);
        }
    };
}
