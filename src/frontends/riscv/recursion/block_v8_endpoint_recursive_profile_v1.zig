//! Shared finite-family implementation; original equation authorities remain independent.
const Family = @import("block_v8_endpoint_recursive_source_v1.zig").Family;
pub fn For(comptime family: Family) type {
    return struct {
        const Traits = @import("block_v8_endpoint_recursive_source_v1.zig").For(family);
        const is_local = Traits.is_local;
        // Independent original-verifier compiler source for the 13-tree B8 endpoint
        // architecture. No producer Scope, cached key or live source rows are used.
        // It authenticates metadata/fixed geometry, not proof or global-closure success.
        const std = @import("std");
        const core = @import("stwo_core");
        const Engine = @import("stwo_prover_engine");
        const Statement = Traits.Statement;
        const Whole = Traits.Proof;
        const Scope = Traits.Scope;
        const Context = Traits.Context.For(false);
        const Ledger = Traits.Ledger;
        const Shape = @import("block_v6_original_fixed_shape_v1.zig");
        const Wire = @import("../prover/block_v7_union_claim_wire_v1.zig");
        const Suite = core.proof_suites.Blake3;
        const Cpu = @import("stwo_cpu_backend").CpuBackend;
        pub const TRACE_TREES: usize = Traits.TRACE_TREES;
        pub const FIRST_ROOTS: usize = Traits.FIRST_ROOTS;
        pub const RELATION_PAIRS: usize = 53;
        pub const Limits = struct {
            original: Whole.Limits = .{},
            shape: Shape.Limits = .{},
            max_claim_bytes: usize = 16 << 20,
            max_claim_items: usize = 1 << 20,
        };
        pub const Owned = struct {
            allocator: std.mem.Allocator,
            arena: std.heap.ArenaAllocator,
            statement: *Statement.Owned,
            claims: Ledger.Claims,
            scope: *Scope.Owned,
            context: *Context,
            shape: Shape.Owned,
            constraint_count: usize,
            fixed_root: [32]u8,
            seal: [32]u8,
            limits: Limits,
            pub fn derive(a: std.mem.Allocator, metadata: *const Statement.Owned, proposed: Ledger.Claims, limits: Limits) !*Owned {
                if (comptime is_local) try @import("../prover/block_v8_native_endpoint_profile_v1.zig").requireShape(metadata.input.shape, metadata.input.native_profile);
                if (limits.max_claim_bytes == 0 or limits.max_claim_items == 0) return error.EndpointOriginalProfileResourceLimit;
                const out = try a.create(Owned);
                errdefer a.destroy(out);
                out.allocator = a;
                out.arena = std.heap.ArenaAllocator.init(a);
                errdefer out.arena.deinit();
                out.limits = limits;
                out.statement = try Statement.Owned.init(a, metadata.trusted, metadata.input);
                errdefer out.statement.deinit();
                var writer = @import("../prover/bounded_artifact_writer_v1.zig").Writer.init(a, limits.max_claim_bytes);
                defer writer.deinit();
                var remaining = limits.max_claim_items;
                try Wire.encode(Ledger.Claims, &writer, proposed, &remaining);
                var cursor = @import("../prover/guest_precompile/proof_artifact_wire.zig").Cursor{ .bytes = writer.bytes.items };
                remaining = limits.max_claim_items;
                out.claims = try Wire.decode(Ledger.Claims, out.arena.allocator(), &cursor, &remaining);
                if (cursor.position != writer.bytes.items.len) return error.NoncanonicalEndpointOriginalClaims;
                out.scope = try Scope.Owned.init(a, out.statement.trusted, out.statement.input, limits.original.scope);
                errdefer out.scope.deinit();
                out.context = try Context.create(a, out.scope, out.statement.input, null, out.claims, limits.original.context);
                errdefer out.context.deinit();
                var fixed = try out.context.fixedColumns();
                defer fixed.deinit();
                const all = core.air.components.Components{ .components = out.context.combined.?.handles, .n_preprocessed_columns = fixed.columns.len };
                const fixed_logs = try a.alloc(u32, fixed.columns.len);
                defer a.free(fixed_logs);
                for (fixed.columns, fixed_logs) |column, *log| log.* = column.log_size;
                const local = out.context.local.?;
                // The complete fixed tree also contains canonical columns omitted by
                // zero-width original components. Retain them just as Whole.verify does.
                const logs = if (is_local) [TRACE_TREES][]const u32{ fixed_logs, local.native.main, &local.endpoint_main_logs, &local.range_main_logs, out.context.program.?.logs[1], out.context.lookup.?.logs[1], local.native.interactions, &local.endpoint_interaction_logs, &local.range_interaction_logs, out.context.program.?.logs[2], out.context.lookup.?.logs[2] } else [TRACE_TREES][]const u32{ fixed_logs, local.native.main, &local.endpoint_main_logs, &local.range_main_logs, out.context.program.?.logs[1], out.context.lookup.?.logs[1], out.context.memory.?.logs[1], local.native.interactions, &local.endpoint_interaction_logs, &local.range_interaction_logs, out.context.program.?.logs[2], out.context.lookup.?.logs[2], out.context.memory.?.logs[2] };
                out.shape = try Shape.Owned.initForBoundedTraceTrees(a, &logs, all, metadata.trusted.config, limits.shape, TRACE_TREES);
                errdefer out.shape.deinit();
                var count: usize = 0;
                for (all.components) |component| count = try std.math.add(usize, count, component.nConstraints());
                out.constraint_count = count;
                var scheme = try Engine.pcs.CommitmentSchemeProver(Cpu, Suite.Hasher, Suite.MerkleChannel).init(a, metadata.trusted.config);
                defer scheme.deinit(a);
                var ignored = Suite.Channel{};
                try scheme.commitBorrowedStreaming(a, fixed.columns, 8, &ignored);
                out.fixed_root = scheme.trees.items[0].root();
                if (!std.meta.eql(out.fixed_root, out.statement.input.native_roots[0])) return error.UntrustedEndpointOriginalFixedRoot;
                out.seal = try out.identity();
                return out;
            }
            pub fn identity(self: *const Owned) ![32]u8 {
                var ch = Suite.Channel{};
                ch.mixU32s(&.{ Traits.PROFILE_TAG, 1, TRACE_TREES, FIRST_ROOTS, RELATION_PAIRS, @intCast(self.constraint_count) });
                ch.mixRoot(if (is_local) self.scope.epoch.statement else try self.scope.policy.digest());
                ch.mixRoot(self.scope.descriptor.scope.native_identity);
                ch.mixRoot(self.scope.epoch.digest);
                ch.mixRoot(self.fixed_root);
                ch.mixRoot(self.shape.deepProfile().identityDigest());
                ch.mixRoot(self.shape.friProfile().identityDigest());
                ch.mixU32s(&.{ self.shape.split, self.shape.composition_log, self.shape.mask_log, self.shape.lifting_log });
                for (self.shape.columns) |columns| {
                    ch.mixU64(columns.len);
                    ch.mixU32s(columns);
                }
                return ch.digestBytes();
            }
            pub fn validate(self: *const Owned) !void {
                if (!std.meta.eql(self.seal, try self.identity())) return error.MutatedEndpointOriginalProfile;
            }
            pub fn requireCapture(self: *const Owned, capture: *const Whole.VerifiedCapture) !void {
                try self.validate();
                const i = self.statement.input;
                const first = if (is_local) i.native_roots ++ [2][32]u8{ i.program_roots[1], i.lookup_roots[1] } else i.native_roots ++ [3][32]u8{ i.program_roots[1], i.lookup_roots[1], i.memory_roots[1] };
                if (capture.proof.commitments.len != TRACE_TREES + 1 or !std.meta.eql(capture.proof.commitments[0..FIRST_ROOTS].*, first) or !std.meta.eql(capture.summary, try self.context.close())) return error.UntrustedEndpointOriginalCapture;
            }
            pub fn deinit(self: *Owned) void {
                const a = self.allocator;
                self.shape.deinit();
                self.context.deinit();
                self.scope.deinit();
                self.statement.deinit();
                self.arena.deinit();
                a.destroy(self);
            }
        };
    };
}
