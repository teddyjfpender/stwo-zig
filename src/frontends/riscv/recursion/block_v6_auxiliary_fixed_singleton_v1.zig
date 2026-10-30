//! Original independently compiled fixed roster -> auxiliary singleton setup.
//! Typed policies below must derive originals from independent admission.
//! Both legacy MAIN identifier schedules come from the original immutable
//! arithmetic plan. No dummy witness, capture, proof or received key is used.
const std = @import("std");
const core = @import("stwo_core");
const Aux = @import("block_v6_auxiliary_direct_public_v1.zig");
const Live = @import("block_v6_auxiliary_direct_prepare_v1.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
const Storage = @import("air/blake3_parent_row_storage.zig");
const Namespace = @import("air/block_v5_recursive_fixed_namespace_v1.zig");
const Rebase = @import("air/blake3_parent_rebase.zig");
pub fn ForPolicy(comptime Policy: type) type {
    const family: Aux.Family = Policy.family;
    return struct {
        pub const Owned = struct {
            original: Policy.Original,
            /// Aliases owned original fixed rows, after the singleton rebase.
            fixed: Storage.FixedTuple(false),
            wires: []Aux.Wire,
            context: Base.Context,
            expected: Aux.Expected,
            /// Complete sorted namespace after the auxiliary rebase; includes
            /// MAIN-only identifiers derived from the actual arithmetic port.
            namespace_ids: []u32,
            pub const fixed_setup_only = true;
            pub const complete_family_setup = true;
            pub const complete_block_authority = false;

            pub fn derive(a: std.mem.Allocator, admitted: *const Policy.Admitted, expected: [32]u8, claims: Policy.Claims, capacity: u32, profile: Base.Profile, limits: Policy.Limits) !Owned {
                var original = try Policy.deriveOriginal(a, admitted, expected, claims, capacity, profile, limits);
                errdefer original.deinit();
                const allocator = original.allocator;
                try original.namespace.requireIndependentMainPort();
                const identity = try original.namespace.identity();
                const end = try original.namespace.end();
                const wires = try allocator.alloc(Aux.Wire, original.wires.len);
                errdefer allocator.free(wires);
                for (original.wires, wires) |wire, *out| out.* = .{
                    .circuit = original.namespace.original.map(wire.circuit) orelse return error.MissingAuxiliaryDirectNamespace,
                    .wire = wire.wire,
                    .uses = wire.uses,
                    .child = 0,
                    .source = @unionInit(Aux.Source, @tagName(family), wire.source),
                    .coordinate = wire.coordinate,
                };
                std.mem.sort(Aux.Wire, wires, {}, struct {
                    fn less(_: void, l: Aux.Wire, r: Aux.Wire) bool {
                        return l.circuit < r.circuit or (l.circuit == r.circuit and l.wire < r.wire);
                    }
                }.less);
                _ = try Aux.scheduleDigest(wires);
                const ids = try allocator.alloc(u32, original.namespace.original.old.len);
                errdefer allocator.free(ids);
                for (ids, original.namespace.original.old) |*id, old| id.* = original.namespace.original.map(old) orelse return error.InvalidParentRebase;
                if (end != 1 + ids.len) return error.InvalidParentRebase;
                // Only fixed identifier cells change; physical MAIN is absent.
                try Namespace.apply(&original.fixed, &original.namespace, identity);
                const index = Policy.index(admitted);
                var contexts: [5]core.channel.blake3.Channel = @splat(.{});
                for (&contexts, 0..) |*channel, i| channel.mixU32s(&.{ 0x42364147, Aux.VERSION, @intCast(i), 1 });
                contexts[0].mixU32s(&.{ @intFromEnum(family), index });
                contexts[0].mixRoot(expected);
                for (contexts[1..4], original.context.graph_ids) |*channel, digest| {
                    channel.mixRoot(digest);
                    channel.mixRoot(identity);
                }
                contexts[4].mixRoot(original.context.transcript_plan_id);
                contexts[4].mixRoot(identity);
                return .{ .original = original, .fixed = original.fixed, .wires = wires, .expected = .{ .family = family, .index = index, .template = expected }, .namespace_ids = ids, .context = .{ .child_key_id = contexts[0].digestBytes(), .child_config = admitted.config, .graph_ids = .{ contexts[1].digestBytes(), contexts[2].digestBytes(), contexts[3].digestBytes() }, .transcript_plan_id = contexts[4].digestBytes() } };
            }
            /// The outer mixed join applies the second rebase. Its complete
            /// domain is derived from the original immutable arithmetic port.
            pub fn outerNamespace(self: *const Owned, a: std.mem.Allocator, first: u32) !Rebase.Plan {
                const old = try a.dupe(u32, self.namespace_ids);
                errdefer a.free(old);
                const plan = Rebase.Plan{ .allocator = a, .first = first, .old = old };
                _ = try plan.end();
                return plan;
            }
            pub fn validateLive(self: *const Owned, live: *Live.Prepared) !void {
                if (live.children.len != 1 or !std.meta.eql(live.children[0].expected(), self.expected) or
                    !std.meta.eql(live.recursive.context, self.context) or live.wires.len != self.wires.len)
                    return error.UntrustedPageAuxiliaryFixed;
                try live.recursive.rows.partitionHashRows();
                var namespace = try Rebase.prepare(self.original.allocator, &live.recursive.rows, 1);
                defer namespace.deinit();
                if (!std.mem.eql(u32, namespace.old, self.namespace_ids)) return error.UntrustedPageAuxiliaryFixed;
                for (self.wires, live.wires) |cold, actual| if (!std.meta.eql(cold, actual)) return error.UntrustedPageAuxiliaryFixed;
                inline for (0..Storage.Airs.len) |i| {
                    if (self.fixed[i].len != live.recursive.rows.fixed[i].len) return error.UntrustedPageAuxiliaryFixed;
                    for (self.fixed[i], live.recursive.rows.fixed[i]) |cold, actual| if (!std.meta.eql(cold, actual)) return error.UntrustedPageAuxiliaryFixed;
                }
            }
            pub fn deinit(self: *Owned) void {
                self.original.allocator.free(self.namespace_ids);
                self.original.allocator.free(self.wires);
                self.original.deinit();
                self.* = undefined;
            }
        };
    };
}
