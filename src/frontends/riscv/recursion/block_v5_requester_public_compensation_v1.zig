//! Direct PUBLIC tuple custody for the requester-only forest. Original typed
//! admission reconstructs B5PD bytes; genuine requester Sources supply digest,
//! compensation and register claims. No global-public proof or RAM leaf replay.
const std = @import("std");
const core = @import("stwo_core");
const Scoped = @import("block_v5_heterogeneous_scoped_plan_v1.zig");
const Catalog = @import("block_v5_heterogeneous_scoped_owner_v1.zig");
const Compact = @import("block_v5_heterogeneous_scoped_source_v1.zig");
const Original = @import("block_v5_global_public_export_policy_v1.zig");
const Fields = @import("block_v5_global_public_fields_v1.zig");
const Windows = @import("../prover/block_v5_register_windows_v1.zig");
const Q = core.fields.qm31.QM31;
pub const VERSION: u32 = 21;
pub const Owner = struct {
    allocator: std.mem.Allocator,
    lease: Catalog.Borrow,
    requester: *const Catalog.Owner,
    compact: *const Compact.Source,
    original: Original.Owner,
    // This facade deliberately uses the SAME original independently admitted
    // public field layout and challenge source as the canonical tuple kernel.
    policy: Original.Policy,
    fields: []Fields.Fields,
    terms: []Original.Terms,
    transition: Q,
    identity: [32]u8,
    pub const complete_block_authority = false;
    pub fn deinit(self: *Owner) void {
        self.original.deinit();
        self.lease.deinit();
        self.* = undefined;
    }
    pub fn validate(self: *const Owner) !void {
        if (self.requester.scoped.recipe != .requesters) return error.UntrustedRequesterPublicRecipe;
        var lease = try self.requester.borrow();
        defer lease.deinit();
        try self.compact.validate();
        const expected = try self.requester.source(self.requester.cohorts.root);
        if (!std.meta.eql(self.compact.ref, expected.ref) or !std.meta.eql(self.compact.seal, expected.seal)) return error.UnpairedRequesterPublicSource;
        if (self.policy.original.children.ptr != self.requester.full.children.ptr or
            self.policy.original.expected.ptr != self.requester.full.expected.ptr or
            self.fields.ptr != self.original.fields.ptr or self.fields.len != self.original.fields.len or
            self.terms.ptr != self.original.terms.ptr or self.terms.len != self.original.terms.len or
            !std.meta.eql(self.policy.windows, self.original.policy.windows)) return error.UnpairedRequesterPublicSource;
        try self.original.validate();
        if (!self.transition.eql(try transitionValue(self.requester, self.compact))) return error.UntrustedRequesterPublicTransition;
        if (!std.meta.eql(self.identity, self.computeIdentity())) return error.MutatedRequesterPublicOwner;
    }
    pub fn computeIdentity(self: *const Owner) [32]u8 {
        var c = core.channel.blake3.Channel{};
        c.mixU32s(&.{ 0x52515043, VERSION });
        c.mixRoot(self.requester.pinned_context);
        c.mixRoot(self.compact.expected_id);
        c.mixRoot(self.compact.public_input_digest);
        c.mixRoot(self.compact.seal);
        c.mixU32s(&.{ self.policy.windows.version, @intCast(self.fields.len) });
        c.mixFelts(&.{self.transition});
        for (self.fields, self.terms) |field, terms| {
            c.mixRoot(field.source_digest);
            c.mixU64(field.first_cycle);
            c.mixU64(field.last_cycle);
            c.mixFelts(&terms);
        }
        return c.digestBytes();
    }
    // Original row facade supplies independently admitted common B5SS seal.
    // The compensation graph compares all its bytes to authenticated retained
    // requester scopes before those same draw outputs enter tuple equations.
    pub fn sealedCells(_: *const Owner) !struct { child: u32, first: u32 } {
        return .{ .child = 1, .first = 0 };
    }
    pub fn requirement(self: *const Owner, key: Scoped.Key) !u32 {
        return findRequirement(self.requester.scoped.requirements, key);
    }
};
/// Original requirements are sorted by the canonical key grammar. A full
/// window scan per byte would turn this root attach into quadratic work.
pub fn findRequirement(requirements: []const Scoped.Requirement, key: Scoped.Key) !u32 {
    const found = std.sort.binarySearch(Scoped.Requirement, requirements, key, struct {
        fn order(wanted: Scoped.Key, item: Scoped.Requirement) std.math.Order {
            if (wanted.kind != item.key.kind) return std.math.order(@intFromEnum(wanted.kind), @intFromEnum(item.key.kind));
            if (wanted.scope != item.key.scope) return std.math.order(wanted.scope, item.key.scope);
            return std.math.order(wanted.coordinate, item.key.coordinate);
        }
    }.order) orelse return error.MissingRequesterPublicScope;
    return std.math.cast(u32, found) orelse error.RequesterPublicResourceLimit;
}
fn transitionValue(requester: *const Catalog.Owner, compact: *const Compact.Source) !Q {
    const id = try findRequirement(requester.scoped.requirements, .{ .kind = .transition, .scope = 0, .coordinate = 0 });
    if (compact.ref == .node) {
        const first = (try compact.findSlot(id)).first;
        if (first > compact.cells.len or compact.cells.len - first < 4) return error.UntrustedRequesterPublicTransition;
        var words: [4]core.fields.m31.M31 = undefined;
        for (&words, 0..) |*word, component| {
            var value: u32 = 0;
            for (compact.cells[first + component], 0..) |byte, part| {
                if (byte.v > 255) return error.UntrustedRequesterPublicTransition;
                value |= byte.v << @as(u5, @intCast(8 * part));
            }
            if (value >= core.fields.m31.Modulus) return error.NoncanonicalScopedSummary;
            word.* = core.fields.m31.M31.fromCanonical(value);
        }
        return Q.fromM31Array(words);
    }
    var sum = Q.zero();
    for (Scoped.Plan.termsFor(requester.scoped.requirements[id], compact.ref.leaf)) |term| {
        const value = try requester.scoped.value(term.selection);
        sum = if (term.negative) sum.sub(value) else sum.add(value);
    }
    return sum;
}
pub fn init(a: std.mem.Allocator, requester: *const Catalog.Owner, compact: *const Compact.Source, windows: Windows.Plan, limits: Fields.Limits) !Owner {
    if (requester.scoped.recipe != .requesters) return error.UntrustedRequesterPublicRecipe;
    var lease = try requester.borrow();
    errdefer lease.deinit();
    const policy = Original.Policy{ .original = requester.full, .windows = windows };
    var original = try Original.init(a, policy, limits);
    errdefer original.deinit();
    var result = Owner{ .allocator = a, .lease = lease, .requester = requester, .compact = compact, .original = original, .policy = policy, .fields = original.fields, .terms = original.terms, .transition = try transitionValue(requester, compact), .identity = undefined };
    result.identity = result.computeIdentity();
    try result.validate();
    return result;
}
