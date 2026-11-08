//! Native LogUp-GKR v1 (`rv64-m5-native-gkr/v1`) instance roster. Stream native-gkr, M5.
//! Soundness/binding argument: design/riscv/rv64-native-gkr.md.
//!
//! One batched LogUp-GKR per native proof, run in stage two (after chi fixes the shared RAM/KIO/Wire
//! challenges), carries EVERY LogUp fraction of the proof: the proof-local relations that M4 already
//! proves with the stage-one local GKR, and the global RAM/KIO/Wire queries that M4 still commits as
//! classic interaction columns (and, for truth proofs, the classic local columns too).
//!
//! Per component the fractions are split into lane groups by relation kind (local, ram, kio, wire).
//! Layout is lane-major (index = lane * 2^row_log + row, the outer-gkr convention): every group of a
//! component then reads the same row point (the last row_log coordinates of the batch point), so ONE eq
//! column and ONE weighted prefix column (2 OM31 = 16 M31 columns) bind all groups of the component.
//! Global groups therefore add no committed column at all; that is the whole saving of v1.
//!
//! The roster is a function of receiver-derived geometry only (row logs and per-kind term counts are
//! class constants), so sumcheck lengths, mask counts and root counts are never proof values.
const std = @import("std");

pub const Kind = enum(u8) { local = 0, ram = 1, kio = 2, wire = 3 };
pub const KINDS = 4;
pub const MAX_INSTANCES: usize = 64; // CUDA batch_max_oracles (shared traversal kernels)
pub const MAX_VARIABLES: u32 = 28; // CUDA gkr.max_variables
pub const MAX_LANE_LOG: u32 = 12; // secp truth rows ~1,276 local fractions (11), Keccak truth 9, sponge perm 8
pub const BINDING_BASE_COLUMNS: usize = 16; // eq + weighted prefix, OM31

/// One physical component of a native proof as the receiver derives it.
pub const ComponentSpec = struct {
    /// Stable origin words (frame.originWords for CPU roles; truth parts use tag 16 + family).
    origin: [2]u32,
    row_log: u32,
    /// Fractions per row of each relation kind (index = @intFromEnum(Kind)).
    terms: [KINDS]u32,
    pub fn present(self: ComponentSpec) bool {
        for (self.terms) |t| if (t != 0) return true;
        return false;
    }
};

pub const Instance = struct {
    component: u16,
    kind: Kind,
    row_log: u32,
    lane_log: u32,
    terms: u32,
    pub fn variables(self: Instance) u32 {
        return self.row_log + self.lane_log;
    }
    pub fn lanes(self: Instance) usize {
        return @as(usize, 1) << @intCast(self.lane_log);
    }
    pub fn facts(self: Instance) u64 {
        return @as(u64, 1) << @intCast(self.variables());
    }
};

pub fn laneLog(terms: u32) u32 {
    if (terms <= 1) return 0;
    return std.math.log2_int_ceil(u32, terms);
}

pub const Roster = struct {
    allocator: std.mem.Allocator,
    components: []ComponentSpec,
    instances: []Instance,
    pub fn deinit(self: *Roster) void {
        self.allocator.free(self.components);
        self.allocator.free(self.instances);
        self.* = undefined;
    }
    pub fn layers(self: *const Roster) u32 {
        var l: u32 = 0;
        for (self.instances) |inst| l = @max(l, inst.variables());
        return l;
    }
    pub fn validate(self: *const Roster) !void {
        return self.validateBounded(MAX_INSTANCES);
    }
    /// Receiver-selected protocol bound; the wire cannot choose this capacity.
    pub fn validateBounded(self: *const Roster, max_instances: usize) !void {
        if (max_instances == 0 or max_instances > 128) return error.NativeGkrRosterShape;
        if (self.instances.len == 0 or self.instances.len > max_instances) return error.NativeGkrRosterShape;
        var previous: ?Instance = null;
        for (self.instances) |inst| {
            if (inst.component >= self.components.len) return error.NativeGkrRosterShape;
            const c = self.components[inst.component];
            if (inst.row_log != c.row_log or inst.terms == 0 or inst.terms != c.terms[@intFromEnum(inst.kind)]) return error.NativeGkrRosterShape;
            if (inst.lane_log != laneLog(inst.terms) or inst.lane_log > MAX_LANE_LOG) return error.NativeGkrRosterShape;
            if (inst.row_log < 1 or inst.variables() > MAX_VARIABLES) return error.NativeGkrRosterShape;
            // Strict canonical order: (component, kind) strictly increasing.
            if (previous) |p| if (p.component > inst.component or (p.component == inst.component and @intFromEnum(p.kind) >= @intFromEnum(inst.kind))) return error.NativeGkrRosterOrder;
            previous = inst;
        }
        // Completeness: every nonzero (component, kind) term count owns exactly one instance. With the
        // strict order and the per-instance term match above, no relation group can be dropped from the
        // batch (a dropped group's fractions would be bound by nothing). Adversarial review A1.
        for (self.components, 0..) |c, ci| {
            var want: usize = 0;
            for (c.terms) |t| want += @intFromBool(t != 0);
            var got: usize = 0;
            for (self.instances) |inst| got += @intFromBool(inst.component == ci);
            if (got != want) return error.NativeGkrRosterShape;
        }
    }
    /// Committed binding pairs = components that own at least one instance.
    pub fn bindingPairs(self: *const Roster) usize {
        var n: usize = 0;
        for (self.components) |c| n += @intFromBool(c.present());
        return n;
    }
    /// Committed INTER cells of v1 (own height, M31 base cells).
    pub fn interCells(self: *const Roster) u64 {
        var n: u64 = 0;
        for (self.components) |c| if (c.present()) {
            n += BINDING_BASE_COLUMNS * (@as(u64, 1) << @intCast(c.row_log));
        };
        return n;
    }
    pub fn gkrFacts(self: *const Roster) u64 {
        var n: u64 = 0;
        for (self.instances) |inst| n += inst.facts();
        return n;
    }
    /// Header words mixed into the transcript before any GKR draw (constant per class):
    /// [n_components, n_instances, (origin0, origin1, row_log, terms[4])*, (component<<16 | kind<<8 | lane_log)*].
    pub fn header(self: *const Roster, a: std.mem.Allocator) ![]u32 {
        var out = std.ArrayList(u32).empty;
        errdefer out.deinit(a);
        try out.appendSlice(a, &.{ @intCast(self.components.len), @intCast(self.instances.len) });
        for (self.components) |c| {
            try out.appendSlice(a, &c.origin);
            try out.append(a, c.row_log);
            try out.appendSlice(a, &c.terms);
        }
        for (self.instances) |inst| try out.append(a, (@as(u32, inst.component) << 16) | (@as(u32, @intFromEnum(inst.kind)) << 8) | inst.lane_log);
        return out.toOwnedSlice(a);
    }
};

/// Canonical roster: components in receiver order, absent components dropped from instances but kept
/// in the component list (their header entry pins the class shape), groups in Kind order.
pub fn derive(a: std.mem.Allocator, specs: []const ComponentSpec) !Roster {
    return deriveBounded(a, specs, MAX_INSTANCES);
}
pub fn deriveBounded(a: std.mem.Allocator, specs: []const ComponentSpec, max_instances: usize) !Roster {
    const components = try a.dupe(ComponentSpec, specs);
    errdefer a.free(components);
    var list = std.ArrayList(Instance).empty;
    errdefer list.deinit(a);
    for (components, 0..) |c, i| {
        if (i > std.math.maxInt(u16)) return error.NativeGkrRosterShape;
        for (c.terms, 0..) |t, k| if (t != 0) {
            try list.append(a, .{ .component = @intCast(i), .kind = @enumFromInt(k), .row_log = c.row_log, .lane_log = laneLog(t), .terms = t });
        };
    }
    const instances = try list.toOwnedSlice(a);
    var roster = Roster{ .allocator = a, .components = components, .instances = instances };
    roster.validateBounded(max_instances) catch |err| {
        a.free(instances);
        return err; // components freed by the errdefer above
    };
    return roster;
}
