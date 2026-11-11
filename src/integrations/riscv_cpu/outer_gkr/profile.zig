//! Outer LogUp-GKR, named profile `outer_gkr_om31_strict_v1` (stream outer-gkr, M5 iteration of
//! the M7 lever). M7 remains explicit opt-in. Its CPU/device producers and
//! independent native/in-circuit receivers share these class constants.
//!
//! What the profile fixes (all of it is a class constant, never a proof value):
//! - the transcript domain (identity string below), mixed before any GKR draw;
//! - the instance roster of each outer class: (component, lane group, row_log, lane_log) in a fixed
//!   order, so the sumcheck lengths, mask counts and root counts are constants (profiles note
//!   rv64-m7-profiles.md section 4.2 finding 4: constant round counts, never muxed);
//! - OM31 challenges drawn from the raw-Blake OM31 channel with STRICT draws: a draw is admissible
//!   only if all eight raw words are < 2p (section 6 of the soundness note);
//! - every round polynomial carries exactly 4 coefficients with a nonzero leading coefficient
//!   (constant mixing length for the in-circuit verifier).
//!
//! Layout: instance index = lane * 2^row_log + row (lanes are the MOST significant variables). With
//! the GKR point convention (instance i reads the last n_i coordinates, MSB first), every instance of a
//! component then shares its row point = the last row_log coordinates of the batch point, so one eq
//! column per component serves all its lane groups (binding columns: eq + weighted prefix, 2 OM31).
const std = @import("std");
const candidate = @import("../word16_execution/om31_security_candidate.zig");

pub const PROFILE_NAME = "outer_gkr_om31_strict_v1";
pub const IDENTITY_DOMAIN = "stwo/rv64/outer-gkr/om31-strict-draw/lane-major/v1";
pub const VERSION: u32 = 1;
/// V2 is the anchored Eq + cyclic prefix construction. Existing v1 section
/// fixtures retain their exact identity and bytes, and are never re-labelled.
pub const BindingVersion = enum(u32) { legacy_v1 = 1, cyclic_eq_v2 = 2 };
pub const PROFILE_NAME_V2 = "outer_gkr_om31_strict_v2";
pub const IDENTITY_DOMAIN_V2 = "stwo/rv64/outer-gkr/om31-strict-draw/lane-major/v2";
pub const MAGIC: u32 = 0x524b474f; // "OGKR"
pub const COEFFICIENTS_PER_ROUND: usize = 4;
pub const MAX_INSTANCES: usize = 64; // = CUDA batch_max_oracles
pub const MAX_VARIABLES: u32 = 28; // = CUDA gkr.max_variables

/// Outer circuit roster (src/frontends/circuit/common/component_list.zig order).
pub const Component = enum(u8) {
    eq,
    qm31_ops,
    triple_xor,
    m_31_to_u_32,
    blake_g_gate,
    verify_bitwise_xor_8,
    verify_bitwise_xor_12,
    verify_bitwise_xor_4,
    verify_bitwise_xor_7,
    verify_bitwise_xor_9,
    range_check_16,
};
pub const N_COMPONENTS = @typeInfo(Component).@"enum".fields.len;
/// component_facts: main columns, classic (QM31-counted) interaction columns, lookups per row.
pub const Facts = struct { main: u32, interaction_qm31: u32, lookups: u32 };
pub const FACTS = [N_COMPONENTS]Facts{
    .{ .main = 4, .interaction_qm31 = 4, .lookups = 2 },
    .{ .main = 12, .interaction_qm31 = 8, .lookups = 3 },
    .{ .main = 20, .interaction_qm31 = 24, .lookups = 12 },
    .{ .main = 4, .interaction_qm31 = 12, .lookups = 5 },
    .{ .main = 52, .interaction_qm31 = 52, .lookups = 26 },
    .{ .main = 2, .interaction_qm31 = 4, .lookups = 2 },
    .{ .main = 16, .interaction_qm31 = 32, .lookups = 16 },
    .{ .main = 1, .interaction_qm31 = 4, .lookups = 1 },
    .{ .main = 1, .interaction_qm31 = 4, .lookups = 1 },
    .{ .main = 1, .interaction_qm31 = 4, .lookups = 1 },
    .{ .main = 1, .interaction_qm31 = 4, .lookups = 1 },
};
/// Committed OM31 base columns per GKR-bound component: eq column + weighted prefix column.
pub const BINDING_BASE_COLUMNS: u32 = 16;
/// Classic outer interaction columns are OM31 (8 base coordinates per secure column): the QM31
/// facts count 4. Measured: 304 committed interaction columns per node (M4.0 item 8).
pub fn classicInteractionBaseColumns(c: Component) u32 {
    return 2 * FACTS[@intFromEnum(c)].interaction_qm31;
}
/// Hybrid rule: a component goes to the GKR only if its classic interaction is wider than the
/// binding columns it needs. Ties stay classic (no gain, more verifier work).
pub fn gkrBound(c: Component) bool {
    return classicInteractionBaseColumns(c) > BINDING_BASE_COLUMNS;
}

pub const Instance = struct {
    component: Component,
    /// Lane group ordinal within the component (binary decomposition of its lookups).
    group: u8,
    row_log: u8,
    lane_log: u8,
    /// Lookups actually carried by this group (<= 2^lane_log; the rest are padding (0, 1)).
    lanes_used: u8,
    pub fn variables(self: Instance) u32 {
        return @as(u32, self.row_log) + self.lane_log;
    }
    pub fn word(self: Instance) u32 {
        return @as(u32, @intFromEnum(self.component)) << 24 | @as(u32, self.group) << 16 | @as(u32, self.row_log) << 8 | self.lane_log;
    }
};

pub const Class = struct {
    id: u32,
    name: []const u8,
    row_logs: [N_COMPONENTS]u8,
    instances: []const Instance,
    binding_version: BindingVersion = .legacy_v1,
    pub fn withBindingV2(self: Class) Class {
        var out = self;
        out.binding_version = .cyclic_eq_v2;
        return out;
    }
    pub fn version(self: Class) u32 {
        return @intFromEnum(self.binding_version);
    }
    pub fn layers(self: Class) u32 {
        var out: u32 = 0;
        for (self.instances) |i| out = @max(out, i.variables());
        return out;
    }
    pub fn rounds(self: Class) u64 {
        const l: u64 = self.layers();
        return l * (l - 1) / 2;
    }
    pub fn instanceLayers(self: Class) u64 {
        var out: u64 = 0;
        for (self.instances) |i| out += i.variables();
        return out;
    }
    pub fn fractions(self: Class) u64 {
        var out: u64 = 0;
        for (self.instances) |i| out += @as(u64, 1) << @intCast(i.variables());
        return out;
    }
    pub fn validate(self: Class) !void {
        if (self.instances.len == 0 or self.instances.len > MAX_INSTANCES) return error.InvalidOuterGkrClass;
        for (self.instances, 0..) |inst, k| {
            if (inst.variables() == 0 or inst.variables() > MAX_VARIABLES) return error.InvalidOuterGkrClass;
            if (inst.row_log != self.row_logs[@intFromEnum(inst.component)]) return error.InvalidOuterGkrClass;
            if (inst.lanes_used == 0 or inst.lanes_used > (@as(u32, 1) << @intCast(inst.lane_log))) return error.InvalidOuterGkrClass;
            if (!gkrBound(inst.component)) return error.InvalidOuterGkrClass;
            // Strictly increasing (component, group): no duplicate or reordered instance.
            if (k > 0) {
                const prev = self.instances[k - 1];
                if (!(prev.word() >> 16 < inst.word() >> 16)) return error.InvalidOuterGkrClass;
            }
        }
        // Every GKR-bound component carries all of its lookups, exactly once.
        for (0..N_COMPONENTS) |c| {
            var lanes: u32 = 0;
            for (self.instances) |inst| if (@intFromEnum(inst.component) == c) {
                lanes += inst.lanes_used;
            };
            const comp: Component = @enumFromInt(c);
            if (gkrBound(comp) and lanes != FACTS[c].lookups) return error.InvalidOuterGkrClass;
        }
    }
    /// Header words mixed into the outer transcript before the GKR section (binding obligation 3
    /// of the profiles note: each instance's (component, group) tag sits inside the mixed list).
    pub fn header(self: Class, out: []u32) ![]u32 {
        const id = identityFor(self.binding_version);
        const need = 8 + 4 + self.instances.len;
        if (out.len < need) return error.NoSpaceLeft;
        for (0..8) |i| out[i] = std.mem.readInt(u32, id[4 * i ..][0..4], .little);
        out[8] = MAGIC;
        out[9] = self.version();
        out[10] = self.id;
        out[11] = @intCast(self.instances.len);
        for (self.instances, 0..) |inst, i| out[12 + i] = inst.word();
        return out[0..need];
    }
    /// Characteristic bound: worst per-relation multiplicity mass. Conservative: all lanes of every
    /// instance of the class feed one relation with |multiplicity| <= MAX_ROW_MULTIPLICITY per lane.
    pub fn conservativeMass(self: Class) u64 {
        var out: u64 = 0;
        for (self.instances) |inst| out += @as(u64, inst.lanes_used) << @intCast(inst.row_log);
        return out * MAX_ROW_MULTIPLICITY;
    }
    pub fn facts(self: Class, outer_proofs: u64) candidate.OuterGkrFacts {
        return .{ .outer_proofs = outer_proofs, .instances = self.instances.len, .max_variables = self.layers(), .max_tuple_arity = MAX_TUPLE_ARITY };
    }
};
/// Max |multiplicity| of one USE lane in one outer row. LogUp over M31 needs the total use mass of
/// a relation below p; table-yield multiplicities may be any field element (they only have to equal
/// the use count mod p). Every lane of every GKR instance is counted as a use (conservative: table
/// lanes are counted too). ASSUMPTION for canon-vk to confirm on the outer AIR: uses carry +-1.
pub const MAX_ROW_MULTIPLICITY: u64 = 1;
/// Max tuple arity of an outer relation (Blake G-gate relation tuples are the widest).
pub const MAX_TUPLE_ARITY: u64 = 32;

pub fn identity() [32]u8 {
    return identityFor(.legacy_v1);
}
pub fn identityFor(version: BindingVersion) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(if (version == .legacy_v1) IDENTITY_DOMAIN else IDENTITY_DOMAIN_V2);
    h.update(&[_]u8{0});
    h.update(if (version == .legacy_v1) PROFILE_NAME else PROFILE_NAME_V2);
    return h.finalResult();
}

/// Binary decomposition of each GKR-bound component's lookups into lane groups, largest first.
pub fn instancesFor(row_logs: [N_COMPONENTS]u8, out: []Instance) ![]Instance {
    var n: usize = 0;
    for (0..N_COMPONENTS) |c| {
        const comp: Component = @enumFromInt(c);
        if (!gkrBound(comp)) continue;
        var remaining: u32 = FACTS[c].lookups;
        var group: u8 = 0;
        var bit: u5 = 7;
        while (remaining > 0) : (bit -%= 1) {
            const lanes = @as(u32, 1) << bit;
            if (remaining & lanes != 0) {
                if (n == out.len) return error.NoSpaceLeft;
                out[n] = .{ .component = comp, .group = group, .row_log = row_logs[c], .lane_log = bit, .lanes_used = @intCast(lanes) };
                n += 1;
                group += 1;
                remaining -= lanes;
            }
            if (bit == 0) break;
        }
    }
    return out[0..n];
}

fn makeClass(comptime id: u32, comptime name: []const u8, comptime row_logs: [N_COMPONENTS]u8) Class {
    @setEvalBranchQuota(100000);
    const list = comptime blk: {
        var buf: [MAX_INSTANCES]Instance = undefined;
        const got = instancesFor(row_logs, &buf) catch unreachable;
        var fixed: [got.len]Instance = undefined;
        @memcpy(&fixed, got);
        break :blk fixed;
    };
    return .{ .id = id, .name = name, .row_logs = row_logs, .instances = &list };
}

/// 24628607 CPU leaf class (census-v2 nodes 0,1,3,4,7,8; row logs from CUDA_OUTER_AUTHORITY).
pub const LEAF_CPU_24628607 = makeClass(0x10, "leaf-cpu-24628607", .{ 18, 23, 20, 21, 23, 16, 20, 8, 14, 18, 16 });
/// 24628607 fold class (census-v2 node 20 and 13 others of the same row geometry).
pub const FOLD_24628607 = makeClass(0x20, "fold-24628607", .{ 15, 22, 19, 20, 23, 16, 20, 8, 14, 18, 16 });
/// Scaled-down class with the production roster (CPU tests, tamper corpus, GPU parity).
pub const TEST_SMALL = makeClass(0x7e, "test-small", .{ 4, 5, 4, 5, 6, 4, 4, 2, 3, 4, 4 });
pub const CLASSES = [_]*const Class{ &LEAF_CPU_24628607, &FOLD_24628607, &TEST_SMALL };
pub fn classByName(name: []const u8) !*const Class {
    for (CLASSES) |c| if (std.mem.eql(u8, c.name, name)) return c;
    return error.UnknownOuterGkrClass;
}
pub fn classById(id: u32) !*const Class {
    for (CLASSES) |c| if (c.id == id) return c;
    return error.UnknownOuterGkrClass;
}

/// Bits target the profiles note asks of the real circuit facts (section 4.3).
pub const REQUIRED_BITS: u16 = 151;
pub fn requireSecurity(class: Class, outer_proofs: u64) !void {
    try class.validate();
    if (class.binding_version == .cyclic_eq_v2) return error.OuterGkrSourceMassRequired;
    const f = class.facts(outer_proofs);
    try candidate.requireOuterGkrBits(f, REQUIRED_BITS);
    try candidate.requireOuterGkrCharacteristic(f, class.conservativeMass());
}

/// Conservative per-relation positive-use mass from independently derived
/// source topology, including classic components sharing GKR relations. ALL
/// uses carry +1 in the original tuple authority; multiplicity yields are
/// negative. Counting all positive uses together bounds every relation.
/// Never take a mass declared by the producer or count only GKR instances.
pub fn sourceUseMass(class: Class, source_outputs: usize) !u64 {
    try class.validate();
    const uses = [_]u32{ 2, 2, 11, 4, 22 };
    var mass = try std.math.add(u64, @intCast(source_outputs), 1);
    for (uses, class.row_logs[0..uses.len]) |count, log| {
        if (log >= 31) return error.OuterGkrSourceMassShape;
        mass = try std.math.add(u64, mass, @as(u64, count) << @intCast(log));
    }
    return mass;
}
pub fn requireSecurityWithSource(class: Class, outer_proofs: u64, source_outputs: usize) !void {
    try class.validate();
    const facts = class.facts(outer_proofs);
    try candidate.requireOuterGkrBits(facts, REQUIRED_BITS);
    try candidate.requireOuterGkrCharacteristic(facts, try sourceUseMass(class, source_outputs));
}
