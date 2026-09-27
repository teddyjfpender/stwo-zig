//! One versioned prechallenge roster for the separately proved block-v5
//! families. A seal is a transcript seed, never proof authority by itself:
//! the receiver reconstructs it from independent pins and freshly checked
//! first-round admissions before accepting any relation receipt.
const std = @import("std");
const core = @import("stwo_core");
const universal_channel = @import("block_v5_universal_channel_v1.zig");

pub const Digest = [32]u8;
pub const Roots = [2]Digest;
pub const VERSION: u32 = universal_channel.VERSION;
pub const TAG: u32 = universal_channel.TAG;
pub const REGISTER_WINDOW_VERSION: u32 = 2;
pub const READONLY_ROSTER_VERSION: u32 = 3;

pub const Family = enum(u32) {
    program = 1,
    execution = 2,
    /// Existing same-root opcode/memory-transition bridge.
    execution_sidecar = 3,
    /// Separate same-root program-access LogUp; never alias the memory bridge.
    program_request = 4,
    memory = 5,
    memory_range = 6,
    initial_register = 7,
    initial_input = 8,
    initial_rw = 9,
    hash = 10,
    precompile = 11,
    /// Sparse same-native-root SHA/Keccak/signer fetch proofs. Each entry index
    /// is the actual execution ordinal, strictly increasing within this family.
    program_extension_request = 12,
    /// Sparse same-native-root external memory projection. Dedicated
    /// precompile arithmetic proofs remain in `.precompile`.
    execution_external_sidecar = 13,
    /// Independently planned native bitwise/range multiplicity providers.
    native_lookup = 14,
};
pub const family_count: usize = @typeInfo(Family).@"enum".fields.len;

pub const Entry = struct {
    family: Family,
    index: u32,
    /// Versioned component instance/claim ID, independently reconstructed by
    /// the receiver. This keeps equal roots in different plans distinct.
    instance_id: Digest,
    roots: Roots,
};

pub const Pins = struct {
    job_id: Digest,
    source_image_digest: Digest,
    /// Singular-template fixtures. A varied-geometry block instead pins the
    /// independently checked ordered template catalog below. Exactly one
    /// template binding mode is allowed in a source seal.
    native_template_id: Digest = @splat(0),
    native_template_catalog_digest: Digest = @splat(0),
    program_root: Digest,
    program_plan_digest: Digest,
    memory_plan_digest: Digest,
    initial_source_plan_digest: Digest,
    /// Zero is allowed in component fixtures; complete block policy must pin
    /// the actual post-execution sparse RW root independently.
    expected_final_rw_root: Digest = @splat(0),
    /// Canonical public endpoint bytes, including their nonadaptive clocks.
    rw_endpoint_plan_digest: Digest = @splat(0),
    /// Global register endpoints and exact clocks; zero is scoped only.
    register_endpoint_plan_digest: Digest = @splat(0),
    /// 0 is the original sorted register/RAM protocol; 1 proves register
    /// custody per execution window and sends only RW events to sorted RAM.
    /// Canonical production selects 1 explicitly. Policy, not a proof, chooses.
    register_custody_mode: u32 = 0,
    /// Optional original classifier inventory committed before every B5SS draw.
    /// Zero keeps the original writable protocol and exact transcript bytes.
    readonly_roster_digest: Digest = @splat(0),
    config: core.pcs.PcsConfig,
    /// Expected per-family proof/first-round counts derived from the trusted
    /// job and the admitted planners, not from a received proof bundle.
    counts: [family_count]u32,

    pub fn validate(self: Pins) !void {
        try @import("blake3_execution_protocol.zig").validateConfig(self.config);
        if (self.register_custody_mode > 1 or (!zero(self.readonly_roster_digest) and self.register_custody_mode != 1)) return error.InvalidBlockV5RegisterCustodyMode;
        if (self.register_custody_mode == 1 and zero(self.register_endpoint_plan_digest)) return error.MissingBlockV5RegisterEndpointPlan;
        if (zero(self.job_id) or zero(self.source_image_digest) or
            zero(self.native_template_id) == zero(self.native_template_catalog_digest) or
            zero(self.program_root) or
            zero(self.program_plan_digest) or zero(self.memory_plan_digest) or
            zero(self.initial_source_plan_digest) or
            self.counts[@intFromEnum(Family.program) - 1] != 1 or
            self.counts[@intFromEnum(Family.execution) - 1] == 0 or
            (self.counts[@intFromEnum(Family.memory) - 1] == 0 and
                (self.register_custody_mode != 1 or self.counts[@intFromEnum(Family.memory_range) - 1] != 0)) or
            self.counts[@intFromEnum(Family.execution_sidecar) - 1] !=
                self.counts[@intFromEnum(Family.execution) - 1] or
            self.counts[@intFromEnum(Family.program_request) - 1] !=
                self.counts[@intFromEnum(Family.execution) - 1] or
            self.counts[@intFromEnum(Family.program_extension_request) - 1] >
                self.counts[@intFromEnum(Family.execution) - 1] or
            self.counts[@intFromEnum(Family.precompile) - 1] >
                self.counts[@intFromEnum(Family.execution) - 1] or
            self.counts[@intFromEnum(Family.execution_external_sidecar) - 1] >
                self.counts[@intFromEnum(Family.execution) - 1])
            return error.InvalidBlockV5SourcePins;
    }

    pub fn validateComplete(self: Pins) !void {
        try self.validate();
        if (zero(self.expected_final_rw_root)) return error.MissingBlockV5FinalRwRoot;
        if (zero(self.rw_endpoint_plan_digest)) return error.MissingBlockV5RwEndpointPlan;
        if (zero(self.register_endpoint_plan_digest)) return error.MissingBlockV5RegisterEndpointPlan;
        const callers = self.counts[@intFromEnum(Family.precompile) - 1];
        if (callers != self.counts[@intFromEnum(Family.program_extension_request) - 1] or
            callers != self.counts[@intFromEnum(Family.execution_external_sidecar) - 1])
            return error.IncompleteBlockV5PrecompileFamilies;
    }
};

pub const Sealed = struct {
    digest: Digest,
    native_roster_digest: Digest,
    native_template_catalog_digest: Digest,
    expected_final_rw_root: Digest,
    rw_endpoint_plan_digest: Digest,
    register_endpoint_plan_digest: Digest,
    register_custody_mode: u32 = 0,
    /// Optional original classifier inventory committed before every B5SS draw.
    /// Zero keeps the original writable protocol and exact transcript bytes.
    readonly_roster_digest: Digest = @splat(0),
    program_first_roots: Roots,
    program_plan_digest: Digest,
    program_root: Digest,
    initial_source_plan_digest: Digest,
    counts: [family_count]u32,
    memory_instance_count: u32,
    execution_instance_count: u32,

    pub fn initialSourcePlanDigest(self: Sealed) Digest {
        return self.initial_source_plan_digest;
    }

    pub fn sharedChannel(self: Sealed) core.proof_suites.Blake3.Channel {
        return universal_channel.init(self.digest);
    }

    pub fn require(self: Sealed, pins: Pins, entries: []const Entry) !void {
        const expected = try seal(pins, entries);
        if (!std.meta.eql(self, expected)) return error.UntrustedBlockV5SourceSeal;
    }

    pub fn requireComplete(self: Sealed, pins: Pins, entries: []const Entry) !void {
        try pins.validateComplete();
        try self.require(pins, entries);
    }

    /// Derive the program-table subproof's challenge seed from the one block
    /// seal. The native-v5 request proofs must use this same derived seed.
    pub fn programSeal(self: Sealed) @import("block_v5_program_table_proof_v1.zig").Seal {
        return .{
            .source_digest = self.digest,
            .native_roster_digest = self.native_roster_digest,
            .plan_digest = self.program_plan_digest,
            .program_root = .{ .bytes = self.program_root },
            .first_roots = self.program_first_roots,
        };
    }
};

/// Canonical family/index order and an exact census are checked before any
/// challenge is drawn. In particular, no proof-carried root can silently add
/// or omit a memory, native, or program component.
pub fn seal(pins: Pins, entries: []const Entry) !Sealed {
    try pins.validate();
    const catalog_mode = !zero(pins.native_template_catalog_digest);
    const template_binding = if (catalog_mode) pins.native_template_catalog_digest else pins.native_template_id;
    var expected_len: usize = 0;
    for (pins.counts) |count| expected_len = try std.math.add(usize, expected_len, count);
    if (entries.len != expected_len) return error.InvalidBlockV5FirstRoundCensus;
    var channel = core.proof_suites.Blake3.Channel{};
    const readonly_mode = !zero(pins.readonly_roster_digest);
    const source_version = if (readonly_mode) READONLY_ROSTER_VERSION else if (pins.register_custody_mode == 0) VERSION else REGISTER_WINDOW_VERSION;
    channel.mixU32s(&.{ TAG, source_version });
    if (pins.register_custody_mode != 0) channel.mixU32s(&.{pins.register_custody_mode});
    channel.mixRoot(pins.job_id);
    channel.mixRoot(pins.source_image_digest);
    channel.mixU32s(&.{if (catalog_mode) 1 else 0});
    channel.mixRoot(template_binding);
    channel.mixRoot(pins.program_root);
    channel.mixRoot(pins.program_plan_digest);
    channel.mixRoot(pins.memory_plan_digest);
    channel.mixRoot(pins.initial_source_plan_digest);
    channel.mixRoot(pins.expected_final_rw_root);
    channel.mixRoot(pins.rw_endpoint_plan_digest);
    channel.mixRoot(pins.register_endpoint_plan_digest);
    if (readonly_mode) channel.mixRoot(pins.readonly_roster_digest);
    pins.config.mixInto(&channel);
    for (pins.counts) |count| channel.mixU32s(&.{count});

    var native_channel = core.proof_suites.Blake3.Channel{};
    native_channel.mixU32s(&.{ TAG, source_version, 0x4e415456 }); // NATV
    if (pins.register_custody_mode != 0) {
        native_channel.mixU32s(&.{pins.register_custody_mode});
        native_channel.mixRoot(pins.register_endpoint_plan_digest);
    }
    if (readonly_mode) native_channel.mixRoot(pins.readonly_roster_digest);
    native_channel.mixRoot(pins.job_id);
    native_channel.mixU32s(&.{if (catalog_mode) 1 else 0});
    native_channel.mixRoot(template_binding);
    var at: usize = 0;
    var program_roots: Roots = undefined;
    var previous_extension: ?u32 = null;
    var previous_external: ?u32 = null;
    var previous_precompile: ?u32 = null;
    inline for (@typeInfo(Family).@"enum".fields, 0..) |field, family_index| {
        const family: Family = @enumFromInt(field.value);
        for (0..pins.counts[family_index]) |index| {
            const entry = entries[at];
            const valid_index = if (family == .program_extension_request)
                entry.index < pins.counts[@intFromEnum(Family.execution) - 1] and
                    (previous_extension == null or entry.index > previous_extension.?)
            else if (family == .execution_external_sidecar)
                entry.index < pins.counts[@intFromEnum(Family.execution) - 1] and
                    (previous_external == null or entry.index > previous_external.?)
            else if (family == .precompile)
                entry.index < pins.counts[@intFromEnum(Family.execution) - 1] and
                    (previous_precompile == null or entry.index > previous_precompile.?)
            else
                entry.index == @as(u32, @intCast(index));
            if (entry.family != family or !valid_index or zero(entry.instance_id))
                return error.InvalidBlockV5FirstRoundOrder;
            if (family == .program_extension_request) previous_extension = entry.index;
            if (family == .execution_external_sidecar) previous_external = entry.index;
            if (family == .precompile) previous_precompile = entry.index;
            channel.mixU32s(&.{ @intFromEnum(entry.family), entry.index });
            channel.mixRoot(entry.instance_id);
            channel.mixRoot(entry.roots[0]);
            channel.mixRoot(entry.roots[1]);
            if (family == .program) program_roots = entry.roots;
            if (family == .execution) {
                native_channel.mixU32s(&.{entry.index});
                native_channel.mixRoot(entry.instance_id);
                native_channel.mixRoot(entry.roots[0]);
                native_channel.mixRoot(entry.roots[1]);
            }
            at += 1;
        }
    }
    std.debug.assert(at == entries.len);
    return .{ .digest = channel.digestBytes(), .native_roster_digest = native_channel.digestBytes(), .native_template_catalog_digest = pins.native_template_catalog_digest, .expected_final_rw_root = pins.expected_final_rw_root, .rw_endpoint_plan_digest = pins.rw_endpoint_plan_digest, .register_endpoint_plan_digest = pins.register_endpoint_plan_digest, .register_custody_mode = pins.register_custody_mode, .readonly_roster_digest = pins.readonly_roster_digest, .program_first_roots = program_roots, .program_plan_digest = pins.program_plan_digest, .program_root = pins.program_root, .initial_source_plan_digest = pins.initial_source_plan_digest, .counts = pins.counts, .memory_instance_count = pins.counts[@intFromEnum(Family.memory) - 1], .execution_instance_count = pins.counts[@intFromEnum(Family.execution) - 1] };
}

fn zero(value: Digest) bool {
    return std.meta.eql(value, @as(Digest, @splat(0)));
}

test "block-v5 seal binds exact ordered family roster and program subproof" {
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var counts: [family_count]u32 = @splat(0);
    counts[@intFromEnum(Family.program) - 1] = 1;
    counts[@intFromEnum(Family.execution) - 1] = 2;
    counts[@intFromEnum(Family.execution_sidecar) - 1] = 2;
    counts[@intFromEnum(Family.program_request) - 1] = 2;
    counts[@intFromEnum(Family.memory) - 1] = 1;
    const pins = Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = @splat(4), .program_plan_digest = @splat(5), .memory_plan_digest = @splat(6), .initial_source_plan_digest = @splat(25), .config = config, .counts = counts };
    const entries = [_]Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(7), .roots = .{ @splat(8), @splat(9) } },
        .{ .family = .execution, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
        .{ .family = .execution, .index = 1, .instance_id = @splat(13), .roots = .{ @splat(14), @splat(15) } },
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(16), .roots = .{ @splat(17), @splat(18) } },
        .{ .family = .execution_sidecar, .index = 1, .instance_id = @splat(19), .roots = .{ @splat(20), @splat(21) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(26), .roots = .{ @splat(27), @splat(28) } },
        .{ .family = .program_request, .index = 1, .instance_id = @splat(29), .roots = .{ @splat(30), @splat(31) } },
        .{ .family = .memory, .index = 0, .instance_id = @splat(22), .roots = .{ @splat(23), @splat(24) } },
    };
    const sealed = try seal(pins, &entries);
    try sealed.require(pins, &entries);
    try std.testing.expectEqual(@as(u32, 1), sealed.memory_instance_count);
    try std.testing.expectEqual(@as(u32, 2), sealed.execution_instance_count);
    try std.testing.expectEqualDeep(pins.initial_source_plan_digest, sealed.initialSourcePlanDigest());
    const subproof = sealed.programSeal();
    try std.testing.expectEqualDeep(entries[0].roots, subproof.first_roots);
    try std.testing.expectEqualDeep(sealed.digest, subproof.source_digest);
    try std.testing.expectEqualDeep(sealed.native_roster_digest, subproof.native_roster_digest);
    var changed = entries;
    changed[2].roots[1][0] ^= 1;
    try std.testing.expectError(error.UntrustedBlockV5SourceSeal, sealed.require(pins, &changed));
    changed = entries;
    changed[2].index = 0;
    try std.testing.expectError(error.InvalidBlockV5FirstRoundOrder, seal(pins, &changed));
    var changed_pins = pins;
    changed_pins.config.fri_config.n_queries = 0;
    if (seal(changed_pins, &entries)) |_|
        return error.AcceptedInvalidBlockV5Config
    else |_| {}
    changed_pins = pins;
    changed_pins.program_root[0] ^= 1;
    try std.testing.expectError(error.UntrustedBlockV5SourceSeal, sealed.require(changed_pins, &entries));
    changed_pins = pins;
    changed_pins.native_template_catalog_digest = @splat(40);
    try std.testing.expectError(error.InvalidBlockV5SourcePins, seal(changed_pins, &entries));
    changed_pins.native_template_id = @splat(0);
    const catalog_seal = try seal(changed_pins, &entries);
    try std.testing.expectEqualDeep(changed_pins.native_template_catalog_digest, catalog_seal.native_template_catalog_digest);
    try std.testing.expect(!std.meta.eql(sealed.digest, catalog_seal.digest));
    try std.testing.expect(!std.meta.eql(sealed.native_roster_digest, catalog_seal.native_roster_digest));
    changed_pins = pins;
    changed_pins.counts[@intFromEnum(Family.program_extension_request) - 1] = 3;
    try std.testing.expectError(error.InvalidBlockV5SourcePins, seal(changed_pins, &entries));
    changed_pins.counts[@intFromEnum(Family.program_extension_request) - 1] = 1;
    const extension_entries = entries ++ [_]Entry{.{ .family = .program_extension_request, .index = 1, .instance_id = @splat(41), .roots = .{ @splat(42), @splat(0) } }};
    const extended = try seal(changed_pins, &extension_entries);
    try std.testing.expect(!std.meta.eql(sealed.digest, extended.digest));
    var duplicate = extension_entries;
    duplicate[duplicate.len - 1].index = 2;
    try std.testing.expectError(error.InvalidBlockV5FirstRoundOrder, seal(changed_pins, &duplicate));
    try std.testing.expectError(error.MissingBlockV5FinalRwRoot, sealed.requireComplete(pins, &entries));
    changed_pins = pins;
    changed_pins.expected_final_rw_root = @splat(43);
    try std.testing.expectError(error.MissingBlockV5RwEndpointPlan, changed_pins.validateComplete());
    changed_pins.rw_endpoint_plan_digest = @splat(46);
    try std.testing.expectError(error.MissingBlockV5RegisterEndpointPlan, changed_pins.validateComplete());
    changed_pins.register_endpoint_plan_digest = @splat(50);
    const final_bound = try seal(changed_pins, &entries);
    try final_bound.requireComplete(changed_pins, &entries);
    try std.testing.expectEqualDeep(changed_pins.expected_final_rw_root, final_bound.expected_final_rw_root);
    try std.testing.expect(!std.meta.eql(sealed.digest, final_bound.digest));
    changed_pins = pins;
    changed_pins.counts[@intFromEnum(Family.execution_external_sidecar) - 1] = 1;
    const external_entries = entries ++ [_]Entry{.{ .family = .execution_external_sidecar, .index = 1, .instance_id = @splat(44), .roots = .{ @splat(45), @splat(0) } }};
    const external_bound = try seal(changed_pins, &external_entries);
    try std.testing.expect(!std.meta.eql(sealed.digest, external_bound.digest));
    var wrong_external = external_entries;
    wrong_external[wrong_external.len - 1].index = 2;
    try std.testing.expectError(error.InvalidBlockV5FirstRoundOrder, seal(changed_pins, &wrong_external));
    changed_pins = pins;
    changed_pins.counts[@intFromEnum(Family.precompile) - 1] = 1;
    const precompile_entries = entries ++ [_]Entry{.{ .family = .precompile, .index = 1, .instance_id = @splat(47), .roots = .{ @splat(48), @splat(49) } }};
    _ = try seal(changed_pins, &precompile_entries);
    var wrong_precompile = precompile_entries;
    wrong_precompile[wrong_precompile.len - 1].index = 2;
    try std.testing.expectError(error.InvalidBlockV5FirstRoundOrder, seal(changed_pins, &wrong_precompile));
    changed_pins.expected_final_rw_root = @splat(43);
    changed_pins.rw_endpoint_plan_digest = @splat(46);
    changed_pins.register_endpoint_plan_digest = @splat(50);
    try std.testing.expectError(error.IncompleteBlockV5PrecompileFamilies, changed_pins.validateComplete());
}
