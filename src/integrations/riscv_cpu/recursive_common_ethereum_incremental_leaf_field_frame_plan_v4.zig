//! Immutable schema-4 frame projection from the shared native emitter.
//! Construction checks exact recorded payloads. It does not admit a native
//! profile, authenticate the execution chain, or establish any AIR endpoint:
//! those remain explicit caller prerequisites and routing obligations.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const frames = @import("ethereum_incremental_field_transcript_v4.zig");
const raw = frontend.recursion.segment_statement_v2_transcript_layout;
const claim = frontend.recursion.vm_public_claim;
const recording = frontend.recursion.recording_poseidon_channel_v4;
const publication = frontend.recursion.ethereum_publication_routing_v1;
const span = frontend.recursion.span_statement.canonical_layout;
const Sha256 = std.crypto.hash.sha2.Sha256;
pub const SCHEMA_VERSION: u32 = 2;
pub const OperationRange = struct { first: u32, count: u32 };
pub const Ranges = struct { pre_tree0: OperationRange, post_tree1: OperationRange };
pub const Descriptor = struct {
    operation_index: u32,
    phase: frames.Phase,
    kind: frames.Kind,
    ordinal: u32,
    encoding: std.meta.Tag(frames.Payload),
    payload_word_first: u32,
    payload_word_count: u32,
};
pub const Encoding = enum { canonical_m31, u16 };
pub const Endpoint = union(enum) {
    statement_word: struct { scope: u32, index: u32 },
    claim_word: u32,
    /// Existing canonical raw publication namespace1114, not a new producer.
    raw_publication: u32,
};
pub const Projection = union(enum) {
    same_value,
    /// Must constrain low + 65536*high = the existing M31 source, with u16
    /// bounds, high<32768, and rejection of the M31 modulus alias.
    canonical_m31_limb: u1,
};
pub const Source = struct {
    endpoint: Endpoint,
    encoding: Encoding,
    projection: Projection = .same_value,
    /// Additional equality to admitted frame geometry. The source endpoint
    /// remains mandatory; this must not become a replacement constant route.
    geometry_expected: ?u16 = null,
};
pub const Geometry = struct {
    expected: u32,
    raw_count: ?struct { section: raw.Section, limb: u1 } = null,
};
pub const Word = union(enum) {
    fixed_protocol: u32,
    admitted_geometry: Geometry,
    /// Available source mapping only. The plan does not establish closure.
    existing_source: Source,
    /// No source endpoint is claimed for these digest, retained snapshot, or
    /// native completion fields. They must never fall back to constants.
    unresolved_v2: raw.Data,
};

pub const OwnedPlan = opaque {
    /// `profile`, `native`, role public data, raw geometry, recording, and
    /// context ranges must already belong to the caller's admitted owners.
    /// Descriptors retain no pointers into any of them. No per-frame replay.
    pub fn initFromAdmitted(allocator: std.mem.Allocator, profile: anytype, native: anytype, role_public: anytype, raw_layout: raw.Layout, execution: *const recording.ExecutionV4, ranges: Ranges) !*OwnedPlan {
        return initFromAdmittedWithClaimShape(allocator, profile, native, role_public, raw_layout, execution, ranges, try claim.defaultShape());
    }

    /// Shape is supplied by the admitted recursive job, not inferred from
    /// this proof's actual (possibly empty) I/O vectors.
    pub fn initFromAdmittedWithClaimShape(allocator: std.mem.Allocator, profile: anytype, native: anytype, role_public: anytype, raw_layout: raw.Layout, execution: *const recording.ExecutionV4, ranges: Ranges, claim_shape: claim.Shape) !*OwnedPlan {
        if (!std.meta.eql(raw_layout, try raw.Layout.init(raw_layout.counts)) or !std.meta.eql(claim_shape, try claim.Shape.init(claim_shape.max_input_words, claim_shape.max_output_words))) return error.InvalidEthereumFramePlan;
        try validateRanges(execution.operations.len, ranges);
        var sink = Collector.init(allocator, raw_layout, execution, ranges);
        sink.claim_shape = claim_shape;
        defer sink.deinit();
        try frames.emitPreTree0(profile, native, role_public, &sink);
        try sink.finishPhase(.pre_tree0);
        try frames.emitPostTree1(profile, native, &sink);
        try sink.finishPhase(.post_tree1);
        return sink.own();
    }

    pub fn deinit(self: *OwnedPlan) void {
        const storage = mutable(self);
        const allocator = storage.allocator;
        allocator.free(storage.descriptors);
        allocator.free(storage.words);
        allocator.destroy(storage);
    }
    pub fn descriptors(self: *const OwnedPlan) []const Descriptor {
        return immutable(self).descriptors;
    }
    pub fn words(self: *const OwnedPlan) []const Word {
        return immutable(self).words;
    }
    pub fn wordsFor(self: *const OwnedPlan, frame_index: usize) ![]const Word {
        const storage = immutable(self);
        if (frame_index >= storage.descriptors.len) return error.InvalidEthereumFramePlan;
        const descriptor = storage.descriptors[frame_index];
        return storage.words[descriptor.payload_word_first..][0..descriptor.payload_word_count];
    }
    pub fn shapeIdentity(self: *const OwnedPlan) [32]u8 {
        return immutable(self).shape_identity;
    }
    pub fn custodyIdentity(self: *const OwnedPlan) [32]u8 {
        return immutable(self).custody_identity;
    }
    pub fn unresolvedWordCount(self: *const OwnedPlan) usize {
        var count: usize = 0;
        for (self.words()) |word| count += @intFromBool(word == .unresolved_v2);
        return count;
    }
    const Storage = struct {
        allocator: std.mem.Allocator,
        descriptors: []const Descriptor,
        words: []const Word,
        shape_identity: [32]u8,
        custody_identity: [32]u8,
    };
    fn mutable(self: *OwnedPlan) *Storage {
        return @ptrCast(@alignCast(self));
    }
    fn immutable(self: *const OwnedPlan) *const Storage {
        return @ptrCast(@alignCast(self));
    }
};

const Collector = struct {
    allocator: std.mem.Allocator,
    raw_layout: raw.Layout,
    claim_shape: claim.Shape = claim.defaultShape() catch unreachable,
    execution: *const recording.ExecutionV4,
    ranges: Ranges,
    counts: [2]u32 = .{ 0, 0 },
    role_counts: ?[2]u32 = null,
    descriptors: std.ArrayList(Descriptor) = .empty,
    words: std.ArrayList(Word) = .empty,
    custody: Sha256 = Sha256.init(.{}),

    fn init(allocator: std.mem.Allocator, layout: raw.Layout, execution: *const recording.ExecutionV4, ranges: Ranges) Collector {
        var result = Collector{ .allocator = allocator, .raw_layout = layout, .execution = execution, .ranges = ranges };
        result.custody.update("stwo-zig/ethereum-field-frame-custody/v2\x00");
        return result;
    }
    fn deinit(self: *Collector) void {
        self.descriptors.deinit(self.allocator);
        self.words.deinit(self.allocator);
    }
    fn range(self: *const Collector, phase: frames.Phase) OperationRange {
        return switch (phase) {
            .pre_tree0 => self.ranges.pre_tree0,
            .post_tree1 => self.ranges.post_tree1,
        };
    }
    pub fn frame(self: *Collector, value: frames.Frame) !void {
        const phase_index = @intFromEnum(value.phase);
        const phase_range = self.range(value.phase);
        if (self.counts[phase_index] >= phase_range.count) return error.InvalidEthereumFramePlan;
        const operation_index = try std.math.add(u32, phase_range.first, self.counts[phase_index]);
        try value.validateRecordedOperation(self.execution, operation_index);
        const count = std.math.cast(u32, try value.recordedWordCount()) orelse return error.InvalidEthereumFramePlan;
        const descriptor = Descriptor{
            .operation_index = operation_index,
            .phase = value.phase,
            .kind = value.kind,
            .ordinal = value.ordinal,
            .encoding = std.meta.activeTag(value.payload),
            .payload_word_first = std.math.cast(u32, self.words.items.len) orelse return error.InvalidEthereumFramePlan,
            .payload_word_count = count,
        };
        try validateFrameShapeWithClaimShape(value, self.raw_layout, self.claim_shape);
        if (value.kind == .role_io_header) {
            if (self.role_counts != null) return error.InvalidEthereumFramePlan;
            self.role_counts = .{ value.payload.u32_words[2], value.payload.u32_words[6] };
        }
        hashValue(&self.custody, descriptor);
        for (0..count) |index| {
            const word = (try value.recordedWord(index)).toU32();
            const classified = try classify(value, index, word, self.raw_layout, self.claim_shape);
            if (classified == .existing_source and classified.existing_source.encoding == .u16 and word > 0xffff)
                return error.InvalidEthereumFrameSourceEncoding;
            try self.words.append(self.allocator, classified);
            hashValue(&self.custody, word);
        }
        try self.descriptors.append(self.allocator, descriptor);
        self.counts[phase_index] += 1;
    }
    fn finishPhase(self: *Collector, phase: frames.Phase) !void {
        if (self.counts[@intFromEnum(phase)] != self.range(phase).count) return error.InvalidEthereumFramePlan;
        if (phase != .pre_tree0) return;
        var header: ?Descriptor = null;
        var input_count: ?u32 = null;
        var output_count: u32 = 0;
        for (self.descriptors.items) |descriptor| switch (descriptor.kind) {
            .role_io_header => header = descriptor,
            .role_input_words => {
                if (input_count != null) return error.InvalidEthereumFramePlan;
                input_count = descriptor.payload_word_count / 2;
            },
            .role_output_word => {
                if (descriptor.ordinal != output_count) return error.InvalidEthereumFramePlan;
                output_count = try std.math.add(u32, output_count, 1);
            },
            else => {},
        };
        const expected = [2]u32{ input_count orelse return error.InvalidEthereumFramePlan, output_count };
        if (!std.meta.eql(self.role_counts orelse return error.InvalidEthereumFramePlan, expected))
            return error.InvalidEthereumFrameCountBinding;
        const first = (header orelse return error.InvalidEthereumFramePlan).payload_word_first;
        for (expected, [_]usize{ 4, 12 }) |count, offset| for (0..2) |limb| {
            const word = &self.words.items[first + offset + limb];
            if (word.* != .existing_source) return error.InvalidEthereumFramePlan;
            word.existing_source.geometry_expected = @intCast((count >> @as(u5, @intCast(16 * limb))) & 0xffff);
        };
    }
    fn own(self: *Collector) !*OwnedPlan {
        var shape = Sha256.init(.{});
        shape.update("stwo-zig/ethereum-field-frame-shape/v2\x00");
        hashValue(&shape, SCHEMA_VERSION);
        hashValue(&shape, frames.SCHEMA_VERSION);
        hashValue(&shape, self.raw_layout.counts);
        if (!std.meta.eql(self.claim_shape, try claim.defaultShape())) {
            shape.update("explicit-claim-shape/v1\x00");
            hashValue(&shape, self.claim_shape.max_input_words);
            hashValue(&shape, self.claim_shape.max_output_words);
        }
        for (self.descriptors.items) |descriptor| hashValue(&shape, descriptor);
        for (self.words.items) |word| hashValue(&shape, word);
        const shape_identity = shape.finalResult();
        self.custody.update(&shape_identity);
        const owned_descriptors = try self.descriptors.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(owned_descriptors);
        const owned_words = try self.words.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(owned_words);
        const storage = try self.allocator.create(OwnedPlan.Storage);
        storage.* = .{ .allocator = self.allocator, .descriptors = owned_descriptors, .words = owned_words, .shape_identity = shape_identity, .custody_identity = self.custody.finalResult() };
        return @ptrCast(storage);
    }
};

fn validateRanges(operation_count: usize, ranges: Ranges) !void {
    const pre_end = try std.math.add(usize, ranges.pre_tree0.first, ranges.pre_tree0.count);
    const post_end = try std.math.add(usize, ranges.post_tree1.first, ranges.post_tree1.count);
    if (ranges.pre_tree0.count == 0 or ranges.post_tree1.count == 0 or pre_end > ranges.post_tree1.first or post_end > operation_count)
        return error.InvalidEthereumFramePlan;
}

fn validateFrameShape(frame: frames.Frame, layout: raw.Layout) !void {
    return validateFrameShapeWithClaimShape(frame, layout, try claim.defaultShape());
}
fn validateFrameShapeWithClaimShape(frame: frames.Frame, layout: raw.Layout, shape: claim.Shape) !void {
    // These mappings address split-u32 source limbs. A different encoding can
    // have the same payload length but must never acquire those source labels.
    switch (frame.kind) {
        .native_statement_header, .native_wire_id, .coordinate, .role_io_header, .role_input_words, .role_output_word, .completion => if (frame.payload != .u32_words) return error.InvalidEthereumFramePlan,
        else => {},
    }
    const count = try frame.recordedWordCount();
    switch (frame.kind) {
        .native_statement_header => if (count != 8 or (try frame.recordedWord(6)).toU32() + ((try frame.recordedWord(7)).toU32() << 16) != layout.wordCount()) return error.InvalidEthereumFramePlan,
        .native_wire_id => if (count != 16) return error.InvalidEthereumFramePlan,
        .native_statement_words => if (count != layout.wordCount() or frame.payload != .canonical_m31) return error.InvalidEthereumFramePlan,
        .coordinate, .completion => if (count != 8) return error.InvalidEthereumFramePlan,
        .role_io_header => if (count != 14) return error.InvalidEthereumFramePlan,
        .role_input_words => if (count % 2 != 0 or count / 2 > shape.max_input_words) return error.InvalidEthereumFramePlan,
        .role_output_word => if (count != 6 or frame.ordinal >= shape.max_output_words) return error.InvalidEthereumFramePlan,
        .pcs, .authority_header, .base_geometry, .lookup_activation, .protocol, .ethereum_geometry, .bridge_geometry, .canonical_main_claim, .shard_manifest, .fixed_program => {},
    }
}

fn classify(frame: frames.Frame, index: usize, value: u32, layout: raw.Layout, shape: claim.Shape) !Word {
    return switch (frame.kind) {
        .pcs, .authority_header, .protocol => .{ .fixed_protocol = value },
        .base_geometry, .lookup_activation, .ethereum_geometry, .bridge_geometry, .canonical_main_claim, .shard_manifest, .fixed_program => .{ .admitted_geometry = .{ .expected = value } },
        .native_statement_header => if (index < 6) .{ .fixed_protocol = value } else .{ .admitted_geometry = .{ .expected = value } },
        .native_wire_id => source(.{ .raw_publication = publication.rawIndex(.wire_id, @intCast(index)) orelse return error.InvalidEthereumFramePlan }, .u16, .same_value),
        .native_statement_words => switch (try layout.word(index)) {
            .fixed => |expected| if (expected == value) .{ .fixed_protocol = expected } else return error.InvalidEthereumFramePlan,
            .geometry => |geometry| if (geometry.value == value) .{ .admitted_geometry = .{ .expected = geometry.value, .raw_count = .{ .section = geometry.section, .limb = geometry.limb } } } else return error.InvalidEthereumFramePlan,
            .data => |data| switch (data) {
                .span_word => |word| statement(word, .canonical_m31, .same_value),
                .register_clock => |coordinate| source(.{ .statement_word = .{ .scope = frontend.recursion.ethereum_clock_routing_v1.STATEMENT_SCOPE, .index = @as(u32, @intFromEnum(coordinate.side)) * 64 + @as(u32, coordinate.register) * 2 + coordinate.limb } }, .u16, .same_value),
                .continuation_root => |coordinate| nativeRoot(coordinate.side, coordinate.limb),
                .digest, .completion, .retained => .{ .unresolved_v2 = data },
            },
        },
        .coordinate => switch (index / 2) {
            0 => statement(@intCast(span.first_segment_start + index % 2), .u16, .same_value),
            1 => statement(@intCast(span.job_segment_count_start + index % 2), .u16, .same_value),
            2 => nativeRoot(.entry, @intCast(index % 2)),
            3 => nativeRoot(.exit, @intCast(index % 2)),
            else => return error.InvalidEthereumFramePlan,
        },
        .role_io_header => blk: {
            const starts = [_]usize{ claim.canonical_layout.input_start_start, claim.canonical_layout.input_length_start, claim.canonical_layout.input_word_count_start, claim.canonical_layout.output_length_address_start, claim.canonical_layout.output_data_address_start, claim.canonical_layout.output_length_start, claim.canonical_layout.outputWordCountStart(shape) };
            if (index / 2 >= starts.len) return error.InvalidEthereumFramePlan;
            break :blk source(.{ .claim_word = @intCast(starts[index / 2] + index % 2) }, .u16, .same_value);
        },
        .role_input_words => source(.{ .claim_word = @intCast(claim.canonical_layout.inputSlotPresent(index / 2) + 1 + index % 2) }, .u16, .same_value),
        .role_output_word => source(.{ .claim_word = @intCast(claim.canonical_layout.outputSlotPresent(shape, frame.ordinal) + 1 + index) }, .u16, .same_value),
        .completion => source(.{ .raw_publication = publication.rawIndex(.completion, @intCast(index)) orelse return error.InvalidEthereumFramePlan }, .u16, .same_value),
    };
}
fn nativeRoot(side: raw.Side, limb: u1) Word {
    return source(.{ .statement_word = .{ .scope = frontend.recursion.air.vm_statement_roots.NATIVE_CONTINUATION_SCOPE, .index = @intFromEnum(side) } }, .u16, .{ .canonical_m31_limb = limb });
}

test "Ethereum initial admitted shape routes canonical frame header and output slots" {
    const shape = try claim.Shape.init(675173, 12);
    const layout = try raw.Layout.init(.{ 0, 0, 0, 0 });
    const header = frames.Frame{ .phase = .pre_tree0, .kind = .role_io_header, .ordinal = 0, .payload = .{ .u32_words = &.{ 0, 0, 675173, 0, 0, 0, 0 } } };
    try validateFrameShapeWithClaimShape(header, layout, shape);
    for (0..2) |limb| {
        const routed = try classify(header, 12 + limb, 0, layout, shape);
        try std.testing.expectEqual(@as(u32, @intCast(claim.canonical_layout.outputWordCountStart(shape) + limb)), routed.existing_source.endpoint.claim_word);
        const legacy = try classify(header, 12 + limb, 0, layout, try claim.defaultShape());
        try std.testing.expect(!std.meta.eql(routed, legacy));
    }
    const output = frames.Frame{ .phase = .pre_tree0, .kind = .role_output_word, .ordinal = 11, .payload = .{ .u32_words = &.{ 0, 0, 0 } } };
    try validateFrameShapeWithClaimShape(output, layout, shape);
    for (0..6) |limb| {
        const routed = try classify(output, limb, 0, layout, shape);
        try std.testing.expectEqual(@as(u32, @intCast(claim.canonical_layout.outputSlotPresent(shape, 11) + 1 + limb)), routed.existing_source.endpoint.claim_word);
    }
    var invalid = output;
    invalid.ordinal = 12;
    try std.testing.expectError(error.InvalidEthereumFramePlan, validateFrameShapeWithClaimShape(invalid, layout, shape));
}
fn source(endpoint: Endpoint, encoding: Encoding, projection: Projection) Word {
    return .{ .existing_source = .{ .endpoint = endpoint, .encoding = encoding, .projection = projection } };
}
fn statement(index: u32, encoding: Encoding, projection: Projection) Word {
    return source(.{ .statement_word = .{ .scope = 0, .index = index } }, encoding, projection);
}
fn hashValue(hash: *Sha256, value: anytype) void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .int => {
            var bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &bytes, @intCast(value), .little);
            hash.update(&bytes);
        },
        .@"enum" => hashValue(hash, @as(u32, @intCast(@intFromEnum(value)))),
        .@"union" => {
            hashValue(hash, std.meta.activeTag(value));
            switch (value) {
                inline else => |payload| hashValue(hash, payload),
            }
        },
        .@"struct" => inline for (std.meta.fields(T)) |field| hashValue(hash, @field(value, field.name)),
        .array => for (value) |item| hashValue(hash, item),
        .optional => {
            hashValue(hash, @as(u8, @intFromBool(value != null)));
            if (value) |payload| hashValue(hash, payload);
        },
        .void => {},
        else => @compileError("unsupported frame-plan identity value"),
    }
}

// These projection fixtures exercise the real shared emitters and recording
// channel, not native profile admission or a recursive proof.
const TestGeometry = struct {
    value: u32 = 7,
    pub fn mixInto(self: @This(), channel: anytype) void {
        channel.mixU32s(&.{self.value});
    }
    pub fn mixIntoV2(self: @This(), _: anytype, channel: anytype) !void {
        self.mixInto(channel);
    }
    pub fn mixIntoV2WithCircuitProfileV1(self: @This(), _: anytype, channel: anytype, _: frontend.prover_mod.ethereum_circuit_profile_v1.CircuitProfileV1) !void {
        self.mixInto(channel);
    }
    pub fn mixFieldAuthority(self: @This(), channel: anytype) void {
        self.mixInto(channel);
    }
    pub fn canonicalMainClaim(self: @This()) @This() {
        return self;
    }
    pub fn mixShardManifest(self: @This(), channel: anytype) void {
        self.mixInto(channel);
    }
};
const TestPcs = struct {
    pow_bits: u32 = 0,
    log_blowup_factor: u32 = 4,
    query_count: u32 = 193,
    fold_step: u32 = 1,
    log_last_layer_degree_bound: u32 = 0,
    lifting_mode: u32 = 1,
    configured_security_bits: u32 = 96,
    identity_sha256: [32]u8 = .{3} ** 32,
    pub fn config(_: @This()) !TestGeometry {
        return .{};
    }
};
const TestProfile = struct {
    pub fn circuitProfile(self: @This()) frontend.prover_mod.ethereum_circuit_profile_v1.CircuitProfileV1 {
        return if (self.schema_version == 5) .fixed_program_narrow_v1 else .legacy_v4;
    }
    schema_version: u16 = frames.SCHEMA_VERSION,
    fixed_program: ?frontend.air.program.fixed_table_v1.DescriptorV1 = null,
    format_version: u16 = 4,
    statement_family: enum(u32) { full_state = 2 } = .full_state,
    boundary_policy: enum(u32) { full_state = 2 } = .full_state,
    coordinate: struct { segment_index: u32 = 0, segment_count: u32 = 2 } = .{},
    continuation_roots: struct { entry: u32 = 11, exit: u32 = 13 } = .{},
    base_geometry: struct {
        component_count: u32 = 35,
        infrastructure_count: u32 = 2,
        maximum_column_log_size: u32 = 4,
        compatibility_tree_columns: [4]u32 = .{ 1, 2, 3, 4 },
        physical_tree_columns: [4]u32 = .{ 1, 2, 3, 4 },
        lookup_activation: TestGeometry = .{},
    } = .{},
    protocol: struct {
        pcs: TestPcs = .{},
        profile_words: [2]u32 = .{ 5, 7 },
        protocol_id: [8]u32 = .{11} ** 8,
        proof_security_identity_sha256: [32]u8 = .{1} ** 32,
        identity_sha256: [32]u8 = .{2} ** 32,
    } = .{},
    ethereum: TestGeometry = .{},
    bridge_geometry: TestGeometry = .{},
};
const TestNative = struct {
    public_data: struct {
        values: []const core.fields.m31.M31,
        pub fn words(self: @This()) []const core.fields.m31.M31 {
            return self.values;
        }
        pub fn wireId(self: @This()) [8]u32 {
            return frontend.recursion.poseidon2_channel.hashCanonicalWords(self.values, frontend.recursion.segment_statement_v2.WIRE_ID_DOMAIN);
        }
    },
    core: TestGeometry = .{},
};
const TestRecording = struct {
    execution: recording.ExecutionV4,
    ranges: Ranges,
    fn init(profile: *const TestProfile, native: *const TestNative, role_public: anytype) !TestRecording {
        var channel = recording.Channel.init(std.testing.allocator);
        defer channel.deinit();
        channel.setContextTag(1);
        var sink = frames.NativeSink(recording.Channel){ .channel = &channel };
        try frames.emitPreTree0(profile, native, role_public, &sink);
        const pre_count: u32 = @intCast(channel.operations.items.len);
        channel.setContextTag(2);
        try frames.emitPostTree1(profile, native, &sink);
        const post_count: u32 = @intCast(channel.operations.items.len - pre_count);
        return .{ .execution = try channel.finish(), .ranges = .{ .pre_tree0 = .{ .first = 0, .count = pre_count }, .post_tree1 = .{ .first = pre_count, .count = post_count } } };
    }
};

fn testWire(layout: raw.Layout, words: []core.fields.m31.M31) !void {
    if (words.len != layout.wordCount()) return error.InvalidEthereumFramePlan;
    for (words, 0..) |*word, index| word.* = core.fields.m31.M31.fromCanonical(switch (try layout.word(index)) {
        .fixed => |value| value,
        .geometry => |geometry| geometry.value,
        .data => 17,
    });
}
fn testRole(inputs: []const u32, outputs: []const frontend.air.public_data.OutputWord) frontend.air.public_data.PublicData {
    var result: frontend.air.public_data.PublicData = undefined;
    result.io_entries = .{ .input_start = 0x1000, .input_len = @intCast(inputs.len * 4), .input_words = inputs, .output_len_addr = 0x2000, .output_data_addr = 0x2004, .output_len = 0, .output_words = outputs };
    result.completion = .{ .kind = .unretired_program_fetch, .address = 0x3000, .value = 0x6f, .clock = 0 };
    return result;
}

test "Ethereum schema4 frame plan separates dynamic custody from admitted shape" {
    const layout = try raw.Layout.init(.{ 1, 0, 0, 0 });
    const wire = try std.testing.allocator.alloc(core.fields.m31.M31, layout.wordCount());
    defer std.testing.allocator.free(wire);
    try testWire(layout, wire);
    const native = TestNative{ .public_data = .{ .values = wire } };
    var profile = TestProfile{};
    var inputs = [_]u32{0x1234abcd};
    const outputs = [_]frontend.air.public_data.OutputWord{.{ .addr = 0x2000, .value = 3, .clock = 7 }};
    var role_public = testRole(&inputs, &outputs);
    var first_recording = try TestRecording.init(&profile, &native, &role_public);
    defer first_recording.execution.deinit();
    const first = try OwnedPlan.initFromAdmitted(std.testing.allocator, &profile, &native, &role_public, layout, &first_recording.execution, first_recording.ranges);
    defer first.deinit();
    // Every raw digest and native completion stays unresolved, even when a
    // native recording supplies it. Retained data adds four obligations here.
    try std.testing.expectEqual(@as(usize, 88 + 8 + 4), first.unresolvedWordCount());
    wire[60] = wire[60].add(core.fields.m31.M31.one());
    inputs[0] ^= 1;
    profile.coordinate.segment_index = 1;
    role_public.completion.?.address += 4;
    var changed_recording = try TestRecording.init(&profile, &native, &role_public);
    defer changed_recording.execution.deinit();
    const changed = try OwnedPlan.initFromAdmitted(std.testing.allocator, &profile, &native, &role_public, layout, &changed_recording.execution, changed_recording.ranges);
    defer changed.deinit();
    try std.testing.expectEqualDeep(first.shapeIdentity(), changed.shapeIdentity());
    try std.testing.expect(!std.meta.eql(first.custodyIdentity(), changed.custodyIdentity()));
    try std.testing.expectEqualDeep(first.descriptors(), changed.descriptors());
    try std.testing.expectEqualDeep(first.words(), changed.words());
    try std.testing.expectError(error.EthereumFieldTranscriptPayloadMismatch, OwnedPlan.initFromAdmitted(std.testing.allocator, &profile, &native, &role_public, layout, &first_recording.execution, first_recording.ranges));
    profile.base_geometry.physical_tree_columns[0] += 1;
    var fixed_recording = try TestRecording.init(&profile, &native, &role_public);
    defer fixed_recording.execution.deinit();
    const fixed = try OwnedPlan.initFromAdmitted(std.testing.allocator, &profile, &native, &role_public, layout, &fixed_recording.execution, fixed_recording.ranges);
    defer fixed.deinit();
    try std.testing.expect(!std.meta.eql(first.shapeIdentity(), fixed.shapeIdentity()));
    var short_range = fixed_recording.ranges;
    short_range.post_tree1.count -= 1;
    try std.testing.expectError(error.InvalidEthereumFramePlan, OwnedPlan.initFromAdmitted(std.testing.allocator, &profile, &native, &role_public, layout, &fixed_recording.execution, short_range));
}

test "Ethereum schema4 frame plan records exact claim and split-root obligations" {
    const layout = try raw.Layout.init(.{ 0, 0, 0, 0 });
    const M31 = core.fields.m31.M31;
    var wire: [frontend.recursion.segment_statement_v2.MIN_CANONICAL_WORDS]M31 = undefined;
    try testWire(layout, &wire);
    const native = TestNative{ .public_data = .{ .values = &wire } };
    const profile = TestProfile{};
    const inputs = [_]u32{1};
    const outputs = [_]frontend.air.public_data.OutputWord{.{ .addr = 2, .value = 3, .clock = 4 }};
    const role_public = testRole(&inputs, &outputs);
    var captured = try TestRecording.init(&profile, &native, &role_public);
    defer captured.execution.deinit();
    const plan = try OwnedPlan.initFromAdmitted(std.testing.allocator, &profile, &native, &role_public, layout, &captured.execution, captured.ranges);
    defer plan.deinit();
    // Regression from the genuine closure: routing both pre/post groups to
    // bind_statement consumed it twice and left protocol/public_claim unused.
    var control_runs = [_]usize{0} ** 4;
    var prior: ?frames.VerifierBinding = null;
    for (plan.descriptors()) |descriptor| {
        const selected = frames.verifierBinding(descriptor.phase, descriptor.kind);
        if (prior != selected) control_runs[@intFromEnum(selected)] += 1;
        prior = selected;
    }
    try std.testing.expectEqual([_]usize{ 1, 1, 1, 1 }, control_runs);
    var checked: usize = 0;
    for (plan.descriptors(), 0..) |descriptor, frame_index| {
        const words = try plan.wordsFor(frame_index);
        try std.testing.expectEqual(@as(usize, descriptor.payload_word_count), words.len);
        switch (descriptor.kind) {
            .coordinate => {
                try std.testing.expectEqualDeep(statement(216, .u16, .same_value), words[0]);
                try std.testing.expectEqualDeep(statement(205, .u16, .same_value), words[2]);
                try std.testing.expectEqualDeep(nativeRoot(.entry, 1), words[5]);
                try std.testing.expectEqualDeep(nativeRoot(.exit, 0), words[6]);
                checked += 1;
            },
            .role_io_header => {
                const starts = [_]u32{ 241, 243, 254, 245, 247, 249, 3329 };
                for (starts, 0..) |start, field| for (0..2) |limb| {
                    var expected = source(.{ .claim_word = start + @as(u32, @intCast(limb)) }, .u16, .same_value);
                    if (field == 2 or field == 6) expected.existing_source.geometry_expected = if (limb == 0) 1 else 0;
                    try std.testing.expectEqualDeep(expected, words[2 * field + limb]);
                };
                checked += 1;
            },
            .role_input_words => {
                try std.testing.expectEqualDeep(source(.{ .claim_word = 257 }, .u16, .same_value), words[0]);
                try std.testing.expectEqualDeep(source(.{ .claim_word = 258 }, .u16, .same_value), words[1]);
                checked += 1;
            },
            .role_output_word => {
                for (words, 0..) |word, index| try std.testing.expectEqualDeep(source(.{ .claim_word = 3332 + @as(u32, @intCast(index)) }, .u16, .same_value), word);
                checked += 1;
            },
            .completion => {
                const indices = [_]u32{ 82, 83, 84, 86, 88, 90, 92, 94 };
                for (words, indices) |word, index| try std.testing.expectEqualDeep(source(.{ .raw_publication = index }, .u16, .same_value), word);
                checked += 1;
            },
            else => {},
        }
    }
    try std.testing.expectEqual(@as(usize, 5), checked);
    try std.testing.expectError(error.InvalidEthereumFramePlan, plan.wordsFor(plan.descriptors().len));
    // Equal lengths do not make canonical M31 or secure payloads split-u32
    // encodings. This gate must reject them before assigning source endpoints.
    const malformed_words = [_]M31{M31.zero()} ** 16;
    inline for (.{
        .{ frames.Kind.native_wire_id, 16 },  .{ frames.Kind.coordinate, 8 },
        .{ frames.Kind.role_io_header, 14 },  .{ frames.Kind.role_input_words, 2 },
        .{ frames.Kind.role_output_word, 6 }, .{ frames.Kind.completion, 8 },
    }) |item| {
        const malformed = frames.Frame{ .phase = .pre_tree0, .kind = item[0], .ordinal = 0, .payload = .{ .canonical_m31 = malformed_words[0..item[1]] } };
        try std.testing.expectError(error.InvalidEthereumFramePlan, validateFrameShape(malformed, layout));
    }
    const malformed_secure = frames.Frame{ .phase = .pre_tree0, .kind = .coordinate, .ordinal = 0, .payload = .{ .secure_words = &.{ core.fields.qm31.QM31.zero(), core.fields.qm31.QM31.zero() } } };
    try std.testing.expectError(error.InvalidEthereumFramePlan, validateFrameShape(malformed_secure, layout));
    // Matching source coordinates alone cannot authorize a header count that
    // disagrees with the admitted number of payload words or output frames.
    var collector = Collector.init(std.testing.allocator, layout, &captured.execution, captured.ranges);
    defer collector.deinit();
    try frames.emitPreTree0(&profile, &native, &role_public, &collector);
    collector.role_counts.?[0] += 1;
    try std.testing.expectError(error.InvalidEthereumFrameCountBinding, collector.finishPhase(.pre_tree0));
    collector.role_counts.?[0] -= 1;
    collector.role_counts.?[1] += 1;
    try std.testing.expectError(error.InvalidEthereumFrameCountBinding, collector.finishPhase(.pre_tree0));
    // Raw clock words have an existing u16 source obligation. A canonical-M31
    // recording alone cannot authorize a value outside that source encoding.
    wire[516] = M31.fromCanonical(65536);
    var wide_recording = try TestRecording.init(&profile, &native, &role_public);
    defer wide_recording.execution.deinit();
    try std.testing.expectError(error.InvalidEthereumFrameSourceEncoding, OwnedPlan.initFromAdmitted(std.testing.allocator, &profile, &native, &role_public, layout, &wide_recording.execution, wide_recording.ranges));
}

test "Ethereum schema4 frame routes preserve source joins and reject changed witnesses" {
    const routing_rows = @import("recursive_common_ethereum_incremental_leaf_field_frame_routing_v4.zig");
    const program_support = @import("recursive_common_ethereum_incremental_leaf_transcript_program_v4_support.zig");
    const Air = frontend.recursion.air.ethereum_publication_control_v1;
    const Payload = frontend.recursion.air.ethereum_transcript_payload_raw_v1;
    const Clocks = frontend.recursion.air.transcript_payload_clocks_v2;
    const interactions = frontend.recursion.air.relation_interaction;
    const allocator = std.testing.allocator;
    const layout = try raw.Layout.init(.{ 0, 0, 0, 0 });
    var wire: [frontend.recursion.segment_statement_v2.MIN_CANONICAL_WORDS]core.fields.m31.M31 = undefined;
    try testWire(layout, &wire);
    const native = TestNative{ .public_data = .{ .values = &wire } };
    const profile = TestProfile{};
    const inputs = [_]u32{0x87654321};
    const outputs = [_]frontend.air.public_data.OutputWord{.{ .addr = 2, .value = 3, .clock = 4 }};
    const role_public = testRole(&inputs, &outputs);
    var captured = try TestRecording.init(&profile, &native, &role_public);
    defer captured.execution.deinit();
    const plan = try OwnedPlan.initFromAdmitted(allocator, &profile, &native, &role_public, layout, &captured.execution, captured.ranges);
    defer plan.deinit();
    const rows = try allocator.alloc(Air.Relation.Row, routing_rows.rowCount(plan));
    defer allocator.free(rows);
    try routing_rows.write(plan, &captured.execution, rows);
    try std.testing.expectEqual(@as(usize, 28), rows.len); // coordinate6, header14, input2, output6.
    try std.testing.expectEqual(@as(u32, 1), routing_rows.claimUses(plan, 257));
    try std.testing.expectEqual(@as(u32, 1), routing_rows.statementUses(plan, frontend.recursion.air.vm_statement_roots.NATIVE_CONTINUATION_SCOPE, 0));
    var payload_rows: std.ArrayList(Payload.Relation.Row) = .empty;
    defer payload_rows.deinit(allocator);
    for (plan.descriptors(), 0..) |descriptor, frame_index| {
        switch (descriptor.kind) {
            .coordinate, .role_io_header, .role_input_words, .role_output_word => {},
            else => continue,
        }
        const values = try frames.recordedOperationPayload(&captured.execution, descriptor.operation_index);
        for (values, 0..) |value, index| {
            const metadata = try program_support.fieldMetadata(plan, @intCast(frame_index), @intCast(index));
            const original = try Clocks.logicalRowForFieldFrame(.{
                .row_mask = 1,
                .segment_mask = 1,
                .binary_mask = 0,
                .verifier_id = 0,
                .sequence = descriptor.operation_index,
                .tag = 1,
                .args = .{0} ** 4,
                .payload_index = @intCast(index),
                .source_kind = @enumFromInt(@intFromEnum(metadata.source_kind)),
                .item_index = metadata.item_index,
                .limb_index = metadata.limb_index,
                .constant_mask = metadata.constant_mask,
                .constant_value = metadata.expected_constant orelse 0,
                .input_use_count = metadata.input_use_count,
                .source_hash_id = 0,
                .source_word_index = @intCast(index + recording.RATE),
            }, value);
            try payload_rows.append(allocator, Payload.logicalRow(original, false));
        }
    }
    var definition = try Air.build(allocator);
    defer definition.deinit();
    const relation = try Air.Relation.authenticate(&definition);
    var payload_definition = try Payload.build(allocator);
    defer payload_definition.deinit();
    const payload_relation = try Payload.Relation.authenticate(&payload_definition);
    const Domain = @FieldType(interactions.TupleContribution, "domain");
    const mask = (@as(u64, 1) << @intFromEnum(Domain.recursion_vm_public_claim_word)) |
        (@as(u64, 1) << @intFromEnum(Domain.recursion_statement_word));
    for (0..2) |mutation| {
        if (mutation != 0) payload_rows.items[0][1] = payload_rows.items[0][1].add(core.fields.m31.M31.one());
        var ledger = interactions.TupleLedger.init(allocator);
        defer ledger.deinit();
        try payload_relation.appendPreparedTupleContributions(&ledger, 5, payload_rows.items, mask);
        try relation.appendPreparedTupleContributions(&ledger, 17, rows, mask);
        // External canonical claim/statement providers are fixed independently
        // of the changed raw witness; their production fanout uses this plan.
        for (rows) |row| {
            const entries = relation.preparedEntries(row);
            for ([_]usize{ 1, 12 }) |event| {
                const entry = entries[event];
                try ledger.append(entry.domain, 12, @intCast(event), .emit, entry.numerator.neg(), entry.values[0..entry.arity]);
            }
        }
        try std.testing.expectEqual(mutation == 0, ledger.classify().isClosed());
    }
}
