//! Resident CUDA implementation of the circuit transcript prefix. The sink
//! uses the same Blake2s channel kernels as Cairo CUDA, with a circuit-only
//! order and field geometry. Roots, claims, nonce and challenges are device
//! slices; only the public salt and FRI configuration enter at ingress.
const std = @import("std");
const core = @import("stwo_core");
const cuda = @import("stwo_cuda_backend");
const common = cuda.runtime.stages.common;
const transcript = cuda.runtime.stages.transcript;

const PcsConfigV2 = core.pcs.config_v2.PcsConfigV2;

pub const pow_search_end: u64 = @as(u64, 0x7fff_ffff) << 20;

pub const Bindings = struct {
    state: common.Words,
    boundary_snapshot: common.Words,
    salt: common.Words,
    fri_config: common.Words,
    lookup: common.SecureFields,
    pow_prefix: common.Words,
    pow_best_nonce: common.Nonce,
    pow_completed_blocks: common.Words,
    pow_nonce_words: common.Words,

    pub fn validate(self: Bindings) !void {
        if (self.state.len != 16 or self.boundary_snapshot.len != 16 or
            self.salt.len != 4 or self.fri_config.len != 8 or
            self.lookup.len != 2 or self.pow_prefix.len != 8 or
            self.pow_best_nonce.len != 1 or self.pow_completed_blocks.len == 0 or
            self.pow_nonce_words.len != 2)
        {
            return error.InvalidCircuitTranscriptBindings;
        }
        const owner = self.state.owner;
        const generation = self.state.generation;
        inline for (.{ self.boundary_snapshot, self.salt, self.fri_config, self.pow_prefix, self.pow_completed_blocks, self.pow_nonce_words }) |view| {
            if (view.owner != owner or view.generation != generation)
                return error.InvalidCircuitTranscriptBindings;
        }
        if (self.lookup.owner != owner or self.lookup.generation != generation or
            self.pow_best_nonce.owner != owner or self.pow_best_nonce.generation != generation)
            return error.InvalidCircuitTranscriptBindings;
        const views = [_]Range{
            try range(self.state, 4),
            try range(self.boundary_snapshot, 4),
            try range(self.salt, 4),
            try range(self.fri_config, 4),
            try range(self.lookup, @sizeOf(cuda.abi.field.SecureField)),
            try range(self.pow_prefix, 4),
            try range(self.pow_best_nonce, 8),
            try range(self.pow_completed_blocks, 4),
            try range(self.pow_nonce_words, 4),
        };
        for (views, 0..) |left, index| {
            for (views[index + 1 ..]) |right| {
                if (left.start < right.end and right.start < left.end)
                    return error.InvalidCircuitTranscriptBindings;
            }
        }
    }
};

const Range = struct { start: usize, end: usize };

fn range(view: anytype, element_bytes: usize) !Range {
    const size = std.math.mul(usize, view.len, element_bytes) catch return error.InvalidCircuitTranscriptBindings;
    return .{
        .start = view.address,
        .end = std.math.add(usize, view.address, size) catch return error.InvalidCircuitTranscriptBindings,
    };
}

pub fn Sink(comptime Session: type, comptime Transcript: type, comptime Fri: type) type {
    return struct {
        session: *Session,
        bindings: Bindings,
        profile: enum { internal, root },
        chain_seed: u64,
        salt_value: u32 = 0,
        fri_value: ?PcsConfigV2 = null,
        salt_host: [4]u32 = .{ 0, 0, 0, 0 },
        fri_host: [8]u32 = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
        primed: bool = false,
        initialized: bool = false,
        next_step: u32 = 0,

        pub const Root = common.Words;
        pub const Felts = common.Words;
        /// A resident sink grinds the nonce itself; a caller cannot provide a
        /// host-selected candidate.
        pub const Nonce = void;
        pub const Lookup = common.SecureFields;

        const Self = @This();

        pub fn init(session: *Session, bindings: Bindings, profile: @FieldType(Self, "profile"), geometry_identity: [32]u8) !Self {
            try bindings.validate();
            if (std.mem.allEqual(u8, &geometry_identity, 0)) return error.InvalidCircuitTranscriptGeometry;
            return .{
                .session = session,
                .bindings = bindings,
                .profile = profile,
                .chain_seed = std.mem.readInt(u64, geometry_identity[0..8], .little),
            };
        }

        /// Must run during CUDA ingress, before entering `.trace_commit`.
        pub fn prime(self: *Self, salt: u32, config: PcsConfigV2) !void {
            if (self.primed or self.initialized) return error.CircuitTranscriptAlreadyPrimed;
            self.salt_value = salt;
            self.fri_value = config;
            self.salt_host = .{ core.fields.m31.M31.fromU64(salt).v, 0, 0, 0 };
            const fri = config.fri_config;
            self.fri_host = .{
                fri.pow_bits,  fri.log_blowup_factor, fri.n_queries, fri.log_last_layer_degree_bound,
                fri.fold_step, 0,                     0,             0,
            };
            try self.session.context.uploadSlice(u32, self.bindings.salt, &self.salt_host);
            try self.session.context.uploadSlice(u32, self.bindings.fri_config, &self.fri_host);
            self.primed = true;
        }

        pub fn initialize(self: *Self) !void {
            if (!self.primed or self.initialized) return error.InvalidCircuitTranscriptState;
            if (self.profile == .internal)
                try Transcript.initializeM31(self.session, .trace_commit, self.bindings.state, null, null, chainAt(self.chain_seed, 0))
            else
                try Transcript.initialize(self.session, .trace_commit, self.bindings.state, null, null, chainAt(self.chain_seed, 0));
            self.initialized = true;
        }

        pub fn mixSalt(self: *Self, salt: u32) !void {
            if (salt != self.salt_value or self.next_step != 0) return error.InvalidCircuitTranscriptPayload;
            try self.mix(self.bindings.salt, true);
        }

        pub fn mixFriConfig(self: *Self, config: PcsConfigV2) !void {
            if (self.next_step != 1 or !std.meta.eql(self.fri_value orelse return error.InvalidCircuitTranscriptState, config))
                return error.InvalidCircuitTranscriptPayload;
            try self.mix(self.bindings.fri_config, true);
        }

        pub fn mixRoot(self: *Self, root: Root) !void {
            if (root.len != 8) return error.InvalidCircuitTranscriptPayload;
            try self.mix(root, false);
        }

        pub fn mixFelts(self: *Self, values: Felts) !void {
            if (values.len == 0 or values.len % 4 != 0)
                return error.InvalidCircuitTranscriptPayload;
            try self.mix(values, true);
        }

        pub fn absorbPow(self: *Self, _: Nonce, bits: u32) !void {
            if (!self.initialized or self.next_step != 6 or bits != 20)
                return error.InvalidCircuitTranscriptState;
            const view = self.bindings;
            try Fri.grindPowAtStage(
                self.session,
                .trace_commit,
                view.state,
                bits,
                pow_search_end,
                view.pow_prefix,
                view.pow_best_nonce,
                view.pow_completed_blocks,
                view.pow_nonce_words,
            );
            try Transcript.absorbPowAtStage(
                self.session,
                .trace_commit,
                view.state,
                self.boundary(),
                view.pow_nonce_words,
                bits,
                view.pow_nonce_words,
            );
            self.next_step += 1;
        }

        pub fn drawLookupElements(self: *Self) !Lookup {
            if (!self.initialized or self.next_step != 7)
                return error.InvalidCircuitTranscriptState;
            try Transcript.drawSecure(
                self.session,
                .trace_commit,
                self.bindings.state,
                self.boundary(),
                2,
                64,
                self.bindings.lookup,
                self.bindings.lookup,
            );
            self.next_step += 1;
            return self.bindings.lookup;
        }

        pub fn readyForComposition(self: Self) bool {
            return self.initialized and self.next_step == 10;
        }

        fn mix(self: *Self, source: common.Words, validate_m31: bool) !void {
            if (!self.initialized or self.next_step >= 10)
                return error.InvalidCircuitTranscriptState;
            try Transcript.mixWords(
                self.session,
                .trace_commit,
                self.bindings.state,
                self.boundary(),
                source,
                validate_m31,
                source,
            );
            self.next_step += 1;
        }

        fn boundary(self: Self) transcript.Boundary {
            return .{
                .expected_step = self.next_step,
                .expected_chain = chainAt(self.chain_seed, self.next_step),
                .next_chain = chainAt(self.chain_seed, self.next_step + 1),
                .snapshot = self.bindings.boundary_snapshot,
            };
        }
    };
}

fn chainAt(seed: u64, step: u32) u64 {
    var value = seed ^ (@as(u64, step) *% 0x9e37_79b9_7f4a_7c15);
    value ^= value >> 30;
    value *%= 0xbf58_476d_1ce4_e5b9;
    value ^= value >> 27;
    value *%= 0x94d0_49bb_1331_11eb;
    value ^= value >> 31;
    return value;
}

test "resident circuit transcript binding requires one device generation" {
    const words = common.Words{ .address = 0x1000, .len = 16, .owner = 7, .generation = 3 };
    const secure = common.SecureFields{ .address = 0x1400, .len = 2, .owner = 7, .generation = 3 };
    const nonce = common.Nonce{ .address = 0x1600, .len = 1, .owner = 7, .generation = 3 };
    var bindings = Bindings{
        .state = words,
        .boundary_snapshot = .{ .address = 0x1100, .len = 16, .owner = 7, .generation = 3 },
        .salt = .{ .address = 0x1200, .len = 4, .owner = 7, .generation = 3 },
        .fri_config = .{ .address = 0x1300, .len = 8, .owner = 7, .generation = 3 },
        .lookup = secure,
        .pow_prefix = .{ .address = 0x1500, .len = 8, .owner = 7, .generation = 3 },
        .pow_best_nonce = nonce,
        .pow_completed_blocks = .{ .address = 0x1700, .len = 16, .owner = 7, .generation = 3 },
        .pow_nonce_words = .{ .address = 0x1800, .len = 2, .owner = 7, .generation = 3 },
    };
    try bindings.validate();
    bindings.lookup.generation = 4;
    try std.testing.expectError(error.InvalidCircuitTranscriptBindings, bindings.validate());
    bindings.lookup.generation = 3;
    bindings.boundary_snapshot = words;
    try std.testing.expectError(error.InvalidCircuitTranscriptBindings, bindings.validate());
}

const FakeSession = struct {
    context: struct {
        uploads: u32 = 0,

        pub fn uploadSlice(self: *@This(), comptime F: type, destination: anytype, source: []const F) !void {
            if (F != u32 or destination.len != source.len) return error.InvalidUpload;
            self.uploads += 1;
        }
    } = .{},
    transcript_calls: u32 = 0,
    pow_calls: u32 = 0,
    m31: bool = false,
};

const FakeTranscript = struct {
    pub fn initialize(session: *FakeSession, stage: cuda.runtime.telemetry.Stage, state: common.Words, _: ?common.Words, _: ?common.Words, _: u64) !void {
        if (stage != .trace_commit or state.len != 16) return error.InvalidFakeCall;
        session.transcript_calls += 1;
    }

    pub fn initializeM31(session: *FakeSession, stage: cuda.runtime.telemetry.Stage, state: common.Words, seed: ?common.Words, snapshot: ?common.Words, chain: u64) !void {
        session.m31 = true;
        try initialize(session, stage, state, seed, snapshot, chain);
    }

    pub fn mixWords(session: *FakeSession, stage: cuda.runtime.telemetry.Stage, _: common.Words, boundary: transcript.Boundary, source: common.Words, _: bool, snapshot: common.Words) !void {
        if (stage != .trace_commit or source.address != snapshot.address or
            boundary.expected_step != session.transcript_calls - 1 or
            boundary.expected_chain == boundary.next_chain)
            return error.InvalidFakeCall;
        session.transcript_calls += 1;
    }

    pub fn absorbPowAtStage(session: *FakeSession, stage: cuda.runtime.telemetry.Stage, _: common.Words, boundary: transcript.Boundary, nonce: common.Words, bits: u32, snapshot: common.Words) !void {
        if (stage != .trace_commit or bits != 20 or nonce.address != snapshot.address or
            boundary.expected_step != 6 or session.pow_calls != 1)
            return error.InvalidFakeCall;
        session.transcript_calls += 1;
    }

    pub fn drawSecure(session: *FakeSession, stage: cuda.runtime.telemetry.Stage, _: common.Words, boundary: transcript.Boundary, count: u32, _: u32, output: common.SecureFields, snapshot: common.SecureFields) !void {
        if (stage != .trace_commit or boundary.expected_step != 7 or
            count != 2 or output.address != snapshot.address)
            return error.InvalidFakeCall;
        session.transcript_calls += 1;
    }
};

const FakeFri = struct {
    pub fn grindPowAtStage(session: *FakeSession, stage: cuda.runtime.telemetry.Stage, _: common.Words, bits: u32, search_end: u64, _: common.Words, _: common.Nonce, _: common.Words, _: common.Words) !void {
        if (stage != .trace_commit or bits != 20 or search_end != pow_search_end)
            return error.InvalidFakeCall;
        session.pow_calls += 1;
    }
};

test "resident circuit prefix uses ten ordered device transcript operations" {
    const Prefix = @import("transcript_prefix.zig").Prefix;
    const Device = Sink(FakeSession, FakeTranscript, FakeFri);
    const words = common.Words{ .address = 0x1000, .len = 16, .owner = 7, .generation = 3 };
    const config = PcsConfigV2.fromFriAndTraceSize(
        try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 4),
        20,
    );
    const bindings = Bindings{
        .state = words,
        .boundary_snapshot = .{ .address = 0x1100, .len = 16, .owner = 7, .generation = 3 },
        .salt = .{ .address = 0x1200, .len = 4, .owner = 7, .generation = 3 },
        .fri_config = .{ .address = 0x1300, .len = 8, .owner = 7, .generation = 3 },
        .lookup = .{ .address = 0x1400, .len = 2, .owner = 7, .generation = 3 },
        .pow_prefix = .{ .address = 0x1500, .len = 8, .owner = 7, .generation = 3 },
        .pow_best_nonce = .{ .address = 0x1600, .len = 1, .owner = 7, .generation = 3 },
        .pow_completed_blocks = .{ .address = 0x1700, .len = 16, .owner = 7, .generation = 3 },
        .pow_nonce_words = .{ .address = 0x1800, .len = 2, .owner = 7, .generation = 3 },
    };
    var session = FakeSession{};
    var device = try Device.init(&session, bindings, .internal, [_]u8{1} ** 32);
    try device.prime(0, config);
    try device.initialize();
    var prefix = Prefix(Device){ .sink = &device };
    try prefix.mixSalt(0);
    try prefix.mixFriConfig(config);
    const root = common.Words{ .address = 0x1900, .len = 8, .owner = 7, .generation = 3 };
    try prefix.commitPreprocessed(root);
    try prefix.mixCircuitHash(root);
    try prefix.mixClaim(.{ .address = 0x1a00, .len = 32, .owner = 7, .generation = 3 });
    try prefix.commitBase(root);
    try prefix.absorbInteractionNonce({});
    const lookup = try prefix.drawLookupElements();
    try std.testing.expectEqual(bindings.lookup.address, lookup.address);
    try prefix.mixInteractionClaim(.{ .address = 0x1b00, .len = 44, .owner = 7, .generation = 3 });
    try prefix.commitInteraction(root);
    try prefix.admitComposition();
    try std.testing.expect(device.readyForComposition());
    try std.testing.expectEqual(@as(u32, 2), session.context.uploads);
    try std.testing.expectEqual(@as(u32, 1), session.pow_calls);
    try std.testing.expectEqual(@as(u32, 11), session.transcript_calls);
    try std.testing.expect(session.m31);
}
