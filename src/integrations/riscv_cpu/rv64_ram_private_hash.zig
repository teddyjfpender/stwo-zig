//! Private-word value-only hash subproof. Public input is only geometry and
//! ordered expected digests. No public permutation ledger or per-cell values.
//! This does not yet prove CPU execution, permission admission or continuation.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64_air;
const ram = rv.memory;
const C = ram.chunk_air;
const W = ram.message_air;
const CC = ram.chunk_component.Component;
const WC = ram.message_component.Component;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const P = rv.protocol;
const poseidon = frontend.testing.component_proof.universal_air;
const legacy = frontend.testing.component_proof.poseidon_air;
const PC = frontend.testing.component_proof.universal_component.Component;
const Relations = frontend.testing.component_proof.relations.Relations;
const Byte = rv.range.provider;
const ProviderInteraction = ram.provider_interaction;
const BC = rv.providers.byte.Component;
const Engine = engine.engine.ProverEngine(@import("stwo_cpu_backend").CpuBackend, P.Hasher, P.MerkleChannel, P.Channel);
const postcard = @import("interop_postcard");
const Column = engine.pcs.ColumnEvaluation;
const physical = rv.witness.physical;
const MAX_HASHES = 1024;
const MAX_BYTES = 64 * 1024 * 1024;
const Suite = enum { diagnostic, receipt };
fn config(suite: Suite) core.pcs.PcsConfig {
    return if (suite == .receipt) P.config() else .{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 10, .fold_step = 1 } };
}
fn magic(suite: Suite) u32 {
    return if (suite == .receipt) 0x52504832 else 0x52504831;
}
pub const Statement = struct {
    geometry: ram.values.Geometry,
    digests: []const ram.values.Digest,
    fn validate(self: Statement) !void {
        if (self.digests.len == 0 or self.digests.len > MAX_HASHES) return error.InvalidPrivateRamHashShape;
        for (self.digests) |digest| for (digest) |value| if (value >= core.fields.m31.Modulus) return error.NonCanonicalDigest;
    }
};
fn logSize(size: usize) u32 {
    return @intCast(@max(4, std.math.log2_int_ceil(usize, size)));
}
const Shapes = struct {
    chunk: C.Shape,
    word: W.Shape,
    provider_log: u32,
    fn init(public: Statement) Shapes {
        const h: u32 = @intCast(public.digests.len);
        return .{ .chunk = .{ .geometry = public.geometry, .hashes = h, .log_size = logSize(h * (public.geometry.permutations() + 1)) }, .word = .{ .geometry = public.geometry, .hashes = h, .log_size = logSize(h * public.geometry.cells()) }, .provider_log = logSize(h * public.geometry.permutations()) };
    }
};
fn prefix(channel: *P.Channel, public: Statement, shapes: Shapes, suite: Suite) void {
    config(suite).mixInto(channel);
    channel.mixU32s(&.{ 0x52504832, ram.values.VERSION, public.geometry.logBytes(), @intCast(public.digests.len), shapes.chunk.log_size, shapes.word.log_size, shapes.provider_log });
    for (public.digests) |digest| channel.mixU32s(&digest);
}
fn appendColumns(out: []Column, data: []M, log: u32) void {
    const size = @as(usize, 1) << @intCast(log);
    std.debug.assert(data.len == out.len * size);
    for (out, 0..) |*column, i| column.* = .{ .log_size = log, .values = data[i * size ..][0..size] };
}
fn fixed(a: std.mem.Allocator, shapes: Shapes, bytes: *const Byte.Trace) !struct { columns: []Column, chunk: []M, word: []M, first: []M } {
    const chunk = try a.alloc(M, C.FIXED * shapes.chunk.size());
    errdefer a.free(chunk);
    for (0..shapes.chunk.size()) |i| for (shapes.chunk.fixedAt(i), 0..) |value, col| {
        chunk[col * shapes.chunk.size() + physical(i, shapes.chunk.log_size)] = value;
    };
    const word = try a.alloc(M, W.FIXED * shapes.word.size());
    errdefer a.free(word);
    for (0..shapes.word.size()) |i| for (shapes.word.fixedAt(i), 0..) |value, col| {
        word[col * shapes.word.size() + physical(i, shapes.word.log_size)] = value;
    };
    const first = try a.alloc(M, @as(usize, 1) << @intCast(shapes.provider_log));
    errdefer a.free(first);
    @memset(first, M.zero());
    first[0] = M.one();
    const columns = try a.alloc(Column, C.FIXED + W.FIXED + 1 + Byte.N_FIXED);
    appendColumns(columns[0..C.FIXED], chunk, shapes.chunk.log_size);
    appendColumns(columns[C.FIXED..][0..W.FIXED], word, shapes.word.log_size);
    appendColumns(columns[C.FIXED + W.FIXED ..][0..1], first, shapes.provider_log);
    appendColumns(columns[C.FIXED + W.FIXED + 1 ..], bytes.fixed, Byte.LOG_SIZE);
    return .{ .columns = columns, .chunk = chunk, .word = word, .first = first };
}
const Trace = struct {
    a: std.mem.Allocator,
    shapes: Shapes,
    chunk: []M,
    word: []M,
    provider: []M,
    recorder: ram.values.Recorder,
    bytes: Byte.Trace,
    fn init(a: std.mem.Allocator, public: Statement, words: []const u64) !Trace {
        try public.validate();
        if (words.len != public.digests.len * public.geometry.cells()) return error.InvalidPrivateRamHashShape;
        const shapes = Shapes.init(public);
        const provider = try a.alloc(M, poseidon.N_MAIN_COLUMNS * (@as(usize, 1) << @intCast(shapes.provider_log)));
        errdefer a.free(provider);
        var writer = try ram.values.ProviderWriter.init(provider, shapes.provider_log);
        var recorder = ram.values.Recorder{ .allocator = a, .writer = &writer };
        errdefer recorder.deinit();
        try recorder.calls.ensureTotalCapacity(a, public.digests.len * public.geometry.permutations());
        for (public.digests, 0..) |expected, id| {
            const digest = try ram.values.hashValues(public.geometry, words[id * public.geometry.cells() ..][0..public.geometry.cells()], &recorder);
            if (!ram.values.equal(digest, expected)) return error.PrivateRamHashMismatch;
        }
        try writer.finishPadding();
        recorder.writer = null;
        const chunk = try a.alloc(M, C.MAIN * shapes.chunk.size());
        errdefer a.free(chunk);
        @memset(chunk, M.zero());
        for (0..public.digests.len) |id| {
            var previous: [16]M = @splat(M.zero());
            for (0..public.geometry.permutations()) |phase| {
                const io = recorder.calls.items[id * public.geometry.permutations() + phase];
                const row = physical(id * shapes.chunk.stride() + phase, shapes.chunk.log_size);
                for (io.output, 0..) |value, col| chunk[col * shapes.chunk.size() + row] = value;
                if (phase < public.geometry.absorptions()) for (0..7) |lane| {
                    chunk[(C.PAYLOAD + lane) * shapes.chunk.size() + row] = io.input[lane].sub(previous[lane]);
                };
                chunk[C.ACTIVE * shapes.chunk.size() + row] = M.one();
                previous = io.output;
            }
            chunk[C.ACTIVE * shapes.chunk.size() + physical(id * shapes.chunk.stride() + public.geometry.permutations(), shapes.chunk.log_size)] = M.one();
        }
        const word = try a.alloc(M, W.MAIN * shapes.word.size());
        errdefer a.free(word);
        @memset(word, M.zero());
        var counts: [256]u64 = @splat(0);
        for (words, 0..) |value, i| {
            const row = physical(i, shapes.word.log_size);
            for (0..8) |j| {
                const byte: u8 = @truncate(value >> @intCast(8 * j));
                word[j * shapes.word.size() + row] = M.fromCanonical(byte);
                counts[byte] += 1;
            }
            word[W.ACTIVE * shapes.word.size() + row] = M.one();
        }
        var bytes = try Byte.Trace.init(a, &counts);
        errdefer bytes.deinit();
        return .{ .a = a, .shapes = shapes, .chunk = chunk, .word = word, .provider = provider, .recorder = recorder, .bytes = bytes };
    }
    fn deinit(self: *Trace) void {
        self.a.free(self.chunk);
        self.a.free(self.word);
        self.a.free(self.provider);
        self.recorder.deinit();
        self.bytes.deinit();
    }
    fn mainColumns(self: *Trace) ![]Column {
        const result = try self.a.alloc(Column, C.MAIN + W.MAIN + poseidon.N_MAIN_COLUMNS + 1);
        appendColumns(result[0..C.MAIN], self.chunk, self.shapes.chunk.log_size);
        appendColumns(result[C.MAIN..][0..W.MAIN], self.word, self.shapes.word.log_size);
        appendColumns(result[C.MAIN + W.MAIN ..][0..poseidon.N_MAIN_COLUMNS], self.provider, self.shapes.provider_log);
        appendColumns(result[C.MAIN + W.MAIN + poseidon.N_MAIN_COLUMNS ..], self.bytes.main, 8);
        return result;
    }
};
const Claims = struct {
    chunk: C.Claims,
    word: W.Claims,
    provider: [2]Q,
    bytes: Q,
    fn mix(self: Claims, channel: *P.Channel) void {
        channel.mixFelts(&self.chunk);
        channel.mixFelts(&self.word);
        channel.mixFelts(&self.provider);
        channel.mixFelts(&.{self.bytes});
    }
};
const Challenges = struct {
    legacy_relations: Relations,
    ram_relation: ram.internal_relations.Prepared,
    bytes: Q,
    fn draw(a: std.mem.Allocator, channel: *P.Channel) !Challenges {
        const relations = try Relations.draw(a, channel);
        const prepared = ram.internal_relations.Challenge.draw(channel).prepare();
        channel.mixU32s(&.{0x52425954});
        return .{ .legacy_relations = relations, .ram_relation = prepared, .bytes = channel.drawSecureFelt() };
    }
};
fn store(data: []M, size: usize, row: usize, group: usize, value: Q) void {
    for (value.toM31Array(), 0..) |coordinate, i| data[(4 * group + i) * size + row] = coordinate;
}
fn sumTerm(denominator: Q, numerator: Q) !Q {
    return if (numerator.isZero()) Q.zero() else numerator.mul(try denominator.inv());
}
const Interaction = struct {
    a: std.mem.Allocator,
    chunk: []M,
    word: []M,
    provider: ProviderInteraction.Interaction,
    claims: Claims,
    fn init(trace: *Trace, challenges: *const Challenges) !Interaction {
        const a = trace.a;
        const chunk = try a.alloc(M, C.INTERACTION * trace.shapes.chunk.size());
        errdefer a.free(chunk);
        const word = try a.alloc(M, W.INTERACTION * trace.shapes.word.size());
        errdefer a.free(word);
        var chunk_claims: C.Claims = @splat(Q.zero());
        for (0..trace.shapes.chunk.size()) |i| {
            const row = physical(i, trace.shapes.chunk.log_size);
            const previous_row = physical((i + trace.shapes.chunk.size() - 1) % trace.shapes.chunk.size(), trace.shapes.chunk.log_size);
            var main: C.SecureRow = undefined;
            var previous: C.SecureRow = undefined;
            var f: C.Fixed = undefined;
            for (&main, &previous, 0..) |*value, *old, j| {
                value.* = Q.fromBase(trace.chunk[j * trace.shapes.chunk.size() + row]);
                old.* = Q.fromBase(trace.chunk[j * trace.shapes.chunk.size() + previous_row]);
            }
            for (&f, trace.shapes.chunk.fixedAt(i)) |*value, base| value.* = Q.fromBase(base);
            const io = C.ioTerm(trace.shapes.chunk, &f, &main, &previous, challenges.legacy_relations.poseidon2_io);
            chunk_claims[0] = chunk_claims[0].add(try sumTerm(io.denominator, io.numerator));
            for (0..3) |group| for (0..3) |slot| {
                const term = C.ramTerm(trace.shapes.chunk, &f, &main, &previous, &challenges.ram_relation, 3 * group + slot);
                chunk_claims[group + 1] = chunk_claims[group + 1].add(try sumTerm(term.denominator, term.numerator));
            };
            for (chunk_claims, 0..) |claim, group| store(chunk, trace.shapes.chunk.size(), row, group, claim);
        }
        var word_claims: W.Claims = @splat(Q.zero());
        for (0..trace.shapes.word.size()) |i| {
            const row = physical(i, trace.shapes.word.log_size);
            var main: W.SecureRow = undefined;
            var f: W.Fixed = undefined;
            for (&main, 0..) |*value, j| value.* = Q.fromBase(trace.word[j * trace.shapes.word.size() + row]);
            for (&f, trace.shapes.word.fixedAt(i)) |*value, base| value.* = Q.fromBase(base);
            for (0..3) |group| for (0..3) |slot| {
                const term = W.byteTerm(&main, challenges.bytes, 3 * group + slot);
                word_claims[group] = word_claims[group].add(try sumTerm(term.denominator, term.numerator));
            };
            for (0..2) |group| for (0..3) |slot| {
                const term = W.ramTerm(&f, &main, &challenges.ram_relation, 3 * group + slot);
                word_claims[3 + group] = word_claims[3 + group].add(try sumTerm(term.denominator, term.numerator));
            };
            for (word_claims, 0..) |claim, group| store(word, trace.shapes.word.size(), row, group, claim);
        }
        var provider = try ProviderInteraction.generate(a, trace.recorder.calls.items, trace.shapes.provider_log, &challenges.legacy_relations);
        errdefer provider.deinit();
        const byte_claim = try trace.bytes.generateInteraction(challenges.bytes);
        return .{ .a = a, .chunk = chunk, .word = word, .provider = provider, .claims = .{ .chunk = chunk_claims, .word = word_claims, .provider = provider.claims, .bytes = byte_claim } };
    }
    fn deinit(self: *Interaction) void {
        self.a.free(self.chunk);
        self.a.free(self.word);
        self.provider.deinit();
    }
    fn columns(self: *Interaction, trace: *Trace) ![]Column {
        const result = try self.a.alloc(Column, C.INTERACTION + W.INTERACTION + legacy.N_INTERACTION_COLUMNS + Byte.N_INTERACTION);
        appendColumns(result[0..C.INTERACTION], self.chunk, trace.shapes.chunk.log_size);
        appendColumns(result[C.INTERACTION..][0..W.INTERACTION], self.word, trace.shapes.word.log_size);
        appendColumns(result[C.INTERACTION + W.INTERACTION ..][0..legacy.N_INTERACTION_COLUMNS], self.provider.columns, trace.shapes.provider_log);
        appendColumns(result[C.INTERACTION + W.INTERACTION + legacy.N_INTERACTION_COLUMNS ..], trace.bytes.interaction, 8);
        return result;
    }
};
fn checkClaims(public: Statement, claims: Claims, challenges: *const Challenges) !void {
    if (!claims.provider[0].isZero() or !claims.chunk[0].add(claims.provider[1]).isZero()) return error.UnbalancedPrivateRamPoseidon;
    var bytes = claims.bytes;
    for (claims.word[0..3]) |claim| bytes = bytes.add(claim);
    if (!bytes.isZero()) return error.UnbalancedPrivateRamBytes;
    var internal = Q.zero();
    for (claims.chunk[1..]) |claim| internal = internal.add(claim);
    for (claims.word[3..]) |claim| internal = internal.add(claim);
    for (public.digests, 0..) |digest, id| {
        var secure: [9]Q = undefined;
        for (&secure, digest) |*out, value| out.* = Q.fromBase(M.fromCanonical(value));
        internal = internal.add(try challenges.ram_relation.digest(Q.fromBase(M.fromCanonical(@intCast(id))), secure).inv());
    }
    if (!internal.isZero()) return error.UnbalancedPrivateRamPackets;
}
const Components = struct {
    chunk: CC,
    word: WC,
    provider: PC,
    bytes: BC,
    fn init(shapes: Shapes, public: Statement, challenges: *const Challenges, claims: Claims) !Components {
        return .{ .chunk = try CC.init(shapes.chunk, .{}, .{ .ram = challenges.ram_relation, .io = challenges.legacy_relations.poseidon2_io }, claims.chunk), .word = try WC.init(shapes.word, .{ .fixed = C.FIXED, .main = C.MAIN, .interaction = C.INTERACTION }, .{ .ram = challenges.ram_relation, .bytes = challenges.bytes }, claims.word), .provider = .{ .log_size = shapes.provider_log, .n_rows = @intCast(public.digests.len * public.geometry.permutations()), .is_first_col_idx = C.FIXED + W.FIXED, .is_active_col_idx = C.FIXED + W.FIXED, .main_col_offset = C.MAIN + W.MAIN, .interaction_col_offset = C.INTERACTION + W.INTERACTION, .relations = &challenges.legacy_relations, .claims = claims.provider }, .bytes = .{ .fixed_offset = C.FIXED + W.FIXED + 1, .main_offset = C.MAIN + W.MAIN + poseidon.N_MAIN_COLUMNS, .interaction_offset = C.INTERACTION + W.INTERACTION + legacy.N_INTERACTION_COLUMNS, .alpha = challenges.bytes, .claim = claims.bytes } };
    }
};
pub fn prove(a: std.mem.Allocator, public: Statement, words: []const u64) ![]u8 {
    return proveSuite(a, public, words, .diagnostic, null);
}
pub fn proveReceipt(a: std.mem.Allocator, public: Statement, words: []const u64) ![]u8 {
    return proveSuite(a, public, words, .receipt, null);
}
/// Fresh-transcript attack fixtures. Every mutation is applied before the main
/// commitment; the ordinary verifier/prover relations must reject it.
pub const Attack = enum { byte_carry_alias, unused_capacity_output };
pub fn proveAttack(a: std.mem.Allocator, public: Statement, words: []const u64, attack: Attack) ![]u8 {
    return proveSuite(a, public, words, .diagnostic, attack);
}
fn proveSuite(a: std.mem.Allocator, public: Statement, words: []const u64, suite: Suite, attack: ?Attack) ![]u8 {
    var trace = try Trace.init(a, public, words);
    defer trace.deinit();
    if (attack) |kind| switch (kind) {
        .byte_carry_alias => {
            // Preserve the packed u16 exactly while introducing non-bytes.
            // This cannot be rejected by the local word-to-limb equation.
            trace.word[0] = trace.word[0].add(M.fromCanonical(256));
            trace.word[trace.shapes.word.size()] = trace.word[trace.shapes.word.size()].sub(M.one());
        },
        .unused_capacity_output => {
            // A true sponge round includes capacity lanes even though digest
            // extraction never exposes this intermediate lane directly.
            trace.chunk[15 * trace.shapes.chunk.size()] = trace.chunk[15 * trace.shapes.chunk.size()].add(M.one());
        },
    };
    var scheme = try Engine.init(a, config(suite));
    var moved = false;
    defer if (!moved) Engine.deinit(&scheme, a);
    var channel = P.Channel{};
    prefix(&channel, public, trace.shapes, suite);
    const f = try fixed(a, trace.shapes, &trace.bytes);
    defer {
        a.free(f.columns);
        a.free(f.chunk);
        a.free(f.word);
        a.free(f.first);
    }
    try scheme.commitBorrowedStreaming(a, f.columns, 8, &channel);
    const main = try trace.mainColumns();
    defer a.free(main);
    try scheme.commitBorrowedStreaming(a, main, 8, &channel);
    const challenges = try Challenges.draw(a, &channel);
    var interaction = try Interaction.init(&trace, &challenges);
    defer interaction.deinit();
    try checkClaims(public, interaction.claims, &challenges);
    interaction.claims.mix(&channel);
    const columns = try interaction.columns(&trace);
    defer a.free(columns);
    try scheme.commitBorrowedStreaming(a, columns, 8, &channel);
    const components = try Components.init(trace.shapes, public, &challenges, interaction.claims);
    moved = true;
    var proof = try Engine.prove(a, &.{ components.chunk.asProverComponent(), components.word.asProverComponent(), try components.provider.asProverComponent().withCompositionGeometryOverrideV1(.{ .max_constraint_log_degree_bound_delta = 1, .composition_log_split = 2 }), components.bytes.asProverComponent() }, &channel, scheme, .{});
    defer proof.deinit(a);
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(a);
    try appendWord(a, &bytes, magic(suite));
    for (interaction.claims.chunk) |claim| try appendQ(a, &bytes, claim);
    for (interaction.claims.word) |claim| try appendQ(a, &bytes, claim);
    for (interaction.claims.provider) |claim| try appendQ(a, &bytes, claim);
    try appendQ(a, &bytes, interaction.claims.bytes);
    try postcard.serializeProof(P.Hasher, bytes.writer(a), proof.proof);
    if (bytes.items.len > MAX_BYTES) return error.InvalidPrivateRamHashShape;
    return bytes.toOwnedSlice(a);
}
fn appendWord(a: std.mem.Allocator, bytes: *std.ArrayList(u8), word: u32) !void {
    var data: [4]u8 = undefined;
    std.mem.writeInt(u32, &data, word, .little);
    try bytes.appendSlice(a, &data);
}
fn appendQ(a: std.mem.Allocator, bytes: *std.ArrayList(u8), value: Q) !void {
    for (value.toM31Array()) |word| try appendWord(a, bytes, word.toU32());
}
fn readQ(bytes: []const u8, at: *usize) !Q {
    var words: [4]M = undefined;
    for (&words) |*word| {
        const value = std.mem.readInt(u32, bytes[at.*..][0..4], .little);
        if (value >= core.fields.m31.Modulus) return error.NonCanonicalDigest;
        word.* = M.fromCanonical(value);
        at.* += 4;
    }
    return Q.fromM31Array(words);
}
pub fn verify(a: std.mem.Allocator, public: Statement, bytes: []const u8) !void {
    return verifySuite(a, public, bytes, .diagnostic);
}
pub fn verifyReceipt(a: std.mem.Allocator, public: Statement, bytes: []const u8) !void {
    return verifySuite(a, public, bytes, .receipt);
}
fn verifySuite(a: std.mem.Allocator, public: Statement, bytes: []const u8, suite: Suite) !void {
    try public.validate();
    const header = 4 + 16 * (C.SUMS + W.SUMS + 2 + 1);
    if (bytes.len <= header or bytes.len > MAX_BYTES or std.mem.readInt(u32, bytes[0..4], .little) != magic(suite)) return error.InvalidPrivateRamHashShape;
    const shapes = Shapes.init(public);
    var at: usize = 4;
    var claims: Claims = undefined;
    for (&claims.chunk) |*claim| claim.* = try readQ(bytes, &at);
    for (&claims.word) |*claim| claim.* = try readQ(bytes, &at);
    for (&claims.provider) |*claim| claim.* = try readQ(bytes, &at);
    claims.bytes = try readQ(bytes, &at);
    const params = config(suite);
    const largest_log = @max(8, @max(shapes.provider_log, @max(shapes.chunk.log_size, shapes.word.log_size)));
    try postcard.proof_preflight.validate(bytes[header..], .{ .config = .{ .pow_bits = params.pow_bits, .log_blowup_factor = params.fri_config.log_blowup_factor, .n_queries = params.fri_config.n_queries, .log_last_layer_degree_bound = params.fri_config.log_last_layer_degree_bound, .fold_step = params.fri_config.fold_step, .lifting_log_size = params.lifting_log_size }, .tree_columns = .{ C.FIXED + W.FIXED + 1 + Byte.N_FIXED, C.MAIN + W.MAIN + poseidon.N_MAIN_COLUMNS + 1, C.INTERACTION + W.INTERACTION + legacy.N_INTERACTION_COLUMNS + Byte.N_INTERACTION, 16 }, .max_column_log_size = largest_log, .hash_size = @sizeOf(P.Hasher.Hash), .max_wire_bytes = MAX_BYTES - header });
    var stream = std.io.fixedBufferStream(bytes[header..]);
    var proof = try postcard.deserializeProof(P.Hasher, a, stream.reader());
    var moved = false;
    defer if (!moved) proof.deinit(a);
    if (stream.pos != bytes.len - header or proof.commitment_scheme_proof.commitments.items.len != 4) return error.InvalidPrivateRamHashShape;
    const roots = proof.commitment_scheme_proof.commitments.items;
    var table = try Byte.Trace.init(a, &@as([256]u64, @splat(0)));
    defer table.deinit();
    const f = try fixed(a, shapes, &table);
    defer {
        a.free(f.columns);
        a.free(f.chunk);
        a.free(f.word);
        a.free(f.first);
    }
    {
        var setup = try Engine.init(a, params);
        defer Engine.deinit(&setup, a);
        var scratch = P.Channel{};
        try setup.commitBorrowedStreaming(a, f.columns, 8, &scratch);
        var canonical = try setup.roots(a);
        defer canonical.deinit(a);
        if (!std.meta.eql(canonical.items[0], roots[0])) return error.InvalidPrivateRamHashFixedRoot;
    }
    var scheme = try core.pcs.verifier.CommitmentSchemeVerifier(P.Hasher, P.MerkleChannel).init(a, params);
    defer scheme.deinit(a);
    var channel = P.Channel{};
    prefix(&channel, public, shapes, suite);
    var fixed_logs: [C.FIXED + W.FIXED + 1 + Byte.N_FIXED]u32 = undefined;
    for (&fixed_logs, f.columns) |*log, column| log.* = column.log_size;
    var main_logs: [C.MAIN + W.MAIN + poseidon.N_MAIN_COLUMNS + 1]u32 = undefined;
    @memset(main_logs[0..C.MAIN], shapes.chunk.log_size);
    @memset(main_logs[C.MAIN..][0..W.MAIN], shapes.word.log_size);
    @memset(main_logs[C.MAIN + W.MAIN ..][0..poseidon.N_MAIN_COLUMNS], shapes.provider_log);
    main_logs[main_logs.len - 1] = 8;
    var inter_logs: [C.INTERACTION + W.INTERACTION + legacy.N_INTERACTION_COLUMNS + Byte.N_INTERACTION]u32 = undefined;
    @memset(inter_logs[0..C.INTERACTION], shapes.chunk.log_size);
    @memset(inter_logs[C.INTERACTION..][0..W.INTERACTION], shapes.word.log_size);
    @memset(inter_logs[C.INTERACTION + W.INTERACTION ..][0..legacy.N_INTERACTION_COLUMNS], shapes.provider_log);
    @memset(inter_logs[inter_logs.len - Byte.N_INTERACTION ..], 8);
    try scheme.commit(a, roots[0], &fixed_logs, &channel);
    try scheme.commit(a, roots[1], &main_logs, &channel);
    const challenges = try Challenges.draw(a, &channel);
    try checkClaims(public, claims, &challenges);
    claims.mix(&channel);
    try scheme.commit(a, roots[2], &inter_logs, &channel);
    const components = try Components.init(shapes, public, &challenges, claims);
    moved = true;
    try core.verifier.verify(P.Hasher, P.MerkleChannel, a, &.{ components.chunk.asVerifierComponent(), components.word.asVerifierComponent(), try components.provider.asVerifierComponent().withCompositionGeometryOverrideV1(.{ .max_constraint_log_degree_bound_delta = 1, .composition_log_split = 2 }), components.bytes.asVerifierComponent() }, &channel, &scheme, proof);
}
