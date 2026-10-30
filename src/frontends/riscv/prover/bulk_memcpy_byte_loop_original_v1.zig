//! Genuine standalone ORIGINAL STARK for an admitted public same-ROM macro.
//! Byte ranges, source-value queries and the complete local RAM endpoint
//! cohort close here. Program/state/register/global-memory projections remain OPEN.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const postcard = @import("interop_postcard");
const S = core.proof_suites.Blake3;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Scope = @import("bulk_memcpy_byte_loop_scope_v1.zig");
const A = @import("bulk_memcpy_byte_loop_components_v1.zig");
const C = @import("../air/guest_precompile/bulk_memcpy_byte_loop_certificate_v1.zig");
const K = @import("../air/guest_precompile/bulk_memcpy_byte_loop_kernel_v1.zig");
const Endpoint = @import("block_v8_ram_endpoint_kernel_v1.zig");
const R = @import("block_v7_memory_relations_v1.zig");
const T = @import("block_v7_memory_trace_v1.zig");
const Column = engine.pcs.ColumnEvaluation;
const Scheme = engine.pcs.CommitmentSchemeProver(Cpu, S.Hasher, S.MerkleChannel);
const Adapter = @import("block_v5_word_quotient_adapter_v1.zig");
const Placement = @import("block_v7_heterogeneous_components_v1.zig");
pub const production_active = false;
pub const whole_source_qualified = false;
pub const Trusted = Scope.Trusted;
pub const Public = Scope.Public;
pub const Witness = struct { source_words: []const u32, destination_before: []const u32 };
pub const Claims = struct { destination: [6]Q, source: [5]Q, bytes: [2]Q, boundary: [3]Q, endpoints: [13]Q, range16: [2]Q };
pub const Summary = struct {
    scope: enum { standalone_original_macro_open_external_relations } = .standalone_original_macro_open_external_relations,
    retired_instructions: u32,
    program_fetches: u32,
    logical_ram_accesses: u32,
    external_ram_word_edges: u32,
    program: Q,
    state: Q,
    registers: Q,
    ram_source: Q,
    ram_destination: Q,
    global_transition: Q,
    local_ram_closed: bool = true,
    local_value_closed: bool = true,
    byte_ranges_closed: bool = true,
    whole_vm_qualified: bool = false,
};
pub const Proof = struct {
    allocator: std.mem.Allocator,
    stark: S.Proof,
    claims: Claims,
    pub fn deinit(self: *Proof) void {
        self.stark.deinit(self.allocator);
        self.allocator.destroy(self);
    }
};
pub const Stage = struct {
    allocator: std.mem.Allocator,
    matrices: Scope.Matrices,
    pub fn create(a: std.mem.Allocator, scope: *const Scope.Scope, witness: Witness) !Stage {
        if (witness.source_words.len != scope.source_words or witness.destination_before.len != scope.destination_words) return error.InvalidByteLoopWitness;
        var matrices = try Scope.fixed(a, scope);
        errdefer matrices.deinit();
        const counts = try a.alloc(u32, scope.source_words);
        defer a.free(counts);
        @memset(counts, 0);
        var byte_counts: [256]u32 = @splat(0);
        for (witness.source_words, 0..) |word, i| for (0..4) |byte| {
            const value = (word >> @as(u5, @intCast(8 * byte))) & 255;
            matrices.source.set(A.Spec(.source).FIXED_COUNT + byte, i, M.fromCanonical(value));
            byte_counts[value] += 1;
        };
        const source_first = scope.trusted.public.call.source & ~@as(u32, 3);
        for (witness.destination_before, 0..) |before, i| {
            const plan = try scope.trusted.public.call.destinationWordPlan(@intCast(i));
            var values: [2]u32 = @splat(0);
            for ([_]?u32{ plan.source_low_word, plan.source_high_word }, 0..) |maybe, port| if (maybe) |address| {
                if (address < source_first or (address - source_first) / 4 >= witness.source_words.len) return error.InvalidByteLoopSourcePort;
                const source_index = (address - source_first) / 4;
                counts[source_index] += 1;
                values[port] = witness.source_words[source_index];
            };
            const row = try K.witness(values[0], values[1], before, plan.start, plan.end, plan.shift);
            for (row, 0..) |value, column| matrices.destination.set(A.Spec(.destination).FIXED_COUNT + column, i, value);
            for (row[K.Layout.destination_before..K.Layout.mask]) |value| byte_counts[value.v] += 1;
        }
        for (counts, 0..) |count, i| matrices.source.set(A.Spec(.source).FIXED_COUNT + 4, i, M.fromCanonical(count));
        const range_counts = try a.alloc(u32, 65536);
        defer a.free(range_counts);
        @memset(range_counts, 0);
        var prior_address: ?u32 = null;
        for (0..scope.endpoint_count) |i| {
            const point = try scope.endpointAt(i);
            const initial = if (point.source) witness.source_words[point.index] else witness.destination_before[point.index];
            var final = initial;
            if (!point.source) {
                final = 0;
                for (0..4) |byte| final |= matrices.destination.get(A.Spec(.destination).FIXED_COUNT + K.Layout.destination_after + byte, point.index).v << @as(u5, @intCast(8 * byte));
            }
            const endpoint_row = try Endpoint.constructWithPrevious(.{ .address = point.address, .initial = initial, .final = final, .last_clock = point.last_clock }, prior_address, scope.endpoint_policy);
            prior_address = point.address;
            for (endpoint_row, 0..) |value, column| matrices.endpoints.set(A.EndpointSpec.FIXED_COUNT + column, i, try value.tryIntoM31());
            for (Endpoint.range16_columns) |column| range_counts[(try endpoint_row[column].tryIntoM31()).v] += 1;
            range_counts[(try Endpoint.derivedRange16(Q, endpoint_row)[0].tryIntoM31()).v] += 1;
            for (endpoint_row[3..11]) |value| byte_counts[(try value.tryIntoM31()).v] += 1;
        }
        for (range_counts, 0..) |count, i| matrices.range16.set(A.RangeSpec.FIXED_COUNT, i, M.fromCanonical(count));
        for (byte_counts, 0..) |count, i| matrices.bytes.set(A.Spec(.bytes).FIXED_COUNT, i, M.fromCanonical(count));
        for (0..matrices.boundary.size()) |i| matrices.boundary.set(A.Spec(.boundary).FIXED_COUNT, i, matrices.boundary.get(3, i));
        return .{ .allocator = a, .matrices = matrices };
    }
    pub fn refreshProviders(self: *Stage, scope: *const Scope.Scope) !void {
        var byte_counts: [256]u32 = @splat(0);
        for (0..scope.source_words) |i| for (0..4) |byte| {
            const value = self.matrices.source.get(A.Spec(.source).FIXED_COUNT + byte, i).v;
            if (value >= 256) return error.InvalidByteLoopWitness;
            byte_counts[value] += 1;
        };
        for (0..scope.destination_words) |i| for (0..8) |byte| {
            const value = self.matrices.destination.get(A.Spec(.destination).FIXED_COUNT + K.Layout.destination_before + byte, i).v;
            if (value >= 256) return error.InvalidByteLoopWitness;
            byte_counts[value] += 1;
        };
        const ranges = try self.allocator.alloc(u32, 65536);
        defer self.allocator.free(ranges);
        @memset(ranges, 0);
        for (0..scope.endpoint_count) |i| {
            const row = self.matrices.endpoints.row(23, A.EndpointSpec.FIXED_COUNT, i);
            for (row[3..11]) |value| {
                const byte = (try value.tryIntoM31()).v;
                if (byte >= 256) return error.InvalidByteLoopWitness;
                byte_counts[byte] += 1;
            }
            for (Endpoint.range16_columns) |column| {
                const value = (try row[column].tryIntoM31()).v;
                if (value >= 65536) return error.InvalidByteLoopWitness;
                ranges[value] += 1;
            }
            const derived = (try Endpoint.derivedRange16(Q, row)[0].tryIntoM31()).v;
            if (derived >= 65536) return error.InvalidByteLoopWitness;
            ranges[derived] += 1;
        }
        for (byte_counts, 0..) |count, i| self.matrices.bytes.set(A.Spec(.bytes).FIXED_COUNT, i, M.fromCanonical(count));
        for (ranges, 0..) |count, i| self.matrices.range16.set(A.RangeSpec.FIXED_COUNT, i, M.fromCanonical(count));
    }
    pub fn deinit(self: *Stage) void {
        self.matrices.deinit();
        self.* = undefined;
    }
};
fn Context(comptime kind: A.Kind) type {
    return struct {
        ch: A.Challenges(Q),
        pub fn termsAt(self: @This(), matrix: T.Matrix, row: usize) ![A.Spec(kind).PLANES]R.Term(Q) {
            return A.Spec(kind).terms(Q, self.ch, matrix.row(A.Spec(kind).FIXED_COUNT, 0, row), matrix.row(A.Spec(kind).MAIN_COUNT, A.Spec(kind).FIXED_COUNT, row));
        }
    };
}
const EndpointContext = struct {
    ch: A.Challenges(Q),
    policy: Endpoint.Policy,
    pub fn termsAt(self: @This(), matrix: T.Matrix, row: usize) ![13]R.Term(Q) {
        return A.EndpointSpec.terms(Q, self.policy, self.ch, matrix.row(5, 0, row), matrix.row(23, 5, row));
    }
};
const RangeContext = struct {
    ch: R.Challenges(Q),
    pub fn termsAt(self: @This(), matrix: T.Matrix, row: usize) ![2]R.Term(Q) {
        return A.RangeSpec.terms(Q, self.ch, matrix.row(2, 0, row), matrix.row(1, 2, row));
    }
};
pub const Generated = struct {
    destination: T.Generated(6),
    source: T.Generated(5),
    bytes: T.Generated(2),
    boundary: T.Generated(3),
    endpoints: T.Generated(13),
    range16: T.Generated(2),
    pub fn create(a: std.mem.Allocator, scope: *const Scope.Scope, stage: *const Stage, drawn: A.Drawn) !Generated {
        const ch = drawn.challenges;
        var destination = try T.interactions(6, a, stage.matrices.destination, Context(.destination){ .ch = ch }, 64 << 20);
        errdefer destination.deinit();
        var source = try T.interactions(5, a, stage.matrices.source, Context(.source){ .ch = ch }, 64 << 20);
        errdefer source.deinit();
        var bytes = try T.interactions(2, a, stage.matrices.bytes, Context(.bytes){ .ch = ch }, 64 << 20);
        errdefer bytes.deinit();
        var boundary = try T.interactions(3, a, stage.matrices.boundary, Context(.boundary){ .ch = ch }, 64 << 20);
        errdefer boundary.deinit();
        var endpoints = try T.interactions(13, a, stage.matrices.endpoints, EndpointContext{ .ch = ch, .policy = scope.endpoint_policy }, 64 << 20);
        errdefer endpoints.deinit();
        var range16 = try T.interactions(2, a, stage.matrices.range16, RangeContext{ .ch = drawn.memory }, 64 << 20);
        errdefer range16.deinit();
        return .{ .destination = destination, .source = source, .bytes = bytes, .boundary = boundary, .endpoints = endpoints, .range16 = range16 };
    }
    pub fn claims(self: Generated) Claims {
        return .{ .destination = self.destination.sums, .source = self.source.sums, .bytes = self.bytes.sums, .boundary = self.boundary.sums, .endpoints = self.endpoints.sums, .range16 = self.range16.sums };
    }
    pub fn deinit(self: *Generated) void {
        self.range16.deinit();
        self.endpoints.deinit();
        self.boundary.deinit();
        self.bytes.deinit();
        self.source.deinit();
        self.destination.deinit();
    }
};
const D = Adapter.For(A.Spec(.destination));
const Source = Adapter.For(A.Spec(.source));
const Bytes = Adapter.For(A.Spec(.bytes));
const Boundary = Adapter.For(A.Spec(.boundary));
const Endpoints = Adapter.For(A.EndpointSpec);
const Range = Adapter.For(A.RangeSpec);
const maps = .{ [_]usize{ 0, 1, 7 }, [_]usize{ 0, 2, 8 }, [_]usize{ 0, 3, 9 }, [_]usize{ 0, 4, 10 }, [_]usize{ 0, 5, 11 }, [_]usize{ 0, 6, 12 } };
pub fn Owner(comptime proving: bool) type {
    return struct {
        allocator: std.mem.Allocator,
        destination: D,
        source: Source,
        bytes: Bytes,
        boundary: Boundary,
        endpoints: Endpoints,
        range16: Range,
        placed: ?Placement.For(maps, 13, proving) = null,
        pub fn create(a: std.mem.Allocator, scope: *const Scope.Scope, drawn: A.Drawn, claims: Claims) !*@This() {
            const ch = drawn.challenges;
            const self = try a.create(@This());
            errdefer a.destroy(self);
            self.* = .{ .allocator = a, .destination = .{ .log_size = scope.destination_log, .spec = .{ .challenges = ch, .sums = claims.destination, .last_byte = scope.trusted.public.last_byte } }, .source = .{ .log_size = scope.source_log, .spec = .{ .challenges = ch, .sums = claims.source } }, .bytes = .{ .log_size = 8, .spec = .{ .challenges = ch, .sums = claims.bytes } }, .boundary = .{ .log_size = 4, .spec = .{ .challenges = ch, .sums = claims.boundary } }, .endpoints = .{ .log_size = scope.endpoint_log, .spec = .{ .policy = scope.endpoint_policy, .challenges = ch, .sums = claims.endpoints } }, .range16 = .{ .log_size = 16, .spec = .{ .challenges = drawn.memory, .sums = claims.range16 } } };
            const H = if (proving) engine.air.component_prover.ComponentProver else core.air.components.Component;
            const d: H = if (proving) self.destination.asProverComponent() else self.destination.asVerifierComponent();
            const source: H = if (proving) self.source.asProverComponent() else self.source.asVerifierComponent();
            const b: H = if (proving) self.bytes.asProverComponent() else self.bytes.asVerifierComponent();
            const boundary: H = if (proving) self.boundary.asProverComponent() else self.boundary.asVerifierComponent();
            const endpoints: H = if (proving) self.endpoints.asProverComponent() else self.endpoints.asVerifierComponent();
            const range16: H = if (proving) self.range16.asProverComponent() else self.range16.asVerifierComponent();
            self.placed = try Placement.For(maps, 13, proving).init(a, .{ &.{d}, &.{source}, &.{b}, &.{boundary}, &.{endpoints}, &.{range16} }, .{ A.Spec(.destination).FIXED_COUNT, A.Spec(.source).FIXED_COUNT, A.Spec(.bytes).FIXED_COUNT, A.Spec(.boundary).FIXED_COUNT, A.EndpointSpec.FIXED_COUNT, A.RangeSpec.FIXED_COUNT });
            return self;
        }
        pub fn rawHandles(self: *const @This()) [6](if (proving) engine.air.component_prover.ComponentProver else core.air.components.Component) {
            return if (proving) .{ self.destination.asProverComponent(), self.source.asProverComponent(), self.bytes.asProverComponent(), self.boundary.asProverComponent(), self.endpoints.asProverComponent(), self.range16.asProverComponent() } else .{ self.destination.asVerifierComponent(), self.source.asVerifierComponent(), self.bytes.asVerifierComponent(), self.boundary.asVerifierComponent(), self.endpoints.asVerifierComponent(), self.range16.asVerifierComponent() };
        }
        pub fn deinit(self: *@This()) void {
            if (self.placed) |*placed| placed.deinit(self.allocator);
            self.allocator.destroy(self);
        }
    };
}
pub fn recordClaims(channel: anytype, claims: Claims) !void {
    channel.mixU32s(&.{ 0x42384d43, 1, 6, 5, 2, 3, 13, 2 });
    inline for (.{ "destination", "source", "bytes", "boundary", "endpoints", "range16" }) |field| for (@field(claims, field)) |claim| {
        for (claim.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.InvalidByteLoopPhysicalClaim;
        channel.mixFelts(&.{claim});
    };
}
pub fn closeResources(scope: *const Scope.Scope, drawn: A.Drawn, claims: Claims) !Summary {
    if (!claims.destination[0].add(claims.source[0]).isZero()) return error.UnclosedByteLoopValueQueries;
    var byte_sum = claims.bytes[0].add(claims.source[2]).add(claims.source[3]);
    for (claims.destination[2..]) |claim| byte_sum = byte_sum.add(claim);
    for (claims.endpoints[9..]) |claim| byte_sum = byte_sum.add(claim);
    var range_sum = claims.range16[0];
    for (claims.endpoints[2..9]) |claim| range_sum = range_sum.add(claim);
    if (!range_sum.isZero() or !claims.range16[1].eql(Q.fromBase(M.fromCanonical(13 * scope.endpoint_count)))) return error.UnclosedByteLoopEndpointRanges;
    if (!byte_sum.isZero() or !claims.bytes[1].eql(Q.fromBase(M.fromCanonical(scope.byte_requests)))) return error.UnclosedByteLoopRanges;
    if (!claims.source[4].eql(Q.fromBase(M.fromCanonical(scope.value_requests)))) return error.UnclosedByteLoopValueCount;
    const p = scope.trusted.public;
    if (!claims.boundary[0].eql(try C.programContribution(scope.certificate, p.call, &drawn.universal)) or
        !claims.boundary[1].eql(try C.stateContribution(scope.certificate, p.call, &drawn.universal)) or
        !claims.boundary[2].eql(try C.registerContribution(p.call, p.previous_register_clocks, p.initial_scratch, p.last_byte, &drawn.universal))) return error.UntrustedByteLoopBoundaryClaims;
    return .{ .retired_instructions = try p.call.retiredInstructions(), .program_fetches = 5 * p.call.length, .logical_ram_accesses = 2 * p.call.length, .external_ram_word_edges = scope.source_words + scope.destination_words, .program = claims.boundary[0], .state = claims.boundary[1], .registers = claims.boundary[2], .ram_source = claims.source[1], .ram_destination = claims.destination[1], .global_transition = claims.endpoints[1] };
}
fn close(scope: *const Scope.Scope, drawn: A.Drawn, claims: Claims) !Summary {
    const summary = try closeResources(scope, drawn, claims);
    if (!claims.source[1].add(claims.destination[1]).add(claims.endpoints[0]).isZero()) return error.UnclosedByteLoopLocalRam;
    return summary;
}
pub fn fixedColumns(a: std.mem.Allocator, matrices: *const Scope.Matrices) ![]Column {
    var list: std.ArrayList(Column) = .empty;
    errdefer list.deinit(a);
    try list.appendSlice(a, matrices.destination.columns[0..A.Spec(.destination).FIXED_COUNT]);
    try list.appendSlice(a, matrices.source.columns[0..A.Spec(.source).FIXED_COUNT]);
    try list.appendSlice(a, matrices.bytes.columns[0..A.Spec(.bytes).FIXED_COUNT]);
    try list.appendSlice(a, matrices.boundary.columns[0..A.Spec(.boundary).FIXED_COUNT]);
    try list.appendSlice(a, matrices.endpoints.columns[0..A.EndpointSpec.FIXED_COUNT]);
    try list.appendSlice(a, matrices.range16.columns[0..A.RangeSpec.FIXED_COUNT]);
    return list.toOwnedSlice(a);
}
pub fn produce(a: std.mem.Allocator, trusted: Trusted, witness: Witness) !*Proof {
    const scope = try Scope.Scope.create(a, trusted);
    defer scope.deinit();
    var stage = try Stage.create(a, scope, witness);
    defer stage.deinit();
    return produceStage(a, scope, &stage);
}
/// Explicit staged entry point supports mathematical mutation qualification.
/// No forged host acceptance, successful receipt, or skipped equations exist.
pub fn produceStage(a: std.mem.Allocator, scope: *const Scope.Scope, stage: *const Stage) !*Proof {
    var scheme = try Scheme.init(a, scope.trusted.config);
    var owned_scheme = true;
    defer if (owned_scheme) scheme.deinit(a);
    var channel = S.Channel{};
    scope.mix(&channel);
    const fixed = try fixedColumns(a, &stage.matrices);
    defer a.free(fixed);
    try scheme.commitBorrowedStreaming(a, fixed, 8, &channel);
    try scheme.commitBorrowedStreaming(a, stage.matrices.destination.columns[A.Spec(.destination).FIXED_COUNT..], 8, &channel);
    try scheme.commitBorrowedStreaming(a, stage.matrices.source.columns[A.Spec(.source).FIXED_COUNT..], 8, &channel);
    try scheme.commitBorrowedStreaming(a, stage.matrices.bytes.columns[A.Spec(.bytes).FIXED_COUNT..], 8, &channel);
    try scheme.commitBorrowedStreaming(a, stage.matrices.boundary.columns[A.Spec(.boundary).FIXED_COUNT..], 8, &channel);
    try scheme.commitBorrowedStreaming(a, stage.matrices.endpoints.columns[A.EndpointSpec.FIXED_COUNT..], 8, &channel);
    try scheme.commitBorrowedStreaming(a, stage.matrices.range16.columns[A.RangeSpec.FIXED_COUNT..], 8, &channel);
    const drawn = try A.draw(a, &channel);
    var generated = try Generated.create(a, scope, stage, drawn);
    defer generated.deinit();
    const claims = generated.claims();
    try recordClaims(&channel, claims);
    _ = try close(scope, drawn, claims);
    try scheme.commitBorrowedStreaming(a, generated.destination.matrix.columns, 8, &channel);
    try scheme.commitBorrowedStreaming(a, generated.source.matrix.columns, 8, &channel);
    try scheme.commitBorrowedStreaming(a, generated.bytes.matrix.columns, 8, &channel);
    try scheme.commitBorrowedStreaming(a, generated.boundary.matrix.columns, 8, &channel);
    try scheme.commitBorrowedStreaming(a, generated.endpoints.matrix.columns, 8, &channel);
    try scheme.commitBorrowedStreaming(a, generated.range16.matrix.columns, 8, &channel);
    const components = try Owner(true).create(a, scope, drawn, claims);
    defer components.deinit();
    const out = try a.create(Proof);
    errdefer a.destroy(out);
    owned_scheme = false;
    out.* = .{ .allocator = a, .claims = claims, .stark = try engine.prove.prove(Cpu, S.Hasher, S.MerkleChannel, a, components.placed.?.handles, &channel, scheme) };
    return out;
}
pub fn verify(a: std.mem.Allocator, trusted: Trusted, stark: *const S.Proof, claims: Claims) !Summary {
    const scope = try Scope.Scope.create(a, trusted);
    defer scope.deinit();
    const roots = stark.commitment_scheme_proof.commitments.items;
    if (roots.len != 14 or !std.meta.eql(stark.commitment_scheme_proof.config, trusted.config)) return error.UntrustedByteLoopProofGeometry;
    var fixed = try Scope.fixed(a, scope);
    defer fixed.deinit();
    const fixed_columns = try fixedColumns(a, &fixed);
    defer a.free(fixed_columns);
    var key = try Scheme.init(a, trusted.config);
    defer key.deinit(a);
    var ignored = S.Channel{};
    try key.commitBorrowedStreaming(a, fixed_columns, 8, &ignored);
    if (!std.meta.eql(key.trees.items[0].root(), roots[0])) return error.UntrustedByteLoopFixedKey;
    const fixed_logs = try a.alloc(u32, fixed_columns.len);
    defer a.free(fixed_logs);
    for (fixed_columns, fixed_logs) |column, *log| log.* = column.log_size;
    const destination_main: [33]u32 = @splat(scope.destination_log);
    const source_main: [5]u32 = @splat(scope.source_log);
    const bytes_main: [1]u32 = .{8};
    const boundary_main: [1]u32 = .{4};
    const endpoint_main: [23]u32 = @splat(scope.endpoint_log);
    const range_main: [1]u32 = .{16};
    const first_logs = [_][]const u32{ fixed_logs, &destination_main, &source_main, &bytes_main, &boundary_main, &endpoint_main, &range_main };
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(S.Hasher, S.MerkleChannel).init(a, trusted.config);
    defer verifier.deinit(a);
    var channel = S.Channel{};
    scope.mix(&channel);
    for (first_logs, 0..) |logs, i| try verifier.commit(a, roots[i], logs, &channel);
    const drawn = try A.draw(a, &channel);
    try recordClaims(&channel, claims);
    const destination_interaction: [24]u32 = @splat(scope.destination_log);
    const source_interaction: [20]u32 = @splat(scope.source_log);
    const bytes_interaction: [8]u32 = @splat(8);
    const boundary_interaction: [12]u32 = @splat(4);
    const endpoint_interaction: [52]u32 = @splat(scope.endpoint_log);
    const range_interaction: [8]u32 = @splat(16);
    const interaction_logs = [_][]const u32{ &destination_interaction, &source_interaction, &bytes_interaction, &boundary_interaction, &endpoint_interaction, &range_interaction };
    for (interaction_logs, 0..) |logs, i| try verifier.commit(a, roots[7 + i], logs, &channel);
    const components = try Owner(false).create(a, scope, drawn, claims);
    defer components.deinit();
    var capture: core.verifier.ProofCapture(S.Hasher) = undefined;
    try core.verifier.verifyBorrowedWithProofCapture(S.Hasher, S.MerkleChannel, a, components.placed.?.handles, &channel, &verifier, stark, &capture);
    defer capture.deinit(a);
    return close(scope, drawn, claims);
}
pub fn encode(a: std.mem.Allocator, proof: *const Proof) ![]u8 {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(a);
    try postcard.serializeProof(S.Hasher, encoded.writer(a), proof.stark);
    if (encoded.items.len > 16 << 20) return error.ByteLoopResourceLimit;
    const header = 20 + 31 * 16;
    const out = try a.alloc(u8, header + encoded.items.len);
    errdefer a.free(out);
    @memcpy(out[0..8], "B8BYTPL1");
    std.mem.writeInt(u32, out[8..12], 1, .little);
    std.mem.writeInt(u32, out[12..16], 31, .little);
    std.mem.writeInt(u32, out[16..20], @intCast(encoded.items.len), .little);
    var offset: usize = 20;
    inline for (.{ "destination", "source", "bytes", "boundary", "endpoints", "range16" }) |name| for (@field(proof.claims, name)) |claim| for (claim.toM31Array()) |limb| {
        std.mem.writeInt(u32, out[offset..][0..4], limb.v, .little);
        offset += 4;
    };
    @memcpy(out[header..], encoded.items);
    return out;
}
pub fn verifyBytes(a: std.mem.Allocator, trusted: Trusted, raw: []const u8) !Summary {
    const header = 20 + 31 * 16;
    if (raw.len < header or raw.len > (16 << 20) + header or !std.mem.eql(u8, raw[0..8], "B8BYTPL1") or std.mem.readInt(u32, raw[8..12], .little) != 1 or std.mem.readInt(u32, raw[12..16], .little) != 31 or std.mem.readInt(u32, raw[16..20], .little) != raw.len - header) return error.InvalidByteLoopEnvelope;
    var claims: Claims = undefined;
    var offset: usize = 20;
    inline for (.{ "destination", "source", "bytes", "boundary", "endpoints", "range16" }) |name| for (&@field(claims, name)) |*claim| {
        var limbs: [4]M = undefined;
        for (&limbs) |*limb| {
            const value = std.mem.readInt(u32, raw[offset..][0..4], .little);
            if (value >= core.fields.m31.Modulus) return error.InvalidByteLoopPhysicalClaim;
            limb.* = M.fromCanonical(value);
            offset += 4;
        }
        claim.* = Q.fromM31Array(limbs);
    };
    const scope = try Scope.Scope.create(a, trusted);
    defer scope.deinit();
    const counts = [_]u32{ 45, 33, 5, 1, 1, 23, 1, 24, 20, 8, 12, 52, 8, 16 };
    const empty: [14]bool = @splat(false);
    const widths: [14]u32 = @splat(6);
    const config = trusted.config;
    try postcard.proof_preflight.validateRuntime(raw[header..], .{ .config = .{ .pow_bits = config.pow_bits, .log_blowup_factor = config.fri_config.log_blowup_factor, .n_queries = config.fri_config.n_queries, .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound, .fold_step = config.fri_config.fold_step, .lifting_log_size = config.lifting_log_size }, .tree_columns = &counts, .empty_tree_flags = &empty, .sample_width_limits = &widths, .allow_zero_samples = false, .max_column_log_size = @as(u32, 16), .max_merkle_column_log_size = @as(u32, 16), .hash_size = 32, .max_wire_bytes = 16 << 20 });
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var stream = std.io.fixedBufferStream(raw[header..]);
    const stark = try postcard.deserializeProof(S.Hasher, arena.allocator(), stream.reader());
    if (stream.pos != raw.len - header) return error.InvalidByteLoopEnvelope;
    return verify(a, trusted, &stark, claims);
}
