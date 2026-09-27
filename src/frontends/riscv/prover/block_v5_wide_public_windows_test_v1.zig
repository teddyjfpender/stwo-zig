//! Only independent pure math/layout fixtures; no successful cryptographic
//! admission, capture, guest, PCS/STARK or root proof is synthesized here.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const R = @import("../recursion/air/composition_graph_recorder.zig");
const G = @import("../recursion/air/block_v5_wide_public_windows_composition_v1.zig");
const P = @import("../recursion/block_v5_wide_public_windows_v1.zig");
const Tuple = @import("../recursion/air/block_v5_global_public_tuple_algebra_v1.zig");
const U = @import("../recursion/air/universal_challenges.zig");
const Domain = @import("../air/lang/relation.zig").Domain;
const Data = @import("../air/public_data.zig");
fn word(raw: u32) [4]Q {
    var out: [4]Q = undefined;
    for (&out, 0..) |*byte, part| byte.* = Q.fromBase(M.fromCanonical((raw >> @as(u5, @intCast(8 * part))) & 255));
    return out;
}
fn wide(raw: u64) [8]Q {
    return word(@truncate(raw)) ++ word(@truncate(raw >> 32));
}
fn tuple(data: *const Data.Blake3PublicData, first: u64) !Tuple.Data(Q) {
    var out: Tuple.Data(Q) = undefined;
    out.initial_pc = word(data.initial_pc);
    out.final_pc = word(data.final_pc);
    out.clock = word(data.clock);
    out.completion_address = word(data.completion.?.address);
    for (&out.initial, &out.final, &out.clocks, data.initial_regs, data.final_regs, data.reg_last_clock) |*a, *b, *c, x, y, z| {
        a.* = word(x);
        b.* = word(y);
        c.* = word(z);
    }
    const decoded = try @import("../air/program/decode.zig").decodeProgramWordForProfile(.rv32im_zkvm_v1, data.completion.?.value);
    for (&out.decoded, decoded) |*a, x| a.* = word(x);
    out.first_cycle = wide(first);
    out.last_cycle = wide(try std.math.add(u64, first, data.clock - 1));
    return out;
}
fn fixture() Data.Blake3PublicData {
    var data = Data.Blake3PublicData{ .initial_pc = 0x1000, .final_pc = 0x1020, .clock = 9, .initial_regs = @splat(0), .final_regs = @splat(0), .reg_last_clock = @splat(0), .program_root = .{ .bytes = @splat(1) }, .initial_rw_root = .{ .bytes = @splat(2) }, .final_rw_root = .{ .bytes = @splat(3) }, .completion = Data.Completion.canonicalSelfLoop(0x1020), .io_entries = .{ .input_start = 0x10000, .input_len = 0, .input_words = &.{}, .output_len = 0, .output_len_addr = 0x20000, .output_data_addr = 0x20004, .output_words = &.{} } };
    data.initial_regs[1] = 0xffee1234;
    data.final_regs[1] = 0xaabbccdd;
    data.reg_last_clock[1] = @import("../access_clock.zig").encode(9, .third);
    return data;
}
fn oracle(data: *const Data.Blake3PublicData, relations: *const U.UniversalRelations) !P.Terms {
    const E = @import("../air/relation_challenges.zig").RelationElements;
    const state = try relations.getExact(.registers_state);
    const memory = try relations.getExact(.memory_access);
    const native = .{ .registers_state = E(2).init(state.z, state.alpha), .memory_access = E(7).init(memory.z, memory.alpha) };
    const arithmetic = @import("../air/public_logup_arithmetic.zig");
    return .{ try arithmetic.registersStateSumFor(Q, data, &native), try arithmetic.nonzeroRegisterMemoryAccessSumFor(Q, data, &native), (try @import("block_v5_program_boundary_v1.zig").deriveFromPinnedNativePublic(.rv32im_zkvm_v1, data, relations)).sum };
}
fn auxiliary(first: u64, clock: u32) ![9][4]Q {
    const carries = try @import("../recursion/block_v5_wide_native_public_values_v1.zig").addCarries(first, clock - 1);
    const inc = try @import("../recursion/air/block_v5_recursive_u64_span_v1.zig").carries(clock - 1);
    var out: [9][4]Q = undefined;
    out[0] = word(clock - 1);
    for (0..4) |i| {
        out[1 + i] = word(carries[i]);
        out[5 + i] = word(inc[i]);
    }
    return out;
}
const Relations = struct {
    inner: *const U.UniversalRelations,
    const Element = struct {
        inner: *const U.Elements,
        pub fn combine(self: @This(), values: []const Q) !Q {
            return self.inner.combineSecure(values);
        }
    };
    pub fn getExact(self: @This(), domain: Domain) !Element {
        return .{ .inner = try self.inner.getExact(domain) };
    }
};
const SinkQ = struct {
    pub fn zero(_: *@This(), value: Q, failure: anyerror) !void {
        if (!value.isZero()) return failure;
    }
};
test "wide public windows: independent native oracle matches full-width compensation and count equations" {
    const data = fixture();
    const relations = U.UniversalRelations.dummy();
    const terms = try oracle(&data, &relations);
    var sink = SinkQ{};
    for ([_]u64{ 1, (1 << 30) - 1, (1 << 32) - 1, (1 << 63) - 1, std.math.maxInt(u64) - 8 }) |first| try G.windowEquations(Q, &sink, try tuple(&data, first), Relations{ .inner = &relations }, true, terms[0], terms, try auxiliary(first, data.clock));
    var modified = terms;
    modified[1] = modified[1].neg();
    try std.testing.expectError(error.UntrustedWidePublicTerms, G.windowEquations(Q, &sink, try tuple(&data, 1), Relations{ .inner = &relations }, true, terms[0], modified, try auxiliary(1, data.clock)));
    try std.testing.expectError(error.UntrustedWidePublicNativeClaims, G.windowEquations(Q, &sink, try tuple(&data, 1), Relations{ .inner = &relations }, true, terms[0].add(Q.one()), terms, try auxiliary(1, data.clock)));
}
test "wide public windows: high clock carry x0 and count faults reject" {
    const data = fixture();
    const relations = U.UniversalRelations.dummy();
    const terms = try oracle(&data, &relations);
    const first: u64 = (1 << 32) - 1;
    var sink = SinkQ{};
    var d = try tuple(&data, first);
    d.last_cycle[7] = Q.one();
    try std.testing.expectError(error.UnclosedWideNativeSpan, G.windowEquations(Q, &sink, d, Relations{ .inner = &relations }, true, terms[0], terms, try auxiliary(first, data.clock)));
    d = try tuple(&data, first);
    d.initial[0][0] = Q.one();
    try std.testing.expectError(error.UntrustedX0LocalPublicBoundary, G.windowEquations(Q, &sink, d, Relations{ .inner = &relations }, true, terms[0], terms, try auxiliary(first, data.clock)));
    var aux = try auxiliary(first, data.clock);
    aux[2][0] = Q.fromBase(M.fromCanonical(2));
    try std.testing.expectError(error.NonbooleanWideNativeCarry, G.windowEquations(Q, &sink, try tuple(&data, first), Relations{ .inner = &relations }, true, terms[0], terms, aux));
    aux = try auxiliary(first, data.clock);
    aux[1][1] = Q.one();
    try std.testing.expectError(error.UntrustedWidePublicCarry, G.windowEquations(Q, &sink, try tuple(&data, first), Relations{ .inner = &relations }, true, terms[0], terms, aux));
}
fn symbolize(comptime T: type, value: anytype, b: *R.Builder, inputs: *std.ArrayList(Q)) !T {
    if (T == R.Scalar) {
        try inputs.append(b.allocator, value);
        return (try b.input()).value;
    }
    var result: T = undefined;
    switch (@typeInfo(T)) {
        .array => |arr| for (&result, 0..) |*entry, i| {
            entry.* = try symbolize(arr.child, value[i], b, inputs);
        },
        .@"struct" => inline for (std.meta.fields(T)) |field| {
            @field(result, field.name) = try symbolize(field.type, @field(value, field.name), b, inputs);
        },
        else => @compileError("invalid fixture shape"),
    }
    return result;
}
const SymbolicRelations = struct {
    set: R.ChallengeSet,
    pub fn getExact(self: *const @This(), domain: Domain) !*const R.ChallengeSet.Element {
        return self.set.get(domain);
    }
};
const Sink = struct {
    b: *R.Builder,
    pub fn zero(self: *@This(), value: R.Scalar, _: anyerror) !void {
        try self.b.check();
        try self.b.constrainZero(value);
    }
};
fn graphFixture(a: std.mem.Allocator) !void {
    const original = fixture();
    const relations = U.UniversalRelations.dummy();
    const expected = try oracle(&original, &relations);
    var builder = R.Builder.init(a);
    defer builder.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    defer inputs.deinit(a);
    const data = try symbolize(Tuple.Data(R.Scalar), try tuple(&original, (1 << 32) - 1), &builder, &inputs);
    const exported = try symbolize([3]R.Scalar, expected, &builder, &inputs);
    const aux = try symbolize([9][4]R.Scalar, try auxiliary((1 << 32) - 1, original.clock), &builder, &inputs);
    var draws: [U.RELATION_COUNT][2]R.Scalar = undefined;
    for (&draws, relations.elements) |*pair, element| {
        pair[0] = try symbolize(R.Scalar, element.z, &builder, &inputs);
        pair[1] = try symbolize(R.Scalar, element.alpha, &builder, &inputs);
    }
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    var sink = Sink{ .b = &builder };
    var challenges = SymbolicRelations{ .set = try R.ChallengeSet.init(draws) };
    try G.windowEquations(R.Scalar, &sink, data, &challenges, true, exported[0], exported, aux);
    try builder.check();
    builder.deactivate();
    var circuit = try builder.finish();
    defer circuit.deinit();
    const values = try a.alloc(Q, circuit.nodes.len);
    defer a.free(values);
    try circuit.evaluateInto(inputs.items, values);
    inputs.items[12 + 4 + 3] = inputs.items[12 + 4 + 3].sub(Q.one());
    const check = circuit.evaluateInto(inputs.items, values);
    if (check) |_| return error.TestUnexpectedSuccess else |failure| {
        if (failure == error.OutOfMemory) return failure;
        try std.testing.expectEqual(error.UnsatisfiedCircuit, failure);
    }
}
test "wide public windows: actual symbolic equation graph rejects original high-byte mutation" {
    try graphFixture(std.testing.allocator);
}
test "wide public windows: symbolic graph construction rolls back exhaustive OOM" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, graphFixture, .{});
}
test "wide public windows: layout keeps million-word input lengths out of bounded lower frame extents" {
    const input: u32 = (1 << 20) + 1;
    var cursor: u32 = 38 + 64;
    const first = try P.layoutFor(&cursor, 128, input + 256, input);
    const second = try P.layoutFor(&cursor, 128, input + 300, input);
    try std.testing.expectEqual(@as(u32, 256), first.public_words);
    try std.testing.expectEqual(@as(u32, 300), second.public_words);
    try std.testing.expectEqual(@as(u32, 38 + 64 + 128 + 256 + 29 + 128 + 300 + 29), cursor);
    try std.testing.expect(second.original_first == first.terms_first + 12);
    var bad: u32 = std.math.maxInt(u32) - 10;
    try std.testing.expectError(error.Overflow, P.layoutFor(&bad, 128, 1, 0));
    bad = 0;
    try std.testing.expectError(error.Overflow, P.layoutFor(&bad, 0, 1, 2));
    try std.testing.expect(!P.Owner.complete_block_authority);
}
test "wide public windows: u64 adjacency gap wrap and register endpoint mutations reject" {
    var sink = SinkQ{};
    try Tuple.nextCycle(Q, &sink, wide((1 << 32) - 1), wide(1 << 32));
    try std.testing.expectError(error.UntrustedGlobalPublicCycleBoundary, Tuple.nextCycle(Q, &sink, wide((1 << 32) - 1), wide((1 << 32) + 1)));
    try std.testing.expectError(error.UntrustedGlobalPublicCycleBoundary, Tuple.nextCycle(Q, &sink, wide(std.math.maxInt(u64)), wide(0)));
    const left: [32][4]Q = @splat(@splat(Q.zero()));
    var right = left;
    right[31][3] = Q.one();
    try std.testing.expectError(error.UntrustedGlobalPublicRegisterBoundary, Tuple.registerContinuity(Q, &sink, left, right));
}

const Input = @import("../recursion/block_v5_wide_expected_input_owner_v1.zig");
test "wide public windows: expected input root has exact length word order and high byte framing" {
    const a = try Input.derive(&.{ 0xffffffff, 0x80000000 });
    const b = try Input.derive(&.{ 0x80000000, 0xffffffff });
    const c = try Input.derive(&.{ 0xffffffff, 0x80000000, 0 });
    try std.testing.expect(!std.meta.eql(a.root, b.root));
    try std.testing.expect(!std.meta.eql(a.root, c.root));
    var oracle_hash = std.crypto.hash.Blake3.init(.{});
    oracle_hash.update("stwo-zig/block-v5/expected-public-input-root/v1\x00");
    oracle_hash.update(&.{ 2, 0, 0, 0, 0, 0, 0, 0 });
    oracle_hash.update(&.{ 255, 255, 255, 255, 0, 0, 0, 128 });
    var root: [32]u8 = undefined;
    oracle_hash.final(&root);
    try std.testing.expectEqualSlices(u8, &root, &a.root);
    try std.testing.expectEqual(@as(u32, 2), a.word_count);
    try std.testing.expect(!Input.Owned.input_digest_link_proved);
}
fn inputOwnerFixture(a: std.mem.Allocator) !void {
    const Job = @import("../recursion/block_v5_global_expected_public_job_v1.zig");
    const File = @import("block_v5_global_expected_public_file_v1.zig");
    const Windows = @import("block_v5_register_windows_v1.zig");
    var data = fixture();
    const input = [_]u32{ 0xffffffff, 0x80000000 };
    data.io_entries.input_words = &input;
    data.io_entries.input_len = 8;
    const windows = [_]Job.Window{.{ .profile = .rv32im_zkvm_v1, .first_cycle = 1, .last_cycle = 9, .data = Job.Data.fromPublic(&data) }};
    const registers = [_]Windows.Window{Windows.Window.fromPublic(0, 1, &data)};
    const expected = Job.Expected{ .coverage_digest = @splat(1), .seal_digest = @splat(2), .recipe = 1, .input_words = &input, .windows = &windows, .register_plan = .{ .version = Windows.LOCAL_ZERO_VERSION, .initial_registers = data.initial_regs, .final_registers = data.final_regs, .windows = &registers } };
    const raw = try File.encode(a, expected, .{});
    defer a.free(raw);
    const file = try File.decode(a, raw, .{ .byte_len = raw.len, .sha256 = @import("block_v5_artifact_files_v1.zig").hash(raw) }, expected, .{});
    defer file.deinit();
    const retained = try Input.Owned.init(a, file);
    defer retained.deinit();
    const independent = try Input.derive(expected.input_words);
    try retained.require(independent);
    const lease = try retained.retain();
    defer lease.deinit();
    try std.testing.expectEqual(@as(usize, 2), retained.references.load(.acquire));
    var changed = independent;
    changed.root[31] ^= 1;
    try std.testing.expectError(error.UntrustedWideExpectedInput, retained.require(changed));
    changed = independent;
    changed.word_count += 1;
    try std.testing.expectError(error.UntrustedWideExpectedInput, retained.require(changed));
    const original = retained.cached;
    retained.cached.root[0] ^= 1;
    try std.testing.expectError(error.UntrustedWideExpectedInput, retained.require(independent));
    retained.cached = original;
}
test "wide public windows: retained input root rejects cache mutation against independent expectation" {
    try inputOwnerFixture(std.testing.allocator);
}
test "wide public windows: input owner retain construction and file custody exhaustively roll back OOM" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, inputOwnerFixture, .{});
}

test "wide public windows: independent contiguous fan-in rejects rounding gaps overflow and oversized roots" {
    try std.testing.expectEqual(@as(u32, 7), try (P.Range{ .first = 3, .count = 4 }).require(9));
    try std.testing.expectEqual(@as(u32, 9), try (P.Range{ .first = 7, .count = 2 }).require(9));
    for ([_]P.Range{ .{ .first = 0, .count = 0 }, .{ .first = 0, .count = 5 }, .{ .first = 8, .count = 2 }, .{ .first = std.math.maxInt(u32), .count = 1 } }) |range| try std.testing.expectError(error.UntrustedWidePublicWindowRoster, range.require(9));
}
