//! Pure public-byte and equation fixtures. No native/provider/root proof or
//! cryptographic positive admission is synthesized or invoked by these tests.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Public = @import("../air/public_data.zig");
const Fields = @import("../recursion/block_v5_global_public_fields_v1.zig");
const Tuple = @import("../recursion/air/block_v5_global_public_tuple_algebra_v1.zig");
const R = @import("../recursion/air/composition_graph_recorder.zig");
const U = @import("../recursion/air/universal_challenges.zig");
const Domain = @import("../air/lang/relation.zig").Domain;
const Fixture = struct {
    input: [2]u32 = .{ 0xfefd1234, 0x7fffffff },
    data: Public.Blake3PublicData = undefined,
    fn init(self: *@This()) void {
        self.data = .{ .initial_pc = 0x1000, .final_pc = 0x1020, .clock = 9, .initial_regs = @splat(0), .final_regs = @splat(0), .reg_last_clock = @splat(0), .program_root = .{ .bytes = @splat(0xA5) }, .initial_rw_root = .{ .bytes = @splat(0x11) }, .final_rw_root = .{ .bytes = @splat(0x22) }, .completion = Public.Completion.canonicalSelfLoop(0x1020), .io_entries = .{ .input_start = 0x10000, .input_len = 8, .input_words = &self.input, .output_len = 0, .output_len_addr = 0x20000, .output_data_addr = 0x20004, .output_words = &.{} } };
        self.data.initial_regs[1] = 0xffee12a5;
        self.data.final_regs[1] = 0x80ff5678;
        self.data.reg_last_clock[1] = @import("../access_clock.zig").encode(9, .third);
    }
};
fn fieldsFixture(a: std.mem.Allocator) !void {
    var fixture: Fixture = .{};
    fixture.init();
    var fields = try Fields.init(a, &fixture.data, .rv32im_zkvm_v1, 0x100000005, 0x10000000D, .{});
    defer fields.deinit();
    try fields.validate(&fixture.data, .rv32im_zkvm_v1, 0x100000005, 0x10000000D);
    try std.testing.expect(fields.borrowed_input.ptr == fixture.input[0..].ptr);
    const chunk = fields.chunks[12];
    try std.testing.expect(!chunk.owned and chunk.words.ptr == fixture.input[0..].ptr);
    try std.testing.expectEqual(@as(u32, 0xffee12a5), try fields.word(fields.layout.initial + 1));
    try std.testing.expectEqual(@as(u32, 1), try fields.word(fields.layout.cycles + 1));
    const native_digest = @import("block_v5_native_public_admission_v1.zig").publicDigest(&fixture.data);
    try std.testing.expectEqualSlices(u8, &native_digest, &fields.source_digest);
}
test "global public export: original B5PD framing preserves full words and borrows shared input" {
    try fieldsFixture(std.testing.allocator);
}
test "global public export: canonical decoder cycles input and zero clock mutations reject" {
    var fixture: Fixture = .{};
    fixture.init();
    var fields = try Fields.init(std.testing.allocator, &fixture.data, .rv32im_zkvm_v1, 1, 9, .{});
    defer fields.deinit();
    const decoded = @constCast(fields.chunks[fields.hashed_chunks].words);
    decoded[1] ^= 1;
    try std.testing.expectError(error.UntrustedGlobalPublicDecode, fields.validate(&fixture.data, .rv32im_zkvm_v1, 1, 9));
    decoded[1] ^= 1;
    const cycles = @constCast(fields.chunks[fields.hashed_chunks + 1].words);
    cycles[1] = 1;
    try std.testing.expectError(error.UntrustedGlobalPublicFields, fields.validate(&fixture.data, .rv32im_zkvm_v1, 1, 9));
    cycles[1] = 0;
    const original_count = fields.hashed_chunks;
    fields.hashed_chunks = std.math.maxInt(usize);
    try std.testing.expectError(error.UntrustedGlobalPublicFields, fields.validate(&fixture.data, .rv32im_zkvm_v1, 1, 9));
    fields.hashed_chunks = original_count;
    fixture.input[1] ^= 1;
    try std.testing.expectError(error.UntrustedGlobalPublicFields, fields.validate(&fixture.data, .rv32im_zkvm_v1, 1, 9));
    fixture.input[1] ^= 1;
    fixture.data.clock = 0;
    fixture.data.reg_last_clock = @splat(0);
    try std.testing.expectError(error.UntrustedGlobalPublicFields, fields.validate(&fixture.data, .rv32im_zkvm_v1, 1, 9));
}
test "global public export: metadata and word caps precede clone and exhaustively roll back" {
    var fixture: Fixture = .{};
    fixture.init();
    try std.testing.expectError(error.GlobalPublicResourceLimit, Fields.init(std.testing.allocator, &fixture.data, .rv32im_zkvm_v1, 1, 9, .{ .max_words = 1 }));
    try std.testing.expectError(error.GlobalPublicResourceLimit, Fields.init(std.testing.allocator, &fixture.data, .rv32im_zkvm_v1, 1, 9, .{ .max_metadata_bytes = 1 }));
    try std.testing.checkAllAllocationFailures(std.testing.allocator, fieldsFixture, .{});
}
fn word(value: u32) [4]Q {
    var result: [4]Q = undefined;
    for (&result, 0..) |*byte, part| byte.* = Q.fromBase(M.fromCanonical((value >> @as(u5, @intCast(8 * part))) & 255));
    return result;
}
fn wide(value: u64) [8]Q {
    return word(@truncate(value)) ++ word(@truncate(value >> 32));
}
fn tupleData(data: *const Public.Blake3PublicData) !Tuple.Data(Q) {
    var result: Tuple.Data(Q) = undefined;
    result.initial_pc = word(data.initial_pc);
    result.final_pc = word(data.final_pc);
    result.clock = word(data.clock);
    for (&result.initial, &result.final, &result.clocks, data.initial_regs, data.final_regs, data.reg_last_clock) |*first, *last, *clock, a, b, c| {
        first.* = word(a);
        last.* = word(b);
        clock.* = word(c);
    }
    result.completion_address = word(data.completion.?.address);
    const decoded = try @import("../air/program/decode.zig").decodeProgramWordForProfile(.rv32im_zkvm_v1, data.completion.?.value);
    for (&result.decoded, decoded) |*target, value| target.* = word(value);
    result.first_cycle = wide(1);
    result.last_cycle = wide(data.clock);
    return result;
}
const NativeRelations = struct {
    relations: *const U.UniversalRelations,
    const Element = struct {
        original: *const U.Elements,
        pub fn combine(self: @This(), values: []const Q) !Q {
            return self.original.combineSecure(values);
        }
    };
    pub fn getExact(self: @This(), domain: Domain) !Element {
        return .{ .original = try self.relations.getExact(domain) };
    }
};
fn relations(a: std.mem.Allocator) !U.UniversalRelations {
    var channel = @import("block_v5_universal_channel_v1.zig").init(@splat(0x42));
    return U.UniversalRelations.draw(a, &channel);
}
fn oracle(a: std.mem.Allocator, data: *const Public.Blake3PublicData) !Tuple.Results(Q) {
    const r = try relations(a);
    const Elements = @import("../air/relation_challenges.zig").RelationElements;
    const state = try r.getExact(.registers_state);
    const memory = try r.getExact(.memory_access);
    const native = .{
        .registers_state = Elements(2).init(state.z, state.alpha),
        .memory_access = Elements(7).init(memory.z, memory.alpha),
    };
    return .{ .native_compensation = try @import("../air/public_logup_arithmetic.zig").registersStateSumFor(Q, data, &native), .register_compensation = try @import("../air/public_logup_arithmetic.zig").nonzeroRegisterMemoryAccessSumFor(Q, data, &native), .program_boundary = (try @import("block_v5_program_boundary_v1.zig").deriveFromPinnedNativePublic(.rv32im_zkvm_v1, data, &r)).sum };
}
test "global public export: exact native register and terminal tuples preserve high bytes and signs" {
    var fixture: Fixture = .{};
    fixture.init();
    const r = try relations(std.testing.allocator);
    const expected = try oracle(std.testing.allocator, &fixture.data);
    const actual = try Tuple.evaluate(Q, try tupleData(&fixture.data), NativeRelations{ .relations = &r }, true, true);
    inline for (std.meta.fields(Tuple.Results(Q))) |field| try std.testing.expect(@field(actual, field.name).eql(@field(expected, field.name)));
    const halt = try Tuple.evaluate(Q, try tupleData(&fixture.data), NativeRelations{ .relations = &r }, true, false);
    try std.testing.expect(halt.program_boundary.isZero());
    var changed = try tupleData(&fixture.data);
    changed.initial[1][3] = changed.initial[1][3].sub(Q.one());
    const bad = try Tuple.evaluate(Q, changed, NativeRelations{ .relations = &r }, true, true);
    try std.testing.expect(!bad.register_compensation.eql(actual.register_compensation));
}
const SinkQ = struct {
    pub fn zero(_: *@This(), value: Q, failure: anyerror) !void {
        if (!value.isZero()) return failure;
    }
};
test "global public export: full u64 byte carry rejects wrap gaps and reordered windows" {
    var sink = SinkQ{};
    try Tuple.nextCycle(Q, &sink, wide(0x1234FFFFFFFF), wide(0x123500000000));
    try std.testing.expectError(error.UntrustedGlobalPublicCycleBoundary, Tuple.nextCycle(Q, &sink, wide(0x1234FFFFFFFF), wide(0x123500000001)));
    try std.testing.expectError(error.UntrustedGlobalPublicCycleBoundary, Tuple.nextCycle(Q, &sink, wide(std.math.maxInt(u64)), wide(0)));
    try Tuple.initialCycle(Q, &sink, wide(1));
    try std.testing.expectError(error.UntrustedGlobalPublicCycleBoundary, Tuple.initialCycle(Q, &sink, wide(0x100000001)));
}
fn symbolize(comptime Out: type, value: anytype, builder: *R.Builder, inputs: *std.ArrayList(Q)) !Out {
    if (Out == R.Scalar) {
        try inputs.append(builder.allocator, value);
        return (try builder.input()).value;
    }
    var result: Out = undefined;
    switch (@typeInfo(Out)) {
        .array => |array| for (&result, 0..) |*target, index| {
            target.* = try symbolize(array.child, value[index], builder, inputs);
        },
        .@"struct" => inline for (std.meta.fields(Out)) |field| {
            @field(result, field.name) = try symbolize(field.type, @field(value, field.name), builder, inputs);
        },
        else => @compileError("invalid public tuple symbolic shape"),
    }
    return result;
}
const SymbolicRelations = struct {
    set: R.ChallengeSet,
    pub fn getExact(self: *const @This(), domain: Domain) !*const R.ChallengeSet.Element {
        return self.set.get(domain);
    }
};
fn graphFixture(a: std.mem.Allocator) !void {
    var fixture: Fixture = .{};
    fixture.init();
    const expected = try oracle(a, &fixture.data);
    const r = try relations(a);
    var builder = R.Builder.init(a);
    defer builder.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    defer inputs.deinit(a);
    const data = try symbolize(Tuple.Data(R.Scalar), try tupleData(&fixture.data), &builder, &inputs);
    var draws: [U.RELATION_COUNT][2]R.Scalar = undefined;
    for (&draws, r.elements) |*pair, element| {
        pair[0] = try symbolize(R.Scalar, element.z, &builder, &inputs);
        pair[1] = try symbolize(R.Scalar, element.alpha_powers[1], &builder, &inputs);
    }
    const anchored = try symbolize(Tuple.Results(R.Scalar), expected, &builder, &inputs);
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    var challenges = SymbolicRelations{ .set = try R.ChallengeSet.init(draws) };
    const actual = try Tuple.evaluate(R.Scalar, data, &challenges, true, true);
    inline for (std.meta.fields(Tuple.Results(R.Scalar))) |field| {
        try builder.check();
        try builder.constrainZero(@field(actual, field.name).sub(@field(anchored, field.name)));
    }
    try builder.check();
    builder.deactivate();
    var circuit = try builder.finish();
    defer circuit.deinit();
    const values = try a.alloc(Q, circuit.nodes.len);
    defer a.free(values);
    try circuit.evaluateInto(inputs.items, values);
    // initial register 1 high byte is a genuine scalar input, not a reduced word.
    inputs.items[12 + 4 + 3] = inputs.items[12 + 4 + 3].sub(Q.one());
    if (circuit.evaluateInto(inputs.items, values)) |_| return error.ExpectedTupleMutationRejection else |failure| {
        if (failure == error.OutOfMemory) return failure;
        try std.testing.expectEqual(error.UnsatisfiedCircuit, failure);
    }
}
test "global public export: original scalar oracle and symbolic inverse graph reject byte substitution" {
    try graphFixture(std.testing.allocator);
}
test "global public export: symbolic construction keeps original allocation error and exact cleanup" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, graphFixture, .{});
}
test "global public export: complete source authority remains unavailable" {
    try std.testing.expect(!@import("../recursion/block_v5_global_public_export_parent_v1.zig").Prepared.complete_block_authority);
    try std.testing.expect(!@import("../recursion/block_v5_global_public_export_receiver_v1.zig").OpenEquation.complete_block_authority);
}
