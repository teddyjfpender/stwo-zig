//! Genuine execution-backed AIR checks. This is not a complete wrapper proof:
//! expected source tuples model the authenticated claim/graph boundary, and
//! range membership is checked explicitly against the existing byte table.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const Air = frontend.recursion.air.ethereum_initial_input_lane_v1;
const direct = frontend.recursion.air.direct_constraint_program;
const interaction = frontend.recursion.air.relation_interaction;
const claim = frontend.recursion.vm_public_claim;
const ClaimAir = frontend.recursion.air.ethereum_vm_public_claim_input_v1;
const claim_witness = frontend.recursion.air.vm_public_claim_input_witness;
const role = @import("recursive_common_ethereum_incremental_leaf_role_aware_io_v4.zig");
const preflight = @import("ethereum_typed_air_preflight_v4.zig");
const fixture = @import("recursive_common_ethereum_incremental_leaf_universal_proof_v4_genuine_fixture.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const N = 40;
const CAP = 64;
const a = std.testing.allocator;
const Memory = frontend.air.relation_challenges.RelationElements(7);
const memory = Memory.dummy();
const coeffs = [6]QM31{ memory.z, memory.alpha, memory.alpha_powers[3], memory.alpha_powers[4], memory.alpha_powers[5], memory.alpha_powers[6] };

pub fn programElf() @TypeOf(fixture.programElf()) {
    var elf = fixture.programElf();
    // Preserve the real guest ELF and enlarge its existing input symbol.
    const start = std.mem.readInt(u32, elf[612..616], .little);
    std.mem.writeInt(u32, elf[628..632], start + N * 4, .little);
    std.mem.writeInt(u32, elf[648..652], 0x00700213, .little); // Actual unretired ADDI.
    return elf;
}

pub const Fixture = struct {
    words: [N]u32,
    start: u32,
    rows: [CAP]Air.Row,
    sum: QM31,
    program_words: [role.TUPLE_WORD_COUNT]u32,
    program_tuple: role.TupleV4,

    pub fn init() !Fixture {
        const elf = programElf();
        var bytes: [N * 4]u8 = undefined;
        for (&bytes, 0..) |*byte, index| byte.* = @truncate(index * 73 + 19);
        var session = try frontend.runner.EthereumExecutionSession.init(a, &elf, .{ .input = &bytes });
        defer session.deinit();
        var segment = try session.startSegment(2);
        defer segment.deinit();
        try std.testing.expect(segment.base.segment_role.is_first);
        try std.testing.expect(!segment.base.segment_role.is_last);
        try std.testing.expectEqual(@as(usize, 0), segment.base.output_words.len);
        const input_words = try frontend.air.public_data.packInputWords(a, segment.base.input.?);
        defer a.free(input_words);
        try std.testing.expectEqual(@as(usize, N), input_words.len);
        var result: Fixture = undefined;
        @memcpy(&result.words, input_words);
        result.start = segment.base.input_start;
        const decoded = try frontend.air.program.decode.decodeProgramWord(std.mem.readInt(u32, elf[648..652], .little));
        result.program_tuple = try role.TupleV4.init(.program_completion, &(.{segment.base.exit_cpu.pc} ++ decoded));
        result.program_words = try result.program_tuple.words();
        try result.generate(coeffs);
        return result;
    }
    pub fn header(self: *const Fixture) [4]M31 {
        return .{ f(self.start & 65535), f(self.start >> 16), f(N), f(0) };
    }
    fn generate(self: *Fixture, coefficients: [6]QM31) !void {
        const shape = try Air.Shape.init(N);
        self.sum = QM31.zero();
        var program_words: [Air.PROGRAM_WORD_COUNT]M31 = undefined;
        for (&program_words, self.program_words) |*word, value| word.* = f(value);
        for (&self.rows, 0..) |*row, index| {
            row.* = try Air.row(shape, @intCast(index), .{
                .header = self.header(),
                .coefficients = coefficients,
                .word = if (index < N) self.words[index] else 0,
                .present = index < N,
                .previous_present = index <= N,
                .previous_sum = self.sum,
                .program_words = if (index == N) program_words else null,
            });
            self.sum = self.sum.add(QM31.fromM31Array(row[40..44].*));
        }
    }
    fn tuple(self: *const Fixture, index: usize) !role.TupleV4 {
        const word = self.words[index];
        return role.TupleV4.init(.input_memory, &.{ 1, self.start + @as(u32, @intCast(4 * index)), 0, word & 255, (word >> 8) & 255, (word >> 16) & 255, word >> 24 });
    }
    fn roleDigest(self: *const Fixture) !claim.Digest {
        var tuples = [_]role.TupleV4{role.TupleV4.zero()} ** CAP;
        for (tuples[0..N], 0..) |*tuple_value, index| tuple_value.* = try self.tuple(index);
        tuples[N] = self.program_tuple;
        const words = try role.testingCanonicalWordsAlloc(a, &tuples, N + 1);
        defer a.free(words);
        const calls = try role.testingBuildCallsAlloc(a, words);
        defer a.free(calls);
        return role.testingDigestFromCalls(calls);
    }
    pub fn nativeSum(self: *const Fixture) !QM31 {
        var sum = QM31.zero();
        for (0..N) |index| {
            const values = try (try self.tuple(index)).values();
            var fields: [7]M31 = undefined;
            for (&fields, values) |*field, value| field.* = f(value);
            sum = sum.add(try memory.combineBase(fields).inv());
        }
        return sum;
    }
};

fn f(value: u32) M31 {
    return M31.fromCanonical(value);
}
fn q(value: u32) QM31 {
    return QM31.fromBase(f(value));
}
fn rootsPass(program: *const direct.Program, row: Air.Row) !bool {
    var scratch: [direct.MAX_NODES]M31 = undefined;
    var roots: [Air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    try program.evaluateBaseInto(&row, &scratch, &roots);
    for (roots) |root| if (!root.isZero()) return false;
    return true;
}
fn rangesPass(plan: *const Air.Relation.Plan, row: Air.Row) bool {
    for (plan.preparedEntries(row)) |entry| if (entry.domain == .range_check_8_8 and !entry.numerator.isZero()) {
        for (entry.values[0..entry.arity]) |word| {
            const limbs = word.toM31Array();
            if (limbs[0].toU32() > 255 or !limbs[1].isZero() or !limbs[2].isZero() or !limbs[3].isZero()) return false;
        }
    };
    return true;
}
fn closed(plan: *const Air.Relation.Plan, expected: *const Fixture, rows: []const Air.Row) !bool {
    var ledger = interaction.TupleLedger.init(a);
    defer ledger.deinit();
    const mask = (@as(u64, 1) << @intFromEnum(frontend.air.relation.Domain.recursion_wire)) |
        (@as(u64, 1) << @intFromEnum(frontend.air.relation.Domain.recursion_vm_public_claim_word));
    try plan.appendPreparedTupleContributions(&ledger, 36, rows, mask);
    // Fixture boundary only: these are the required authentic graph outputs.
    // No production route can use these test-side producers as an admission.
    for (coeffs, 0..) |coefficient, index| {
        const limbs = coefficient.toM31Array();
        try ledger.append(.recursion_wire, 16, @intCast(index), .emit, q(CAP - 1), &.{ q(Air.SOURCE_SCOPE), q(@intCast(index)), QM31.fromBase(limbs[0]), QM31.fromBase(limbs[1]), QM31.fromBase(limbs[2]), QM31.fromBase(limbs[3]) });
    }
    const header = expected.header();
    try ledger.append(.recursion_wire, 16, Air.HEADER_SLOT, .emit, q(CAP), &.{ q(Air.SOURCE_SCOPE), q(Air.HEADER_SLOT), QM31.fromBase(header[0]), QM31.fromBase(header[1]), QM31.fromBase(header[2]), QM31.fromBase(header[3]) });
    const sum = (try expected.nativeSum()).toM31Array();
    try ledger.append(.recursion_wire, 16, Air.SUM_SLOT, .consume, q(1).neg(), &.{ q(Air.SOURCE_SCOPE), q(Air.SUM_SLOT), QM31.fromBase(sum[0]), QM31.fromBase(sum[1]), QM31.fromBase(sum[2]), QM31.fromBase(sum[3]) });
    var claim_definition = try ClaimAir.build(a);
    defer claim_definition.deinit();
    const claim_plan = try ClaimAir.Relation.authenticate(&claim_definition);
    const claim_direct = try direct.authenticate(&claim_definition.arena, ClaimAir.SEMANTIC_DIGEST, ClaimAir.LOGICAL_INPUT_COUNT);
    var preprocessing = try claim_witness.Preprocessed.init(a, try claim.Shape.init(N, 1));
    defer preprocessing.deinit();
    var scratch: [direct.MAX_NODES]M31 = undefined;
    var roots: [ClaimAir.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    const lane_shape = try Air.Shape.init(N);
    for (expected.words, 0..) |word, index| {
        const first = claim.canonical_layout.inputSlotPresent(index);
        for ([_]u32{ 1, word & 65535, word >> 16 }, 0..) |limb, offset| {
            const main = claim_witness.MainRow{ .value = f(limb), .low_byte = f(if (offset == 0) 0 else limb & 255), .high_byte = f(if (offset == 0) 0 else limb >> 8) };
            const source = ClaimAir.logicalRow(claim_witness.logicalInputs(main, preprocessing.rows[first + offset], .segment_leaf), .{ try lane_shape.claimSourceUses(first + offset), 0, 0 });
            try claim_direct.evaluateBaseInto(&source, &scratch, &roots);
            for (roots) |root| try std.testing.expect(root.isZero());
            const entries = claim_plan.preparedEntries(source);
            const entry = entries[2]; // Shared Ethereum extra-use claim emitter.
            try ledger.append(entry.domain, 12, 2, .emit, entry.numerator, entry.values[0..entry.arity]);
            // The public-input hash projection reads that exact same main value.
            try std.testing.expect(entries[3].values[2].eql(entry.values[2]));
        }
    }
    for (0..Air.PROGRAM_PACKET_COUNT) |packet| {
        var payload: [4]QM31 = @splat(QM31.zero());
        for (&payload, 0..) |*word, limb| if (packet * 4 + limb < expected.program_words.len) {
            word.* = q(expected.program_words[packet * 4 + limb]);
        };
        try ledger.append(.recursion_wire, 16, @intCast(Air.PROGRAM_FIRST_SLOT + packet), .emit, q(1), &(.{ q(Air.SOURCE_SCOPE), q(@intCast(Air.PROGRAM_FIRST_SLOT + packet)) } ++ payload));
    }
    for (0..CAP) |index| {
        const words = if (index == N) expected.program_words else if (index < N) try (try expected.tuple(index)).words() else [_]u32{0} ** role.TUPLE_WORD_COUNT;
        for (words, 0..) |word, offset| {
            const destination = role.HEADER_WORD_COUNT + index * role.TUPLE_WORD_COUNT + offset;
            try ledger.append(.recursion_vm_public_claim_word, 13, @intCast(offset), .consume, q(1).neg(), &.{ q(Air.ROLE_HASH_SCOPE), q(@intCast(destination)), q(word) });
        }
    }
    const report = ledger.classify();
    if (!report.isClosed() and rows.ptr == expected.rows[0..].ptr) ledger.printUnmatched(4);
    return report.isClosed();
}

test "Ethereum initial input lane admits genuine forty word input and native memory sum" {
    const value = try Fixture.init();
    var definition = try Air.build(a);
    defer definition.deinit();
    const plan = try Air.Relation.authenticate(&definition);
    const program = try direct.authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
    const degree = preflight.degrees(Air, &program, &plan, null);
    try std.testing.expectEqual(@as(u32, 3), degree.direct);
    try std.testing.expectEqual(@as(u32, 5), degree.logup);
    try std.testing.expectEqual(Air.MAXIMUM_CONSTRAINT_DEGREE, @max(degree.direct, degree.logup));
    for (value.rows) |row| {
        try std.testing.expect(try rootsPass(&program, row));
        try std.testing.expect(rangesPass(&plan, row));
    }
    std.debug.print("INITIAL_INPUT_LANE direct_and_range=true degree_direct={d} degree_logup={d}\n", .{ degree.direct, degree.logup });
    try std.testing.expect(value.sum.eql(try value.nativeSum()));
    std.debug.print("INITIAL_INPUT_LANE native_sum=true\n", .{});
    try std.testing.expect(try closed(&plan, &value, &value.rows));
    std.debug.print("INITIAL_INPUT_LANE source_closure=true\n", .{});
    // Fixed large-shape counter boundaries without allocating the full lane.
    // The genuine execution above remains the evidence for actual input data.
    const large = try Air.Shape.init(675173);
    var program_words: [Air.PROGRAM_WORD_COUNT]M31 = undefined;
    for (&program_words, value.program_words) |*word, raw| word.* = f(raw);
    for ([_]u32{ 65535, 65536, 675172, 675173 }) |index| {
        const row = try Air.row(large, index, .{ .header = .{ f(value.start & 65535), f(value.start >> 16), f(675173 & 65535), f(675173 >> 16) }, .coefficients = coeffs, .word = 0xffffffff, .present = index < 675173, .previous_present = true, .previous_sum = QM31.one(), .program_words = if (index == 675173) program_words else null });
        if (!try rootsPass(&program, row)) std.debug.print("INITIAL_INPUT_LANE large_boundary_failure={d}\n", .{index});
        try std.testing.expect(try rootsPass(&program, row));
        try std.testing.expect(rangesPass(&plan, row));
    }
}

test "Ethereum initial input lane rejects changed claims challenges and missing rows" {
    const expected = try Fixture.init();
    var definition = try Air.build(a);
    defer definition.deinit();
    const plan = try Air.Relation.authenticate(&definition);
    const program = try direct.authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
    var changed = expected;
    changed.words[35] ^= 0x80010001;
    try changed.generate(coeffs);
    for (changed.rows) |row| try std.testing.expect(try rootsPass(&program, row));
    try std.testing.expect(!try closed(&plan, &expected, &changed.rows));
    const shape = try claim.Shape.init(N, 1);
    const original_digest = try claim.publicInputDigestFromProjection(.{ .start = expected.start, .len = N * 4, .words = &expected.words }, shape);
    const changed_digest = try claim.publicInputDigestFromProjection(.{ .start = changed.start, .len = N * 4, .words = &changed.words }, shape);
    try std.testing.expect(!std.meta.eql(original_digest, changed_digest));
    try std.testing.expect(!std.meta.eql(try expected.roleDigest(), try changed.roleDigest()));
    var changed_coeffs = coeffs;
    changed_coeffs[0] = changed_coeffs[0].add(QM31.one());
    changed = expected;
    try changed.generate(changed_coeffs);
    for (changed.rows) |row| try std.testing.expect(try rootsPass(&program, row));
    try std.testing.expect(!try closed(&plan, &expected, &changed.rows));
    changed = expected;
    changed.rows[N][16 + 10] = changed.rows[N][16 + 10].add(M31.one());
    try std.testing.expect(try rootsPass(&program, changed.rows[N]));
    try std.testing.expect(!try closed(&plan, &expected, &changed.rows));
    const final_packet = plan.preparedEntries(expected.rows[N])[18];
    try std.testing.expect(final_packet.values[4].isZero());
    try std.testing.expect(final_packet.values[5].isZero());
    try std.testing.expect(!try closed(&plan, &expected, expected.rows[1..]));
    changed = expected;
    changed.rows[35] = changed.rows[34];
    try std.testing.expect(!try closed(&plan, &expected, &changed.rows));
    changed = expected;
    changed.rows[35][44] = changed.rows[35][44].add(M31.one());
    try std.testing.expect(!try closed(&plan, &expected, &changed.rows));
}

test "Ethereum initial input lane rejects forged count order address and byte ranges" {
    const expected = try Fixture.init();
    var definition = try Air.build(a);
    defer definition.deinit();
    const plan = try Air.Relation.authenticate(&definition);
    const program = try direct.authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
    for ([_]usize{ 6, 7 }) |limb| {
        var row = expected.rows[N];
        row[limb] = row[limb].add(M31.one());
        try std.testing.expect(!try rootsPass(&program, row));
    }
    for ([_]usize{ 8, 9, 10, 11, 12, 13, 14, 40 }) |column| {
        var row = expected.rows[35];
        row[column] = row[column].add(M31.one());
        try std.testing.expect(!try rootsPass(&program, row));
    }
    var row = expected.rows[N + 1];
    row[8] = M31.one(); // A prefix cannot restart after its authenticated end.
    try std.testing.expect(!try rootsPass(&program, row));
    row = expected.rows[N + 1];
    row[0] = M31.one();
    try std.testing.expect(!try rootsPass(&program, row));
    row = expected.rows[35];
    row[0] = f(256);
    try std.testing.expect(!rangesPass(&plan, row));
    row[13] = f(128);
    row[15] = f(256);
    try std.testing.expect(!rangesPass(&plan, row));
    for ([_]u32{ 0, 65534, 0x7ffffffe }) |start| {
        const boundary = try Air.row(try Air.Shape.init(N), 0, .{ .header = .{ f(start & 65535), f(start >> 16), f(N), f(0) }, .coefficients = coeffs, .word = 0xffffffff, .present = true, .previous_present = true, .previous_sum = QM31.zero() });
        try std.testing.expect(try rootsPass(&program, boundary));
        try std.testing.expect(rangesPass(&plan, boundary));
    }
    row = expected.rows[0];
    row[4] = f(65535);
    row[5] = f(32767);
    row[10..14].* = .{ f(255), f(255), f(255), f(127) };
    row[14] = M31.zero();
    row[15] = f(254);
    row[48] = M31.zero();
    // The byte table accepts the modulus limbs; the canonical join rejects it.
    try std.testing.expect(rangesPass(&plan, row));
    try std.testing.expect(!try rootsPass(&program, row));
    var header = expected.header();
    header[0] = f(65536);
    try std.testing.expectError(error.InvalidEthereumInitialInputHeader, Air.row(try Air.Shape.init(N), 0, .{ .header = header, .coefficients = coeffs, .word = 1, .present = true, .previous_present = true, .previous_sum = QM31.zero() }));
}
