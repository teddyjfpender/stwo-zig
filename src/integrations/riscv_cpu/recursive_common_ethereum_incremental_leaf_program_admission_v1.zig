//! Whole-ELF completion admission for the Ethereum wrapper.
//! The default interpolation profile remains bounded to 64 executable words.
//! The explicit fixed-program constructor instead borrows an authenticated
//! full-width opening tree, with logarithmic graph size and nonfinal policy.
//! Private ownership reuses the existing cold ELF/program commitment loader;
//! completion values never select the table or the admitted image identity.

const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const prepared = @import("ethereum_incremental_prepared_program_commitment_v1.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const arithmetic = frontend.recursion.arithmetic_circuit;
const decode = frontend.air.program.decode;
const Sha256 = std.crypto.hash.sha2.Sha256;
const fixed_program = @import("ethereum_fixed_program_admission_v1.zig");

pub const SCHEMA_VERSION: u16 = 1;
pub const MAX_EXECUTABLE_ROWS: usize = 64;
pub const COMPLETION_OPENING_VERSION = fixed_program.completion.VERSION;
pub const MAX_COMPLETION_OPENING_WORD_COUNT: usize = @as(usize, fixed_program.completion.MAX_DEPTH) * 9;
pub const MAINNET_PROFILE = false; // The default bounded64 constructor.
pub const SERIALIZABLE = false;
const OUTPUT_COLUMNS: usize = 6;
const IDENTITY_DOMAIN = "stwo-zig/ethereum-completion-whole-program/bounded64/v1\x00";

pub const Row = fixed_program.completion.Row;

pub const Inputs = struct {
    active: arithmetic.Value,
    pc: arithmetic.Value,
    raw_word_limbs: [2]arithmetic.Value,
    decoded: [4]arithmetic.Value,
    program_root: arithmetic.Value,
};

/// No mutable program, table, coefficient or source-byte pointer escapes.
/// Existing prepared-program tokens are custody only; the separately admitted
/// whole image and fixed polynomial constants define this circuit profile.
pub const ProgramAdmissionV1 = opaque {
    const Self = @This();

    /// Borrows the independently pinned immutable ELF owner. Its lifetime must
    /// cover this admission and every prepared graph using it. The whole image
    /// descriptor, opening version, geometry and all eight root words are fixed
    /// circuit data; no observed completion selects any of them.
    pub fn createWithFixedProgram(allocator: std.mem.Allocator, program: *const fixed_program.OwnedV1) !*Self {
        const descriptor = program.descriptor();
        try program.validateDescriptor(descriptor);
        const root = try program.completionRoot();
        const depth = try program.completionDepth();
        const rows = try program.completionRows();
        var hash = Sha256.init(.{});
        hash.update("stwo-zig/ethereum-completion-whole-program/opening/v1\x00");
        for ((try descriptor.canonicalWords()) ++ [_]u32{ fixed_program.completion.VERSION, @intCast(rows.len), depth } ++ root) |word| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word, .little);
            hash.update(&bytes);
        }
        var identity_sha256: [32]u8 = undefined;
        hash.final(&identity_sha256);
        const owned = try allocator.create(Storage);
        owned.* = .{ .allocator = allocator, .program = null, .fixed = program, .rows = rows, .polynomials = null, .root = descriptor.compatibility_root, .source_sha256 = descriptor.elf_sha256, .identity_sha256 = identity_sha256 };
        return @ptrCast(owned);
    }

    pub fn createFromElf(allocator: std.mem.Allocator, elf_bytes: []const u8) !*Self {
        const program = try prepared.PreparedProgramCommitmentV1.create(allocator, elf_bytes);
        errdefer program.deinit();
        const source = try program.borrow();
        var count: usize = 0;
        for (source.declared_rows) |word| {
            if (word.initial_word == 0 or decode.isDeclaredPaddingForProfile(.rv32im_zkvm_ethereum_v1, word.initial_word)) continue;
            _ = try decode.decodeProgramWordForProfile(.rv32im_zkvm_ethereum_v1, word.initial_word);
            count = try std.math.add(usize, count, 1);
        }
        // This check precedes table/coefficient allocation and graph creation.
        try requireRowBudget(count);
        const rows = try allocator.alloc(Row, count);
        errdefer allocator.free(rows);
        var at: usize = 0;
        for (source.declared_rows) |word| {
            if (word.initial_word == 0 or decode.isDeclaredPaddingForProfile(.rv32im_zkvm_ethereum_v1, word.initial_word)) continue;
            rows[at] = .{ .pc = word.addr, .raw_word = word.initial_word, .decoded = try decode.decodeProgramWordForProfile(.rv32im_zkvm_ethereum_v1, word.initial_word) };
            at += 1;
        }
        var polynomials = try Polynomials.init(allocator, rows);
        errdefer polynomials.deinit(allocator);
        const storage = try allocator.create(Storage);
        storage.* = .{ .allocator = allocator, .program = program, .rows = rows, .polynomials = polynomials, .root = source.inventory.sparse_tree_root, .source_sha256 = source.inventory.source_bytes_sha256, .identity_sha256 = identity(source.inventory.identity_sha256, rows) };
        return @ptrCast(storage);
    }

    pub fn deinit(self: *Self) void {
        const storage = mutable(self);
        const allocator = storage.allocator;
        if (storage.program) |program| program.deinit();
        if (storage.polynomials) |*polynomials| polynomials.deinit(allocator);
        if (storage.fixed == null) allocator.free(storage.rows);
        allocator.destroy(storage);
    }

    pub fn completionRows(self: *const Self) []const Row {
        return immutable(self).rows;
    }

    pub fn programRoot(self: *const Self) u32 {
        return immutable(self).root;
    }

    pub fn sourceSha256(self: *const Self) [32]u8 {
        return immutable(self).source_sha256;
    }

    pub fn identitySha256(self: *const Self) [32]u8 {
        return immutable(self).identity_sha256;
    }

    pub fn openingInputWordCount(self: *const Self) usize {
        const program = immutable(self).fixed orelse return 0;
        return @as(usize, program.completionDepth() catch unreachable) * 9;
    }
    pub fn openingVersion(self: *const Self) u16 {
        return if (immutable(self).fixed != null) fixed_program.completion.VERSION else 0;
    }
    pub fn haltFlagAddress(self: *const Self) !u32 {
        const program = immutable(self).fixed orelse return error.EthereumFixedProgramAdmissionRequired;
        return program.haltFlagAddress();
    }
    pub fn validateFixedProgramOwner(self: *const Self, expected: ?*const fixed_program.OwnedV1) !void {
        if (immutable(self).fixed) |program| {
            if (expected != program) return error.EthereumCompletionProgramOwnerMismatch;
        }
    }

    pub fn openingWord(self: *const Self, pc: u32, index: usize) !u32 {
        const program = immutable(self).fixed orelse return error.EthereumCompletionOpeningNotAdmitted;
        return (try program.completionOpening(pc)).word(index);
    }

    pub fn constrainCompletion(self: *const Self, builder: *arithmetic.Builder, inputs: Inputs) !void {
        return self.constrainCompletionWithOpening(builder, inputs, &.{});
    }

    pub fn constrainCompletionWithOpening(self: *const Self, builder: *arithmetic.Builder, inputs: Inputs, opening: []const arithmetic.Value) !void {
        const storage = immutable(self);
        _ = try builder.markOutput(try builder.sub(inputs.program_root, arithmetic.Value.fromBase(M31.fromCanonical(storage.root))));
        if (storage.fixed) |program| {
            // This version admits nonfinal completion only, exactly as the
            // caller's existing completion-policy and role-order constraints.
            _ = try builder.markOutput(try builder.sub(inputs.active, arithmetic.Value.one()));
            try fixed_program.completion.constrain(builder, try program.completionRoot(), try program.completionDepth(), @intCast(storage.rows.len), .{inputs.pc} ++ inputs.raw_word_limbs ++ inputs.decoded, opening);
        } else {
            if (opening.len != 0) return error.InvalidCompletionOpening;
            try storage.polynomials.?.constrain(builder, inputs);
        }
    }

    fn immutable(self: *const Self) *const Storage {
        return @ptrCast(@alignCast(self));
    }

    fn mutable(self: *Self) *Storage {
        return @ptrCast(@alignCast(self));
    }
};

const Storage = struct {
    allocator: std.mem.Allocator,
    program: ?*prepared.PreparedProgramCommitmentV1,
    fixed: ?*const fixed_program.OwnedV1 = null,
    rows: []const Row,
    polynomials: ?Polynomials,
    root: u32,
    source_sha256: [32]u8,
    identity_sha256: [32]u8,
};

fn requireRowBudget(count: usize) !void {
    if (count == 0) return error.EmptyEthereumCompletionProgram;
    if (count > MAX_EXECUTABLE_ROWS) return error.EthereumCompletionProgramExceedsBoundedProfile;
}

const Polynomials = struct {
    membership: []M31,
    columns: []M31,
    row_count: usize,

    fn init(allocator: std.mem.Allocator, rows: []const Row) !Polynomials {
        try requireRowBudget(rows.len);
        for (rows, 0..) |row, index| {
            if (row.pc >= core.fields.m31.Modulus or (row.pc & 3) != 0 or
                (index != 0 and rows[index - 1].pc >= row.pc)) return error.InvalidEthereumCompletionProgramTable;
            for (row.values()) |value| if (value >= core.fields.m31.Modulus)
                return error.InvalidEthereumCompletionProgramTable;
        }
        const membership = try allocator.alloc(M31, rows.len + 1);
        errdefer allocator.free(membership);
        @memset(membership, M31.zero());
        membership[0] = M31.one();
        for (rows, 0..) |row, index| {
            const pc = M31.fromCanonical(row.pc);
            var degree = index + 1;
            while (degree > 0) : (degree -= 1)
                membership[degree] = membership[degree - 1].sub(pc.mul(membership[degree]));
            membership[0] = membership[0].mul(pc).neg();
        }
        const columns = try allocator.alloc(M31, try std.math.mul(usize, OUTPUT_COLUMNS, rows.len));
        errdefer allocator.free(columns);
        @memset(columns, M31.zero());
        // Synthetic division of the common membership polynomial gives each
        // Lagrange basis in linear time; no per-proof table subset is compiled.
        var basis_storage: [MAX_EXECUTABLE_ROWS]M31 = undefined;
        const basis = basis_storage[0..rows.len];
        for (rows) |row| {
            const pc = M31.fromCanonical(row.pc);
            basis[rows.len - 1] = membership[rows.len];
            var degree = rows.len - 1;
            while (degree > 0) : (degree -= 1)
                basis[degree - 1] = membership[degree].add(pc.mul(basis[degree]));
            const scale = try evaluatePolynomial(basis, pc).inv();
            for (row.values(), 0..) |value, column| {
                const weighted = M31.fromCanonical(value).mul(scale);
                for (basis, columns[column * rows.len ..][0..rows.len]) |coefficient, *output|
                    output.* = output.add(coefficient.mul(weighted));
            }
        }
        return .{ .membership = membership, .columns = columns, .row_count = rows.len };
    }

    fn deinit(self: *Polynomials, allocator: std.mem.Allocator) void {
        allocator.free(self.columns);
        allocator.free(self.membership);
        self.* = undefined;
    }

    fn constrain(self: Polynomials, builder: *arithmetic.Builder, inputs: Inputs) !void {
        _ = try builder.markOutput(try builder.mul(inputs.active, try builder.sub(inputs.active, arithmetic.Value.one())));
        _ = try builder.markOutput(try builder.mul(inputs.active, try polynomialValue(builder, self.membership, inputs.pc)));
        const values = inputs.raw_word_limbs ++ inputs.decoded;
        for (values, 0..) |value, column| {
            const expected = try polynomialValue(builder, self.columns[column * self.row_count ..][0..self.row_count], inputs.pc);
            _ = try builder.markOutput(try builder.mul(inputs.active, try builder.sub(value, expected)));
        }
    }
};

fn polynomialValue(builder: *arithmetic.Builder, coefficients: []const M31, at: arithmetic.Value) !arithmetic.Value {
    var result = arithmetic.Value.zero();
    var index = coefficients.len;
    while (index > 0) {
        index -= 1;
        result = try builder.add(try builder.mul(result, at), arithmetic.Value.fromBase(coefficients[index]));
    }
    return result;
}

fn evaluatePolynomial(coefficients: []const M31, at: M31) M31 {
    var result = M31.zero();
    var index = coefficients.len;
    while (index > 0) {
        index -= 1;
        result = result.mul(at).add(coefficients[index]);
    }
    return result;
}

fn identity(whole_program: [32]u8, rows: []const Row) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(IDENTITY_DOMAIN);
    hash.update(&whole_program);
    hashWord(&hash, SCHEMA_VERSION);
    hashWord(&hash, @intCast(rows.len));
    for (rows) |row| {
        hashWord(&hash, row.pc);
        hashWord(&hash, row.raw_word);
        for (row.decoded) |value| hashWord(&hash, value);
    }
    return hash.finalResult();
}

fn hashWord(hash: *Sha256, value: u32) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    hash.update(&bytes);
}

test "Ethereum bounded program admission owns the whole ELF and distinguishes unused bytes" {
    const allocator = std.testing.allocator;
    // Use the exact admitted producer image, whose terminal word is the
    // canonical self-loop rather than the generic test builder's halt opcode.
    const elf = @import("recursive_common_ethereum_incremental_leaf_universal_proof_v4_genuine_fixture.zig").programElf();
    const admission = blk: {
        const source = try allocator.dupe(u8, &elf);
        defer allocator.free(source);
        const result = try ProgramAdmissionV1.createFromElf(allocator, source);
        source[0] ^= 0xff;
        break :blk result;
    };
    defer admission.deinit();
    var expected_sha: [32]u8 = undefined;
    Sha256.hash(&elf, &expected_sha, .{});
    try std.testing.expectEqual(expected_sha, admission.sourceSha256());
    try std.testing.expect(admission.completionRows().len > 0);
    try std.testing.expect(admission.completionRows().len <= MAX_EXECUTABLE_ROWS);
    const extended = try allocator.alloc(u8, elf.len + 1);
    defer allocator.free(extended);
    @memcpy(extended[0..elf.len], &elf);
    extended[elf.len] = 0x5a;
    const other = try ProgramAdmissionV1.createFromElf(allocator, extended);
    defer other.deinit();
    try std.testing.expectEqualDeep(admission.completionRows(), other.completionRows());
    try std.testing.expectEqual(admission.programRoot(), other.programRoot());
    try std.testing.expect(!std.mem.eql(u8, &admission.identitySha256(), &other.identitySha256()));
    try std.testing.expect(!MAINNET_PROFILE);
    try std.testing.expect(!SERIALIZABLE);
}

test "Ethereum bounded completion graph admits every executable PC and rejects field mutations" {
    const allocator = std.testing.allocator;
    // Use the exact admitted producer image, whose terminal word is the
    // canonical self-loop rather than the generic test builder's halt opcode.
    const elf = @import("recursive_common_ethereum_incremental_leaf_universal_proof_v4_genuine_fixture.zig").programElf();
    const admission = try ProgramAdmissionV1.createFromElf(allocator, &elf);
    defer admission.deinit();
    var builder = arithmetic.Builder.initDefault(allocator);
    var builder_live = true;
    defer if (builder_live) builder.deinit();
    var inputs: [9]arithmetic.Value = undefined;
    for (&inputs, 0..) |*input, index| input.* = try builder.input(@intCast(index));
    try admission.constrainCompletion(&builder, .{
        .active = inputs[0],
        .pc = inputs[1],
        .raw_word_limbs = inputs[2..4].*,
        .decoded = inputs[4..8].*,
        .program_root = inputs[8],
    });
    var circuit = try builder.finish();
    builder_live = false;
    defer circuit.deinit();
    const node_count = circuit.nodes().len;
    for (admission.completionRows()) |row| {
        var values: [9]QM31 = undefined;
        values[0] = QM31.one();
        values[1] = QM31.fromBase(M31.fromCanonical(row.pc));
        for (row.values(), values[2..8]) |word, *value| value.* = QM31.fromBase(M31.fromCanonical(word));
        values[8] = QM31.fromBase(M31.fromCanonical(admission.programRoot()));
        {
            var evaluation = try circuit.evaluate(allocator, &values);
            defer evaluation.deinit();
            try std.testing.expect(try circuit.outputsAreZero(evaluation.values));
        }
        for (0..values.len) |index| {
            const original = values[index];
            values[index] = original.add(QM31.one());
            var changed = try circuit.evaluate(allocator, &values);
            defer changed.deinit();
            try std.testing.expect(!try circuit.outputsAreZero(changed.values));
            values[index] = original;
        }
        values[0] = QM31.zero();
        values[1] = QM31.one();
        for (values[2..8]) |*value| value.* = QM31.zero();
        var inactive = try circuit.evaluate(allocator, &values);
        defer inactive.deinit();
        try std.testing.expect(try circuit.outputsAreZero(inactive.values));
        try std.testing.expectEqual(node_count, circuit.nodes().len);
    }
}

test "Ethereum completion polynomial preflight rejects oversized and duplicate PC tables" {
    const allocator = std.testing.allocator;
    const decoded = try decode.decodeProgramWordForProfile(.rv32im_zkvm_ethereum_v1, 0x00100093);
    var rows: [MAX_EXECUTABLE_ROWS + 1]Row = undefined;
    for (&rows, 0..) |*row, index| row.* = .{
        .pc = @intCast(0x1000 + index * 4),
        .raw_word = 0x00100093,
        .decoded = decoded,
    };
    try std.testing.expectError(error.EmptyEthereumCompletionProgram, Polynomials.init(allocator, &.{}));
    try std.testing.expectError(error.EthereumCompletionProgramExceedsBoundedProfile, Polynomials.init(allocator, &rows));
    var admitted = try Polynomials.init(allocator, rows[0..MAX_EXECUTABLE_ROWS]);
    defer admitted.deinit(allocator);
    for (rows[0..MAX_EXECUTABLE_ROWS]) |row| {
        const pc = M31.fromCanonical(row.pc);
        try std.testing.expect(evaluatePolynomial(admitted.membership, pc).isZero());
        for (row.values(), 0..) |value, column| try std.testing.expectEqual(value, evaluatePolynomial(admitted.columns[column * MAX_EXECUTABLE_ROWS ..][0..MAX_EXECUTABLE_ROWS], pc).toU32());
    }
    rows[1].pc = rows[0].pc;
    try std.testing.expectError(error.InvalidEthereumCompletionProgramTable, Polynomials.init(allocator, rows[0..2]));
}
