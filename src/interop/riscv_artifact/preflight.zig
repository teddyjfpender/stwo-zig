//! Fixed-memory structural preflight for untrusted schema-v4 JSON.
//!
//! The typed JSON parser allocates slices as it encounters them. This scanner
//! therefore runs first, rejects non-canonical structure, and proves every
//! variable-length field is within the producer contract before typed parsing.

const std = @import("std");
const schema = @import("schema.zig");
const protocol = @import("protocol.zig");

const MAX_KEY_BYTES: usize = 64;
const SCANNER_STORAGE_BYTES: usize = 16 * 1024;
const MAX_OPCODE_SUMS: usize = protocol.MAX_OPCODE_INTERACTION_BATCHES;
const MAX_INFRA_SUMS: usize = 4;
const M31_MODULUS: u32 = 0x7fff_ffff;

pub const Route = struct {
    artifact_kind_present: bool = false,
    artifact_kind_is_riscv: bool = false,
    schema_version: ?u32 = null,
    exchange_mode_present: bool = false,
    exchange_mode_is_v4: bool = false,
    exchange_mode_is_v1: bool = false,
    exchange_mode_is_v2: bool = false,
    exchange_mode_is_v3: bool = false,
    exchange_mode_is_riscv: bool = false,

    pub fn isRiscV(self: Route) bool {
        return self.artifact_kind_is_riscv or self.exchange_mode_is_riscv;
    }

    pub fn validateRiscV(self: Route) !void {
        if (!self.exchange_mode_present) return error.UnsupportedExchangeMode;
        const version = self.schema_version orelse return error.UnsupportedSchemaVersion;
        if (version == 1 or version == 2 or version == 3 or
            self.exchange_mode_is_v1 or self.exchange_mode_is_v2 or
            self.exchange_mode_is_v3)
            return error.LegacySchemaVersion;
        if (version != schema.SCHEMA_VERSION) return error.UnsupportedSchemaVersion;
        if (!self.exchange_mode_is_v4) return error.UnsupportedExchangeMode;
        if (!self.artifact_kind_present or !self.artifact_kind_is_riscv)
            return error.UnsupportedArtifactKind;
    }
};

pub fn route(raw: []const u8) !Route {
    if (raw.len > schema.MAX_ARTIFACT_BYTES) return error.StreamTooLong;
    var storage: [SCANNER_STORAGE_BYTES]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&storage);
    var scanner = std.json.Scanner.initCompleteInput(fixed.allocator(), raw);
    defer scanner.deinit();

    try expect(&scanner, .object_begin);
    var result = Route{};
    var routing_seen: u8 = 0;
    while (true) {
        const token = try scanner.next();
        if (token == .object_end) break;
        const key = try directString(token, MAX_KEY_BYTES);
        if (std.mem.eql(u8, key, "artifact_kind")) {
            try mark(&routing_seen, 0);
            result.artifact_kind_present = true;
            const value = try readString(&scanner, 64);
            result.artifact_kind_is_riscv = std.mem.eql(u8, value, schema.ARTIFACT_KIND);
        } else if (std.mem.eql(u8, key, "schema_version")) {
            try mark(&routing_seen, 1);
            result.schema_version = try readU32(&scanner);
        } else if (std.mem.eql(u8, key, "exchange_mode")) {
            try mark(&routing_seen, 2);
            result.exchange_mode_present = true;
            const value = try readString(&scanner, 64);
            result.exchange_mode_is_v4 = std.mem.eql(u8, value, schema.EXCHANGE_MODE);
            result.exchange_mode_is_v1 = std.mem.eql(u8, value, schema.LEGACY_EXCHANGE_MODE_V1);
            result.exchange_mode_is_v2 = std.mem.eql(u8, value, schema.LEGACY_EXCHANGE_MODE_V2);
            result.exchange_mode_is_v3 = std.mem.eql(u8, value, schema.LEGACY_EXCHANGE_MODE_V3);
            result.exchange_mode_is_riscv = std.mem.startsWith(
                u8,
                value,
                schema.EXCHANGE_MODE_PREFIX,
            );
        } else {
            try scanner.skipValue();
        }
    }
    try expect(&scanner, .end_of_document);
    return result;
}

pub fn validate(raw: []const u8) !void {
    if (raw.len > schema.MAX_ARTIFACT_BYTES) return error.StreamTooLong;
    var storage: [SCANNER_STORAGE_BYTES]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&storage);
    var scanner = std.json.Scanner.initCompleteInput(fixed.allocator(), raw);
    defer scanner.deinit();

    var shape = Shape{};
    try parseArtifact(&scanner, &shape);
    try expect(&scanner, .end_of_document);
    try shape.finish();
}

const Shape = struct {
    component_count: usize = 0,
    component_sums: [schema.MAX_COMPONENTS]u32 = .{0} ** schema.MAX_COMPONENTS,
    infrastructure_count: usize = 0,
    infrastructure_sums: [schema.MAX_INFRA_COMPONENTS]u32 = .{0} ** schema.MAX_INFRA_COMPONENTS,
    opcode_claim_count: usize = 0,
    opcode_claim_indices: [schema.MAX_COMPONENTS]u32 = .{0} ** schema.MAX_COMPONENTS,
    opcode_claim_sums: [schema.MAX_COMPONENTS]u32 = .{0} ** schema.MAX_COMPONENTS,
    infrastructure_claim_count: usize = 0,
    infrastructure_claim_indices: [schema.MAX_INFRA_COMPONENTS]u32 = .{0} ** schema.MAX_INFRA_COMPONENTS,
    infrastructure_claim_sums: [schema.MAX_INFRA_COMPONENTS]u32 = .{0} ** schema.MAX_INFRA_COMPONENTS,
    input_len: u32 = 0,
    input_word_count: usize = 0,
    output_len: u32 = 0,
    output_word_count: usize = 0,

    fn finish(self: *const Shape) !void {
        if (self.component_count == 0 or self.component_count > schema.MAX_COMPONENTS)
            return error.InvalidComponentCount;
        if (self.infrastructure_count < 10 or
            self.infrastructure_count > schema.MAX_INFRA_COMPONENTS)
            return error.InvalidInfrastructureCount;
        if (self.opcode_claim_count != self.component_count)
            return error.InvalidInteractionClaimCount;
        if (self.infrastructure_claim_count != self.infrastructure_count)
            return error.InvalidInteractionClaimCount;
        for (0..self.component_count) |index| {
            if (self.opcode_claim_indices[index] != index or
                self.opcode_claim_sums[index] != self.component_sums[index])
                return error.InvalidOpcodeClaim;
        }
        for (0..self.infrastructure_count) |index| {
            if (self.infrastructure_claim_indices[index] != index or
                self.infrastructure_claim_sums[index] != self.infrastructure_sums[index])
                return error.InvalidInfrastructureClaim;
        }

        const expected_input = std.math.divCeil(usize, self.input_len, 4) catch
            return error.GeometryOverflow;
        if (self.input_word_count != expected_input) return error.InvalidInputWords;
        const output_data_words = std.math.divCeil(usize, self.output_len, 4) catch
            return error.GeometryOverflow;
        if (self.output_word_count != output_data_words + 1) {
            return error.InvalidOutputWords;
        }
    }
};

const ArtifactField = enum {
    artifact_kind,
    schema_version,
    exchange_mode,
    release_status,
    generator,
    air,
    backend,
    protocol,
    source,
    provenance,
    pcs_config,
    statement,
    interaction_claim,
    proof_bytes_hex,
};

fn parseArtifact(scanner: *std.json.Scanner, shape: *Shape) !void {
    try expect(scanner, .object_begin);
    var seen: u64 = 0;
    while (true) {
        const token = try scanner.next();
        if (token == .object_end) break;
        switch (try objectField(ArtifactField, token, &seen)) {
            .artifact_kind => _ = try readString(scanner, 64),
            .schema_version => _ = try readU32(scanner),
            .exchange_mode => _ = try readString(scanner, 64),
            .release_status => _ = try readString(scanner, 32),
            .generator => _ = try readString(scanner, 32),
            .air => _ = try readString(scanner, 64),
            .backend => _ = try readString(scanner, 32),
            .protocol => _ = try readString(scanner, 32),
            .source => try parseSource(scanner),
            .provenance => try parseProvenance(scanner),
            .pcs_config => try parsePcsConfig(scanner),
            .statement => try parseStatement(scanner, shape),
            .interaction_claim => try parseInteractionClaim(scanner, shape),
            .proof_bytes_hex => {
                const value = try readString(scanner, schema.MAX_PROOF_BYTES * 2);
                if (value.len == 0 or (value.len & 1) != 0)
                    return error.InvalidProofPayload;
            },
        }
    }
    try requireAll(ArtifactField, seen);
}

const SourceField = enum { elf_sha256, input_sha256 };
fn parseSource(scanner: *std.json.Scanner) !void {
    try expect(scanner, .object_begin);
    var seen: u64 = 0;
    while (true) {
        const token = try scanner.next();
        if (token == .object_end) break;
        switch (try objectField(SourceField, token, &seen)) {
            .elf_sha256, .input_sha256 => {
                const value = try readString(scanner, 64);
                if (value.len != 64) return error.InvalidSha256;
            },
        }
    }
    try requireAll(SourceField, seen);
}

const ProvenanceField = enum {
    oracle_repository,
    oracle_commit,
    implementation_repository,
    implementation_commit,
    implementation_dirty,
    witness_layout_sha256,
};
fn parseProvenance(scanner: *std.json.Scanner) !void {
    try expect(scanner, .object_begin);
    var seen: u64 = 0;
    while (true) {
        const token = try scanner.next();
        if (token == .object_end) break;
        switch (try objectField(ProvenanceField, token, &seen)) {
            .oracle_repository, .implementation_repository => _ = try readString(scanner, 512),
            .witness_layout_sha256 => {
                const value = try readString(scanner, 64);
                if (value.len != 64) return error.InvalidSha256;
            },
            .oracle_commit, .implementation_commit => {
                const value = try readString(scanner, 40);
                if (value.len != 40) return error.InvalidImplementationCommit;
            },
            .implementation_dirty => _ = try readBool(scanner),
        }
    }
    try requireAll(ProvenanceField, seen);
}

const PcsField = enum { pow_bits, fri_config, lifting_log_size };
fn parsePcsConfig(scanner: *std.json.Scanner) !void {
    try expect(scanner, .object_begin);
    var seen: u64 = 0;
    while (true) {
        const token = try scanner.next();
        if (token == .object_end) break;
        switch (try objectField(PcsField, token, &seen)) {
            .pow_bits => _ = try readU32(scanner),
            .fri_config => try parseFriConfig(scanner),
            .lifting_log_size => _ = try readOptionalU32(scanner),
        }
    }
    try requireAll(PcsField, seen);
}

const FriField = enum {
    log_blowup_factor,
    log_last_layer_degree_bound,
    n_queries,
    fold_step,
};
fn parseFriConfig(scanner: *std.json.Scanner) !void {
    try expect(scanner, .object_begin);
    var seen: u64 = 0;
    while (true) {
        const token = try scanner.next();
        if (token == .object_end) break;
        switch (try objectField(FriField, token, &seen)) {
            .log_blowup_factor, .log_last_layer_degree_bound, .fold_step => _ = try readU32(scanner),
            .n_queries => _ = try readU64(scanner),
        }
    }
    try requireAll(FriField, seen);
}

const StatementField = enum {
    segment_ordinal,
    segment_count,
    initial_pc,
    final_pc,
    total_steps,
    components,
    infrastructure,
    public_data,
};
fn parseStatement(scanner: *std.json.Scanner, shape: *Shape) !void {
    try expect(scanner, .object_begin);
    var seen: u64 = 0;
    while (true) {
        const token = try scanner.next();
        if (token == .object_end) break;
        switch (try objectField(StatementField, token, &seen)) {
            .segment_ordinal, .segment_count, .initial_pc, .final_pc, .total_steps => _ = try readU32(scanner),
            .components => shape.component_count = try parseComponents(scanner, &shape.component_sums),
            .infrastructure => shape.infrastructure_count = try parseInfrastructure(
                scanner,
                &shape.infrastructure_sums,
            ),
            .public_data => try parsePublicData(scanner, shape),
        }
    }
    try requireAll(StatementField, seen);
}

const ComponentField = enum {
    index,
    family,
    family_shard_index,
    family_shard_count,
    row_offset,
    log_size,
    n_rows,
    n_columns,
    interaction_batch_count,
};
fn parseComponents(scanner: *std.json.Scanner, widths: *[schema.MAX_COMPONENTS]u32) !usize {
    try expect(scanner, .array_begin);
    var count: usize = 0;
    while (try nextArrayElement(scanner)) |first| {
        if (count == widths.len) return error.InvalidComponentCount;
        try expectConsumed(first, .object_begin);
        var seen: u64 = 0;
        var width: u32 = 0;
        while (true) {
            const token = try scanner.next();
            if (token == .object_end) break;
            switch (try objectField(ComponentField, token, &seen)) {
                .family => _ = try readU8(scanner),
                .index,
                .family_shard_index,
                .family_shard_count,
                .row_offset,
                .log_size,
                .n_rows,
                .n_columns,
                => _ = try readU32(scanner),
                .interaction_batch_count => width = try readU32(scanner),
            }
        }
        try requireAll(ComponentField, seen);
        if (width > MAX_OPCODE_SUMS) return error.InvalidOpcodeClaim;
        widths[count] = width;
        count += 1;
    }
    return count;
}

const InfrastructureField = enum { index, kind, log_size, n_rows, n_columns, claim_count };
fn parseInfrastructure(
    scanner: *std.json.Scanner,
    widths: *[schema.MAX_INFRA_COMPONENTS]u32,
) !usize {
    try expect(scanner, .array_begin);
    var count: usize = 0;
    while (try nextArrayElement(scanner)) |first| {
        if (count == widths.len) return error.InvalidInfrastructureCount;
        try expectConsumed(first, .object_begin);
        var seen: u64 = 0;
        var width: u32 = 0;
        while (true) {
            const token = try scanner.next();
            if (token == .object_end) break;
            switch (try objectField(InfrastructureField, token, &seen)) {
                .index, .kind, .log_size, .n_rows, .n_columns => _ = try readU32(scanner),
                .claim_count => width = try readU32(scanner),
            }
        }
        try requireAll(InfrastructureField, seen);
        if (width > MAX_INFRA_SUMS) return error.InvalidInfrastructureClaim;
        widths[count] = width;
        count += 1;
    }
    return count;
}

const PublicField = enum {
    initial_pc,
    final_pc,
    clock,
    initial_regs,
    final_regs,
    reg_last_clock,
    program_root,
    initial_rw_root,
    final_rw_root,
    completion,
    input_start,
    input_len,
    input_words,
    output_len,
    output_len_addr,
    output_data_addr,
    output_words,
};
fn parsePublicData(scanner: *std.json.Scanner, shape: *Shape) !void {
    try expect(scanner, .object_begin);
    var seen: u64 = 0;
    while (true) {
        const token = try scanner.next();
        if (token == .object_end) break;
        switch (try objectField(PublicField, token, &seen)) {
            .initial_pc, .final_pc, .clock, .input_start, .output_len_addr, .output_data_addr => _ = try readU32(scanner),
            .input_len => {
                shape.input_len = try readU32(scanner);
                if (shape.input_len > schema.MAX_IO_BYTES) return error.IoLimitExceeded;
            },
            .output_len => {
                shape.output_len = try readU32(scanner);
                if (shape.output_len > schema.MAX_IO_BYTES) return error.IoLimitExceeded;
            },
            .initial_regs, .final_regs, .reg_last_clock => try parseFixedU32Array(scanner, 32),
            .program_root, .initial_rw_root, .final_rw_root => _ = try readOptionalU32(scanner),
            .completion => try parseCompletion(scanner),
            .input_words => shape.input_word_count = try parseU32Array(
                scanner,
                schema.MAX_IO_BYTES / 4,
            ),
            .output_words => shape.output_word_count = try parseOutputWords(scanner),
        }
    }
    try requireAll(PublicField, seen);
}

const CompletionField = enum { kind, address, value, clock };
fn parseCompletion(scanner: *std.json.Scanner) !void {
    try expect(scanner, .object_begin);
    var seen: u64 = 0;
    while (true) {
        const token = try scanner.next();
        if (token == .object_end) break;
        switch (try objectField(CompletionField, token, &seen)) {
            .kind => _ = try readString(scanner, 32),
            .address, .value, .clock => _ = try readU32(scanner),
        }
    }
    try requireAll(CompletionField, seen);
}

const OutputWordField = enum { addr, value, clock };
fn parseOutputWords(scanner: *std.json.Scanner) !usize {
    try expect(scanner, .array_begin);
    var count: usize = 0;
    while (try nextArrayElement(scanner)) |first| {
        if (count == schema.MAX_IO_BYTES / 4 + 1) return error.InvalidOutputWords;
        try expectConsumed(first, .object_begin);
        var seen: u64 = 0;
        while (true) {
            const token = try scanner.next();
            if (token == .object_end) break;
            switch (try objectField(OutputWordField, token, &seen)) {
                .addr, .value, .clock => _ = try readU32(scanner),
            }
        }
        try requireAll(OutputWordField, seen);
        count += 1;
    }
    return count;
}

const InteractionField = enum { interaction_pow, opcode_claims, infrastructure_claims };
fn parseInteractionClaim(scanner: *std.json.Scanner, shape: *Shape) !void {
    try expect(scanner, .object_begin);
    var seen: u64 = 0;
    while (true) {
        const token = try scanner.next();
        if (token == .object_end) break;
        switch (try objectField(InteractionField, token, &seen)) {
            .interaction_pow => _ = try readU64(scanner),
            .opcode_claims => shape.opcode_claim_count = try parseOpcodeClaims(shape, scanner),
            .infrastructure_claims => shape.infrastructure_claim_count = try parseInfraClaims(
                shape,
                scanner,
            ),
        }
    }
    try requireAll(InteractionField, seen);
}

const OpcodeClaimField = enum { component_index, claimed_sums };
fn parseOpcodeClaims(shape: *Shape, scanner: *std.json.Scanner) !usize {
    try expect(scanner, .array_begin);
    var count: usize = 0;
    while (try nextArrayElement(scanner)) |first| {
        if (count == schema.MAX_COMPONENTS) return error.InvalidInteractionClaimCount;
        try expectConsumed(first, .object_begin);
        var seen: u64 = 0;
        while (true) {
            const token = try scanner.next();
            if (token == .object_end) break;
            switch (try objectField(OpcodeClaimField, token, &seen)) {
                .component_index => shape.opcode_claim_indices[count] = try readU32(scanner),
                .claimed_sums => shape.opcode_claim_sums[count] = @intCast(
                    try parseQm31Array(scanner, MAX_OPCODE_SUMS),
                ),
            }
        }
        try requireAll(OpcodeClaimField, seen);
        count += 1;
    }
    return count;
}

const InfraClaimField = enum { infrastructure_index, claimed_sums };
fn parseInfraClaims(shape: *Shape, scanner: *std.json.Scanner) !usize {
    try expect(scanner, .array_begin);
    var count: usize = 0;
    while (try nextArrayElement(scanner)) |first| {
        if (count == schema.MAX_INFRA_COMPONENTS) return error.InvalidInteractionClaimCount;
        try expectConsumed(first, .object_begin);
        var seen: u64 = 0;
        while (true) {
            const token = try scanner.next();
            if (token == .object_end) break;
            switch (try objectField(InfraClaimField, token, &seen)) {
                .infrastructure_index => shape.infrastructure_claim_indices[count] = try readU32(scanner),
                .claimed_sums => shape.infrastructure_claim_sums[count] = @intCast(
                    try parseQm31Array(scanner, MAX_INFRA_SUMS),
                ),
            }
        }
        try requireAll(InfraClaimField, seen);
        count += 1;
    }
    return count;
}

fn parseQm31Array(scanner: *std.json.Scanner, maximum: usize) !usize {
    try expect(scanner, .array_begin);
    var count: usize = 0;
    while (try nextArrayElement(scanner)) |first| {
        if (count == maximum) return error.InvalidInteractionClaimCount;
        try expectConsumed(first, .array_begin);
        var limbs: usize = 0;
        while (try nextArrayElement(scanner)) |limb| {
            if (limbs == 4) return error.InvalidQm31Shape;
            const value = try readU32Token(limb);
            if (value >= M31_MODULUS) return error.NonCanonicalM31;
            limbs += 1;
        }
        if (limbs != 4) return error.InvalidQm31Shape;
        count += 1;
    }
    return count;
}

fn parseU32Array(scanner: *std.json.Scanner, maximum: usize) !usize {
    try expect(scanner, .array_begin);
    var count: usize = 0;
    while (try nextArrayElement(scanner)) |element| {
        if (count == maximum) return error.ArrayLimitExceeded;
        _ = try readU32Token(element);
        count += 1;
    }
    return count;
}

fn parseFixedU32Array(scanner: *std.json.Scanner, expected: usize) !void {
    const count = try parseU32Array(scanner, expected);
    if (count != expected) return error.InvalidFixedArrayLength;
}

fn nextArrayElement(scanner: *std.json.Scanner) !?std.json.Token {
    const token = try scanner.next();
    if (token == .array_end) return null;
    return token;
}

fn expect(scanner: *std.json.Scanner, expected: std.json.Token) !void {
    const actual = try scanner.next();
    try expectConsumedToken(actual, expected);
}

fn expectConsumed(actual: std.json.Token, expected: std.json.Token) !void {
    try expectConsumedToken(actual, expected);
}

fn expectConsumedToken(actual: std.json.Token, expected: std.json.Token) !void {
    if (std.meta.activeTag(actual) != std.meta.activeTag(expected)) return error.UnexpectedToken;
}

fn readString(scanner: *std.json.Scanner, maximum: usize) ![]const u8 {
    return directString(try scanner.next(), maximum);
}

fn directString(token: std.json.Token, maximum: usize) ![]const u8 {
    const value = switch (token) {
        .string => |bytes| bytes,
        else => return error.NonCanonicalJsonString,
    };
    if (value.len > maximum) return error.StringLimitExceeded;
    return value;
}

fn readU8(scanner: *std.json.Scanner) !u8 {
    const value = try readU64(scanner);
    return std.math.cast(u8, value) orelse error.ValueOutOfRange;
}

fn readU32(scanner: *std.json.Scanner) !u32 {
    return readU32Token(try scanner.next());
}

fn readU32Token(token: std.json.Token) !u32 {
    const value = switch (token) {
        .number => |bytes| bytes,
        else => return error.UnexpectedToken,
    };
    return std.fmt.parseUnsigned(u32, value, 10) catch return error.ValueOutOfRange;
}

fn readU64(scanner: *std.json.Scanner) !u64 {
    const token = try scanner.next();
    const value = switch (token) {
        .number => |bytes| bytes,
        else => return error.UnexpectedToken,
    };
    return std.fmt.parseUnsigned(u64, value, 10) catch return error.ValueOutOfRange;
}

fn readOptionalU32(scanner: *std.json.Scanner) !?u32 {
    const token = try scanner.next();
    if (token == .null) return null;
    return try readU32Token(token);
}

fn readBool(scanner: *std.json.Scanner) !bool {
    return switch (try scanner.next()) {
        .true => true,
        .false => false,
        else => error.UnexpectedToken,
    };
}

fn objectField(comptime E: type, token: std.json.Token, seen: *u64) !E {
    const key = try directString(token, MAX_KEY_BYTES);
    const field = std.meta.stringToEnum(E, key) orelse return error.UnknownField;
    try mark(seen, @intFromEnum(field));
    return field;
}

fn mark(seen: anytype, index: usize) !void {
    const bit = @as(@TypeOf(seen.*), 1) << @intCast(index);
    if ((seen.* & bit) != 0) return error.DuplicateField;
    seen.* |= bit;
}

fn requireAll(comptime E: type, seen: u64) !void {
    const count = @typeInfo(E).@"enum".fields.len;
    const expected = (@as(u64, 1) << @intCast(count)) - 1;
    if (seen != expected) return error.MissingField;
}

test "preflight routing rejects duplicate security headers without typed allocation" {
    try std.testing.expectError(
        error.DuplicateField,
        route("{\"artifact_kind\":\"stwo_riscv_proof\",\"artifact_kind\":\"x\"}"),
    );
}

test "preflight rejects unknown nested fields and oversized arrays" {
    const unknown =
        "{\"artifact_kind\":\"stwo_riscv_proof\",\"schema_version\":4," ++
        "\"exchange_mode\":\"riscv_proof_json_wire_v4\",\"unknown\":0}";
    try std.testing.expectError(error.UnknownField, validate(unknown));

    var bytes: std.ArrayList(u8) = .{};
    defer bytes.deinit(std.testing.allocator);
    try bytes.appendSlice(std.testing.allocator, "{\"artifact_kind\":\"stwo_riscv_proof\",\"schema_version\":4," ++
        "\"exchange_mode\":\"riscv_proof_json_wire_v4\",\"release_status\":\"not_release_gated\"," ++
        "\"generator\":\"zig\",\"air\":\"sail_rv32im_zkvm_v1\",\"backend\":\"cpu\",\"protocol\":\"smoke\"," ++
        "\"source\":{\"elf_sha256\":\"" ++ "00" ** 32 ++ "\",\"input_sha256\":\"" ++ "00" ** 32 ++ "\"}," ++
        "\"provenance\":{\"oracle_repository\":\"x\",\"oracle_commit\":\"" ++ "00" ** 20 ++
        "\",\"implementation_repository\":\"x\",\"implementation_commit\":\"" ++ "00" ** 20 ++
        "\",\"implementation_dirty\":true,\"witness_layout_sha256\":\"" ++ "00" ** 32 ++ "\"}," ++
        "\"pcs_config\":{\"pow_bits\":0,\"fri_config\":{\"log_blowup_factor\":1,\"log_last_layer_degree_bound\":0,\"n_queries\":3,\"fold_step\":1},\"lifting_log_size\":null}," ++
        "\"statement\":{\"segment_ordinal\":0,\"segment_count\":1,\"initial_pc\":0,\"final_pc\":0,\"total_steps\":1,\"components\":[");
    for (0..schema.MAX_COMPONENTS + 1) |index| {
        if (index != 0) try bytes.append(std.testing.allocator, ',');
        try bytes.appendSlice(std.testing.allocator, "{\"index\":0,\"family\":0,\"family_shard_index\":0,\"family_shard_count\":1," ++
            "\"row_offset\":0,\"log_size\":4,\"n_rows\":1,\"n_columns\":1,\"interaction_batch_count\":1}");
    }
    try bytes.appendSlice(std.testing.allocator, "]}");
    try std.testing.expectError(error.InvalidComponentCount, validate(bytes.items));
}

test "preflight admits the registry-derived DIV interaction width" {
    const component =
        "[{\"index\":0,\"family\":15,\"family_shard_index\":0," ++
        "\"family_shard_count\":1,\"row_offset\":0,\"log_size\":4," ++
        "\"n_rows\":1,\"n_columns\":67,\"interaction_batch_count\":25}]";
    var storage: [SCANNER_STORAGE_BYTES]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&storage);
    var scanner = std.json.Scanner.initCompleteInput(fixed.allocator(), component);
    defer scanner.deinit();
    var widths = [_]u32{0} ** schema.MAX_COMPONENTS;
    try std.testing.expectEqual(@as(usize, 1), try parseComponents(&scanner, &widths));
    try std.testing.expectEqual(@as(u32, 25), widths[0]);
    try expect(&scanner, .end_of_document);
}
