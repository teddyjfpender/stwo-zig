//! Stable identity records for degree-bounded materializations.
//!
//! Kept separate from graph selection so diagnostics and identity formatting
//! cannot consume the materializer's remaining source-conformance headroom.

const std = @import("std");
const digest = @import("digest.zig");
const expr = @import("expr.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const Degree = u64;
pub const Policy = struct {
    maximum_constraint_degree: Degree = 3,
    /// Degree contributed by a row or boundary mask outside the logical DAG.
    row_mask_degree: Degree = 0,
};

pub const SourceOp = enum(u8) {
    constant,
    input,
    add,
    sub,
    mul,
    neg,
    select,
    hint_output,
    call_output,
    register_address,
    access_clock,
    strict_clock_gap,
    aligned_word_address,
};

const maximum_name_length = 112;

/// Copy-safe fixed storage; `slice` borrows from the containing descriptor.
pub const StableName = struct {
    bytes: [maximum_name_length]u8 = .{0} ** maximum_name_length,
    len: u8 = 0,

    pub fn slice(self: *const StableName) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub fn fingerprint(
    program_digest: digest.Digest,
    value: types.ValueId,
    gate: ?types.ValueId,
    policy: Policy,
) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/materialization/v1");
    hash.update(&program_digest);
    hashInt(&hash, u32, @intFromEnum(value));
    hashInt(&hash, u32, if (gate) |item| @intFromEnum(item) else std.math.maxInt(u32));
    hashInt(&hash, u64, policy.maximum_constraint_degree);
    hashInt(&hash, u64, policy.row_mask_degree);
    return hash.finalResult();
}

pub const IdentityError = error{UnsupportedProgramDigestFormat};

/// Extends materialization identity to typed semantic formats without changing
/// one byte of the accepted format-1 preimage. Typed formats bind the semantic
/// format before its digest bytes so a digest cannot be re-labelled across
/// projection versions.
pub fn fingerprintForIdentity(
    program_digest_format: u16,
    program_digest: digest.Digest,
    value: types.ValueId,
    gate: ?types.ValueId,
    policy: Policy,
) IdentityError!digest.Digest {
    if (program_digest_format == digest.format_version)
        return fingerprint(program_digest, value, gate, policy);
    if (program_digest_format != digest.typed_effect_format_version and
        program_digest_format != digest.register_group_format_version and
        program_digest_format != digest.memory_access_format_version)
    {
        return error.UnsupportedProgramDigestFormat;
    }

    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/materialization/v2");
    hashInt(&hash, u16, program_digest_format);
    hash.update(&program_digest);
    hashInt(&hash, u32, @intFromEnum(value));
    hashInt(&hash, u32, if (gate) |item| @intFromEnum(item) else std.math.maxInt(u32));
    hashInt(&hash, u64, policy.maximum_constraint_degree);
    hashInt(&hash, u64, policy.row_mask_degree);
    return hash.finalResult();
}

pub fn makeName(
    op: SourceOp,
    span: source.SourceSpan,
    value_fingerprint: digest.Digest,
) error{InvalidStableName}!StableName {
    var result = StableName{};
    const hex = std.fmt.bytesToHex(value_fingerprint, .lower);
    const written = if (span.source == null)
        std.fmt.bufPrint(&result.bytes, "air.mat.v1.{s}.generated.{s}", .{ @tagName(op), hex })
    else
        std.fmt.bufPrint(
            &result.bytes,
            "air.mat.v1.{s}.L{d}C{d}.{s}",
            .{ @tagName(op), span.start.line, span.start.column, hex },
        );
    const name = written catch return error.InvalidStableName;
    result.len = std.math.cast(u8, name.len) orelse return error.InvalidStableName;
    return result;
}

pub fn validName(
    actual: StableName,
    op: SourceOp,
    span: source.SourceSpan,
    value_fingerprint: digest.Digest,
) bool {
    const expected = makeName(op, span, value_fingerprint) catch return false;
    return std.meta.eql(actual, expected);
}

pub fn sourceOp(op: expr.Op) SourceOp {
    return switch (op) {
        .constant => .constant,
        .input => .input,
        .add => .add,
        .sub => .sub,
        .mul => .mul,
        .neg => .neg,
        .select => .select,
        .hint_output => .hint_output,
        .call_output => .call_output,
        .machine_derived => |derived| switch (derived) {
            .register_address => .register_address,
            .aligned_word_address => .aligned_word_address,
            .access_clock => .access_clock,
            .strict_clock_gap => .strict_clock_gap,
        },
    };
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}
