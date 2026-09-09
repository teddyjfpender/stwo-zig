//! Diagnostic parity for the Metal FRI fold path.
//!
//! This module is deliberately process-local and codec-free.  The proof path
//! calls it only when `STWO_ZIG_METAL_FRI_PARITY` is present.  It recomputes
//! each butterfly from the exact host-visible resident inputs after the Metal
//! command completes, so it neither changes the transcript nor supplies proof
//! authority.

const std = @import("std");
const core = @import("stwo_core");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const CircleDomain = core.poly.circle.domain.CircleDomain;
const LineDomain = core.poly.line.LineDomain;

pub const ENV = "STWO_ZIG_METAL_FRI_PARITY";

pub const Kind = enum {
    circle_to_line,
    line,
};

pub const Mismatch = struct {
    row: usize,
    coordinate: usize,
    expected: u32,
    actual: u32,
};

pub const Receipt = struct {
    kind: Kind,
    source_log_size: u32,
    destination_log_size: u32,
    source_count: usize,
    destination_count: usize,
    domain_initial_index: u32,
    domain_step_size: u32,
    alpha: [4]u32,
    source_identity_sha256: [32]u8,
    output_identity_sha256: [32]u8,
    terminal_coefficient_one: ?[4]u32,

    pub fn print(self: Receipt) void {
        const identity_hex = std.fmt.bytesToHex(
            self.output_identity_sha256,
            .lower,
        );
        const source_hex = std.fmt.bytesToHex(
            self.source_identity_sha256,
            .lower,
        );
        if (self.terminal_coefficient_one) |coefficient| {
            std.log.info(
                "METAL_FRI_PARITY_V1 kind={s} source_log={} destination_log={} " ++
                    "source_count={} destination_count={} domain_initial={} " ++
                    "domain_step={} alpha={},{},{},{} source_sha256={s} " ++
                    "output_sha256={s} " ++
                    "terminal_coefficient_one={},{},{},{}",
                .{
                    @tagName(self.kind),
                    self.source_log_size,
                    self.destination_log_size,
                    self.source_count,
                    self.destination_count,
                    self.domain_initial_index,
                    self.domain_step_size,
                    self.alpha[0],
                    self.alpha[1],
                    self.alpha[2],
                    self.alpha[3],
                    &source_hex,
                    &identity_hex,
                    coefficient[0],
                    coefficient[1],
                    coefficient[2],
                    coefficient[3],
                },
            );
        } else {
            std.log.info(
                "METAL_FRI_PARITY_V1 kind={s} source_log={} destination_log={} " ++
                    "source_count={} destination_count={} domain_initial={} " ++
                    "domain_step={} alpha={},{},{},{} source_sha256={s} " ++
                    "output_sha256={s}",
                .{
                    @tagName(self.kind),
                    self.source_log_size,
                    self.destination_log_size,
                    self.source_count,
                    self.destination_count,
                    self.domain_initial_index,
                    self.domain_step_size,
                    self.alpha[0],
                    self.alpha[1],
                    self.alpha[2],
                    self.alpha[3],
                    &source_hex,
                    &identity_hex,
                },
            );
        }
    }
};

pub fn enabled() bool {
    return std.process.hasEnvVarConstant(ENV);
}

pub fn validateCircle(
    source: [4][]const M31,
    source_domain: CircleDomain,
    inverses_y: []const M31,
    alpha: QM31,
    actual: []const QM31,
) !Receipt {
    if (try firstCircleMismatch(source, inverses_y, alpha, actual)) |mismatch| {
        reportMismatch(.circle_to_line, source_domain.logSize(), mismatch);
        return error.MetalFriFoldParityMismatch;
    }

    return receipt(
        .circle_to_line,
        source_domain.logSize(),
        source_domain.half_coset.initial_index.v,
        source_domain.half_coset.step_size.v,
        alpha,
        actual,
        source[0].len,
        sourceIdentityCircle(source),
        null,
    );
}

/// Returns the exact first scalar mismatch without logging.  Mutation tests
/// use this surface so an expected rejection cannot emit an error-level log.
pub fn firstCircleMismatch(
    source: [4][]const M31,
    inverses_y: []const M31,
    alpha: QM31,
    actual: []const QM31,
) !?Mismatch {
    if (source[0].len < 2 or source[0].len != actual.len * 2 or
        inverses_y.len != actual.len)
    {
        return error.InvalidMetalFriParityShape;
    }
    for (source[1..]) |column| {
        if (column.len != source[0].len)
            return error.InvalidMetalFriParityShape;
    }

    for (actual, inverses_y, 0..) |actual_value, inverse_y, row| {
        const left_index = row * 2;
        const right_index = left_index + 1;
        const left = QM31.fromM31Array(.{
            source[0][left_index],
            source[1][left_index],
            source[2][left_index],
            source[3][left_index],
        });
        const right = QM31.fromM31Array(.{
            source[0][right_index],
            source[1][right_index],
            source[2][right_index],
            source[3][right_index],
        });
        const expected = foldPair(left, right, inverse_y, alpha);
        if (firstCoordinateMismatch(expected, actual_value)) |found| {
            var mismatch = found;
            mismatch.row = row;
            return mismatch;
        }
    }
    return null;
}

pub fn validateLine(
    source: []const QM31,
    source_domain: LineDomain,
    inverses_x: []const M31,
    alpha: QM31,
    actual: []const QM31,
) !Receipt {
    if (try firstLineMismatch(source, inverses_x, alpha, actual)) |mismatch| {
        reportMismatch(.line, source_domain.logSize(), mismatch);
        return error.MetalFriFoldParityMismatch;
    }

    const destination_domain = source_domain.double();
    const terminal = if (actual.len == 2)
        (try terminalCoefficientOne(actual, destination_domain)).toM31Array()
    else
        null;
    const coset = source_domain.coset();
    return receipt(
        .line,
        source_domain.logSize(),
        coset.initial_index.v,
        coset.step_size.v,
        alpha,
        actual,
        source.len,
        sourceIdentityLine(source),
        terminal,
    );
}

pub fn firstLineMismatch(
    source: []const QM31,
    inverses_x: []const M31,
    alpha: QM31,
    actual: []const QM31,
) !?Mismatch {
    if (source.len < 2 or source.len != actual.len * 2 or
        inverses_x.len != actual.len)
    {
        return error.InvalidMetalFriParityShape;
    }
    for (actual, inverses_x, 0..) |actual_value, inverse_x, row| {
        const expected = foldPair(
            source[row * 2],
            source[row * 2 + 1],
            inverse_x,
            alpha,
        );
        if (firstCoordinateMismatch(expected, actual_value)) |found| {
            var mismatch = found;
            mismatch.row = row;
            return mismatch;
        }
    }
    return null;
}

/// For a two-point bit-reversed line evaluation, this is exactly ordered
/// coefficient one produced by `LineEvaluation.interpolate`.
pub fn terminalCoefficientOne(
    values: []const QM31,
    domain: LineDomain,
) !QM31 {
    if (values.len != 2 or domain.size() != 2)
        return error.InvalidMetalFriParityShape;
    const inverse_x = try domain.at(0).inv();
    const inverse_two = M31.fromCanonical(1 << 30);
    return values[0].sub(values[1]).mulM31(inverse_x).mulM31(inverse_two);
}

fn foldPair(left: QM31, right: QM31, inverse: M31, alpha: QM31) QM31 {
    return left.add(right).add(alpha.mul(left.sub(right).mulM31(inverse)));
}

fn firstCoordinateMismatch(expected: QM31, actual: QM31) ?Mismatch {
    const expected_coordinates = expected.toM31Array();
    const actual_coordinates = actual.toM31Array();
    inline for (0..4) |coordinate| {
        if (!expected_coordinates[coordinate].eql(actual_coordinates[coordinate])) {
            return .{
                .row = 0,
                .coordinate = coordinate,
                .expected = expected_coordinates[coordinate].toU32(),
                .actual = actual_coordinates[coordinate].toU32(),
            };
        }
    }
    return null;
}

fn reportMismatch(
    kind: Kind,
    source_log_size: u32,
    mismatch: Mismatch,
) void {
    std.log.err(
        "METAL_FRI_PARITY_MISMATCH_V1 kind={s} source_log={} row={} " ++
            "coordinate={} expected={} actual={}",
        .{
            @tagName(kind),
            source_log_size,
            mismatch.row,
            mismatch.coordinate,
            mismatch.expected,
            mismatch.actual,
        },
    );
}

fn receipt(
    kind: Kind,
    source_log_size: u32,
    domain_initial_index: usize,
    domain_step_size: usize,
    alpha: QM31,
    actual: []const QM31,
    source_count: usize,
    source_identity_sha256: [32]u8,
    terminal_coefficient_one: ?[4]M31,
) !Receipt {
    if (actual.len == 0 or !std.math.isPowerOfTwo(actual.len))
        return error.InvalidMetalFriParityShape;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("stwo/metal/fri-fold-parity/v1\x00");
    hasher.update(std.mem.sliceAsBytes(actual));
    const alpha_coordinates = alpha.toM31Array();
    var terminal_words: ?[4]u32 = null;
    if (terminal_coefficient_one) |coordinates| {
        terminal_words = .{
            coordinates[0].toU32(),
            coordinates[1].toU32(),
            coordinates[2].toU32(),
            coordinates[3].toU32(),
        };
    }
    return .{
        .kind = kind,
        .source_log_size = source_log_size,
        .destination_log_size = @intCast(std.math.log2_int(usize, actual.len)),
        .source_count = source_count,
        .destination_count = actual.len,
        .domain_initial_index = std.math.cast(u32, domain_initial_index) orelse
            return error.InvalidMetalFriParityDomain,
        .domain_step_size = std.math.cast(u32, domain_step_size) orelse
            return error.InvalidMetalFriParityDomain,
        .alpha = .{
            alpha_coordinates[0].toU32(),
            alpha_coordinates[1].toU32(),
            alpha_coordinates[2].toU32(),
            alpha_coordinates[3].toU32(),
        },
        .source_identity_sha256 = source_identity_sha256,
        .output_identity_sha256 = hasher.finalResult(),
        .terminal_coefficient_one = terminal_words,
    };
}

fn sourceIdentityCircle(source: [4][]const M31) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("stwo/metal/fri-circle-source/v1\x00");
    for (source) |column| hasher.update(std.mem.sliceAsBytes(column));
    return hasher.finalResult();
}

fn sourceIdentityLine(source: []const QM31) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("stwo/metal/fri-line-source/v1\x00");
    hasher.update(std.mem.sliceAsBytes(source));
    return hasher.finalResult();
}
