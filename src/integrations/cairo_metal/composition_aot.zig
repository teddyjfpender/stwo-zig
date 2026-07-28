//! Integrity admission for the Cairo AIR composition metallib.
//!
//! Before this module the composition metallib was the only Metal artifact on
//! any Cairo path loaded with no integrity check at all: the runner derived its
//! filesystem path by string substitution on the `.bin` companion
//! (`src/tools/metal_arena_plan/main.zig`) and handed it straight to
//! `loadEvalLibrary`. The only in-repo binding between the AIR and the library
//! was by-name kernel resolution in `composition_prewarm.zig`, which is a
//! *completeness* check and not an *integrity* check: a library exporting
//! correctly-named kernels with substituted bodies resolves cleanly.
//!
//! This applies the same discipline the core AOT bundle and the generated
//! witness metallib already use (`witness_aot.zig`): measure the file, compare
//! against an in-tree manifest of approved digests, and fail closed. Callers
//! must treat any error here as "do not load this library" and fall back to the
//! host evaluator, recording the fallback as evidence.
//!
//! Fail-closed is the whole point. A composition library is an AIR evaluator;
//! a substituted one produces a proof that a verifier recomputing composition
//! at the OODS point rejects, but it produces it after the prover has spent the
//! full proving cost, and it does so without any artifact naming the swap.

const std = @import("std");

pub const Error = error{
    InvalidCompositionMetallibPath,
    CompositionMetallibChangedDuringAuthentication,
    CompositionMetallibLengthOverflow,
    CompositionMetallibLengthMismatch,
    CompositionMetallibDigestMismatch,
    UnapprovedCompositionMetallib,
    InvalidApprovedDigestEncoding,
};

pub const Measurement = struct {
    length: u64,
    sha256: [32]u8,

    pub fn hex(self: Measurement) [64]u8 {
        return std.fmt.bytesToHex(self.sha256, .lower);
    }
};

/// An approved composition metallib, identified by content.
///
/// `label` names the provenance of the artifact for evidence and for review; it
/// is never used in admission. Admission is by digest and length only, so
/// renaming, relocating or path-substituting an artifact cannot affect it.
pub const ApprovedMetallib = struct {
    label: []const u8,
    sha256_hex: *const [64:0]u8,
    length: u64,
};

/// The manifest. Entries are added only with an accompanying provenance record
/// in the campaign note and an independent security review of the artifact.
///
/// `sn_pie_2_composition_v1` is `vectors/cairo/sn_pie_2_composition.metallib`,
/// the conformance-vector composition library compiled offline by CI
/// (`.github/workflows/ci.yml`, the only producer — there is no local build
/// step, and this host has no full Xcode). It covers 58 components / 279 parts
/// / 1,325 constraints at `max_evaluation_log_size = 24`, unfused.
pub const approved_metallibs = [_]ApprovedMetallib{
    .{
        .label = "sn_pie_2_composition_v1",
        .sha256_hex = "85db09e024a661d78e34e53ed2ae36c150567977223f34bba88f119b3c7b21ab",
        .length = 7740844,
    },
};

/// How much authority a caller grants over which library may load.
///
/// There is deliberately no `.unchecked` variant: every caller either accepts
/// the manifest or names one specific digest it expects. Diagnostic tooling
/// that wants an arbitrary library must pass its digest explicitly, which keeps
/// the artifact identified in whatever evidence that tooling emits.
pub const Policy = union(enum) {
    /// Admit any library in `approved_metallibs`. This is the only policy a
    /// proving path may use.
    approved_manifest,
    /// Admit exactly one digest, whether or not it is in the manifest.
    pinned_digest: [32]u8,
    /// Measure and report, admit anything. Reserved for offline codegen and
    /// pipeline-prewarm tooling whose output is a compiled library and never a
    /// proof: `metal-eval-prepare` legitimately operates on libraries it has
    /// just generated, which by construction cannot be in a checked-in
    /// manifest. Admission still measures the file, so the digest lands in that
    /// tooling's evidence. **No path that produces a proof may pass this.**
    report_only,

    pub fn fromEncodedDigest(encoded: ?[]const u8) Error!Policy {
        const text = encoded orelse return .approved_manifest;
        return .{ .pinned_digest = try parseDigest(text) };
    }

    /// True when this policy can reject a library. Proving paths assert it.
    pub fn gates(self: Policy) bool {
        return switch (self) {
            .approved_manifest, .pinned_digest => true,
            .report_only => false,
        };
    }
};

pub const Admission = struct {
    measurement: Measurement,
    /// The manifest label when admission came from the manifest, else null.
    label: ?[]const u8,
};

/// Measures `path` and admits it under `policy`, or fails closed.
///
/// The measurement is a full read with a stat before and after, so a library
/// replaced between the digest check and `loadEvalLibrary` is caught by the
/// re-stat rather than silently loaded (the same TOCTOU handling as
/// `witness_aot.measureFile`).
pub fn authenticate(path: []const u8, policy: Policy) Error!Admission {
    const measurement = try measureFile(path);
    switch (policy) {
        .pinned_digest => |expected| {
            if (!std.mem.eql(u8, &measurement.sha256, &expected))
                return Error.CompositionMetallibDigestMismatch;
            return .{ .measurement = measurement, .label = labelFor(measurement) };
        },
        .approved_manifest => {
            const label = labelFor(measurement) orelse
                return Error.UnapprovedCompositionMetallib;
            return .{ .measurement = measurement, .label = label };
        },
        .report_only => return .{ .measurement = measurement, .label = labelFor(measurement) },
    }
}

fn labelFor(measurement: Measurement) ?[]const u8 {
    for (approved_metallibs) |approved| {
        const expected = parseDigest(approved.sha256_hex) catch continue;
        if (std.mem.eql(u8, &measurement.sha256, &expected) and
            measurement.length == approved.length) return approved.label;
    }
    return null;
}

pub fn parseDigest(encoded: []const u8) Error![32]u8 {
    if (encoded.len != 64) return Error.InvalidApprovedDigestEncoding;
    var digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, encoded) catch
        return Error.InvalidApprovedDigestEncoding;
    // Reject uppercase and other non-canonical spellings so that a digest in a
    // report is comparable byte-for-byte with a digest in the manifest.
    const canonical = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, encoded, &canonical))
        return Error.InvalidApprovedDigestEncoding;
    return digest;
}

fn measureFile(path: []const u8) Error!Measurement {
    if (path.len == 0) return Error.InvalidCompositionMetallibPath;
    const file = openFile(path) catch return Error.InvalidCompositionMetallibPath;
    defer file.close();
    const before = file.stat() catch return Error.InvalidCompositionMetallibPath;
    if (before.kind != .file or before.size == 0)
        return Error.InvalidCompositionMetallibPath;

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [256 * 1024]u8 = undefined;
    var length: u64 = 0;
    while (true) {
        const read = file.read(&buffer) catch
            return Error.CompositionMetallibChangedDuringAuthentication;
        if (read == 0) break;
        hasher.update(buffer[0..read]);
        length = std.math.add(u64, length, read) catch
            return Error.CompositionMetallibLengthOverflow;
    }
    const after = file.stat() catch
        return Error.CompositionMetallibChangedDuringAuthentication;
    if (length != before.size or !sameFile(before, after))
        return Error.CompositionMetallibChangedDuringAuthentication;
    return .{ .length = length, .sha256 = hasher.finalResult() };
}

fn openFile(path: []const u8) !std.fs.File {
    return if (std.fs.path.isAbsolute(path))
        std.fs.openFileAbsolute(path, .{})
    else
        std.fs.cwd().openFile(path, .{});
}

fn sameFile(left: std.fs.File.Stat, right: std.fs.File.Stat) bool {
    return left.inode == right.inode and
        left.size == right.size and
        left.mtime == right.mtime and
        left.ctime == right.ctime and
        left.mode == right.mode;
}

test "the approved manifest is canonically encoded" {
    try std.testing.expect(approved_metallibs.len > 0);
    for (approved_metallibs) |approved| {
        _ = try parseDigest(approved.sha256_hex);
        try std.testing.expect(approved.length > 0);
        try std.testing.expect(approved.label.len > 0);
    }
}

test "non-canonical digest encodings are rejected" {
    try std.testing.expectError(
        Error.InvalidApprovedDigestEncoding,
        parseDigest("85DB09E024A661D78E34E53ED2AE36C150567977223F34BBA88F119B3C7B21AB"),
    );
    try std.testing.expectError(Error.InvalidApprovedDigestEncoding, parseDigest("85db09e0"));
    try std.testing.expectError(
        Error.InvalidApprovedDigestEncoding,
        parseDigest("zzdb09e024a661d78e34e53ed2ae36c150567977223f34bba88f119b3c7b21ab"),
    );
}

test "the checked-in composition metallib is admitted by the manifest" {
    const admission = try authenticate(
        "vectors/cairo/sn_pie_2_composition.metallib",
        .approved_manifest,
    );
    try std.testing.expectEqualStrings("sn_pie_2_composition_v1", admission.label.?);
    try std.testing.expectEqual(@as(u64, 7740844), admission.measurement.length);
    try std.testing.expectEqualStrings(
        "85db09e024a661d78e34e53ed2ae36c150567977223f34bba88f119b3c7b21ab",
        &admission.measurement.hex(),
    );
}

test "a pinned digest admits only that digest" {
    const approved = try parseDigest(approved_metallibs[0].sha256_hex);
    const admission = try authenticate(
        "vectors/cairo/sn_pie_2_composition.metallib",
        .{ .pinned_digest = approved },
    );
    try std.testing.expectEqualStrings("sn_pie_2_composition_v1", admission.label.?);

    var wrong = approved;
    wrong[0] ^= 0xff;
    try std.testing.expectError(Error.CompositionMetallibDigestMismatch, authenticate(
        "vectors/cairo/sn_pie_2_composition.metallib",
        .{ .pinned_digest = wrong },
    ));
}

test "a corrupted library fails closed under the manifest" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();

    const original = try std.fs.cwd().readFileAlloc(
        std.testing.allocator,
        "vectors/cairo/sn_pie_2_composition.metallib",
        16 * 1024 * 1024,
    );
    defer std.testing.allocator.free(original);

    // A single flipped byte in a kernel body: same length, same name table, a
    // library that resolves every required pipeline by name and evaluates the
    // wrong AIR. This is the case by-name resolution cannot see.
    const corrupted = try std.testing.allocator.dupe(u8, original);
    defer std.testing.allocator.free(corrupted);
    corrupted[corrupted.len / 2] ^= 0x01;
    try temporary.dir.writeFile(.{ .sub_path = "composition.metallib", .data = corrupted });

    const path = try temporary.dir.realpathAlloc(std.testing.allocator, "composition.metallib");
    defer std.testing.allocator.free(path);

    try std.testing.expectError(
        Error.UnapprovedCompositionMetallib,
        authenticate(path, .approved_manifest),
    );
    try std.testing.expectError(
        Error.CompositionMetallibDigestMismatch,
        authenticate(path, .{ .pinned_digest = try parseDigest(approved_metallibs[0].sha256_hex) }),
    );

    // Length preservation is what makes this a real substitution rather than a
    // truncation, so assert the corruption kept it.
    try std.testing.expectEqual(original.len, corrupted.len);
}

test "a missing or empty library fails closed" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(.{ .sub_path = "empty.metallib", .data = "" });
    const path = try temporary.dir.realpathAlloc(std.testing.allocator, "empty.metallib");
    defer std.testing.allocator.free(path);

    try std.testing.expectError(
        Error.InvalidCompositionMetallibPath,
        authenticate(path, .approved_manifest),
    );
    try std.testing.expectError(
        Error.InvalidCompositionMetallibPath,
        authenticate("", .approved_manifest),
    );
    try std.testing.expectError(
        Error.InvalidCompositionMetallibPath,
        authenticate("/nonexistent/composition.metallib", .approved_manifest),
    );
}

test "policy defaults to the manifest and accepts an explicit digest" {
    try std.testing.expectEqual(Policy.approved_manifest, try Policy.fromEncodedDigest(null));
    const policy = try Policy.fromEncodedDigest(approved_metallibs[0].sha256_hex);
    try std.testing.expectEqual(
        try parseDigest(approved_metallibs[0].sha256_hex),
        policy.pinned_digest,
    );
    try std.testing.expectError(
        Error.InvalidApprovedDigestEncoding,
        Policy.fromEncodedDigest("not-a-digest"),
    );
}

/// The admission policy for this process.
///
/// Defaults to the checked-in manifest. `STWO_ZIG_COMPOSITION_METALLIB_SHA256`
/// pins one specific digest instead, which is how a CI- or locally-compiled
/// library that predates a manifest entry is admitted — by naming it, never by
/// disabling the check. A malformed value is an error, not a downgrade.
pub const policy_env = "STWO_ZIG_COMPOSITION_METALLIB_SHA256";

pub fn policyFromProcess(allocator: std.mem.Allocator) !Policy {
    const encoded = std.process.getEnvVarOwned(allocator, policy_env) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return .approved_manifest,
        else => return err,
    };
    defer allocator.free(encoded);
    return Policy.fromEncodedDigest(std.mem.trim(u8, encoded, " \t\r\n"));
}

/// Authenticates `path` under the process policy and returns its admission.
/// Any error means "do not load"; callers must fall back to the host evaluator
/// and record the fallback rather than retrying with a weaker policy.
pub fn authenticateFromProcess(allocator: std.mem.Allocator, path: []const u8) !Admission {
    const policy = try policyFromProcess(allocator);
    return authenticate(path, policy) catch |err| {
        std.log.err("composition metallib rejected: {s} ({t})", .{ path, err });
        return err;
    };
}

test "the process policy defaults to the manifest" {
    // The env var is not set in the test environment, so this exercises the
    // default. A policy that defaulted to permissive would be the whole bug.
    const policy = try policyFromProcess(std.testing.allocator);
    try std.testing.expectEqual(Policy.approved_manifest, policy);
    try std.testing.expect(policy.gates());
    try std.testing.expect(!(Policy{ .report_only = {} }).gates());
}
