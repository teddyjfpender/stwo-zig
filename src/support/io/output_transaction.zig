//! Logical transaction for publishing a proof and its machine-readable report.
//!
//! The proof path is the commit marker. A report may be visible by itself if
//! the process stops at the publication boundary, but a proof produced by this
//! transaction is never visible before its report.

const std = @import("std");

pub const Boundary = enum {
    prepared,
    report_visible,
    committed,
};

pub fn prepare(proof_output: ?[]const u8, report_output: ?[]const u8) !void {
    if (proof_output) |proof| {
        if (report_output) |report| {
            if (std.mem.eql(u8, proof, report)) return error.OutputPathCollision;
        }
        try requireAbsent(proof);
    }
    if (report_output) |report| try requireAbsent(report);
}

pub fn publishResult(
    comptime AtomicFile: type,
    allocator: std.mem.Allocator,
    proof_temporary: []const u8,
    proof_output: []const u8,
    report: []const u8,
    report_output: ?[]const u8,
    report_writer: anytype,
) !void {
    return publishResultObserved(
        AtomicFile,
        allocator,
        proof_temporary,
        proof_output,
        report,
        report_output,
        report_writer,
        NoObserver{},
    );
}

pub fn publishReport(
    comptime AtomicFile: type,
    allocator: std.mem.Allocator,
    report: []const u8,
    report_output: ?[]const u8,
    report_writer: anytype,
) !void {
    try prepare(null, report_output);
    if (report_output) |output| return AtomicFile.writeExclusive(allocator, output, report);
    try writeLine(report_writer, report);
}

fn publishResultObserved(
    comptime AtomicFile: type,
    allocator: std.mem.Allocator,
    proof_temporary: []const u8,
    proof_output: []const u8,
    report: []const u8,
    report_output: ?[]const u8,
    report_writer: anytype,
    observer: anytype,
) !void {
    try prepare(proof_output, report_output);
    try observer.reached(.prepared);

    if (report_output) |output| {
        const report_temporary = try AtomicFile.temporaryPathAlloc(allocator, output, "report");
        defer allocator.free(report_temporary);
        defer std.fs.cwd().deleteFile(report_temporary) catch {};
        try AtomicFile.writeExclusive(allocator, report_temporary, report);
        try AtomicFile.publishExclusive(report_temporary, output);

        observer.reached(.report_visible) catch |err| return rollbackReport(output, err);
        AtomicFile.publishExclusive(proof_temporary, proof_output) catch |err|
            return rollbackReport(output, err);
        try observer.reached(.committed);
        return;
    }

    try writeLine(report_writer, report);
    try observer.reached(.report_visible);
    try AtomicFile.publishExclusive(proof_temporary, proof_output);
    try observer.reached(.committed);
}

fn rollbackReport(path: []const u8, original: anyerror) anyerror {
    std.fs.cwd().deleteFile(path) catch return error.ReportRollbackFailed;
    return original;
}

fn requireAbsent(path: []const u8) !void {
    if (path.len == 0) return error.InvalidOutputPath;
    std.fs.cwd().access(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    return error.OutputAlreadyExists;
}

fn writeLine(writer: anytype, bytes: []const u8) !void {
    try writer.writeAll(bytes);
    try writer.writeByte('\n');
}

const NoObserver = struct {
    fn reached(_: NoObserver, _: Boundary) !void {}
};

const TestAtomicFile = struct {
    fn temporaryPathAlloc(
        allocator: std.mem.Allocator,
        output_path: []const u8,
        label: []const u8,
    ) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}.{s}.tmp", .{ output_path, label });
    }

    fn publishExclusive(temporary_path: []const u8, output_path: []const u8) !void {
        try requireAbsent(output_path);
        try std.fs.cwd().rename(temporary_path, output_path);
    }

    fn writeExclusive(
        allocator: std.mem.Allocator,
        output_path: []const u8,
        bytes: []const u8,
    ) !void {
        const temporary_path = try temporaryPathAlloc(allocator, output_path, "write");
        defer allocator.free(temporary_path);
        defer std.fs.cwd().deleteFile(temporary_path) catch {};
        const file = try std.fs.cwd().createFile(temporary_path, .{ .exclusive = true });
        var open = true;
        defer if (open) file.close();
        try file.writeAll(bytes);
        try file.sync();
        file.close();
        open = false;
        try publishExclusive(temporary_path, output_path);
    }
};

const StateObserver = struct {
    proof_output: []const u8,
    report_output: []const u8,
    seen: *[3]bool,

    fn reached(self: StateObserver, boundary: Boundary) !void {
        self.seen[@intFromEnum(boundary)] = true;
        switch (boundary) {
            .prepared => {
                try expectAbsent(self.proof_output);
                try expectAbsent(self.report_output);
            },
            .report_visible => {
                try expectAbsent(self.proof_output);
                try expectContents(self.report_output, "report");
            },
            .committed => {
                try expectContents(self.report_output, "report");
                try expectContents(self.proof_output, "proof");
            },
        }
    }
};

const FailAtReportBoundary = struct {
    fn reached(_: FailAtReportBoundary, boundary: Boundary) !void {
        if (boundary == .report_visible) return error.InjectedPreCommitFailure;
    }
};

fn expectAbsent(path: []const u8) !void {
    try std.testing.expectError(error.FileNotFound, std.fs.cwd().access(path, .{}));
}

fn expectContents(path: []const u8, expected: []const u8) !void {
    const actual = try std.fs.cwd().readFileAlloc(std.testing.allocator, path, 64);
    defer std.testing.allocator.free(actual);
    try std.testing.expectEqualStrings(expected, actual);
}

test "crash-boundary states keep proof publication as the logical commit point" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const proof_temporary = try std.fs.path.join(std.testing.allocator, &.{ root, "proof.tmp" });
    defer std.testing.allocator.free(proof_temporary);
    const proof_output = try std.fs.path.join(std.testing.allocator, &.{ root, "proof.json" });
    defer std.testing.allocator.free(proof_output);
    const report_output = try std.fs.path.join(std.testing.allocator, &.{ root, "report.json" });
    defer std.testing.allocator.free(report_output);
    try TestAtomicFile.writeExclusive(std.testing.allocator, proof_temporary, "proof");

    var sink_storage: [1]u8 = undefined;
    var sink = std.Io.Writer.fixed(&sink_storage);
    var seen = [_]bool{false} ** 3;
    try publishResultObserved(
        TestAtomicFile,
        std.testing.allocator,
        proof_temporary,
        proof_output,
        "report",
        report_output,
        &sink,
        StateObserver{
            .proof_output = proof_output,
            .report_output = report_output,
            .seen = &seen,
        },
    );
    try std.testing.expectEqualSlices(bool, &.{ true, true, true }, &seen);
}

test "failed report writer never exposes the proof" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const proof_temporary = try std.fs.path.join(std.testing.allocator, &.{ root, "proof.tmp" });
    defer std.testing.allocator.free(proof_temporary);
    const proof_output = try std.fs.path.join(std.testing.allocator, &.{ root, "proof.json" });
    defer std.testing.allocator.free(proof_output);
    try TestAtomicFile.writeExclusive(std.testing.allocator, proof_temporary, "proof");

    var sink_storage: [0]u8 = .{};
    var sink = std.Io.Writer.fixed(&sink_storage);
    try std.testing.expectError(error.WriteFailed, publishResult(
        TestAtomicFile,
        std.testing.allocator,
        proof_temporary,
        proof_output,
        "report",
        null,
        &sink,
    ));
    try expectAbsent(proof_output);
    try expectContents(proof_temporary, "proof");
}

test "ordinary pre-commit failure removes the visible report" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const proof_temporary = try std.fs.path.join(std.testing.allocator, &.{ root, "proof.tmp" });
    defer std.testing.allocator.free(proof_temporary);
    const proof_output = try std.fs.path.join(std.testing.allocator, &.{ root, "proof.json" });
    defer std.testing.allocator.free(proof_output);
    const report_output = try std.fs.path.join(std.testing.allocator, &.{ root, "report.json" });
    defer std.testing.allocator.free(report_output);
    try TestAtomicFile.writeExclusive(std.testing.allocator, proof_temporary, "proof");

    var sink_storage: [1]u8 = undefined;
    var sink = std.Io.Writer.fixed(&sink_storage);
    try std.testing.expectError(error.InjectedPreCommitFailure, publishResultObserved(
        TestAtomicFile,
        std.testing.allocator,
        proof_temporary,
        proof_output,
        "report",
        report_output,
        &sink,
        FailAtReportBoundary{},
    ));
    try expectAbsent(proof_output);
    try expectAbsent(report_output);
    try expectContents(proof_temporary, "proof");
}

test "colliding and existing outputs are rejected before publication" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const proof_output = try std.fs.path.join(std.testing.allocator, &.{ root, "proof.json" });
    defer std.testing.allocator.free(proof_output);
    const report_output = try std.fs.path.join(std.testing.allocator, &.{ root, "report.json" });
    defer std.testing.allocator.free(report_output);

    try std.testing.expectError(error.OutputPathCollision, prepare(proof_output, proof_output));
    try temporary.dir.writeFile(.{ .sub_path = "proof.json", .data = "existing proof" });
    try std.testing.expectError(error.OutputAlreadyExists, prepare(proof_output, report_output));
    try temporary.dir.deleteFile("proof.json");
    try temporary.dir.writeFile(.{ .sub_path = "report.json", .data = "existing report" });
    try std.testing.expectError(error.OutputAlreadyExists, prepare(proof_output, report_output));
    try expectAbsent(proof_output);
    try expectContents(report_output, "existing report");
}
