//! `zig build circuit-air-projection-check`: authenticates the committed
//! compiled-AIR projection against `vectors/circuit/provenance.json` (byte
//! count and SHA-256) and decodes it completely, verifying every record
//! digest and generator invariant. Runs from the repository root.

const std = @import("std");
const circuit = @import("stwo_circuit_frontend");

const provenance_path = "vectors/circuit/provenance.json";
const projection_path = "vectors/circuit/official/compiled_air_constraints_v1.bin";

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    const provenance_bytes = try std.fs.cwd().readFileAlloc(gpa, provenance_path, 1 << 20);
    defer gpa.free(provenance_bytes);
    const provenance = try std.json.parseFromSlice(std.json.Value, gpa, provenance_bytes, .{});
    defer provenance.deinit();

    const entry = findArtifact(provenance.value) orelse return fail("{s}: no entry for {s}", .{ provenance_path, projection_path });
    const expected_bytes = entry.object.get("bytes") orelse return fail("{s}: entry without bytes", .{provenance_path});
    const expected_sha = entry.object.get("sha256") orelse return fail("{s}: entry without sha256", .{provenance_path});
    if (expected_bytes != .integer or expected_sha != .string) return fail("{s}: malformed entry", .{provenance_path});

    const bytes = try std.fs.cwd().readFileAlloc(gpa, projection_path, 64 << 20);
    defer gpa.free(bytes);
    if (bytes.len != expected_bytes.integer)
        return fail("{s}: {d} bytes, provenance says {d}", .{ projection_path, bytes.len, expected_bytes.integer });
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, &hex, expected_sha.string))
        return fail("{s}: sha256 {s}, provenance says {s}", .{ projection_path, &hex, expected_sha.string });

    var projection = circuit.air_eval.projection.parse(gpa, bytes) catch |err|
        return fail("{s}: {s}", .{ projection_path, @errorName(err) });
    defer projection.deinit();
    var cairo = try circuit.air_eval.cairo_components.build(gpa, &projection);
    defer cairo.deinit();
    var circuit_table = try circuit.air_eval.circuit_components.build(gpa, &projection);
    defer circuit_table.deinit();

    var stdout_buffer: [256]u8 = undefined;
    var stdout = std.fs.File.stdout().writer(&stdout_buffer);
    try stdout.interface.print("{s}: ok ({d} bytes, {d} cairo slots, {d} circuit components, revision {s})\n", .{
        projection_path,
        bytes.len,
        cairo.entries.len,
        circuit_table.entries.len,
        projection.str(projection.revision),
    });
    try stdout.interface.flush();
}

fn findArtifact(document: std.json.Value) ?std.json.Value {
    if (document != .object) return null;
    const artifacts = document.object.get("artifacts") orelse return null;
    if (artifacts != .array) return null;
    for (artifacts.array.items) |artifact| {
        if (artifact != .object) continue;
        const path = artifact.object.get("path") orelse continue;
        if (path == .string and std.mem.eql(u8, path.string, projection_path)) return artifact;
    }
    return null;
}

fn fail(comptime format: []const u8, args: anytype) error{ProjectionCheckFailed} {
    std.debug.print("circuit-air-projection-check: " ++ format ++ "\n", args);
    return error.ProjectionCheckFailed;
}
