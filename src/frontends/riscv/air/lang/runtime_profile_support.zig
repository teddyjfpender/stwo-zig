//! Arithmetic, source hashing, and task-key helpers for runtime profiles.

const std = @import("std");
const task_profile = @import("stwo_prover_api").task_profile;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Digest = [Sha256.digest_length]u8;

pub fn containsTaskKey(
    events: []const task_profile.TaskEvent,
    key: task_profile.TaskKey,
) bool {
    for (events) |event| if (event.key.eql(key)) return true;
    return false;
}

pub fn secondsToNanoseconds(seconds: f64) !u64 {
    if (!std.math.isFinite(seconds) or seconds < 0)
        return error.InvalidRuntimeProfileInput;
    const nanoseconds = seconds * @as(f64, @floatFromInt(std.time.ns_per_s));
    if (!std.math.isFinite(nanoseconds) or
        nanoseconds > @as(f64, @floatFromInt(std.math.maxInt(u64))))
    {
        return error.InvalidRuntimeProfileInput;
    }
    return @intFromFloat(@round(nanoseconds));
}

pub fn addInput(lhs: u64, rhs: anytype) !u64 {
    const value = std.math.cast(u64, rhs) orelse
        return error.InvalidRuntimeProfileInput;
    return std.math.add(u64, lhs, value) catch
        return error.InvalidRuntimeProfileInput;
}

pub fn addOptionalInput(lhs: ?u64, rhs: ?u64) !?u64 {
    if (lhs == null or rhs == null) return null;
    return try addInput(lhs.?, rhs.?);
}

pub fn checkedAdd(lhs: u64, rhs: u64) ?u64 {
    return std.math.add(u64, lhs, rhs) catch null;
}

pub fn computeDigest(profile: anytype, domain: []const u8) Digest {
    var hash = Sha256.init(.{});
    hash.update(domain);
    hashValue(&hash, profile.schema_version);
    hashValue(&hash, profile.static_schema_version);
    hashValue(&hash, profile.static_report_digest);
    hashValue(&hash, profile.static_totals);
    hashValue(&hash, profile.runtime_digest);
    hashValue(&hash, profile.example_digest);
    hashValue(&hash, profile.identity);
    hashValue(&hash, profile.backend);
    hashValue(&hash, profile.optimize);
    hashValue(&hash, profile.configured_workers);
    hashValue(&hash, profile.independently_verified);
    hashValue(&hash, profile.timings);
    hashValue(&hash, profile.proof_bytes);
    hashValue(&hash, profile.committed_trace_cells);
    hashValue(&hash, profile.resources);
    hashValue(&hash, profile.work);
    hashValue(&hash, profile.stages);
    hashValue(&hash, profile.tasks);
    return hash.finalResult();
}

pub fn digestSource(domain: []const u8, source: anytype) Digest {
    var hash = Sha256.init(.{});
    hash.update(domain);
    hashValue(&hash, source);
    return hash.finalResult();
}

pub fn digestBytes(bytes: []const u8, domain: []const u8) Digest {
    var hash = Sha256.init(.{});
    hash.update(domain);
    hashValue(&hash, bytes);
    return hash.finalResult();
}

/// Architecture-independent canonical hashing for the fixed source schemas.
/// Slice lengths are u64; integers retain their declared width; optionals and
/// enum tags carry explicit discriminants. Unsupported types fail at compile
/// time instead of falling back to in-memory representation.
pub fn hashValue(hash: *Sha256, value: anytype) void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .bool => hashInt(hash, u8, @intFromBool(value)),
        .int => hashInt(hash, T, value),
        .float => if (T == f64) {
            hashInt(hash, u64, @bitCast(value));
        } else if (T == f32) {
            hashInt(hash, u32, @bitCast(value));
        } else @compileError("unsupported runtime-profile float width"),
        .@"enum" => hashInt(hash, u64, @intFromEnum(value)),
        .optional => {
            if (value) |payload| {
                hashInt(hash, u8, 1);
                hashValue(hash, payload);
            } else {
                hashInt(hash, u8, 0);
            }
        },
        .array => {
            for (value) |item| hashValue(hash, item);
        },
        .@"struct" => |info| {
            inline for (info.fields) |field|
                hashValue(hash, @field(value, field.name));
        },
        .pointer => |info| {
            if (info.size != .slice)
                @compileError("runtime-profile source contains a non-slice pointer");
            hashInt(hash, u64, value.len);
            if (info.child == u8) {
                hash.update(value);
            } else {
                for (value) |item| hashValue(hash, item);
            }
        },
        else => @compileError("unsupported runtime-profile source field"),
    }
}

pub fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

pub fn digestEmpty(digest: Digest) bool {
    return std.mem.allEqual(u8, &digest, 0);
}
