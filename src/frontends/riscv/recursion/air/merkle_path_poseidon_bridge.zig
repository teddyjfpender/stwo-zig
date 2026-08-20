//! Zero-copy scheduling bridge from Merkle-path rows to shared Poseidon2.
//!
//! Row 34 is the already compiler-authored H-002/H-006 shared primitive, not
//! a second recursion-local permutation transcription.  This adapter derives
//! its exact `io = 1, wide = 0` calls from authenticated row-33 invocations,
//! seals the derived workload, and hands it directly to the typed Poseidon2
//! executor. Thus the row-33 `poseidon2_io` request cancels the existing
//! provider's positive IO tuple without another semantic owner or hot copy.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const digest = @import("../../air/lang/digest.zig");
const poseidon_executor = @import("../../air/lang/typed_poseidon2_witness.zig");
const path = @import("merkle_path_witness.zig");

pub const Call = poseidon_executor.Call;
pub const Executor = poseidon_executor.Executor;
pub const MAIN_COLUMN_COUNT = poseidon_executor.N_MAIN_COLUMNS;
pub const WIDTH = poseidon_executor.WIDTH;
pub const FORMAT_VERSION: u16 = 1;
pub const DOMAIN = "stwo-zig/typed-air/recursion-merkle-path-poseidon/v1\x00";

pub const Error = path.Error || poseidon_executor.ExecutionError || error{
    AuthorityMismatch,
    InvalidCallGeometry,
};

pub const PreparedBatch = struct {
    allocator: std.mem.Allocator,
    calls: []Call,
    authority_digest: digest.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        invocations: []const path.Invocation,
    ) Error!PreparedBatch {
        // Validate the entire source before allocation so an invalid suffix
        // cannot leave even temporary retained state behind.
        for (invocations) |invocation| try path.validateInvocation(invocation);
        const calls = try allocator.alloc(Call, invocations.len);
        errdefer allocator.free(calls);
        for (calls, invocations) |*target, invocation|
            target.* = callAssumeValid(invocation);
        return .{
            .allocator = allocator,
            .calls = calls,
            .authority_digest = callsDigest(calls),
        };
    }

    pub fn deinit(self: *PreparedBatch) void {
        self.allocator.free(self.calls);
        self.* = undefined;
    }

    /// Allocation-free hot seal checked before the typed provider mutates any
    /// destination byte.
    pub fn validate(self: *const PreparedBatch) Error!void {
        for (self.calls) |call_value| try validateCall(call_value);
        if (!std.mem.eql(u8, &self.authority_digest, &callsDigest(self.calls)))
            return error.AuthorityMismatch;
    }

    pub fn generateMainInto(
        self: *const PreparedBatch,
        executor: *Executor,
        columns: *[MAIN_COLUMN_COUNT][]M31,
        log_size: u32,
    ) Error!void {
        try self.validate();
        try rejectDestinationOverlapWithBatch(columns, self);
        return executor.generateMainInto(columns, self.calls, log_size);
    }
};

pub fn call(invocation: path.Invocation) Error!Call {
    try path.validateInvocation(invocation);
    return callAssumeValid(invocation);
}

pub fn fillCallsInto(
    destination: []Call,
    invocations: []const path.Invocation,
) Error!void {
    if (destination.len != invocations.len) return error.InvalidCallGeometry;
    try rejectSlicesAlias(destination, invocations);
    for (invocations) |invocation| try path.validateInvocation(invocation);
    for (destination, invocations) |*target, invocation|
        target.* = callAssumeValid(invocation);
}

inline fn callAssumeValid(invocation: path.Invocation) Call {
    const input = if (invocation.step.direction == 0)
        invocation.child ++ invocation.step.sibling
    else
        invocation.step.sibling ++ invocation.child;
    return .{
        .input = input,
        .wide = false,
        .io = true,
        .narrow_output = null,
    };
}

fn validateCall(call_value: Call) Error!void {
    if (call_value.wide or !call_value.io or call_value.narrow_output != null)
        return error.InvalidCallGeometry;
    for (call_value.input) |word| if (word >= m31.Modulus)
        return error.InvalidCallGeometry;
}

fn callsDigest(calls: []const Call) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u64, calls.len);
    for (calls) |call_value| {
        for (call_value.input) |word| hashInt(&hash, u32, word);
        hashInt(&hash, u8, @intFromBool(call_value.wide));
        hashInt(&hash, u8, @intFromBool(call_value.io));
        hashInt(&hash, u8, @intFromBool(call_value.narrow_output != null));
        if (call_value.narrow_output) |value| hashInt(&hash, u32, value);
    }
    return hash.finalResult();
}

const AddressRange = struct {
    start: usize,
    end: usize,

    fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

fn rejectSlicesAlias(
    destination: []Call,
    invocations: []const path.Invocation,
) poseidon_executor.ExecutionError!void {
    const output = try sliceRange(Call, destination);
    const input = try sliceRange(path.Invocation, invocations);
    if (output.overlaps(input)) return error.AliasedInput;
}

fn rejectDestinationOverlapWithBatch(
    columns: *const [MAIN_COLUMN_COUNT][]M31,
    batch: *const PreparedBatch,
) poseidon_executor.ExecutionError!void {
    const protected = try objectRange(batch);
    for (columns) |column| {
        const destination = try sliceRange(M31, column);
        if (destination.overlaps(protected)) return error.AliasedDestination;
    }
}

fn sliceRange(comptime T: type, values: []const T) poseidon_executor.ExecutionError!AddressRange {
    const byte_len = std.math.mul(usize, values.len, @sizeOf(T)) catch
        return error.AddressOverflow;
    const start = @intFromPtr(values.ptr);
    return .{
        .start = start,
        .end = std.math.add(usize, start, byte_len) catch return error.AddressOverflow,
    };
}

fn objectRange(value: anytype) poseidon_executor.ExecutionError!AddressRange {
    const T = @TypeOf(value.*);
    const start = @intFromPtr(value);
    return .{
        .start = start,
        .end = std.math.add(usize, start, @sizeOf(T)) catch return error.AddressOverflow,
    };
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (WIDTH != 16 or MAIN_COLUMN_COUNT != 445)
        @compileError("shared typed Poseidon2 geometry drifted");
}
