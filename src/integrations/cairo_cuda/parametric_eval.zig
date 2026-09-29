//! Current Cairo AIR body normalization and proof-owned constant tables.
//! Only classified base literals and domain size vary through live binding.
//! Extension literals remain authenticated executable constants so the device
//! compiler can fold scalar and zero operations.
//! Callers must obtain the actual programs from the authenticated template
//! library's live binding; arbitrary externally supplied AIR is not admitted.
const std = @import("std");
const cairo = @import("stwo_cairo_frontend");
const eval = cairo.witness.eval_program;
const codegen = @import("eval_codegen.zig");
pub const authority_hex = "550200479d03f3cc5df12d3795cfe4645824bd96368f3cd6e70c0df8669c62ec";
pub const source_authority: [32]u8 = result: {
    var bytes: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, authority_hex) catch unreachable;
    break :result bytes;
};

pub fn normalize(allocator: std.mem.Allocator, program: eval.Program) !eval.Program {
    try program.validate();
    if (program.header.n_base_params != 0) return error.UnsupportedAirBaseParameters;
    var result = try program.clone(allocator);
    errdefer result.deinit();
    result.header.domain_log_size = 4;
    @memset(result.base_consts, 0);
    for (result.base_insts) |*inst| if (inst.op == .constant) {
        inst.a = 0;
    };
    result.header.semantic_hash = result.semanticHash();
    try result.validate();
    return result;
}

pub fn constantWordCount(program: eval.Program) !u32 {
    var count: u32 = 0;
    for (program.base_insts) |inst| if (inst.op == .constant) {
        count = std.math.add(u32, count, 1) catch return error.AirConstantOverflow;
    };
    return count;
}

pub fn writeConstants(program: eval.Program, output: []u32) !void {
    if (output.len != try constantWordCount(program)) return error.AirConstantExtentMismatch;
    var cursor: usize = 0;
    for (program.base_insts) |inst| if (inst.op == .constant) {
        output[cursor] = inst.a;
        cursor += 1;
    };
}

pub fn cacheKey(program_identity: [32]u8, source_identity: [32]u8, authority: [32]u8) u64 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo-cuda-eval-parametric/v3\x00");
    hash.update(&program_identity);
    hash.update(&source_identity);
    hash.update(&authority);
    const digest = hash.finalResult();
    return std.mem.readInt(u64, digest[0..8], .big);
}

pub fn loadLibrary(allocator: std.mem.Allocator, manifest_path: []const u8) !cairo.air.template_library.Library {
    const absolute = try std.fs.cwd().realpathAlloc(allocator, manifest_path);
    defer allocator.free(absolute);
    const encoded = try std.fs.cwd().readFileAlloc(allocator, absolute, 64 * 1024);
    defer allocator.free(encoded);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &digest, .{});
    if (!std.mem.eql(u8, &digest, &source_authority)) return error.CanonicalAirAuthorityMismatch;
    return cairo.air.template_library.Library.readFile(allocator, absolute);
}

pub const Bound = struct {
    program: eval.Program,
    dynamic_constants: []bool,
    pub fn deinit(self: *Bound) void {
        self.program.allocator.free(self.dynamic_constants);
        self.program.deinit();
        self.* = undefined;
    }
};

/// Classify constants by the authenticated *source* template. A live segment
/// start may legitimately become zero or one; guessing from its current value
/// would turn such a dynamic address into a fixed arithmetic constant.
pub fn bind(allocator: std.mem.Allocator, library: cairo.air.template_library.Library, label: []const u8, part_index: usize, live: eval.Program) !Bound {
    var result = try normalize(allocator, live);
    errdefer result.deinit();
    const shape = codegen.programIdentity(result);
    const dynamic = try allocator.alloc(bool, try constantWordCount(live));
    errdefer allocator.free(dynamic);
    @memset(dynamic, false);
    var matched = false;
    for (library.sources) |source| {
        const component = source.find(label) orelse continue;
        if (part_index >= component.parts.len) continue;
        const original = component.parts[part_index].program;
        var original_shape = try normalize(allocator, original);
        defer original_shape.deinit();
        if (!std.mem.eql(u8, &shape, &codegen.programIdentity(original_shape))) continue;
        var candidate = true;
        for (original.base_insts, live.base_insts) |recorded, actual| {
            if (recorded.op == .constant and !isDynamic(recorded.a, label, source.segment_starts, component.trace_log_size) and recorded.a != actual.a) {
                candidate = false;
                break;
            }
        }
        matched = matched or candidate;
        var cursor: usize = 0;
        for (original.base_insts) |inst| if (inst.op == .constant) {
            dynamic[cursor] = dynamic[cursor] or isDynamic(inst.a, label, source.segment_starts, component.trace_log_size);
            cursor += 1;
        };
    }
    if (!matched) return error.UnboundCanonicalAirConstants;
    var cursor: usize = 0;
    for (result.base_insts, live.base_insts) |*normalized, actual| if (actual.op == .constant) {
        if (!dynamic[cursor]) normalized.a = actual.a;
        cursor += 1;
    };
    result.header.semantic_hash = result.semanticHash();
    try result.validate();
    return .{ .program = result, .dynamic_constants = dynamic };
}

fn isDynamic(value: u32, label: []const u8, starts: cairo.air.template_library.SegmentStarts, trace_log: u32) bool {
    if (starts.get(label)) |start| if (value == start) return true;
    if (std.mem.eql(u8, label, "memory_address_to_id")) {
        const stride = @as(u64, 1) << @intCast(trace_log);
        for (1..cairo.claim_generator.memory_address_to_id_split) |chunk|
            if (@as(u64, value) == chunk * stride) return true;
    }
    return false;
}

test "canonical CUDA parametric AIR binds fixed literals and zero segment addresses" {
    var library = try loadLibrary(std.testing.allocator, "vectors/cairo/official/air_template_library_v1.json");
    defer library.deinit();
    var dynamic_count: usize = 0;
    var fixed_count: usize = 0;
    for (library.sources) |source| for (source.bundle.components) |component| for (component.parts, 0..) |part, pi| {
        var original = try bind(std.testing.allocator, library, component.label, pi, part.program);
        defer original.deinit();
        for (original.dynamic_constants) |dynamic| {
            if (dynamic) dynamic_count += 1 else fixed_count += 1;
        }
        // Fixed arithmetic literals must not silently become live parameters.
        var tampered = try part.program.clone(std.testing.allocator);
        defer tampered.deinit();
        var constant_index: usize = 0;
        for (tampered.base_insts) |*inst| if (inst.op == .constant) {
            if (!original.dynamic_constants[constant_index]) {
                inst.a = (inst.a + 12345) % eval.m31_prime;
                tampered.header.semantic_hash = tampered.semanticHash();
                try std.testing.expectError(error.UnboundCanonicalAirConstants, bind(std.testing.allocator, library, component.label, pi, tampered));
                break;
            }
            constant_index += 1;
        };
        for ([_]u32{ 0, 1, eval.m31_prime - 1 }) |address| {
            var live = try part.program.clone(std.testing.allocator);
            defer live.deinit();
            live.header.domain_log_size = 9;
            var cursor: usize = 0;
            for (live.base_insts) |*inst| if (inst.op == .constant) {
                if (original.dynamic_constants[cursor]) inst.a = address;
                cursor += 1;
            };
            live.header.semantic_hash = live.semanticHash();
            var rebound = try bind(std.testing.allocator, library, component.label, pi, live);
            defer rebound.deinit();
            try std.testing.expectEqualSlices(bool, original.dynamic_constants, rebound.dynamic_constants);
            try std.testing.expectEqualSlices(u8, &codegen.programIdentity(original.program), &codegen.programIdentity(rebound.program));
        }
    };
    try std.testing.expect(dynamic_count > 0 and fixed_count > dynamic_count);
}
