//! `RegistryDefinition` of `crates/circuit_params/src/lib.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230): the input of
//! `circuit-params --definition`, read as serde reads it. The three paths
//! are relative to the directory the generator runs in (upstream runs from
//! the repository root); resolving them is the caller's business.

const std = @import("std");
const json_text = @import("json_text.zig");
const registry = @import("registry.zig");

pub const LogSizes = registry.LogSizes;

pub const RegistryDefinition = struct {
    /// The verified Cairo proofs' `ProverParameters` JSON.
    cairo_prover_params_json: []const u8,
    /// The circuit proofs' `FriConfig` JSON.
    circuit_fri_config_json: []const u8,
    /// The compiled program every leaf circuit verifies.
    program: []const u8,
    min_trace_log_size: u32,
    max_trace_log_size: u32,
    /// Raises the shared target to another registry's shape.
    pad_to_component_log_sizes: ?LogSizes,
    add_zk_blinding: bool,
};

pub const ReadError = json_text.ReadError || error{
    /// `min_trace_log_size > max_trace_log_size`: upstream's range is empty
    /// and its `expect("the trace range is non-empty")` panics.
    EmptyTraceRange,
};

pub const OwnedDefinition = struct {
    arena: std.heap.ArenaAllocator,
    definition: RegistryDefinition,

    pub fn deinit(self: *OwnedDefinition) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub fn parseRegistryDefinition(gpa: std.mem.Allocator, text: []const u8) ReadError!OwnedDefinition {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const allocator = arena.allocator();
    const root = try json_text.object((try json_text.parse(allocator, text)).value);
    // serde reads a missing or null `Option` field as `None`.
    const pad_to = root.get("pad_to_component_log_sizes") orelse .null;
    const definition: RegistryDefinition = .{
        .cairo_prover_params_json = try json_text.string(try json_text.field(root, "cairo_prover_params_json")),
        .circuit_fri_config_json = try json_text.string(try json_text.field(root, "circuit_fri_config_json")),
        .program = try json_text.string(try json_text.field(root, "program")),
        .min_trace_log_size = try json_text.unsigned(u32, try json_text.field(root, "min_trace_log_size")),
        .max_trace_log_size = try json_text.unsigned(u32, try json_text.field(root, "max_trace_log_size")),
        .pad_to_component_log_sizes = if (pad_to == .null) null else try registry.readLogSizes(try json_text.object(pad_to)),
        .add_zk_blinding = try json_text.boolean(try json_text.field(root, "add_zk_blinding")),
    };
    if (definition.min_trace_log_size > definition.max_trace_log_size) return error.EmptyTraceRange;
    return .{ .arena = arena, .definition = definition };
}

test "registry definition: fields, optional padding target and an empty range" {
    const allocator = std.testing.allocator;
    const head =
        \\{"cairo_prover_params_json":"a.json","circuit_fri_config_json":"b.json","program":"p.json",
        \\"min_trace_log_size":20,"max_trace_log_size":21,"add_zk_blinding":false
    ;
    var plain = try parseRegistryDefinition(allocator, head ++ "}");
    defer plain.deinit();
    try std.testing.expectEqualStrings("p.json", plain.definition.program);
    try std.testing.expectEqual(@as(?LogSizes, null), plain.definition.pad_to_component_log_sizes);
    try std.testing.expectEqual(@as(u32, 21), plain.definition.max_trace_log_size);

    var padded = try parseRegistryDefinition(allocator, head ++
        \\,"pad_to_component_log_sizes":{"eq":20,"qm31_ops":23,"m31_to_u32":21,"triple_xor":20,"blake_g_gate":23}}
    );
    defer padded.deinit();
    try std.testing.expectEqual(@as(u32, 23), padded.definition.pad_to_component_log_sizes.?.blake_g_gate);

    try std.testing.expectError(error.EmptyTraceRange, parseRegistryDefinition(allocator,
        \\{"cairo_prover_params_json":"a","circuit_fri_config_json":"b","program":"p",
        \\"min_trace_log_size":22,"max_trace_log_size":21,"add_zk_blinding":true}
    ));
    try std.testing.expectError(error.MissingField, parseRegistryDefinition(allocator, "{}"));
}
