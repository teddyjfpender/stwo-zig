//! The circuit registry JSON: the verifier circuits recursion supports.
//!
//! Port of `crates/circuit_registry` (`schema.rs`, `methods.rs`) and of the
//! `ProverParameters` it embeds (`crates/common/src/prover_params.rs`) at
//! https://github.com/starkware-libs/proving commit
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230. `circuit-params` writes it with
//! `serde_json::to_string_pretty` followed by a newline; `writeRegistry`
//! reproduces those bytes.
//!
//! Serde surface reproduced here:
//!
//! - struct fields in declaration order (`LogSizes` is `eq, qm31_ops,
//!   m31_to_u32, triple_xor, blake_g_gate`, not the component order);
//! - `circuit_proof_configs` is a `BTreeMap<String, _>`: keys in byte order;
//! - enums are snake_case strings; `LiftingSizePolicy::Fixed(n)` is
//!   `{"fixed": n}`; `opt_n_id_to_big_components: None` is `null`;
//! - digests are `DigestHex` arrays.
//!
//! Reading ignores unknown fields, as serde's derive does, and rejects a
//! duplicate map key (serde would keep the last one).

const std = @import("std");
const json_text = @import("json_text.zig");
const leaf_proof_json = @import("leaf_proof_json.zig");

pub const DigestHex = leaf_proof_json.DigestHex;
/// The `ProverParameters` types are the single definition in
/// `src/interop/cairo_prover_parameters.zig`, injected as a module and shared
/// with the Cairo frontend's leaf lane; this file owns their serde JSON.
const prover_parameters = @import("interop_cairo_prover_parameters");

pub const FriConfig = prover_parameters.FriConfig;
pub const ChannelHash = prover_parameters.ChannelHash;
pub const PreprocessedTraceVariant = prover_parameters.PreprocessedTraceVariant;
pub const LiftingSizePolicy = prover_parameters.LiftingSizePolicy;
/// `stwo_cairo_common::prover_params::ProverParameters`.
pub const ProverParameters = prover_parameters.ProverParameters;

/// Padded log sizes of the components circuits share a target on.
pub const LogSizes = struct {
    eq: u32,
    qm31_ops: u32,
    m31_to_u32: u32,
    triple_xor: u32,
    blake_g_gate: u32,
};

pub const CircuitProofConfig = struct {
    fri_config: FriConfig,
    component_log_sizes: LogSizes,
};

/// One `circuit_proof_configs` entry.
pub const NamedProofConfig = struct {
    name: []const u8,
    config: CircuitProofConfig,
};

pub const LeafVerifier = struct {
    config: []const u8,
    trace_log_size: u32,
    preprocessed_root: DigestHex,
    circuit_hash: DigestHex,
    zk_blinding: bool,
};

pub const Multiverifier = struct {
    config: []const u8,
    input_configs: [2][]const u8,
    preprocessed_root: DigestHex,
    circuit_hash: DigestHex,
};

pub const QueryError = error{
    /// `RegistryError::UnknownConfig`.
    UnknownConfig,
    /// `RegistryError::UnsupportedLeaf`.
    UnsupportedLeaf,
    /// `RegistryError::NoLeafVerifiers`.
    NoLeafVerifiers,
    /// `RegistryError::NotExactlyOneMultiverifier`.
    NotExactlyOneMultiverifier,
};

pub const CircuitRegistry = struct {
    cairo_prover_params: ProverParameters,
    /// Sorted by name in byte order, names unique.
    circuit_proof_configs: []const NamedProofConfig,
    leaf_verifiers: []const LeafVerifier,
    multiverifiers: []const Multiverifier,

    /// The proof config a registry entry names.
    pub fn config(self: CircuitRegistry, name: []const u8) QueryError!CircuitProofConfig {
        for (self.circuit_proof_configs) |entry| {
            if (std.mem.eql(u8, entry.name, name)) return entry.config;
        }
        return error.UnknownConfig;
    }

    /// The leaf verifier for a Cairo proof of `trace_log_size`.
    pub fn leafVerifier(self: CircuitRegistry, trace_log_size: u32) QueryError!LeafVerifier {
        for (self.leaf_verifiers) |leaf| {
            if (leaf.trace_log_size == trace_log_size) return leaf;
        }
        return error.UnsupportedLeaf;
    }

    pub fn maxLeafTraceLogSize(self: CircuitRegistry) QueryError!u32 {
        if (self.leaf_verifiers.len == 0) return error.NoLeafVerifiers;
        var max: u32 = 0;
        for (self.leaf_verifiers) |leaf| max = @max(max, leaf.trace_log_size);
        return max;
    }

    /// The registry's single multiverifier.
    pub fn multiverifier(self: CircuitRegistry) QueryError!Multiverifier {
        if (self.multiverifiers.len != 1) return error.NotExactlyOneMultiverifier;
        return self.multiverifiers[0];
    }
};

pub const ReadError = json_text.ReadError;

pub const OwnedRegistry = struct {
    arena: std.heap.ArenaAllocator,
    registry: CircuitRegistry,

    pub fn deinit(self: *OwnedRegistry) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

/// `CircuitRegistry::from_path`, minus the file read.
pub fn parseRegistry(gpa: std.mem.Allocator, text: []const u8) ReadError!OwnedRegistry {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const allocator = arena.allocator();
    const root = try json_text.object((try json_text.parse(allocator, text)).value);

    const config_map = try json_text.object(try json_text.field(root, "circuit_proof_configs"));
    const configs = try allocator.alloc(NamedProofConfig, config_map.count());
    for (config_map.keys(), config_map.values(), configs) |name, value, *slot| {
        slot.* = .{ .name = name, .config = try readProofConfig(try json_text.object(value)) };
    }
    std.sort.block(NamedProofConfig, configs, {}, nameLessThan);

    const leaf_items = try json_text.array(try json_text.field(root, "leaf_verifiers"));
    const leaves = try allocator.alloc(LeafVerifier, leaf_items.len);
    for (leaf_items, leaves) |item, *slot| slot.* = try readLeafVerifier(try json_text.object(item));

    const multi_items = try json_text.array(try json_text.field(root, "multiverifiers"));
    const multis = try allocator.alloc(Multiverifier, multi_items.len);
    for (multi_items, multis) |item, *slot| slot.* = try readMultiverifier(try json_text.object(item));

    return .{ .arena = arena, .registry = .{
        .cairo_prover_params = try readProverParameters(try json_text.object(try json_text.field(root, "cairo_prover_params"))),
        .circuit_proof_configs = configs,
        .leaf_verifiers = leaves,
        .multiverifiers = multis,
    } };
}

fn nameLessThan(_: void, lhs: NamedProofConfig, rhs: NamedProofConfig) bool {
    return std.mem.lessThan(u8, lhs.name, rhs.name);
}

fn readProverParameters(map: std.json.ObjectMap) ReadError!ProverParameters {
    // serde reads a missing `Option` field as `None`.
    const opt_n = map.get("opt_n_id_to_big_components") orelse .null;
    return .{
        .channel_hash = try readEnum(ChannelHash, try json_text.field(map, "channel_hash")),
        .channel_salt = try json_text.unsigned(u32, try json_text.field(map, "channel_salt")),
        .fri_config = try readFriConfig(try json_text.object(try json_text.field(map, "fri_config"))),
        .preprocessed_trace = try readEnum(PreprocessedTraceVariant, try json_text.field(map, "preprocessed_trace")),
        .store_polynomials_coefficients = try json_text.boolean(try json_text.field(map, "store_polynomials_coefficients")),
        .include_all_preprocessed_columns = try json_text.boolean(try json_text.field(map, "include_all_preprocessed_columns")),
        .opt_n_id_to_big_components = if (opt_n == .null) null else try json_text.unsigned(u64, opt_n),
        .lifting_size_policy = try readLiftingSizePolicy(try json_text.field(map, "lifting_size_policy")),
    };
}

fn readEnum(comptime E: type, value: std.json.Value) ReadError!E {
    return std.meta.stringToEnum(E, try json_text.string(value)) orelse error.InvalidValue;
}

fn readLiftingSizePolicy(value: std.json.Value) ReadError!LiftingSizePolicy {
    switch (value) {
        .string => |name| {
            if (std.mem.eql(u8, name, "auto")) return .auto;
            if (std.mem.eql(u8, name, "at_least_preprocessed")) return .at_least_preprocessed;
            return error.InvalidValue;
        },
        .object => |map| {
            if (map.count() != 1 or !std.mem.eql(u8, map.keys()[0], "fixed")) return error.InvalidValue;
            return .{ .fixed = try json_text.unsigned(u32, map.values()[0]) };
        },
        else => return error.InvalidValue,
    }
}

fn readFriConfig(map: std.json.ObjectMap) ReadError!FriConfig {
    return .{
        .pow_bits = try json_text.unsigned(u32, try json_text.field(map, "pow_bits")),
        .log_blowup_factor = try json_text.unsigned(u32, try json_text.field(map, "log_blowup_factor")),
        .log_last_layer_degree_bound = try json_text.unsigned(u32, try json_text.field(map, "log_last_layer_degree_bound")),
        // `usize` upstream; the Zig config holds a `u32`.
        .n_queries = try json_text.unsigned(u32, try json_text.field(map, "n_queries")),
        .fold_step = try json_text.unsigned(u32, try json_text.field(map, "fold_step")),
    };
}

fn readProofConfig(map: std.json.ObjectMap) ReadError!CircuitProofConfig {
    const sizes = try json_text.object(try json_text.field(map, "component_log_sizes"));
    return .{
        .fri_config = try readFriConfig(try json_text.object(try json_text.field(map, "fri_config"))),
        .component_log_sizes = .{
            .eq = try json_text.unsigned(u32, try json_text.field(sizes, "eq")),
            .qm31_ops = try json_text.unsigned(u32, try json_text.field(sizes, "qm31_ops")),
            .m31_to_u32 = try json_text.unsigned(u32, try json_text.field(sizes, "m31_to_u32")),
            .triple_xor = try json_text.unsigned(u32, try json_text.field(sizes, "triple_xor")),
            .blake_g_gate = try json_text.unsigned(u32, try json_text.field(sizes, "blake_g_gate")),
        },
    };
}

fn readLeafVerifier(map: std.json.ObjectMap) ReadError!LeafVerifier {
    return .{
        .config = try json_text.string(try json_text.field(map, "config")),
        .trace_log_size = try json_text.unsigned(u32, try json_text.field(map, "trace_log_size")),
        .preprocessed_root = try DigestHex.fromJson(try json_text.field(map, "preprocessed_root")),
        .circuit_hash = try DigestHex.fromJson(try json_text.field(map, "circuit_hash")),
        .zk_blinding = try json_text.boolean(try json_text.field(map, "zk_blinding")),
    };
}

fn readMultiverifier(map: std.json.ObjectMap) ReadError!Multiverifier {
    const inputs = try json_text.array(try json_text.field(map, "input_configs"));
    if (inputs.len != 2) return error.InvalidValue;
    return .{
        .config = try json_text.string(try json_text.field(map, "config")),
        .input_configs = .{ try json_text.string(inputs[0]), try json_text.string(inputs[1]) },
        .preprocessed_root = try DigestHex.fromJson(try json_text.field(map, "preprocessed_root")),
        .circuit_hash = try DigestHex.fromJson(try json_text.field(map, "circuit_hash")),
    };
}

/// `serde_json::to_string_pretty(&registry)` followed by `\n`, as
/// `circuit-params --registry` writes it. `circuit_proof_configs` must be
/// sorted by name with unique names (as `parseRegistry` returns it).
pub fn writeRegistry(out: *std.Io.Writer, registry: CircuitRegistry) std.Io.Writer.Error!void {
    for (registry.circuit_proof_configs[0..registry.circuit_proof_configs.len -| 1], 1..) |entry, next| {
        std.debug.assert(std.mem.lessThan(u8, entry.name, registry.circuit_proof_configs[next].name));
    }
    var writer = json_text.Writer.init(out, true);
    try writer.beginObject();
    try writer.key("cairo_prover_params");
    try writeProverParameters(&writer, registry.cairo_prover_params);
    try writer.key("circuit_proof_configs");
    try writer.beginObject();
    for (registry.circuit_proof_configs) |entry| {
        try writer.key(entry.name);
        try writer.beginObject();
        try writer.key("fri_config");
        try writeFriConfig(&writer, entry.config.fri_config);
        try writer.key("component_log_sizes");
        const sizes = entry.config.component_log_sizes;
        try writer.beginObject();
        inline for (.{ "eq", "qm31_ops", "m31_to_u32", "triple_xor", "blake_g_gate" }) |name| {
            try writer.key(name);
            try writer.unsignedValue(@field(sizes, name));
        }
        try writer.endObject();
        try writer.endObject();
    }
    try writer.endObject();
    try writer.key("leaf_verifiers");
    try writer.beginArray();
    for (registry.leaf_verifiers) |leaf| {
        try writer.beginObject();
        try writer.key("config");
        try writer.stringValue(leaf.config);
        try writer.key("trace_log_size");
        try writer.unsignedValue(leaf.trace_log_size);
        try writer.key("preprocessed_root");
        try leaf.preprocessed_root.writeJson(&writer);
        try writer.key("circuit_hash");
        try leaf.circuit_hash.writeJson(&writer);
        try writer.key("zk_blinding");
        try writer.boolValue(leaf.zk_blinding);
        try writer.endObject();
    }
    try writer.endArray();
    try writer.key("multiverifiers");
    try writer.beginArray();
    for (registry.multiverifiers) |multi| {
        try writer.beginObject();
        try writer.key("config");
        try writer.stringValue(multi.config);
        try writer.key("input_configs");
        try writer.beginArray();
        for (multi.input_configs) |name| try writer.stringValue(name);
        try writer.endArray();
        try writer.key("preprocessed_root");
        try multi.preprocessed_root.writeJson(&writer);
        try writer.key("circuit_hash");
        try multi.circuit_hash.writeJson(&writer);
        try writer.endObject();
    }
    try writer.endArray();
    try writer.endObject();
    try out.writeByte('\n');
}

fn writeProverParameters(writer: *json_text.Writer, params: ProverParameters) std.Io.Writer.Error!void {
    try writer.beginObject();
    try writer.key("channel_hash");
    try writer.stringValue(@tagName(params.channel_hash));
    try writer.key("channel_salt");
    try writer.unsignedValue(params.channel_salt);
    try writer.key("fri_config");
    try writeFriConfig(writer, params.fri_config);
    try writer.key("preprocessed_trace");
    try writer.stringValue(@tagName(params.preprocessed_trace));
    try writer.key("store_polynomials_coefficients");
    try writer.boolValue(params.store_polynomials_coefficients);
    try writer.key("include_all_preprocessed_columns");
    try writer.boolValue(params.include_all_preprocessed_columns);
    try writer.key("opt_n_id_to_big_components");
    if (params.opt_n_id_to_big_components) |n| try writer.unsignedValue(n) else try writer.nullValue();
    try writer.key("lifting_size_policy");
    switch (params.lifting_size_policy) {
        .fixed => |size| {
            try writer.beginObject();
            try writer.key("fixed");
            try writer.unsignedValue(size);
            try writer.endObject();
        },
        else => |policy| try writer.stringValue(@tagName(policy)),
    }
    try writer.endObject();
}

fn writeFriConfig(writer: *json_text.Writer, config: FriConfig) std.Io.Writer.Error!void {
    try writer.beginObject();
    inline for (.{ "pow_bits", "log_blowup_factor", "log_last_layer_degree_bound", "n_queries", "fold_step" }) |name| {
        try writer.key(name);
        try writer.unsignedValue(@field(config, name));
    }
    try writer.endObject();
}

const test_registry_head =
    \\{"cairo_prover_params":{"channel_hash":"blake2s_m31","channel_salt":3,
    \\"fri_config":{"pow_bits":1,"log_blowup_factor":2,"log_last_layer_degree_bound":3,"n_queries":4,"fold_step":5},
    \\"preprocessed_trace":"canonical","store_polynomials_coefficients":true,
    \\"include_all_preprocessed_columns":false,"opt_n_id_to_big_components":null,
    \\"lifting_size_policy":{"fixed":25},"ignored":[1]},
;

fn testConfig(comptime name: []const u8) []const u8 {
    return "\"" ++ name ++ "\":{\"fri_config\":{\"pow_bits\":1,\"log_blowup_factor\":1,\"log_last_layer_degree_bound\":0," ++
        "\"n_queries\":1,\"fold_step\":1},\"component_log_sizes\":{\"blake_g_gate\":5,\"triple_xor\":4," ++
        "\"m31_to_u32\":3,\"qm31_ops\":2,\"eq\":1}}";
}

test "registry: maps sort, variants and null follow serde" {
    const allocator = std.testing.allocator;
    const text = comptime test_registry_head ++ "\"circuit_proof_configs\":{" ++ testConfig("b") ++ "," ++ testConfig("B") ++ "," ++
        testConfig("a") ++ "},\"leaf_verifiers\":[],\"multiverifiers\":[]}";
    var owned = try parseRegistry(allocator, text);
    defer owned.deinit();
    const registry = owned.registry;
    // Byte order: uppercase sorts first.
    try std.testing.expectEqualStrings("B", registry.circuit_proof_configs[0].name);
    try std.testing.expectEqualStrings("b", registry.circuit_proof_configs[2].name);
    try std.testing.expectEqual(@as(u32, 25), registry.cairo_prover_params.lifting_size_policy.fixed);
    try std.testing.expectEqual(@as(?u64, null), registry.cairo_prover_params.opt_n_id_to_big_components);
    try std.testing.expectEqual(@as(u32, 3), (try registry.config("a")).component_log_sizes.m31_to_u32);
    try std.testing.expectError(error.UnknownConfig, registry.config("c"));
    try std.testing.expectError(error.NoLeafVerifiers, registry.maxLeafTraceLogSize());
    try std.testing.expectError(error.NotExactlyOneMultiverifier, registry.multiverifier());

    var buffer: std.Io.Writer.Allocating = .init(allocator);
    defer buffer.deinit();
    try writeRegistry(&buffer.writer, registry);
    const written = buffer.written();
    try std.testing.expect(std.mem.indexOf(u8, written, "\"lifting_size_policy\": {\n      \"fixed\": 25\n    }") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "\"opt_n_id_to_big_components\": null") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "\"leaf_verifiers\": [],\n  \"multiverifiers\": []\n}\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "\"eq\": 1,\n        \"qm31_ops\": 2,\n        \"m31_to_u32\": 3") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "ignored") == null);

    // The emitted text parses back to the same bytes.
    var reparsed = try parseRegistry(allocator, written);
    defer reparsed.deinit();
    var again: std.Io.Writer.Allocating = .init(allocator);
    defer again.deinit();
    try writeRegistry(&again.writer, reparsed.registry);
    try std.testing.expectEqualStrings(written, again.written());
}

test "registry: malformed registries are rejected" {
    const allocator = std.testing.allocator;
    const tail = "\"circuit_proof_configs\":{},\"leaf_verifiers\":[],\"multiverifiers\":[]}";
    try std.testing.expectError(error.InvalidJson, parseRegistry(
        allocator,
        comptime test_registry_head ++ "\"circuit_proof_configs\":{" ++ testConfig("a") ++ "," ++ testConfig("a") ++
            "},\"leaf_verifiers\":[],\"multiverifiers\":[]}",
    ));
    const bad_heads = [_][]const u8{
        std.mem.replaceOwned(u8, allocator, test_registry_head, "blake2s_m31", "sha256") catch unreachable,
        std.mem.replaceOwned(u8, allocator, test_registry_head, "{\"fixed\":25}", "\"fixed\"") catch unreachable,
        std.mem.replaceOwned(u8, allocator, test_registry_head, "\"channel_salt\":3", "\"channel_salt\":-3") catch unreachable,
    };
    defer for (bad_heads) |head| allocator.free(head);
    for (bad_heads) |head| {
        const text = try std.mem.concat(allocator, u8, &.{ head, tail });
        defer allocator.free(text);
        try std.testing.expectError(error.InvalidValue, parseRegistry(allocator, text));
    }
    try std.testing.expectError(error.MissingField, parseRegistry(allocator, "{}"));
}

test "registry: a missing optional field reads as None" {
    const allocator = std.testing.allocator;
    const head = try std.mem.replaceOwned(u8, allocator, test_registry_head, "\"opt_n_id_to_big_components\":null,", "");
    defer allocator.free(head);
    const text = try std.mem.concat(allocator, u8, &.{ head, "\"circuit_proof_configs\":{},\"leaf_verifiers\":[],\"multiverifiers\":[]}" });
    defer allocator.free(text);
    var owned = try parseRegistry(allocator, text);
    defer owned.deinit();
    try std.testing.expectEqual(@as(?u64, null), owned.registry.cairo_prover_params.opt_n_id_to_big_components);
}
