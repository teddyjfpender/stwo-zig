//! Immutable admission of a native Ethereum child's fixed preprocessing.
//! Root derivation accepts geometry and PCS parameters, never a proof root.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const statement = frontend.air.statement;
const extension_mod = frontend.air.guest_precompile.ethereum_statement;
const bridge = frontend.prover_mod.incremental_bridge_external_v3;
const Sha256 = std.crypto.hash.sha2.Sha256;
pub const VERSION: u16 = 1;
const fixed_program = @import("ethereum_fixed_program_admission_v1.zig");

// Copy only fixed circuit data. Native PCs, registers, memory and I/O values
// do not enter preprocessing. The extension's memory_relation_terms is a
// boundary-specific admission bound, not a Tree0 generator input.
const Shape = struct {
    n_components: u32,
    components: @FieldType(statement.RiscVStatement, "component_descs"),
    n_infra: u32,
    infrastructure: @FieldType(statement.RiscVStatement, "infra_descs"),
    total_steps: u32,
    extension: extension_mod.Statement,
    geometry: bridge.GeometryV3,
    pcs: core.pcs.PcsConfig,

    fn init(native: *const statement.RiscVStatement, extension: *const extension_mod.Statement, geometry: *const bridge.GeometryV3, pcs: core.pcs.PcsConfig) !Shape {
        if (native.n_components > statement.MAX_COMPONENTS or native.n_infra > statement.MAX_INFRA_COMPONENTS)
            return error.InvalidEthereumNativeTree0Shape;
        var normalized: statement.RiscVStatement = undefined;
        normalized.initializeDescriptorStorage();
        @memcpy(normalized.component_descs[0..native.n_components], native.component_descs[0..native.n_components]);
        @memcpy(normalized.infra_descs[0..native.n_infra], native.infra_descs[0..native.n_infra]);
        var fixed_extension = extension.*;
        fixed_extension.admission.memory_relation_terms = 0;
        return .{ .n_components = native.n_components, .components = normalized.component_descs, .n_infra = native.n_infra, .infrastructure = normalized.infra_descs, .total_steps = native.total_steps, .extension = fixed_extension, .geometry = geometry.*, .pcs = pcs };
    }

    fn fingerprint(self: *const Shape) [32]u8 {
        var hash = Sha256.init(.{});
        hash.update("stwo-zig/ethereum-native-tree0-admission/v1\x00");
        // Field-wise hashing excludes struct padding and borrowed pointers.
        std.hash.autoHash(&hash, self.*);
        return hash.finalResult();
    }
};

pub const NativeTree0AdmissionV1 = opaque {
    const Self = @This();
    const Storage = struct {
        allocator: std.mem.Allocator,
        shape: Shape,
        shape_identity: [32]u8,
        expected_root: [8]u32,
        program_descriptor: ?fixed_program.DescriptorV1 = null,
    };

    pub fn create(comptime Engine: type, allocator: std.mem.Allocator, native: *const statement.RiscVStatement, extension: *const extension_mod.Statement, geometry: *const bridge.GeometryV3, pcs: core.pcs.PcsConfig) !*Self {
        const shape = try Shape.init(native, extension, geometry, pcs);
        const expected = try frontend.prover_mod.deriveIncrementalEthereumPreprocessedRootV4(Engine, allocator, native, extension, geometry, pcs);
        if (std.mem.allEqual(u32, &expected, 0)) return error.InvalidEthereumNativeTree0Root;
        for (expected) |word| if (word >= core.fields.m31.Modulus) return error.InvalidEthereumNativeTree0Root;
        const owned = try allocator.create(Storage);
        owned.* = .{ .allocator = allocator, .shape = shape, .shape_identity = shape.fingerprint(), .expected_root = expected };
        return @ptrCast(owned);
    }

    /// Admission derives the root from independently pinned ELF rows. A
    /// different ELF with identical decoded rows still has a different identity.
    pub fn createWithProgram(comptime Engine: type, allocator: std.mem.Allocator, native: *const statement.RiscVStatement, extension: *const extension_mod.Statement, geometry: *const bridge.GeometryV3, pcs: core.pcs.PcsConfig, program: *const fixed_program.OwnedV1) !*Self {
        const shape = try Shape.init(native, extension, geometry, pcs);
        const descriptor = program.descriptor();
        try program.validateDescriptor(descriptor);
        if (native.n_infra == 0 or native.infra_descs[0].n_rows != descriptor.row_count) return error.InvalidEthereumNativeTree0Shape;
        const expected = try frontend.prover_mod.deriveIncrementalEthereumPreprocessedRootWithFixedProgramV1(Engine, allocator, native, extension, geometry, pcs, try program.rows());
        if (std.mem.allEqual(u32, &expected, 0)) return error.InvalidEthereumNativeTree0Root;
        for (expected) |word| if (word >= core.fields.m31.Modulus) return error.InvalidEthereumNativeTree0Root;
        const owned = try allocator.create(Storage);
        owned.* = .{ .allocator = allocator, .shape = shape, .shape_identity = try programShapeIdentity(shape.fingerprint(), descriptor), .expected_root = expected, .program_descriptor = descriptor };
        return @ptrCast(owned);
    }

    pub fn validateShapeWithProgram(self: *const Self, native: *const statement.RiscVStatement, extension: *const extension_mod.Statement, geometry: *const bridge.GeometryV3, pcs: core.pcs.PcsConfig, program: *const fixed_program.OwnedV1) !void {
        const descriptor = self.storage().program_descriptor orelse return error.InvalidEthereumNativeTree0Shape;
        try program.validateDescriptor(descriptor);
        const candidate = try Shape.init(native, extension, geometry, pcs);
        if (!std.meta.eql(self.storage().shape, candidate)) return error.InvalidEthereumNativeTree0Shape;
    }

    pub fn root(self: *const Self) *const [8]u32 {
        return &self.storage().expected_root;
    }

    pub fn shapeIdentity(self: *const Self) [32]u8 {
        return self.storage().shape_identity;
    }

    /// Explicit source-shape check against privately owned admitted metadata.
    /// No Merkle/FFT work, allocation or native ownership traversal occurs.
    pub fn validateShape(self: *const Self, native: *const statement.RiscVStatement, extension: *const extension_mod.Statement, geometry: *const bridge.GeometryV3, pcs: core.pcs.PcsConfig) !void {
        if (self.storage().program_descriptor != null) return error.InvalidEthereumNativeTree0Shape;
        const candidate = try Shape.init(native, extension, geometry, pcs);
        if (!std.meta.eql(self.storage().shape, candidate)) return error.InvalidEthereumNativeTree0Shape;
    }

    pub fn deinit(self: *Self) void {
        const owned: *Storage = @ptrCast(@alignCast(self));
        owned.allocator.destroy(owned);
    }

    fn storage(self: *const Self) *const Storage {
        return @ptrCast(@alignCast(self));
    }
};

fn programShapeIdentity(shape: [32]u8, descriptor: fixed_program.DescriptorV1) ![32]u8 {
    var hash = Sha256.init(.{});
    hash.update("stwo-zig/ethereum-native-tree0-fixed-program/v1\x00");
    hash.update(&shape);
    for (try descriptor.canonicalWords()) |word| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, word, .little);
        hash.update(&bytes);
    }
    return hash.finalResult();
}
