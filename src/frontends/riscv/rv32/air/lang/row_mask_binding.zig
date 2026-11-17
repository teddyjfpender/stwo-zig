//! Compiler-owned compatibility and semantic row-mask binding identities.

pub fn For(comptime owner_context: anytype) type {
    const std = owner_context.std;
    const qm31 = owner_context.qm31;
    const compat_layout = owner_context.compat_layout;
    const opcode_entries = owner_context.opcode_entries;
    const static_registry = owner_context.static_registry;
    const trace = owner_context.trace;
    const witness_layout = owner_context.witness_layout;
    const format_version = owner_context.format_version;
    const Digest = owner_context.Digest;
    const EXPECTED_NATIVE_PLAN_DIGEST_HEX = owner_context.EXPECTED_NATIVE_PLAN_DIGEST_HEX;
    const component_binding_domain = owner_context.component_binding_domain;
    const semantic_component_binding_domain = owner_context.semantic_component_binding_domain;
    const Error = owner_context.Error;
    const runtime = owner_context.runtime;
    return struct {
        pub const ComponentMaskBinding = struct {
            pub const Mode = enum(u8) {
                compatibility = 0,
                compiler_selected = 1,
            };

            local_zero: bool = false,
            schema_version: u16 = format_version,
            family: trace.OpcodeFamily,
            mode: Mode,
            semantic_program_digest: Digest,
            witness_layout_digest: Digest,
            geometry_source_digest: Digest,
            preprocessed_current_columns: u8,
            borrowed_main_current_columns: u32,
            owned_interaction_current_previous_columns: u32,
            binding_digest: Digest,

            pub fn initCompatibility(
                family: trace.OpcodeFamily,
            ) Error!ComponentMaskBinding {
                const family_index: usize = @intFromEnum(family);
                if (family_index >= static_registry.DESCRIPTORS.len)
                    return error.InvalidOwner;
                var result = ComponentMaskBinding{
                    .family = family,
                    .mode = .compatibility,
                    .semantic_program_digest = static_registry.DESCRIPTORS[family_index].semantic_program_digest,
                    .witness_layout_digest = witness_layout.digest(),
                    .geometry_source_digest = try runtime.digestFromHex(
                        EXPECTED_NATIVE_PLAN_DIGEST_HEX[family_index],
                    ),
                    .preprocessed_current_columns = 1,
                    .borrowed_main_current_columns = @intCast(
                        trace.nColumnsForFamily(family),
                    ),
                    .owned_interaction_current_previous_columns = @intCast(
                        opcode_entries.interactionColumnCount(family),
                    ),
                    .binding_digest = .{0} ** 32,
                };
                result.binding_digest = result.identityDigest();
                try result.validate();
                return result;
            }

            pub fn initCompilerSelected(
                family: trace.OpcodeFamily,
                selected_plan_digest: Digest,
                interaction_columns: usize,
            ) Error!ComponentMaskBinding {
                const family_index: usize = @intFromEnum(family);
                if (family_index >= static_registry.DESCRIPTORS.len)
                    return error.InvalidOwner;
                const interaction_count = std.math.cast(
                    u32,
                    interaction_columns,
                ) orelse return error.CountOverflow;
                var result = ComponentMaskBinding{
                    .family = family,
                    .mode = .compiler_selected,
                    .semantic_program_digest = static_registry.DESCRIPTORS[family_index].semantic_program_digest,
                    .witness_layout_digest = witness_layout.digest(),
                    .geometry_source_digest = selected_plan_digest,
                    .preprocessed_current_columns = 1,
                    .borrowed_main_current_columns = @intCast(
                        trace.nColumnsForFamily(family),
                    ),
                    .owned_interaction_current_previous_columns = interaction_count,
                    .binding_digest = .{0} ** 32,
                };
                result.binding_digest = result.identityDigest();
                try result.validate();
                return result;
            }

            pub fn initLocalZero(family: trace.OpcodeFamily) Error!ComponentMaskBinding {
                var result = try initCompatibility(family);
                result.local_zero = true;
                result.borrowed_main_current_columns = @intCast(@import("../x0_native_envelope.zig").mainColumnCount(family) catch return error.InvalidWindowDigest);
                result.binding_digest = result.identityDigest();
                try result.validate();
                return result;
            }

            pub fn validate(self: *const ComponentMaskBinding) Error!void {
                const family_index: usize = @intFromEnum(self.family);
                if (family_index >= static_registry.DESCRIPTORS.len)
                    return error.InvalidOwner;
                const descriptor = static_registry.DESCRIPTORS[family_index];
                const expected_witness_layout = witness_layout.digest();
                if (self.schema_version != format_version or
                    descriptor.family != self.family or
                    !std.mem.eql(
                        u8,
                        &self.semantic_program_digest,
                        &descriptor.semantic_program_digest,
                    ) or
                    !std.mem.eql(
                        u8,
                        &self.witness_layout_digest,
                        &expected_witness_layout,
                    ) or
                    self.preprocessed_current_columns != 1 or
                    self.borrowed_main_current_columns !=
                        (if (self.local_zero) @import("../x0_native_envelope.zig").mainColumnCount(self.family) catch return error.InvalidWindowDigest else trace.nColumnsForFamily(self.family)) or
                    self.owned_interaction_current_previous_columns == 0 or
                    self.owned_interaction_current_previous_columns %
                        qm31.SECURE_EXTENSION_DEGREE != 0 or
                    self.owned_interaction_current_previous_columns >
                        compat_layout.MAX_INTERACTION_COLUMNS or
                    runtime.digestIsZero(self.geometry_source_digest))
                {
                    return error.InvalidWindowDigest;
                }
                if (self.local_zero and self.mode != .compatibility) return error.InvalidWindowDigest;
                switch (self.mode) {
                    .compatibility => {
                        if (self.owned_interaction_current_previous_columns !=
                            opcode_entries.interactionColumnCount(self.family))
                        {
                            return error.InvalidWindowDigest;
                        }
                        const expected_plan = try runtime.digestFromHex(
                            EXPECTED_NATIVE_PLAN_DIGEST_HEX[family_index],
                        );
                        if (!std.mem.eql(
                            u8,
                            &self.geometry_source_digest,
                            &expected_plan,
                        )) return error.InvalidWindowDigest;
                    },
                    .compiler_selected => {},
                }
                const actual = self.identityDigest();
                if (!std.mem.eql(u8, &actual, &self.binding_digest))
                    return error.InvalidWindowDigest;
            }

            pub fn identityDigest(self: *const ComponentMaskBinding) Digest {
                var hash = std.crypto.hash.sha2.Sha256.init(.{});
                hash.update(component_binding_domain);
                if (self.local_zero) hash.update(&@import("../x0_local_custody.zig").abiId());
                runtime.hashInteger(&hash, u16, self.schema_version);
                runtime.hashInteger(&hash, u8, @intFromEnum(self.family));
                runtime.hashInteger(&hash, u8, @intFromEnum(self.mode));
                hash.update(&self.semantic_program_digest);
                hash.update(&self.witness_layout_digest);
                hash.update(&self.geometry_source_digest);
                runtime.hashInteger(&hash, u8, self.preprocessed_current_columns);
                runtime.hashInteger(&hash, u32, self.borrowed_main_current_columns);
                runtime.hashInteger(
                    &hash,
                    u32,
                    self.owned_interaction_current_previous_columns,
                );
                return hash.finalResult();
            }
        };

        /// Fixed projection consumed by the live semantic component. This retires its
        /// independent mask-width table: the semantic adapter now derives the same
        /// current-row Tree-0/Tree-1 geometry from the pinned row-window authority as
        /// the lookup adapter, while owning no Tree-2 columns.
        pub const SemanticMaskBinding = struct {
            local_zero: bool = false,
            schema_version: u16 = format_version,
            family: trace.OpcodeFamily,
            semantic_program_digest: Digest,
            witness_layout_digest: Digest,
            geometry_source_digest: Digest,
            preprocessed_current_columns: u8,
            owned_main_current_columns: u32,
            owned_interaction_columns: u8,
            binding_digest: Digest,

            pub fn init(family: trace.OpcodeFamily) Error!SemanticMaskBinding {
                const family_index: usize = @intFromEnum(family);
                if (family_index >= static_registry.DESCRIPTORS.len)
                    return error.InvalidOwner;
                var result = SemanticMaskBinding{
                    .family = family,
                    .semantic_program_digest = static_registry.DESCRIPTORS[
                        family_index
                    ].semantic_program_digest,
                    .witness_layout_digest = witness_layout.digest(),
                    .geometry_source_digest = try runtime.digestFromHex(
                        EXPECTED_NATIVE_PLAN_DIGEST_HEX[family_index],
                    ),
                    .preprocessed_current_columns = 1,
                    .owned_main_current_columns = @intCast(
                        trace.nColumnsForFamily(family),
                    ),
                    .owned_interaction_columns = 0,
                    .binding_digest = .{0} ** 32,
                };
                result.binding_digest = result.identityDigest();
                try result.validate();
                return result;
            }

            pub fn initLocalZero(family: trace.OpcodeFamily) Error!SemanticMaskBinding {
                var result = try init(family);
                result.local_zero = true;
                result.owned_main_current_columns = @intCast(@import("../x0_native_envelope.zig").mainColumnCount(family) catch return error.InvalidWindowDigest);
                result.binding_digest = result.identityDigest();
                try result.validate();
                return result;
            }

            pub fn validate(self: *const SemanticMaskBinding) Error!void {
                const family_index: usize = @intFromEnum(self.family);
                if (family_index >= static_registry.DESCRIPTORS.len)
                    return error.InvalidOwner;
                const descriptor = static_registry.DESCRIPTORS[family_index];
                const expected_witness_layout = witness_layout.digest();
                const expected_plan = try runtime.digestFromHex(
                    EXPECTED_NATIVE_PLAN_DIGEST_HEX[family_index],
                );
                if (self.schema_version != format_version or
                    descriptor.family != self.family or
                    !std.mem.eql(
                        u8,
                        &self.semantic_program_digest,
                        &descriptor.semantic_program_digest,
                    ) or
                    !std.mem.eql(
                        u8,
                        &self.witness_layout_digest,
                        &expected_witness_layout,
                    ) or
                    !std.mem.eql(
                        u8,
                        &self.geometry_source_digest,
                        &expected_plan,
                    ) or
                    self.preprocessed_current_columns != 1 or
                    self.owned_main_current_columns !=
                        (if (self.local_zero) @import("../x0_native_envelope.zig").mainColumnCount(self.family) catch return error.InvalidWindowDigest else trace.nColumnsForFamily(self.family)) or
                    self.owned_interaction_columns != 0)
                {
                    return error.InvalidWindowDigest;
                }
                const actual = self.identityDigest();
                if (!std.mem.eql(u8, &actual, &self.binding_digest))
                    return error.InvalidWindowDigest;
            }

            pub fn identityDigest(self: *const SemanticMaskBinding) Digest {
                var hash = std.crypto.hash.sha2.Sha256.init(.{});
                hash.update(semantic_component_binding_domain);
                if (self.local_zero) hash.update(&@import("../x0_local_custody.zig").abiId());
                runtime.hashInteger(&hash, u16, self.schema_version);
                runtime.hashInteger(&hash, u8, @intFromEnum(self.family));
                hash.update(&self.semantic_program_digest);
                hash.update(&self.witness_layout_digest);
                hash.update(&self.geometry_source_digest);
                runtime.hashInteger(&hash, u8, self.preprocessed_current_columns);
                runtime.hashInteger(&hash, u32, self.owned_main_current_columns);
                runtime.hashInteger(&hash, u8, self.owned_interaction_columns);
                return hash.finalResult();
            }
        };
    };
}
