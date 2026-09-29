//! Pure authenticated AIR metadata for host compilation; no runtime prover imports.
pub const core = @import("stwo_core");
pub const frontends = struct {
    pub const cairo = struct {
        pub const air = struct {
            pub const template_library = @import("air/template_library.zig");
        };
        pub const witness = struct {
            pub const eval_program = @import("witness/eval_program.zig");
            pub const eval_program_identity = @import("witness/eval_program_identity.zig");
        };
        pub const codegen = struct {
            pub const eval_program = @import("codegen/eval_program.zig");
            pub const field_shapes = @import("codegen/field_shapes.zig");
        };
    };
};
