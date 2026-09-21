//! Compositional opcode semantic evaluators.
//!
//! Direct polynomial constraints and sibling lookup requests live together per
//! family, while transcript orchestration and LogUp accumulation remain in the
//! component layer. This keeps semantic review independent of PCS machinery.
//!
//! Production opcode families are owned by fixed typed authorities. This
//! namespace retains only shared primitives; retired family evaluators are imported
//! explicitly by tests through `_legacy_test_oracle.zig` paths.

const QM31 = @import("stwo_core").fields.qm31.QM31;

pub fn Families(comptime S: type) type {
    return struct {
        pub const common = @import("common.zig").Ops(S);
        pub const control_common = @import("control_common.zig").Ops(S);
        pub const shift_common = @import("shift_common.zig").Semantics(S);
    };
}

const shipped = Families(QM31);

pub const common = shipped.common;
pub const control_common = shipped.control_common;
pub const shift_common = shipped.shift_common;

test {
    @import("std").testing.refAllDeclsRecursive(@This());
}
