//! Column type abstraction for backend-specific field element storage.
//!
//! For CpuBackend:  ColumnType(M31) = []M31  (plain heap slice)
//! For SimdBackend: ColumnType(M31) = []PackedM31 (SIMD-packed lanes)
//! For CudaBackend: ColumnType(M31) = DeviceSlice(M31) (GPU device pointer)

const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

/// Returns the backend-specific column type for field element `F`.
pub fn Column(comptime B: type, comptime F: type) type {
    return B.ColumnType(F);
}

/// Validates that backend `B` exposes a usable generic column type function.
pub fn assertColumnOps(comptime B: type) void {
    comptime {
        if (!@hasDecl(B, "ColumnType")) {
            @compileError("Backend must declare `pub fn ColumnType(comptime F: type) type`.");
        }
        const BaseColumn = B.ColumnType(M31);
        const SecureColumn = B.ColumnType(QM31);
        if (BaseColumn == void or SecureColumn == void) {
            @compileError("Backend `ColumnType` must return a non-void type.");
        }
    }
}
