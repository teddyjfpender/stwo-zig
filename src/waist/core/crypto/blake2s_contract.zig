pub const BackendMode = enum(u8) {
    auto,
    scalar,
    simd,
};

pub const BackendSelection = struct {
    requested: BackendMode,
    effective: BackendMode,
    simd_supported: bool,
    explicit_simd_width: usize,
};

pub const SimdContract = struct {
    pub const explicit_width = 4;
    pub const input_alignment = @alignOf(u8);
    pub const scalar_tail_supported = true;
    pub const read_only_input_aliasing_supported = true;
    pub const caller_scratch_bytes = 0;
};
