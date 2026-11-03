//! Borrowed metadata/coefficient ABI for the in-process native CUDA PCS lane.
pub const section_count = 17;
pub const Words = extern struct { words: ?[*]const u32, count: u64 };
pub const Column = extern struct { kind: u32 = 0, coefficient_log: u32, words: ?[*]const u32, count: u64, context_token: u64 = 0, generation: u64 = 0 };
pub const Lease = extern struct { context_token: u64 = 0, generation: u64 = 0, words: ?[*]u32 = null, count: u64 = 0, kind: u32 = 0, reserved: u32 = 0 };
pub const Callback = *const fn (*anyopaque, u64, ?*anyopaque) callconv(.c) c_int;
pub const Submit = *const fn (*anyopaque, Callback, ?*anyopaque) callconv(.c) c_int;
pub const LeaseAllocate = *const fn (*anyopaque, u64, u32, *const [8]u32, *Lease) callconv(.c) c_int;
pub const LeaseValidate = *const fn (*anyopaque, *const Lease, *const [8]u32) callconv(.c) c_int;
pub const LeaseRelease = *const fn (*anyopaque, *Lease) callconv(.c) c_int;
pub const LeaseValidateRange = *const fn (*anyopaque, [*]const u32, u64, u64, u64, *const [8]u32) callconv(.c) c_int;
pub const Upload = *const fn (*anyopaque, *anyopaque, *const anyopaque, usize) callconv(.c) c_int;
pub const Download = Upload;
pub const CopyDevice = Upload;
pub const Sync = *const fn (*anyopaque) callconv(.c) c_int;
pub const LaneStream = *const fn (*anyopaque, u32, *?*anyopaque) callconv(.c) c_int;
pub const ValidateAllocation = *const fn (*anyopaque, *const anyopaque, usize) callconv(.c) c_int;
pub const Request = extern struct {
    version: u32 = 1,
    section_count: u32 = 17,
    sections: [17]Words,
    coefficients: [*]const Column,
    coefficient_count: u64,
    scope: [8]u32 = @splat(0),
};
pub const Result = extern struct {
    words: ?[*]const u32 = null,
    count: u64 = 0,
    device_ns: u64 = 0,
    requested_bytes: u64 = 0,
    retained_bytes: u64 = 0,
    owner: ?*anyopaque = null,
};
pub const Create = *const fn (u32, u64, *?*anyopaque) callconv(.c) c_int;
pub const Prove = *const fn (*anyopaque, *const Request, *Result) callconv(.c) c_int;
pub const Release = *const fn (*Result) callconv(.c) void;
pub const Destroy = *const fn (*anyopaque) callconv(.c) c_int;
pub const Error = *const fn (*anyopaque) callconv(.c) [*:0]const u8;
comptime {
    if (@sizeOf(Words) != 16 or @sizeOf(Result) != 48 or @sizeOf(Request) != 328 or @sizeOf(Lease) != 40 or @sizeOf(Column) != 40)
        @compileError("native PCS ABI changed");
}
