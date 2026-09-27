//! Original range capture API; one genuine kernel also serves explicitly
//! independently admitted external range providers without family relabeling.
pub const API = @import("block_v5_range16_recursive_capture_common_v1.zig").ForAdmission(@import("block_v5_range16_recursive_admission_v1.zig"));
pub const VerifiedCapture = API.VerifiedCapture;
pub const ForBackend = API.ForBackend;
