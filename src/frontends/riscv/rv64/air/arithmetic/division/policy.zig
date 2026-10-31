//! Public protocol selection; the default preserves the existing CPU profile.
pub const Policy = enum(u32) { inline_v4 = 4, division_service_v2 = 6, division_multiplication_services_v3 = 7 };
