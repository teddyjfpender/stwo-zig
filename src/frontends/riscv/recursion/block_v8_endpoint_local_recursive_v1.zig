//! Compact Local11 recursive theorem. Native/clock/endpoints/ranges/ROM/tables
//! close in this proof. Global RAM is OPEN: a late bridge must prove openings
//! of the identical endpoint-main root and close against global providers.
pub const Profile = @import("block_v8_endpoint_recursive_profile_v1.zig").For(.local_open);
pub const Composition = @import("air/block_v8_endpoint_recursive_composition_v1.zig").For(.local_open);
pub const Transcript = @import("air/block_v8_endpoint_recursive_transcript_v1.zig").For(.local_open);
pub const Pcs = @import("block_v8_endpoint_recursive_pcs_preparation_v1.zig").For(.local_open);
pub const Public = @import("block_v8_endpoint_recursive_public_v1.zig").For(.local_open);
pub const Preparation = @import("block_v8_endpoint_recursive_preparation_v1.zig").For(.local_open);
pub const Fixed = @import("block_v8_endpoint_recursive_fixed_roster_v1.zig").For(.local_open);
pub const Protocol = @import("block_v8_endpoint_recursive_protocol_v1.zig").For(.local_open);
pub const Receiver = @import("block_v8_endpoint_recursive_receiver_v1.zig").For(.local_open);
pub const Pipeline = @import("block_v8_endpoint_recursive_pipeline_v1.zig").For(.local_open);
pub const SourceReport = @import("block_v8_endpoint_recursive_report_v1.zig").For(.local_open);
pub const production_active = false;
pub const global_ram_closed = false;
