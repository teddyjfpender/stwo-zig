//! Real driver/source/loader/receiver bodies retained, never invoked here.
const std = @import("std");
const Source = @import("prover/block_v5_cpu_source_pages_v1.zig");
const Loader = @import("prover/block_v5_memory_source_page_job_loader_v1.zig").Loader;
const Join = @import("prover/block_v5_memory_source_page_join_owner_v1.zig");
test "CPU source PAGE path bodies: durable publication and independent complete receive in both actual drivers" {
    inline for (.{ &Source.collect, &Source.publish, &Source.publishAndVerify, &Loader.init, &Loader.pageLoader, &Loader.transitionLoader, &Join.Owner.createWithSetups, &@import("prover/block_v5_cpu_source_pages_detached_receive_v1.zig").verify, &@import("prover/block_v5_cpu_capacity_driver_v1.zig").run, &@import("prover/block_v5_cpu_driver_v1.zig").run }) |body| std.mem.doNotOptimizeAway(body);
}
