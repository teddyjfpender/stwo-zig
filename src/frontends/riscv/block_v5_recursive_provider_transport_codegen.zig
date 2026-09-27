//! All real provider publication/strict fresh loader bodies; never invoked.
const std = @import("std");
const Transport = @import("prover/block_v5_recursive_provider_store_v1.zig");
pub export fn stwo_recursive_provider_transport_body_gate() void {
    inline for (.{ Transport.Family.range16, Transport.Family.ram_lanes, Transport.Family.program_table, Transport.Family.native_lookup }) |family| {
        const T = Transport.ForFamily(family);
        const D = @import("prover/block_v5_recursive_provider_definition_v1.zig").ForFamily(family);
        const Stage = D.Stage.ForBackend(@import("stwo_cpu_backend").CpuBackend);
        std.mem.doNotOptimizeAway(&Stage.publish);
        const Catalog = @import("prover/block_v5_recursive_provider_templates_v1.zig").ForFamily(family);
        inline for (.{ &Catalog.init, &Catalog.intern, &Catalog.deinit }) |body| std.mem.doNotOptimizeAway(body);
        inline for (.{ &T.Store.initWriter, &T.Store.initReader, &T.Store.put, &T.Store.takeFresh, &T.Store.requireVerified, &T.Store.sink }) |body| std.mem.doNotOptimizeAway(body);
    }
}
