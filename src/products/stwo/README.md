# Stwo library and aggregate facade

[`root.zig`](root.zig) defines the `stwo` facade. Its primary exports are
`core`, `backend`, `prover_api`, `proof_wire`, `recursion_wire` and `prover`.
The [waist guide](../../waist/README.md) and [engine guide](../../engine/README.md)
document the underlying package APIs. The facade's legacy namespaces support
existing aggregate consumers. New consumers can use the named package modules.

Use `zig build stwo-core` or `zig build stwo-prover` for the focused library
builds, and `zig build stwo-zig` for the aggregate CLI. See the
[product matrix](../../../README.md#product-support) for host support.
