# Shared Native transaction helpers

[`transaction.zig`](transaction.zig) implements proof and benchmark
publication for the focused Native and aggregate CLIs. It prepares output
paths, delegates proving to the selected runner, and publishes the result
with the shared [output transaction helpers](../../support/README.md).

[`product_identity.zig`](product_identity.zig) maps the build-generated
product identity into the runtime record. These files are wired by the
product build as internal modules. The [Native product](../../products/native/README.md)
documents the CLI and package entry points.
