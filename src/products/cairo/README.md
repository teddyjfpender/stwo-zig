# Cairo products

This line owns the Cairo command-line applications and recursion products.
[`cpu/`](cpu/), [`metal/`](metal/) and [`cuda/`](cuda/) bind a runtime to the
Cairo frontend. The canonical user commands and backend qualification scope
are in the [Cairo quick start](../../../README.md#cairo-frontend).

- [CPU circuit recursion](recursion/circuit_cpu/README.md) documents the fold-tree
  and circuit-parameter CLI.
- [Metal circuit recursion](recursion/metal/README.md) documents the equivalent
  Metal product and its device requirements.
- The [Cairo frontend guide](../../frontends/cairo/README.md) documents
  `stwo_cairo_frontend` for library consumers.
