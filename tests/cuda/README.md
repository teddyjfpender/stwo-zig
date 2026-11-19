# CUDA tests

| Directory | Coverage |
| --- | --- |
| [`native/`](native/README.md) | Native CUDA host contracts and device smoke harnesses |
| [`cumetal/`](cumetal/) | Cairo CUDA execution harnesses |
| [`runtime/`](runtime/) | CUDA runtime policy checks |
| [`rv64/`](rv64/README.md) | RV64 CUDA execution, PCS and recursion tests |
| [`fixtures/`](fixtures/) | Shared test data also read by the Cairo frontend and integration tests |

The [CUDA backend guide](../../src/backends/cuda/README.md) describes the
backend's interfaces and hardware requirements.
