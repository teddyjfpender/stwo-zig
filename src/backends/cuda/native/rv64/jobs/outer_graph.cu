// Per-class CUDA graph capture of one OuterNodeJob enqueue sequence
// (ZisK pil2-stark cuda_graph_cache.cuh pattern: capture once warm, memory
// charged per instantiated executable, failure blacklists the key). Policy
// (threshold, budget, blacklist) lives in Zig (jobs/outer_graph_cache.zig);
// this file is only the thin, stateless CUDA graph API surface.
//
// Pointer rebind: every node re-records its enqueue body under capture and
// the cached executable is refreshed with cudaGraphExecUpdate, so per-node
// buffers (staged inputs, slab, channel, arena placement) rebind without a
// re-instantiation. A topology change (update refused) is reported, and the
// caller re-instantiates. Capture records work without executing it.
#include <cuda_runtime.h>
#include <stdint.h>
#include <new>

namespace {
inline int status(cudaError_t e) { return e == cudaSuccess ? 0 : int(e); }
}

extern "C" int stwo_rv64_outer_graph_begin(void *stream) {
  if (!stream) return int(cudaErrorInvalidValue);
  return status(cudaStreamBeginCapture(static_cast<cudaStream_t>(stream),
                                       cudaStreamCaptureModeThreadLocal));
}

// Ends the capture on `stream`; on failure the stream is no longer capturing
// and *graph is null. The sticky error is cleared so the caller can run the
// body directly.
extern "C" int stwo_rv64_outer_graph_end(void *stream, void **graph) {
  if (!stream || !graph) return int(cudaErrorInvalidValue);
  cudaGraph_t g = nullptr;
  const cudaError_t e = cudaStreamEndCapture(static_cast<cudaStream_t>(stream), &g);
  if (e != cudaSuccess || g == nullptr) {
    (void)cudaGetLastError();
    if (g) cudaGraphDestroy(g);
    *graph = nullptr;
    return e == cudaSuccess ? int(cudaErrorStreamCaptureInvalidated) : int(e);
  }
  *graph = g;
  return 0;
}

// Instantiates and reports the device bytes the executable took (free-memory
// delta across instantiation; an overcharge if another stream allocated
// meanwhile, never an undercharge). The caller serializes instantiation per
// device.
extern "C" int stwo_rv64_outer_graph_instantiate(void *graph, void **exec,
                                                 uint64_t *charged) {
  if (!graph || !exec || !charged) return int(cudaErrorInvalidValue);
  size_t before = 0, after = 0, total = 0;
  const bool measured = cudaMemGetInfo(&before, &total) == cudaSuccess;
  cudaGraphExec_t x = nullptr;
  const cudaError_t e = cudaGraphInstantiate(&x, static_cast<cudaGraph_t>(graph), 0);
  if (e != cudaSuccess) {
    (void)cudaGetLastError();
    *exec = nullptr;
    return int(e);
  }
  const bool measured_after = measured && cudaMemGetInfo(&after, &total) == cudaSuccess;
  *charged = measured_after ? (before > after ? uint64_t(before - after) : 0) : UINT64_MAX;
  *exec = x;
  return 0;
}

// Rebinds a cached executable to a freshly recorded graph of the same
// topology. *updated = 1 on success; 0 when the update was refused (topology
// or node-type change): the executable is untouched and the caller
// re-instantiates.
extern "C" int stwo_rv64_outer_graph_update(void *exec, void *graph, uint32_t *updated) {
  if (!exec || !graph || !updated) return int(cudaErrorInvalidValue);
  cudaGraphExecUpdateResultInfo info{};
  const cudaError_t e = cudaGraphExecUpdate(static_cast<cudaGraphExec_t>(exec),
                                            static_cast<cudaGraph_t>(graph), &info);
  if (e == cudaErrorGraphExecUpdateFailure) {
    (void)cudaGetLastError();
    *updated = 0;
    return 0;
  }
  if (e != cudaSuccess) {
    (void)cudaGetLastError();
    *updated = 0;
    return int(e);
  }
  *updated = info.result == cudaGraphExecUpdateSuccess ? 1u : 0u;
  return 0;
}

extern "C" int stwo_rv64_outer_graph_launch(void *exec, void *stream) {
  if (!exec || !stream) return int(cudaErrorInvalidValue);
  return status(cudaGraphLaunch(static_cast<cudaGraphExec_t>(exec),
                                static_cast<cudaStream_t>(stream)));
}

// Node census of a recorded graph, for launch accounting: kernel nodes are
// the launches one graph launch replaces; total includes memcpy/memset/host.
extern "C" int stwo_rv64_outer_graph_nodes(void *graph, uint64_t *kernels,
                                           uint64_t *total) {
  if (!graph || !kernels || !total) return int(cudaErrorInvalidValue);
  size_t n = 0;
  cudaGraph_t g = static_cast<cudaGraph_t>(graph);
  cudaError_t e = cudaGraphGetNodes(g, nullptr, &n);
  if (e != cudaSuccess) return int(e);
  *total = n;
  *kernels = 0;
  if (n == 0) return 0;
  cudaGraphNode_t *nodes = new (std::nothrow) cudaGraphNode_t[n];
  if (!nodes) return int(cudaErrorMemoryAllocation);
  e = cudaGraphGetNodes(g, nodes, &n);
  for (size_t i = 0; e == cudaSuccess && i < n; ++i) {
    cudaGraphNodeType type;
    if (cudaGraphNodeGetType(nodes[i], &type) == cudaSuccess && type == cudaGraphNodeTypeKernel)
      ++*kernels;
  }
  delete[] nodes;
  return status(e);
}

extern "C" void stwo_rv64_outer_graph_destroy_graph(void *graph) {
  if (graph) cudaGraphDestroy(static_cast<cudaGraph_t>(graph));
}

extern "C" void stwo_rv64_outer_graph_destroy_exec(void *exec) {
  if (exec) cudaGraphExecDestroy(static_cast<cudaGraphExec_t>(exec));
}
