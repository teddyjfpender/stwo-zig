/* Package-only link shim for the CUDA context's ingress copy. Never linked
 * into a device product. The native dispatch test takes a function pointer
 * to type-check the resident controller but does not execute it. */
int stwo_exec_context_memcpy_h2d_async() { return 0; }
