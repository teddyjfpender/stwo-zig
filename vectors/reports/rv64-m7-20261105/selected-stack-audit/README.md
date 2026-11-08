# Selected CUDA stack audit — measured names, static frames

**NO-GO for lowering the whole-request stack limit.** Both dev blocks actually launch the image's 12,544-byte secp Add witness kernel. **GO for investigating a separate recursion-phase stack policy**, subject to the activation and memory gates below. No limit was changed, no GPU job or build was launched, and two recursion lanes remain held.

The pinned production library is `a25cc3b23ae21994e01cf0e332f1f79b666c402197bc5ed84920bf7575226e45`. Its `cuobjdump -res-usage` output contains 2,804 functions. Both D2/coalesced Nsight captures contain 516 distinct launched kernel names; all 516 map exactly by mangled name to that image. `raw-resource-map.json` preserves the complete resource output and both complete selected-name censuses. `receipt.json` binds the image, resource output and SQLite hashes, phase windows, counts and top functions.

| Scope | Block | Kernel names | Calls | Sum kernel GPU-s | Largest static frame |
|---|---:|---:|---:|---:|---:|
| Entire recorded cold+warm capture [M] | 26235156 | 516 | 97,692 | 16.304567 | 12,544 B |
| Entire recorded cold+warm capture [M] | 24628607 | 516 | 143,838 | 21.158939 | 12,544 B |
| After-native cold [M] | 26235156 | 94 | 23,268 | 4.991695 | 680 B |
| After-native warm [M] | 26235156 | 94 | 23,268 | 5.000175 | 680 B |
| After-native cold [M] | 24628607 | 94 | 29,822 | 6.197873 | 680 B |
| After-native warm [M] | 24628607 | 94 | 29,822 | 6.204127 | 680 B |

Phase windows are the existing accepted ownership receipt's after-native windows, including its 5 ms uncertainty band. GPU-seconds are sums of selected kernel durations, not wall time or a new performance measurement; they recover the published phase totals exactly up to floating-point rounding. All four phase captures declare complete kernel activity.

The whole-request maximum is `secp::witness<Add>`: four calls in each cold+warm capture, 0.111809 GPU-s small and 0.121985 GPU-s headline. Other active high frames include `rv64_truth_domain_0_shard_47` (11,664 B, six calls, 0.407488/0.577486 GPU-s), `rv64_joined_domain_44_shard_26` (9,040 B, eight/twelve calls), and `secp::witness<Double>` (8,944 B, four calls). These cannot be removed from admission as unused functions.

After native, the maximum is `circuit_base::generate<4>` at 680 B (15/19 calls per small/headline trial). The other nonzero selected frames are sample-prefill 128 B, assignment chain-run 56 B and PoW search 40 B. This is observed coverage of these exact two source/profile/geometry configurations; it does not authorize arbitrary class geometries or different backends.

Nsight `localMemoryPerThread` is zero for these records and `localMemoryTotal` contains signed-overflow values. Neither is used as a stack-size measurement. Frames come from the exact selected cubin's resource table.

## Model and activation boundary

Using the repository's existing RTX5090 model, 170 SM × 1,536 resident threads × 12,544 B = 3,275,489,280 B. A 1,024 B phase policy models 267,386,880 B, a difference of **3,008,102,400 B [MODEL]** per physical context. This is not measured reclaimed memory, an exact process peak or evidence that the 28,000,000,000 B gate passes. Native's larger stack still contributes to the whole-request peak.

The existing arena initialization only raises the CUDA stack limit and then auto-carves available memory. A later policy must not expand the arena after lowering the stack. Before changing a limit it must close native production and join all GPU work across the physical context, reject overlapping native/admission work, and pin an independently enumerated source/class kernel contract. After setting the candidate limit it must read back the driver's actual rounded value and measure whether memory was reclaimed. Before the next native request it must restore and verify the larger requirement. Failure is terminal. New classes/backends require a fresh admission census.

CUDA 12.8 documents that launches automatically increase stack requirements and do not reset them after a launch; explicit `cuCtxSetLimit` takes effect immediately and may synchronize. Local-memory resize-to-maximum behavior is the default and cannot be disabled. Therefore neither automatic shrinking nor an exact byte saving follows from this census. See [NVIDIA's context-management contract](https://docs.nvidia.com/cuda/archive/12.8.0/cuda-driver-api/group__CUDA__CTX.html).

Any later activation still requires both-dev full proof parity, fresh receivers, memcheck, and an exact whole-process peak at or below 28 GB before trying two lanes. No such activation or gate is claimed here.

## P1 independent review checkpoint

The new `outer_fs_lookup_params_on` helper matches Core OM31 `Witness.Elements`: z then alpha^0 through alpha^5. Its wrapper rejects overlapping writable/input ranges, host/foreign/retired pointers and bad geometry before enqueue. Root's independent Core corpus and GPU/memcheck receipts remain the qualification authority.

Review found a blocking observer handoff: the generic PCS wrapper copies the authoritative channel before passing it to the device stage, so a hook inside `pcs_native.prove` misses an observer pinned to the original object. The implementation owner moved the hook into the exact OM31 branch immediately before that copy. The consumer's recorder-owned parameter lease is generation/scope-checked, survives INTER, and is released after joined proof work. This is a check-mode replay with a real INTER device-parameter consumer; composition/OODS host consumers and full P1 performance gates remain open.
