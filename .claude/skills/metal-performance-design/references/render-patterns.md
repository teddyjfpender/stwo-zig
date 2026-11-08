# Apple GPU render and tile-memory patterns

Read this reference only for render or hybrid workloads, after the common
reference. Apple GPUs use tile-based deferred rendering, but normal compute
buffers do not inherit render-pass tile-memory behavior.

## Derive attachment actions from dataflow

For every color, depth, stencil, and resolve attachment, record its first and
last use, whether every consumed pixel is written, and whether later work needs
the result. Select actions from that table:

- Use `.dontCare` at load only when initial contents are irrelevant and every
  consumed pixel is written; initial values are undefined.
- Use `.clear` when previous contents are irrelevant but untouched pixels need a
  defined clear value.
- Use `.load` only when the pass consumes preserved attachment contents.
- Use `.dontCare` at store when no later work consumes the result.
- Use `.store`, resolve, or combined store-and-resolve only when the output must
  survive the pass. Depth/stencil commonly use `.dontCare`, but not when sampled,
  copied, or reused later.

Memoryless attachments make a pass-local lifetime explicit and reduce
system-memory storage. They cannot be loaded from or stored to system memory.
Use them only when the entire consumer lifetime fits inside the render pass and
the target feature path supports the required texture configuration.

## Spend tile memory deliberately

Programmable blending can read the current pixel's color-attachment values
inside a render pass and avoid an intermediate device-memory round trip. It is
not an arbitrary texture read, does not expose depth automatically, and does not
remove the need to prove ordering for transparency or other order-dependent
effects.

Imageblocks, tile shaders, and persistent threadgroup memory enable more complex
on-chip algorithms. Feature-gate the exact design and budget attachment bytes,
imageblock data, sample count, and other tile-local state. Never hard-code an
example such as 16x16 as the hardware tile dimension.

Merging passes can remove attachment stores, loads, and intermediate textures.
It can also increase tile-memory or register pressure, enlarge shaders, repeat
work, or constrain useful overlap. Predict both sides, inspect the resulting
pipeline and counters, and retain the merge only when end-to-end evidence wins.

## Preserve render semantics

State sorting, GPU-driven culling, pass merging, and custom blending may change
visibility or draw order. Define the required ordering, depth/stencil behavior,
blending result, sample behavior, and attachment precision before transforming
the pass graph. Keep a simpler feature fallback and compare image or domain
outputs under the workload's actual correctness tolerance.

Treat tile and GPU-driven techniques as later-stage options. First remove
unnecessary attachment traffic, hot allocation/compilation, blocking CPU
readbacks, and measured CPU encoding costs. Include command reset, compaction,
residency, empty slots, and synchronization when evaluating indirect rendering.

## Render guardrails

- Do not apply TBDR attachment rules to ordinary compute buffers.
- Do not use `.dontCare` at load unless every consumed value is overwritten.
- Do not discard depth/stencil stores when later work consumes those values.
- Do not assume programmable blending makes arbitrary order-dependent blending
  correct.
- Do not merge passes without budgeting tile memory and verifying end-to-end
  timing.
- Do not infer physical tile dimensions from sample code or a chip family name.
- Do not reorder draws merely because state changes appear expensive.

## Primary Apple sources

- [Setting render-target load and store actions](https://developer.apple.com/documentation/metal/setting-load-and-store-actions)
- [Optimize Metal Performance for Apple silicon Macs](https://developer.apple.com/videos/play/wwdc2020/10632/)
- [Harness Apple GPUs with Metal](https://developer.apple.com/videos/play/wwdc2020/10631/)
- [Optimizing GPU performance with Xcode](https://developer.apple.com/documentation/xcode/optimizing-gpu-performance/)
- [Metal Shading Language Specification](https://developer.apple.com/metal/Metal-Shading-Language-Specification.pdf)
