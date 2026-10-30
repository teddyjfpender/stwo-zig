---
title: Bounded native LogUp batch inversion and invariant quotient normalization
author: Teddy Pender
created_utc: 2026-10-29T07:25:50Z
---

Task and required semantics: generate each existing typed LogUp fraction and its canonical logical-order prefix exactly; every physical claim, AIR and transcript unchanged. Optimize composition only by invariant arithmetic removal.
Inputs/model: canonical mixed421 has 17.05s native interaction preparation and 37.52s composition. Sample /tmp/v7-deep-profile-421-20261029/sample.txt places 4,699 inclusive samples in native projection domain evaluation. Field arithmetic over QM31; trace sizes powers of two; no denominator-zero promise may be silently assumed.
Structure: each denominator inverse independent, same domain-size normalization reused at every quotient row. Existing core batchInverseInPlace is strict on zero, unlike zero-skipping external implementations.
Candidates: scalar inversion exact O(n inversions), no extra scratch; tiled Montgomery batch exact O(n multiplications + ceil(n/B) inversions), bounded scratch; whole-trace inversion same operation reduction but unbounded incremental storage. Selected tiled B=4096 initially; no new parallel lease until measured.
Mapping: original request numerator/denominator -> denominator tile -> existing core batch inverse -> identical numerator*inverse term; recover same sum and prefix in unchanged logical order. No dropping zero numerators and no aggregated claims substituted.
Complexity: O(n) arithmetic, O(B) extra temporary fields, 1 inversion/tile. Sourced Montgomery implementation: https://github.com/arkworks-rs/algebra/blob/master/ff/src/fields/mod.rs; reuse local src/core/fields/mod.zig, not copied code. External zero handling is deliberately not transferred.
Integration: hoist column shape checks, use typed original Source.fromCommittedMain unchanged. Composition normalize claim once before loop, original point evaluator stays exact. Encoding research methods suggest first remove passes; proposed cell encodings would require new AIR and are rejected for this stream.
Prediction/falsifier: substantial interaction improvement if inversions matter; modest composition improvement from invariant divide. No end-to-end magnitude promised. If typed entry reconstruction dominates, next specialize/batch original extraction, measured separately.
Correctness: all families and custody modes against scalar inversion reference, original domain-vs-point parity, malformed geometry/zero denominator/allocation errors, complete proof byte parity then same-source full benchmark. Timing controlled by root; correctness runs unranked.
Uncertainty: exact inversion share of early interaction not sampled; first bounded kernel and matched measurements will settle it.

Implementation qualification (not a throughput measurement):
- ReleaseSafe focused gate: 328 passed, 1 unrelated skip, 0 failed; /tmp/v7-native-base-run.log, binary /tmp/v7-native-projection-base.
- Additional sample-supported transfer: use original caller-owned typed lookup builders; avoid large by-value list returns. Base-domain requests use existing semantic_eval.BaseScalar and existing combineBase; secure OODS and symbolic evaluators retain the original secure-field builder.
- Same partition/ordinal/arity validation body is shared between secure and base routes. Exact all-family/mode secure-vs-base quotient parity and scalar-vs-tiled physical prefix parity passed.
- Optional scoped WorkPool tiles use a nonblocking lease, no worker allocation, joined lifetime and serial fallback when another lease owns capacity. Three workers exercise uneven 32768-row partitions. Scratch is bounded by two 4096-element QM31 buffers per worker (128 KiB/worker), in addition to the original prefix/term storage.
- Malformed geometry and zero-denominator requests reject; all-zero challenge fixture retains arities so it reaches the actual inverse error. Nested lease fallback returns exact columns.
- Full same-contract proof timing and byte-equivalence under the integrated daily harness remain root-coordinated pending checks. No measured end-to-end improvement is claimed here.
