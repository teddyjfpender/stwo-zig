---
title: Native BLAKE3 arithmetic fusion census problem match
author: Teddy Pender
created_utc: 2026-09-22T05:12:46Z
---

# Native arithmetic fusion census

Measurement before changing the native BLAKE3 AIR roster. Current native parent
assembly uses verifier_arithmetic_lowering and separate multiply/linear rows;
detached_parent_arithmetic_v1 already uses the canonical dot4 and multiply-add
matchers. Reuse those exact matchers to census the five actual native graphs,
including canonical graph-output use counts, rather than inventing a new pattern
recognizer. No lowering, proof equations, key or protocol changes in this step.

Count remaining multiply/linear rows after dot4-first reservation and FMA matching.
Each dot4 removes seven internal operation rows/consume-emit pairs; each FMA removes
one. These are structural opportunities, not implemented savings or proof speedup.
Source maps and non-graph exports must be re-audited before applying fusion; current
native lowering references have no extra exports. The later typed roster/key
integration must preserve selectors, public terms and external multiplicities.

A dedicated native diagnostic target stops before parent assembly/proving, keeping
this census separate from unchanged full parent qualification. It still obtains
its graph from a real verified native BLAKE3 capture.
