---
title: Reuse independently compiled native verifier graphs across cold and live preparation
author: Teddy Pender
created_utc: 2026-10-29T09:53:54Z
---

Target: remove native verifier composition/DEEP/FRI/arithmetic reconstruction between cold independent key setup and live witness emission. Use an opaque independently derived compiler capsule, cloned immutable graphs, fresh capture operands, and borrowed immutable Lower.Plan only through emission. No proof or witness caching. Bound the active batch with the existing request budget; clear capsules before wide proving. Default disabled. Qualify exact fixed/main rows, wires/context, proof bytes and detached receiver, no-access/access/q3, stale metadata and claim rejection. Existing caller capsule is the problem-matched implementation pattern; no unrelated library abstraction required.
