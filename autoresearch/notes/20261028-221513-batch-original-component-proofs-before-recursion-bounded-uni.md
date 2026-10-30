---
title: Batch original component proofs before recursion: bounded union versus row batching
author: Teddy Pender
created_utc: 2026-10-28T22:15:13Z
---

Problem match: exact random-linear-combination batching of AIR identities and PCS openings, with separate bounded-memory scheduling. Detailed pre-implementation brief and qualification plan: design/riscv-proving-stack/performance/v7-heterogeneous-original-stark-20261029.md. Reproducible existing-run census: vectors/reports/block-v7-heterogeneous-design-20261029/receipt.json and verifier-census.tsv. Current active-caller 20,495-cycle diagnostic root: 62.981 s, 11 originals, 650,166 recursive arithmetic rows, 2,622,592 G rows. Caller contributes 79.7% of arithmetic. Core supports heterogeneous component proofs and retained-tree adoption already; fixed-tree remapping, exact new transcript/source cover and bounded source lifetimes are required. Fusion removes proof shells, not automatically column-wise work. Row batching is the stronger scaling hypothesis. No new protocol, proof run or performance claim; production paths unchanged.
