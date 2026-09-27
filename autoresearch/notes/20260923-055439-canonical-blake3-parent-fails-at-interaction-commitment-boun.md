---
title: Canonical BLAKE3 parent fails at interaction commitment; bound coefficient and batch residency
author: Teddy Pender
created_utc: 2026-09-23T05:54:39Z
---

# Bound canonical BLAKE3 parent commitment residency

Status: implemented; canonical Metal AOT gate compiling, not qualified.

The checked-allocator baseline passed leaf CPU verification, parent preparation,
key admission and interaction generation, but exceeded the 36 GiB worker cap at
interaction commitment. It retained 10,150,562,296 prepared bytes outside the
worker. Tracked worker peak before refusal was 36,176,603,674 bytes.

Parent plans and proofs now select the core PCS `.never` coefficient-retention
policy: committed extended-domain columns supply openings without a second
persistent coefficient copy. Interaction commitment uses existing owned streaming
PCS with eight columns per preparation batch, including Metal (which otherwise
prefers monolithic commitment). Original column indices, roots, transcript and
70-query/26-PoW parameters must remain unchanged. The worker cap stays 36 GiB.

The gate includes the allocator-authority fix; it uses the checked allocator.
A successful stateless-allocator parent run remains separate work. CPU verification
and real Metal dispatches during parent proving are required by the fixture.
No lower peak, speedup or completed proof is claimed until the run completes.
