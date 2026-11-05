# Outer rawmod OM31 device Fiat–Shamir: first consumer

Status: production qualification pending. This is an opt-in check path, not the completed device-resident outer prover or a measured performance improvement.

The existing `native/rv64/channel.cu` already matches production `Om31Channel`: raw Blake digest, eight raw words reduced modulo M31 per OM31 draw, and raw digest concatenated with little endian field words for mixing. The generic QM31 transcript secure draw is not substituted. The existing native PCS already owns the GPU DEEP/FRI/PoW/query suffix after its imported OODS checkpoint.

`STWO_RV64_OUTER_DEVICE_FS=check` installs an observer scoped to one exact host channel object and thread. It imports the checkpoint after `Native.begin`, records every prefix mix and draw, and compares all sixteen GPU state words and every challenge word. The before-PCS hook executes on the authoritative channel before the PCS makes its transactional copy; it disables observation for the already resident suffix. Missing observation, missing consumer, unknown modes, hybrid GKR, and global admission are refused.

The first actual consumer replays FIXED/MAIN roots and z/alpha draws, then derives the INTER parameter vector on the GPU: z followed by alpha^0 through alpha^5. The real INTER fraction kernels borrow this scoped lease instead of uploading the CPU's 56 words. CPU shadow values and the lookup sum check remain authoritative checks. The lease survives through the proof's joined stages and is released on the healthy owner path, with terminal cleanup as the error fallback. The additive helper library remains loaded until cleanup completes.

The checker replays the remaining prefix once before PCS and checks all recorded boundaries. RC alpha tables and OODS point recipes still consume host values. MAIN root publication and other existing joins remain. This code does not establish the <=10 blocking call or 75% kernel busy gates, and check mode adds diagnostic work.

The addon is explicitly loaded through `STWO_RV64_OUTER_FS_OPS_LIBRARY`; receipt fingerprints include this library independently of the frozen native image. No mode is enabled by default. Two logical proofs per GPU remain held behind the separate exact-process 28 GB gate.
