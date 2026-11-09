# C3 mechanical leaf-import checkpoint — PARTIAL / NOT ACCEPTED

This import-only continuation is based on `d469068b5113f3937a4bffcb75ddc4409f641aee`.
C4 explicitly owns the old-umbrella canonical records and typed Owner foundation;
C3 owns only the eleven consumer files listed in the adjacent receipt. There is
no new provider, API surface, dependency, schema, error, test owner or launcher.
The original-main/C2-canonical replay map is data in that receipt, so the same
sixteen exact imports can be replayed after C4 without projecting package names
into C4's source.

The actual read-only checker changed from FAIL 334 findings to FAIL 318 findings:
sixteen removed, zero introduced. The source classification before this slice
was 173 test-composition occurrences, 57 direct product-policy occurrences and
102 generic-owner/barrel occurrences, plus two README findings. This patch only
removes sixteen of the generic-owner occurrences. All policy and test ownership
cuts remain open. Do not treat this tree as accepted or mergeable.

All eleven files pass Zig AST checks (syntax only). Bytes outside the listed
import expressions are exact; the one inline test body in the changed files is
byte-identical. Named source tests remain 3225. The existing aggregate floor is
1103; its actual execution remains UNRUN. Target-tree `scripts/dev_test.py
--dry-run` selects the three existing package-owned commands (PLAN only).
Debug/ReleaseFast CPU, full package tests, nominal type acceptance and frozen
Native proof identity remain UNRUN. No GPU or heavy laptop build was run.

Complexity budget relative to the checkpoint parent:
code +16 / -16 / net 0; flags +0 / -0 / live 249 (286 registered); scripts +0 / -0.
Documentation and the adjacent JSON receipt are separate. Cumulative C3 code is
+14329 / -11897 / net +2432 within the approved +4000 ceiling; moves receive no
removal credit. The patch consumes no additional net allowance. Do not replay
the rejected broad alias renderer or the synthetic test-access extractor.
