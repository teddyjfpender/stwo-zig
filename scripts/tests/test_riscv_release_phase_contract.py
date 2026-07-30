import unittest

from scripts.riscv_release_gate_lib.contract import phase_errors


class PhaseContractTests(unittest.TestCase):
    @staticmethod
    def capability(*, promoted: bool = False, reason: str = "soundness gates pending") -> str:
        return (
            f"pub const adapter_release_gated = {str(promoted).lower()}; "
            'pub const adapter = "sail-rv32im-zkvm-elf"; '
            'pub const air = "sail_rv32im_zkvm_v1"; '
            'pub const isa = "rv32im"; '
            'pub const backend = "cpu"; '
            f'pub const deferred_reason = "{reason}"; '
            "pub fn requireAdmission(experimental: bool) !void { _ = experimental; }"
        )

    @staticmethod
    def registry() -> str:
        return r'''
            const riscv = @import("riscv_cpu_capabilities");
            pub const RISCV_ADAPTER_RELEASE_GATED = riscv.adapter_release_gated;
            pub fn requireRiscVAdmission(experimental: bool) !void {
                return riscv.requireAdmission(experimental);
            }
            pub fn write(writer: anytype) !void {
                if (RISCV_ADAPTER_RELEASE_GATED) try writer.print(
                    \\,{{"adapter":"{s}","air":"{s}","status":"release_gated","isa":"{s}","backends":["{s}"]}}
                , .{ riscv.adapter, riscv.air, riscv.isa, riscv.backend });
                if (!RISCV_ADAPTER_RELEASE_GATED) try writer.print(
                    \\{{"adapter":"{s}","status":"not_release_gated","isa":"{s}","backends":["{s}"],"reason":"{s}"}}
                , .{ riscv.adapter, riscv.isa, riscv.backend, riscv.deferred_reason });
            }
        '''

    def test_candidate_requires_one_reasoned_deferred_adapter_and_typed_flag(self) -> None:
        registry = self.registry()
        capability = self.capability()
        artifact = 'pub const RELEASE_STATUS = "not_release_gated";'
        cli = 'const Flag = enum { experimental }; _ = Flag.experimental; "--experimental";'
        self.assertEqual([], phase_errors("candidate", registry, capability, artifact, cli))

        self.assertIn(
            "CLI lacks the typed --experimental admission flag",
            phase_errors("candidate", registry, capability, artifact, ""),
        )
        self.assertIn(
            "RISC-V capability owner does not select the promoted phase",
            phase_errors(
                "promoted", registry, capability,
                'pub const RELEASE_STATUS = "release_gated";', cli,
            ),
        )
        self.assertIn(
            "RISC-V capability owner lacks a non-empty deferred reason",
            phase_errors("candidate", registry, self.capability(reason=""), artifact, cli),
        )

    def test_promoted_requires_atomic_registry_artifact_and_flag_transition(self) -> None:
        registry = self.registry()
        capability = self.capability(promoted=True)
        artifact = 'pub const RELEASE_STATUS = "release_gated";'
        cli = 'const Flag = enum { experimental }; _ = Flag.experimental; "--experimental";'
        self.assertEqual([], phase_errors("promoted", registry, capability, artifact, cli))

        mixed = phase_errors(
            "promoted",
            registry,
            self.capability(),
            'pub const RELEASE_STATUS = "not_release_gated";',
            cli,
        )
        self.assertTrue(any("capability owner" in error for error in mixed))
        self.assertTrue(any("RELEASE_STATUS" in error for error in mixed))

    def test_registry_requires_typed_import_alias_and_branch_wiring(self) -> None:
        artifact = 'pub const RELEASE_STATUS = "not_release_gated";'
        cli = 'const Flag = enum { experimental }; _ = Flag.experimental; "--experimental";'

        missing_import = phase_errors(
            "candidate",
            self.registry().replace('@import("riscv_cpu_capabilities")', '@import("other")'),
            self.capability(),
            artifact,
            cli,
        )
        self.assertIn(
            "registry does not import the typed RISC-V CPU capabilities",
            missing_import,
        )

        wrong_switch = phase_errors(
            "candidate",
            self.registry().replace(
                "riscv.adapter_release_gated", "riscv.some_other_switch"
            ),
            self.capability(),
            artifact,
            cli,
        )
        self.assertIn(
            "registry admission switch does not alias the RISC-V capability owner",
            wrong_switch,
        )

        missing_reason_wiring = phase_errors(
            "candidate",
            self.registry().replace("riscv.deferred_reason", '"pending"'),
            self.capability(),
            artifact,
            cli,
        )
        self.assertIn(
            "registry deferred branch is not wired to the typed RISC-V capability",
            missing_reason_wiring,
        )

    def test_capability_values_are_authoritative_not_registry_json_literals(self) -> None:
        artifact = 'pub const RELEASE_STATUS = "not_release_gated";'
        cli = 'const Flag = enum { experimental }; _ = Flag.experimental; "--experimental";'
        errors = phase_errors(
            "candidate",
            self.registry(),
            self.capability().replace('pub const isa = "rv32im";', 'pub const isa = "rv64im";'),
            artifact,
            cli,
        )
        self.assertIn("RISC-V capability isa is not rv32im", errors)


if __name__ == "__main__":
    unittest.main()
