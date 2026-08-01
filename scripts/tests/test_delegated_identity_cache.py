#!/usr/bin/env python3
"""Regression-test Git identity invalidation across the delegated build cache."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[2]


ROOT_BUILD = r'''const std = @import("std");
const delegation = @import("build_support/graph/delegation.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    delegation.addProxy(
        b,
        target,
        optimize,
        delegation.Options.read(b),
        "identity-probe",
        "Emit the delegated identity probe",
        "probe",
    );
}
'''


INTERNAL_BUILD = r'''const std = @import("std");
const build_identity = @import("build_identity.zig");

pub fn build(b: *std.Build) void {
    const repository_root = b.option([]const u8, "repository-root", "fixture root") orelse
        @panic("missing repository root");
    _ = b.option([]const u8, "product-scope", "fixture scope") orelse
        @panic("missing product scope");
    _ = b.standardTargetOptions(.{});
    _ = b.standardOptimizeOption(.{});

    const commit = b.option([]const u8, "implementation-commit", "source commit");
    const dirty = b.option(bool, "implementation-dirty", "source dirty");
    const tree = b.option([]const u8, "implementation-tree", "source tree");
    const dirty_digest = b.option(
        []const u8,
        "implementation-dirty-content-sha256",
        "dirty digest",
    );
    if ((commit == null) != (dirty == null)) @panic("partial identity override");
    const source = build_identity.resolveWithOverride(
        b.allocator,
        repository_root,
        if (commit) |value| .{
            .commit = value,
            .tree = tree,
            .dirty = dirty.?,
            .dirty_content_sha256 = dirty_digest,
        } else null,
    ) catch @panic("cannot resolve fixture identity");
    const source_tree = source.implementation_tree orelse @panic("missing source tree");
    const digest = if (source.dirty_content_sha256) |value|
        std.fmt.bytesToHex(value, .lower)
    else
        [_]u8{'0'} ** 64;
    const encoded = b.fmt(
        "{{\"commit\":\"{s}\",\"tree\":\"{s}\",\"dirty\":{}," ++
            "\"dirty_content_sha256\":\"{s}\"}}\n",
        .{ &source.implementation_commit, &source_tree, source.implementation_dirty, &digest },
    );
    const generated = b.addWriteFiles().add("identity.json", encoded);
    const install = b.addInstallFile(generated, "identity.json");
    b.step("identity-probe", "Emit identity").dependOn(&install.step);
}
'''


class DelegatedIdentityCacheTest(unittest.TestCase):
    def git(self, repository: Path, *arguments: str) -> str:
        result = subprocess.run(
            ["git", *arguments],
            cwd=repository,
            text=True,
            capture_output=True,
            check=True,
        )
        return result.stdout.strip()

    def commit(self, repository: Path, message: str, *, allow_empty: bool = False) -> None:
        arguments = [
            "-c",
            "user.name=Identity Cache Test",
            "-c",
            "user.email=identity-cache@example.invalid",
            "commit",
            "-qm",
            message,
        ]
        if allow_empty:
            arguments.append("--allow-empty")
        self.git(repository, *arguments)

    def build(
        self,
        repository: Path,
        prefix: Path,
        *,
        cpu: str | None = None,
    ) -> tuple[dict[str, object], str]:
        command = [
            "zig",
            "build",
            "identity-probe",
            "-p",
            str(prefix),
            "--verbose",
        ]
        if cpu is not None:
            command.append(f"-Dcpu={cpu}")
        result = subprocess.run(
            command,
            cwd=repository,
            text=True,
            capture_output=True,
            check=True,
        )
        return (
            json.loads((prefix / "identity.json").read_text()),
            result.stdout + result.stderr,
        )

    def test_commit_tree_and_dirty_content_invalidate_delegated_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="stwo-delegated-identity-") as raw:
            repository = Path(raw) / "repository"
            prefix = Path(raw) / "prefix"
            (repository / "build_support/graph").mkdir(parents=True)
            shutil.copy2(
                REPOSITORY / "build_support/build_identity.zig",
                repository / "build_support/build_identity.zig",
            )
            shutil.copy2(
                REPOSITORY / "build_support/graph/delegation.zig",
                repository / "build_support/graph/delegation.zig",
            )
            (repository / "build.zig").write_text(ROOT_BUILD)
            (repository / "build_support/internal_build.zig").write_text(INTERNAL_BUILD)
            (repository / "README.md").write_text("baseline\n")
            (repository / ".gitignore").write_text(".zig-cache/\nzig-out/\n")
            self.git(repository, "init", "-q")
            self.git(repository, "add", ".")
            self.commit(repository, "baseline")

            baseline, baseline_build = self.build(repository, prefix)
            self.assertIn(
                f"-Dimplementation-commit={baseline['commit']}", baseline_build
            )
            self.assertIn(f"-Dimplementation-tree={baseline['tree']}", baseline_build)
            self.assertIn("-Dimplementation-dirty=false", baseline_build)

            _, cpu_build = self.build(repository, prefix, cpu="baseline")
            self.assertIn("-Dcpu=baseline", cpu_build)

            self.commit(repository, "identity-only", allow_empty=True)
            commit_only, commit_build = self.build(repository, prefix)
            self.assertIn(
                f"-Dimplementation-commit={commit_only['commit']}", commit_build
            )
            self.assertNotEqual(baseline["commit"], commit_only["commit"])
            self.assertEqual(baseline["tree"], commit_only["tree"])
            self.assertFalse(commit_only["dirty"])

            (repository / "README.md").write_text("new committed tree\n")
            self.git(repository, "add", "README.md")
            self.commit(repository, "tree change")
            tree_change, tree_build = self.build(repository, prefix)
            self.assertIn(f"-Dimplementation-tree={tree_change['tree']}", tree_build)
            self.assertNotEqual(commit_only["commit"], tree_change["commit"])
            self.assertNotEqual(commit_only["tree"], tree_change["tree"])
            self.assertFalse(tree_change["dirty"])

            (repository / "README.md").write_text("dirty one\n")
            dirty_one, dirty_one_build = self.build(repository, prefix)
            self.assertIn("-Dimplementation-dirty=true", dirty_one_build)
            self.assertIn("-Dimplementation-dirty-content-sha256=", dirty_one_build)
            (repository / "README.md").write_text("dirty two\n")
            dirty_two, dirty_two_build = self.build(repository, prefix)
            self.assertIn(
                f"-Dimplementation-dirty-content-sha256="
                f"{dirty_two['dirty_content_sha256']}",
                dirty_two_build,
            )
            self.assertTrue(dirty_one["dirty"])
            self.assertTrue(dirty_two["dirty"])
            self.assertNotEqual(
                dirty_one["dirty_content_sha256"],
                dirty_two["dirty_content_sha256"],
            )


if __name__ == "__main__":
    unittest.main()
