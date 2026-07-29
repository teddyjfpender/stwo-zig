import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "autoresearch" / "backend"))
sys.path.insert(0, str(ROOT / "autoresearch" / "cli"))

import server  # noqa: E402
from store import Store  # noqa: E402
from stwo_perf import feed as feed_mod  # noqa: E402


IDENTITY = {
    "github_id": 101, "login": "alice", "name": "Alice",
    "profile_url": "https://github.com/alice",
    "noreply_email": "101+alice@users.noreply.github.com",
}
CLAIM = {"board": "core_cpu", "workload_class": "small",
         "dimension": "time", "shipping_index": 0.9}
NOTE = """# Faster field loop

## Model and harness
Agent and stwo-perf.
## Hypothesis
Fewer loads.
## Changes
Loop change.
## Results
Public R 0.9.
## Caveats
Central judge pending.
"""


def submission_payload():
    receipt = {
        "schema_version": 1,
        "candidate_commit": "b" * 40,
        "frontier_commit": "a" * 40,
        "candidate_tree": "c" * 40,
        "changed_paths": ["src/core/fields/value.zig"],
        "patch_bytes": 123,
        "patch_digest": "sha256:" + "d" * 64,
        "locked_tree_digest": "sha256:" + "e" * 64,
        "submitter_login": "alice",
        "checks": {
            "allowed_diff": True, "locked_tree": True, "source_modes": True,
            "harness_tests": True, "release_build": True, "public_benchmark": True,
        },
        "claim": dict(CLAIM), "workflow": {},
    }
    return {
        "schema_version": 2,
        "source": {
            "repository": "https://github.com/alice/stwo-zig-fork",
            "commit": "b" * 40, "frontier_commit": "a" * 40,
            "ref": "refs/heads/faster",
        },
        "qualification": {
            "receipt": receipt,
            "attestation": {
                "artifact_digest": "sha256:" + "f" * 64,
                "url": "https://github.com/alice/stwo-zig-fork/attestations/1",
            },
        },
        "claim": dict(CLAIM), "note": NOTE, "coauthors": [],
    }


class BackendServerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "store.json")
        self.handler = server.make_handler(
            ROOT, b"s" * 32, self.store, "client-id",
            identity_resolver=lambda _token: dict(IDENTITY),
        )

    def tearDown(self):
        self.tmp.cleanup()

    def call(self, method, path, body=None, credential=None):
        raw = json.dumps(body).encode() if body is not None else b""
        headers = [
            f"{method} {path} HTTP/1.1", "Host: backend.test",
            f"Content-Length: {len(raw)}",
        ]
        if credential:
            headers.append(f"Authorization: Bearer {credential}")
        request_bytes = ("\r\n".join(headers) + "\r\n\r\n").encode() + raw

        class FakeSocket:
            def __init__(self, data):
                self.reader = io.BytesIO(data)
                self.output = bytearray()

            def makefile(self, mode, _buffering=None):
                if "r" in mode:
                    return self.reader
                return io.BytesIO()

            def sendall(self, data):
                self.output.extend(data)

            def shutdown(self, _how):
                pass

            def close(self):
                pass

        class FakeServer:
            server_name = "backend.test"
            server_port = 80

        sock = FakeSocket(request_bytes)
        self.handler(sock, ("127.0.0.1", 1), FakeServer())
        head, payload = bytes(sock.output).split(b"\r\n\r\n", 1)
        status = int(head.split(b" ", 2)[1])
        return status, json.loads(payload)

    def test_feed_route_serves_the_committed_contract_document(self):
        status, feed = self.call("GET", "/v1/feed")
        self.assertEqual(status, 200)
        # Identical to the committed file: one contract, two transports.
        committed = json.loads(
            (ROOT / "autoresearch" / "site" / "feed.json").read_text()
        )
        self.assertEqual(feed, committed)
        self.assertEqual(feed["feed_schema_version"], feed_mod.FEED_SCHEMA_VERSION)
        self.assertIn("promotion_scope", feed)
        self.assertIn("inputs_sha256", feed["provenance"])

    def test_frontier_classes_are_derived_from_manifest_board_exposure(self):
        status, response = self.call("GET", "/v1/frontier/core_cpu/xlarge")
        self.assertEqual(status, 200)
        self.assertEqual(response["class"], "xlarge")

        status, response = self.call("GET", "/v1/frontier/riscv/xlarge")
        self.assertEqual(status, 400)
        self.assertIn("does not expose", response["error"])

        status, response = self.call("GET", "/v1/frontier/core_cpu/invented")
        self.assertEqual(status, 400)
        self.assertIn("unknown workload class", response["error"])

    def test_api_key_drives_cli_identity_submission_status_and_revocation(self):
        status, issued = self.call("POST", "/v1/auth/github/keys", {}, "github-device-token")
        self.assertEqual(status, 200)
        key = issued["key"]
        self.assertIn("submissions:write", issued["scopes"])
        status, me = self.call("GET", "/v1/me", credential=key)
        self.assertEqual(status, 200)
        self.assertEqual(me["identity"]["github_id"], 101)

        status, response = self.call("POST", "/v1/submissions", submission_payload(), key)
        self.assertEqual(status, 201)
        created = response["submission"]
        self.assertEqual(created["state"], "received")
        status, response = self.call("GET", "/v1/submissions", credential=key)
        self.assertEqual(status, 200)
        listed = response["submissions"]
        self.assertEqual([item["id"] for item in listed], [created["id"]])
        status, response = self.call(
            "GET", f"/v1/submissions/{created['id']}", credential=key,
        )
        self.assertEqual(status, 200)
        detail = response["submission"]
        self.assertEqual(detail["source"]["commit"], "b" * 40)

        status, response = self.call(
            "POST", f"/v1/submissions/{created['id']}/withdraw", {}, key,
        )
        self.assertEqual(status, 200)
        withdrawn = response["submission"]
        self.assertEqual(withdrawn["state"], "withdrawn")
        status, response = self.call("POST", "/v1/keys/revoke", {}, key)
        self.assertEqual(status, 200)
        self.assertTrue(response["revoked"])
        status, _ = self.call("GET", "/v1/me", credential=key)
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
