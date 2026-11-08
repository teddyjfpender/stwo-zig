"""Shared constants and value types for the C-013 capture boundary."""

from __future__ import annotations

import re


PLAN_SCHEMA = "stwo.typed-air.c013-capture-plan.v1"
PLAN_SCHEMA_VERSION = 1
PROTOCOL_SCHEMA = "stwo-typed-air-m5-m9-performance-protocol-v1"
SCHEDULE_SHA256 = (
    "20153896cdcc903d6784499fba267f0ff5c8e532573b9b415b28121352775dd4"
)
CORPUS_MANIFEST_SHA256 = (
    "91c9f0b4a0efc9620739eb7fd18c940852ffadce85889aa1af598e360c6fc903"
)
CORPUS_DIGESTS = {
    0: (
        "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    1: (
        "eb07af873dd1211b8e033da3093a2c51c1a8dee325e13e9497dbda1549222d4b",
        "0c425365ef3800a7bcd30f37b94cdf08f1ab3028a87b7dbc00749b6bb5087d06",
    ),
    8: (
        "efcf4956a010c85866868b5e45f712980addd512f4d0462d54df2115e0ed6e82",
        "e22e1f8b0f013b325ccc527005fa2be2eb524a4930b4dab853d5fd9309cc567d",
    ),
    64: (
        "b471155f881907d2c0abbf09eb6b48e84175eed95ccabfdae45c7d2d154b6c9c",
        "e0e1c7ad0501674270f0e5e931840d34cdfa51bfdf779c49729ca839894c7319",
    ),
    512: (
        "046883825581c7a2a113bd7a7712212047905ba7e650a8062e17695dc3970124",
        "9ae5674ce75b471a11d92dbb96cbe74bced8e9c293d42bd8cc20c181f6412a16",
    ),
    4096: (
        "ff798e2438279ac57ab9ea8cb7d5816d4500f628850e00c02c202f2eb32455ca",
        "52d315c0e5c036e672f2462c4c35245b6f4eed5fa0e581ea3917e15fa83f7208",
    ),
}
PROTOCOL_PATH = "design/typed-air/performance/m5-m9-protocol-v1.json"
PROTOCOL_SHA256 = (
    "7c213ae7c35ac8f60f204fba8fa96357195186a29a6a626c0a67fd47984cf985"
)
PRIMARY_TARGET = {
    "lane": "cpu-native",
    "workload": "poseidon2_dominant:calls=4096",
    "metric": "verified_request_speed",
    "decision": "lower_ci_greater_than_or_equal",
    "threshold": 1.10,
}
ENVIRONMENT = {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
SESSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
GIT_OID_RE = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")


class CaptureError(RuntimeError):
    """The requested plan or evidence is not admissible."""
